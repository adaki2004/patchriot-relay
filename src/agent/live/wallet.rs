//! Login-only EIP-4361/EIP-191 signing. An ephemeral, unfunded key stays in this
//! broker and is discarded after one attempt. There is no model signing tool,
//! imported key, chain RPC, typed-data signer or transaction submission path.
use super::*;
use chrono::DateTime;
use k256::ecdsa::SigningKey;
use sha3::Keccak256;
use zeroize::Zeroizing;

impl LiveBroker {
    pub(super) async fn start_wallet_session(
        &self,
        login: &WalletLogin,
    ) -> Result<(), &'static str> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| "wallet_key_unavailable")?;
        let key = SigningKey::from_slice(seed.as_ref()).map_err(|_| "wallet_key_unavailable")?;
        drop(seed);
        let address = wallet_address(&key);
        let origin = &self.scope.origins[0];
        let mut request = json!({"address": address});
        if let Some(network) = &login.network {
            request["network"] = json!(network);
        }
        let challenge = self.wallet_post(&login.challenge_path, request).await?;
        let message = challenge["message"]
            .as_str()
            .ok_or("wallet_challenge_invalid")?;
        let nonce = challenge["nonce"]
            .as_str()
            .ok_or("wallet_challenge_invalid")?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "wallet_clock_unavailable")?
            .as_secs() as i64;
        validate_message(message, nonce, origin, &address, login.chain_id, now)?;
        // Sign the exact bytes, never a reconstructed or model-edited message.
        let signature = sign_login(&key, message);
        drop(key);
        self.access.remember_secret(signature.clone());
        self.access.remember_secret(nonce.to_owned());
        let mut verification = match login.verify_payload {
            WalletVerifyPayload::NonceSignature => json!({"nonce":nonce,"signature":signature}),
            WalletVerifyPayload::MessageSignature => {
                json!({"message":message,"signature":signature})
            }
        };
        if login.include_address {
            verification["address"] = json!(address);
        }
        self.wallet_post(&login.verify_path, verification).await?;
        let check = public_url(&format!(
            "{origin}{}",
            self.scope
                .auth_check_path
                .as_deref()
                .ok_or("invalid_login_scope")?
        ))?;
        if self.access.cookies(&check, true).is_none() {
            return Err("login_session_missing");
        }
        // The ordinary protected GET and its anonymous control prove access.
        // A successful verification response or a binding cookie alone does not.
        Ok(())
    }

    async fn wallet_post(&self, path: &str, body: Value) -> Result<Value, &'static str> {
        let origin = &self.scope.origins[0];
        let response = self
            .exchange(
                Probe {
                    method: "POST".into(),
                    url: format!("{origin}{path}"),
                    headers: [
                        ("content-type".into(), "application/json".into()),
                        ("origin".into(), origin.clone()),
                    ]
                    .into(),
                    data: Some(body.to_string()),
                    authenticated: true,
                },
                true,
            )
            .await?;
        if !response["evidence"]["error"].is_null()
            || !response["evidence"]["status"]
                .as_u64()
                .is_some_and(|s| (200..300).contains(&s))
            || response["body_truncated"] == true
            || !response["login_redirect"].is_null()
        {
            return Err("wallet_login_rejected");
        }
        let body = response["body"].as_str().unwrap_or("");
        // A verify endpoint may return an empty 204 with a session cookie.
        if body.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(body).map_err(|_| "wallet_challenge_invalid")
    }
}

fn wallet_address(key: &SigningKey) -> String {
    let point = key.verifying_key().to_sec1_point(false);
    let digest = Keccak256::digest(&point.as_bytes()[1..]);
    let lower = hex::encode(&digest[12..]);
    let checksum = hex::encode(Keccak256::digest(lower.as_bytes()));
    let address: String = lower
        .bytes()
        .zip(checksum.bytes())
        .map(|(c, h)| {
            if h >= b'8' {
                (c as char).to_ascii_uppercase()
            } else {
                c as char
            }
        })
        .collect();
    format!("0x{address}")
}

fn sign_login(key: &SigningKey, message: &str) -> String {
    let mut digest = Keccak256::new();
    digest.update(format!("\x19Ethereum Signed Message:\n{}", message.len()));
    digest.update(message.as_bytes());
    let (signature, recovery) = key.sign_prehash_recoverable(&digest.finalize());
    format!(
        "0x{}{:02x}",
        hex::encode(signature.to_bytes()),
        27 + recovery.to_byte()
    )
}

/// A deliberately small SIWE subset: HTTPS origin, EOA, one chain, fresh nonce,
/// issued-at and <=10-minute expiry. Resources, request IDs, extra fields and
/// arbitrary signing formats are not login capabilities for this runner.
fn validate_message(
    message: &str,
    nonce: &str,
    origin: &str,
    address: &str,
    chain: u64,
    now: i64,
) -> Result<(), &'static str> {
    let invalid = "wallet_challenge_not_login";
    if message.len() > 4096
        || !message.is_ascii()
        || message.bytes().any(|b| b.is_ascii_control() && b != b'\n')
        || !(8..=128).contains(&nonce.len())
        || !nonce.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        return Err(invalid);
    }
    let mut lines = message.split('\n');
    let authority = origin.strip_prefix("https://").ok_or(invalid)?;
    let header = lines.next().ok_or(invalid)?;
    if header != format!("{authority} wants you to sign in with your Ethereum account:")
        && header != format!("{origin} wants you to sign in with your Ethereum account:")
    {
        return Err(invalid);
    }
    if lines.next() != Some(address) || lines.next() != Some("") {
        return Err(invalid);
    }
    let statement = lines.next().ok_or(invalid)?;
    if !statement.is_empty()
        && (statement.len() > 512
            || !statement
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~:/?#[]@!$&'()*+,;=% ".contains(&b))
            || lines.next() != Some(""))
    {
        return Err(invalid);
    }
    let uri = lines
        .next()
        .and_then(|s| s.strip_prefix("URI: "))
        .ok_or(invalid)?;
    if public_url(uri)?.origin().ascii_serialization() != origin {
        return Err(invalid);
    }
    if lines.next() != Some("Version: 1")
        || lines.next() != Some(format!("Chain ID: {chain}").as_str())
        || lines.next() != Some(format!("Nonce: {nonce}").as_str())
    {
        return Err(invalid);
    }
    let timestamp = |line: Option<&str>, prefix: &str| -> Result<i64, &'static str> {
        DateTime::parse_from_rfc3339(line.and_then(|s| s.strip_prefix(prefix)).ok_or(invalid)?)
            .map(|t| t.timestamp())
            .map_err(|_| invalid)
    };
    let issued = timestamp(lines.next(), "Issued At: ")?;
    let expiry = timestamp(lines.next(), "Expiration Time: ")?;
    if issued > now + 30
        || issued < now - 300
        || expiry <= now
        || expiry <= issued
        || expiry > issued + 600
    {
        return Err("wallet_challenge_expired");
    }
    if let Some(next) = lines.next() {
        let not_before = timestamp(Some(next), "Not Before: ")?;
        if not_before > now || not_before > expiry || lines.next().is_some() {
            return Err(invalid);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use std::{os::unix::fs::PermissionsExt, sync::Arc};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    const ORIGIN: &str = "https://owned.example";
    const NONCE: &str = "ownedFixtureNonce123";
    fn message(address: &str, now: i64) -> String {
        let time = |n| DateTime::from_timestamp(n, 0).unwrap().to_rfc3339();
        format!(
            "owned.example wants you to sign in with your Ethereum account:\n{address}\n\nSign in to the owned fixture.\n\nURI: {ORIGIN}/login\nVersion: 1\nChain ID: 1\nNonce: {NONCE}\nIssued At: {}\nExpiration Time: {}",
            time(now),
            time(now + 300)
        )
    }
    fn fixture_key() -> SigningKey {
        SigningKey::from_slice(&Sha256::digest(
            b"public synthetic wallet login fixture; never fund",
        ))
        .unwrap()
    }
    fn recover(message: &str, signature: &str) -> VerifyingKey {
        let bytes = hex::decode(signature.strip_prefix("0x").unwrap()).unwrap();
        assert_eq!(bytes.len(), 65);
        let hash = Keccak256::digest(
            format!("\x19Ethereum Signed Message:\n{}{message}", message.len()).as_bytes(),
        );
        VerifyingKey::recover_from_prehash(
            &hash,
            &Signature::from_slice(&bytes[..64]).unwrap(),
            RecoveryId::from_byte(bytes[64] - 27).unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn rejects_foreign_expired_and_non_login_signatures() {
        let key = fixture_key();
        let address = wallet_address(&key);
        // Independent vector produced with ethers 6 signMessage. This public
        // fixture key is derived above, never used by a deployed wallet.
        assert_eq!(address, "0x529eD56e2c4cA17D8EC486F28032a0Bda8F02910");
        assert_eq!(
            sign_login(&key, "Synthetic login interoperability fixture"),
            "0x10e67faaa572d441405d23046b8619a66c95310bf579f12478de981e2aea254d6d8f0926952229da2053fedbd7af89b950c4ad1de0dde67f0065f87e9171f62b1c"
        );
        let now = 1_794_000_000;
        let valid = message(&address, now);
        assert_eq!(
            validate_message(&valid, NONCE, ORIGIN, &address, 1, now),
            Ok(())
        );
        assert_eq!(
            recover(&valid, &sign_login(&key, &valid)),
            *key.verifying_key()
        );
        for bad in [
            valid.replace("owned.example wants", "other.example wants"),
            valid.replace(&address, "0x0000000000000000000000000000000000000001"),
            valid.replace(
                "URI: https://owned.example/login",
                "URI: https://other.example/login",
            ),
            valid.replace("Version: 1", "Version: 2"),
            valid.replace("Chain ID: 1", "Chain ID: 10"),
            valid.replace(NONCE, "otherNonce"),
            valid.replace("Nonce: ", "Nonce: injected\nNonce: "),
            format!("{valid}\nResources:\n- urn:recap:delegated-capability"),
            format!("{valid}\nRequest ID: delegated-permission"),
            format!("{valid}\nNonce: {NONCE}"),
            valid.replace('\n', "\r\n"),
            message(&address, now - 3600),
            message(&address, now + 3600),
            valid.split("\nExpiration Time:").next().unwrap().to_owned(),
            "0x1234".into(),
            r#"{"primaryType":"Permit","message":{"spender":"someone"}}"#.into(),
            "Please sign this to transfer tokens".into(),
        ] {
            assert!(
                validate_message(&bad, NONCE, ORIGIN, &address, 1, now).is_err(),
                "accepted {bad}"
            );
        }
        assert!(validate_message(&valid, "short", ORIGIN, &address, 1, now).is_err());
    }

    async fn fixture(
        payload: WalletVerifyPayload,
        wrong_domain: bool,
    ) -> (Arc<LiveBroker>, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();
            let mut login_message = String::new();
            let mut wallet = String::new();
            let mut signature = String::new();
            for index in 0..if wrong_domain { 1 } else { 5 } {
                let (mut stream, _) =
                    tokio::time::timeout(Duration::from_secs(5), listener.accept())
                        .await
                        .unwrap()
                        .unwrap();
                let mut bytes = Vec::new();
                let (head, body) = loop {
                    let mut chunk = [0; 4096];
                    let size = stream.read(&mut chunk).await.unwrap();
                    assert!(size > 0 && bytes.len() < 32768);
                    bytes.extend_from_slice(&chunk[..size]);
                    if let Some(pos) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8(bytes[..pos].to_vec()).unwrap();
                        let length = head
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length: ")
                                    .and_then(|n| n.parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if bytes.len() >= pos + 4 + length {
                            break (head, String::from_utf8(bytes[pos + 4..].to_vec()).unwrap());
                        }
                    }
                };
                let (status, cookies, result) = match index {
                    0 => {
                        assert!(head.starts_with("POST /challenge "));
                        assert!(
                            head.to_lowercase()
                                .contains("origin: https://owned.example")
                        );
                        let body: Value = serde_json::from_str(&body).unwrap();
                        wallet = body["address"].as_str().unwrap().into();
                        assert_eq!(body["network"], "ethereum");
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs() as i64;
                        login_message = message(&wallet, now);
                        if wrong_domain {
                            login_message = login_message
                                .replace("owned.example wants", "foreign.example wants");
                        }
                        (
                            "200 OK",
                            "Set-Cookie: binding=private-binding-fixture; Path=/; Secure\r\n",
                            json!({"nonce": NONCE, "message": login_message}).to_string(),
                        )
                    }
                    1 => {
                        assert!(head.starts_with("POST /verify "));
                        assert!(head.contains("binding=private-binding-fixture"));
                        let body: Value = serde_json::from_str(&body).unwrap();
                        let expected = match payload {
                            WalletVerifyPayload::NonceSignature => "nonce",
                            WalletVerifyPayload::MessageSignature => "message",
                        };
                        assert_eq!(body.as_object().unwrap().len(), 3);
                        assert_eq!(
                            body[expected],
                            if expected == "nonce" {
                                NONCE
                            } else {
                                &login_message
                            }
                        );
                        assert_eq!(body["address"], wallet);
                        signature = body["signature"].as_str().unwrap().into();
                        let recovered = recover(&login_message, &signature);
                        let digest =
                            Keccak256::digest(&recovered.to_sec1_point(false).as_bytes()[1..]);
                        assert_eq!(
                            format!("0x{}", hex::encode(&digest[12..])),
                            wallet.to_lowercase()
                        );
                        (
                            "200 OK",
                            "Set-Cookie: session=private-session-fixture; Path=/; Secure; HttpOnly\r\n",
                            "{}".into(),
                        )
                    }
                    3 => {
                        assert!(head.starts_with("GET /private "));
                        assert!(!head.to_lowercase().contains("cookie:"));
                        ("401 Unauthorized", "", "Anonymous control".into())
                    }
                    _ => {
                        assert!(head.starts_with("GET /private "));
                        assert!(head.contains("session=private-session-fixture"));
                        (
                            "200 OK",
                            "",
                            format!(
                                "{signature} {NONCE} private-session-fixture private-binding-fixture"
                            ),
                        )
                    }
                };
                requests.push(format!("{head}\r\n\r\n{body}"));
                let response = format!(
                    "HTTP/1.1 {status}\r\n{cookies}Content-Length: {}\r\nConnection: close\r\n\r\n{result}",
                    result.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
            requests
        });
        let scope = serde_json::from_value::<LiveScope>(json!({"origins":[ORIGIN],"methods":["GET","HEAD","OPTIONS"],"profile":"web_baseline_v1","tools":["authenticated_http_v1","wallet_login_v1"],"authentication":"wallet","auth_check_path":"/private","wallet_login":{"challenge_path":"/challenge","verify_path":"/verify","chain_id":1,"verify_payload":payload,"network":"ethereum","include_address":true}})).unwrap().normalized().unwrap();
        let key = tempfile::NamedTempFile::new().unwrap();
        std::fs::set_permissions(key.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(key.path(), "synthetic-model-key-never-used").unwrap();
        let mut broker = LiveBroker::new_with_credentials(
            LiveProvider::Abliteration,
            key.path(),
            scope,
            Instant::now() + Duration::from_secs(30),
            Some(&TestCredentials::Wallet {}),
            None,
        )
        .unwrap();
        Arc::get_mut(&mut broker).unwrap().test_target = Some(address);
        (broker, server)
    }
    #[tokio::test]
    async fn both_json_login_formats_verify_signatures_and_keep_sessions_private() {
        for payload in [
            WalletVerifyPayload::NonceSignature,
            WalletVerifyPayload::MessageSignature,
        ] {
            let (broker, server) = fixture(payload, false).await;
            let probe = json!({"method":"GET","url":"https://owned.example/private"});
            let result = broker.http(probe.clone()).await.unwrap();
            assert_eq!(result["evidence"]["authenticated"], true);
            assert_eq!(result["body"], "REDACTED REDACTED REDACTED REDACTED");
            let anonymous = broker.http(json!({"method":"GET","url":"https://owned.example/private","authenticated":false})).await.unwrap();
            assert_eq!(anonymous["evidence"]["status"], 401);
            broker.http(probe).await.unwrap();
            let requests = server.await.unwrap();
            assert_eq!(requests.iter().filter(|r| r.starts_with("POST")).count(), 2);
            let evidence =
                serde_json::to_string(&broker.counters.lock().unwrap().evidence).unwrap();
            for secret in [NONCE, "private-session-fixture", "private-binding-fixture"] {
                assert!(!evidence.contains(secret));
            }
            assert!(
                broker
                    .http(json!({"method":"POST","url":"https://owned.example/verify"}))
                    .await
                    .is_err()
            );
        }
    }
    #[tokio::test]
    async fn a_foreign_challenge_is_never_signed_or_retried() {
        let (broker, server) = fixture(WalletVerifyPayload::NonceSignature, true).await;
        let probe = json!({"method":"GET","url":"https://owned.example/private"});
        assert_eq!(
            broker.http(probe.clone()).await.unwrap_err(),
            "wallet_challenge_not_login"
        );
        assert_eq!(
            broker.http(probe).await.unwrap_err(),
            "wallet_challenge_not_login"
        );
        assert_eq!(server.await.unwrap().len(), 1);
    }
}
