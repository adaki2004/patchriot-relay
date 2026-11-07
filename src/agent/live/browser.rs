//! Browser I/O crosses the same origin/DNS/lease boundary as HTTP tools. Raw
//! responses go only to the isolated browser; retained evidence is redacted.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use k256::ecdsa::SigningKey;
use zeroize::Zeroizing;

const MAX_BODY: usize = 8 * 1024 * 1024;
const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_LOGIN_POSTS: usize = 8;

#[derive(Default)]
pub(super) struct BrowserState {
    key: Option<SigningKey>,
    signatures: usize,
    posts: usize,
    requests: usize,
    bytes: usize,
    login_deadline: Option<Instant>,
    pub(super) proof: Option<BrowserAccessProof>,
    // Learned only from a successful paired access check. Never sent to the
    // engine or model; the relay injects it for this exact origin only.
    pub(super) verified_authorization: Option<Zeroizing<String>>,
    pub(super) verified_origin: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserRequest {
    method: String,
    url: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    data: Option<String>,
    #[serde(default = "enabled")]
    authenticated: bool,
    #[serde(default)]
    login: bool,
}
struct BrowserReply {
    evidence: HttpEvidence,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl LiveBroker {
    fn require_browser(&self) -> Result<(), &'static str> {
        if self.scope.browser_login.is_none() {
            return Err("browser_not_selected");
        }
        if Instant::now() >= self.deadline {
            return Err("role_deadline_reached");
        }
        Ok(())
    }

    pub(super) async fn browser_call(
        &self,
        path: &str,
        input: Value,
    ) -> Result<Value, &'static str> {
        self.require_browser()?;
        match path {
            "/patchriot/browser/http" => {
                let request =
                    serde_json::from_value(input).map_err(|_| "invalid_browser_request")?;
                let reply = self.browser_exchange(request).await?;
                Ok(
                    json!({"evidence":reply.evidence,"headers":reply.headers,"body_base64":STANDARD.encode(reply.body)}),
                )
            }
            "/patchriot/browser/credentials" => self.access.browser_credentials(),
            "/patchriot/browser/begin" => {
                let mut state = self.browser.lock().map_err(|_| "browser_unavailable")?;
                if state
                    .login_deadline
                    .is_some_and(|deadline| Instant::now() >= deadline)
                    && state.proof.is_none()
                {
                    return Err("browser_login_expired");
                }
                if state.login_deadline.is_some() || state.proof.is_some() {
                    return Err("browser_login_already_started");
                }
                state.login_deadline = Some(Instant::now() + Duration::from_secs(300));
                Ok(json!({"login_submissions":MAX_LOGIN_POSTS,"expires_in_seconds":300}))
            }
            "/patchriot/browser/wallet" => self.browser_wallet(input),
            "/patchriot/browser/check" => self.browser_check(input).await,
            "/patchriot/browser/status" => {
                let state = self.browser.lock().map_err(|_| "browser_unavailable")?;
                let remaining = state
                    .login_deadline
                    .map(|deadline| deadline.saturating_duration_since(Instant::now()).as_secs());
                // The agent needs to distinguish a spent login window from a
                // broken website. Status never renews it or resets attempts.
                let phase = if state.verified_origin.is_some() {
                    "verified"
                } else if remaining.is_none() {
                    "not_started"
                } else if state
                    .login_deadline
                    .is_some_and(|deadline| Instant::now() >= deadline)
                {
                    "expired"
                } else if state.posts >= MAX_LOGIN_POSTS {
                    "exhausted"
                } else {
                    "active"
                };
                Ok(
                    json!({"verified":state.verified_origin.is_some(),"proof":state.proof,
                    "login":{"state":phase,"seconds_remaining":remaining,
                        "submissions_remaining":MAX_LOGIN_POSTS.saturating_sub(state.posts),
                        "signatures_remaining":4_usize.saturating_sub(state.signatures)}}),
                )
            }
            _ => Err("unsupported_browser_operation"),
        }
    }

    async fn browser_exchange(
        &self,
        mut input: BrowserRequest,
    ) -> Result<BrowserReply, &'static str> {
        self.require_browser()?;
        let resource = self
            .scope
            .browser_login
            .as_ref()
            .is_some_and(|login| login.permits_resource(&input.method, &input.url));
        let url = if resource {
            if input.authenticated || input.login || input.data.is_some() {
                return Err("browser_resource_must_be_anonymous_read");
            }
            public_url(&input.url)?
        } else if input.login && self.scope.permits_login(&input.method, &input.url) {
            public_url(&input.url)?
        } else if input.login {
            return Err("outside_approved_scope");
        } else {
            self.scope.permits(&input.method, &input.url)?
        };
        if input.headers.len() > 40
            || input.headers.iter().any(|(k, v)| {
                k.len() > 80
                    || v.len() > 8192
                    || k.chars().any(char::is_control)
                    || v.chars().any(char::is_control)
            })
        {
            return Err("unsupported_browser_headers");
        }
        let mut headers = BTreeMap::new();
        for (key, value) in input.headers {
            let name = key.to_ascii_lowercase();
            if headers.contains_key(&name) {
                return Err("duplicate_browser_header");
            }
            if resource {
                // Public page dependencies receive no session, referrer or
                // caller-selected account headers. CORS still sees the app's
                // actual origin; Chromium enforces the response policy.
                if name == "accept" {
                    headers.insert(name, value);
                } else if name == "origin" {
                    headers.insert(name, self.scope.origins[0].clone());
                }
                continue;
            }
            if [
                "host",
                "connection",
                "content-length",
                "transfer-encoding",
                "proxy-authorization",
                "accept-encoding",
            ]
            .contains(&name.as_str())
            {
                continue;
            }
            if matches!(name.as_str(), "origin" | "referer")
                && url::Url::parse(&value).is_ok_and(|v| v.origin() != url.origin())
            {
                return Err("browser_header_outside_scope");
            }
            if !input.authenticated && matches!(name.as_str(), "cookie" | "authorization") {
                continue;
            }
            if name == "authorization" {
                self.access.remember_secret(value.clone())?;
                if let Some((_, secret)) = value.split_once(' ') {
                    self.access.remember_secret(secret.into())?;
                }
            }
            if name == "cookie" {
                for pair in value.split(';') {
                    if let Some((_, secret)) = pair.trim().split_once('=') {
                        self.access.remember_secret(secret.into())?;
                    }
                }
            }
            headers.insert(name, value);
        }
        input.headers = headers;
        // Validate bodies with the existing HTTP limits after separating browser
        // session headers. No uploads, arbitrary bytes or new methods are added.
        if !resource {
            self.probe_url(
                &Probe {
                    account_change: false,
                    method: input.method.clone(),
                    url: input.url.clone(),
                    headers: input
                        .headers
                        .iter()
                        .filter(|(k, _)| {
                            matches!(k.as_str(), "content-type" | "origin" | "referer")
                        })
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                    data: input.data.clone(),
                    authenticated: input.authenticated,
                },
                input.login,
            )?;
            if let Some(data) = &input.data {
                safety::remember_body_secrets(&self.access, data)?;
            }
        }
        {
            let count = self.counters.lock().map_err(|_| "counter_unavailable")?;
            if count.evidence.len() >= MAX_HTTP_REQUESTS
                || count.evidence_bytes + HTTP_RECORD_RESERVE > HTTP_EVIDENCE_BUDGET
            {
                return Err("target_request_budget_reached");
            }
            let mut state = self.browser.lock().map_err(|_| "browser_unavailable")?;
            if state.requests >= MAX_HTTP_REQUESTS || state.bytes >= MAX_BYTES {
                return Err("browser_budget_reached");
            }
            if input.login && input.method == "POST" {
                if state.posts >= MAX_LOGIN_POSTS
                    || state.proof.is_some()
                    || state
                        .login_deadline
                        .is_none_or(|deadline| Instant::now() >= deadline)
                {
                    return Err("browser_login_submission_limit");
                }
                state.posts += 1;
            }
            state.requests += 1;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        let (client, destination) = self.target_transport(&url).await?;
        let mut request = client
            .request(
                reqwest::Method::from_bytes(input.method.as_bytes())
                    .map_err(|_| "unsupported_method")?,
                destination,
            )
            .header("user-agent", "Patchriot-authorized-review/0.0.11")
            .header("accept-encoding", "identity");
        for (key, value) in &input.headers {
            request = request.header(key, value);
        }
        // Basic/bearer access is injected by the relay. Cookie-based browser
        // contexts send their own cookies, including an empty anonymous context.
        if !resource
            && !input.headers.contains_key("authorization")
            && let Some(value) = self.access.authorization(input.authenticated)
        {
            request = request.header("authorization", value);
        }
        let authenticated = input.authenticated
            && (input.headers.contains_key("authorization")
                || input.headers.contains_key("cookie")
                || self.access.authorization(true).is_some());
        if let Some(data) = &input.data {
            request = request.body(data.clone());
        }
        let response = tokio::time::timeout_at(self.deadline.into(), request.send())
            .await
            .map_err(|_| "role_deadline_reached")?;
        let mut retained_url = url.clone();
        if url.query().is_some() {
            let names: Vec<_> = url.query_pairs().map(|(key, _)| key.into_owned()).collect();
            retained_url.set_query(None);
            for name in names {
                retained_url
                    .query_pairs_mut()
                    .append_pair(&name, "REDACTED");
            }
        }
        let mut evidence = HttpEvidence {
            account: if authenticated || input.login {
                self.account
            } else {
                None
            },
            id: 0,
            method: input.method,
            url: retained_url.to_string(),
            request_headers: BTreeMap::new(),
            status: None,
            headers: BTreeMap::new(),
            body_excerpt: String::new(),
            body_sha256: None,
            truncated: false,
            error: None,
            observed_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
            request_body_excerpt: None,
            request_body_sha256: None,
            authenticated: authenticated && !input.login,
            login: input.login,
        };
        let mut headers = Vec::new();
        let mut body = Vec::new();
        let mut json_response = false;
        match response {
            Err(_) => evidence.error = Some("target_request_failed".into()),
            Ok(mut response) => {
                json_response = response
                    .headers()
                    .get("content-type")
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| {
                        value
                            .split(';')
                            .next()
                            .unwrap_or("")
                            .trim()
                            .ends_with("json")
                    });
                evidence.status = Some(response.status().as_u16());
                // A browser receives raw response headers. If a new session
                // secret cannot be tracked for redaction, do not deliver it to
                // the page or retain a body that might echo it.
                for cookie in response
                    .headers()
                    .get_all(reqwest::header::SET_COOKIE)
                    .iter()
                    .filter(|_| !resource)
                {
                    if let Ok(value) = cookie.to_str()
                        && let Some((_, secret)) =
                            value.split(';').next().unwrap_or("").split_once('=')
                    {
                        self.access
                            .remember_secret(secret.trim_matches('"').into())?;
                    }
                }
                if !resource {
                    self.access
                        .remember(&url, response.headers(), input.authenticated);
                }
                let mut size = 0;
                for (name, value) in response.headers() {
                    let Ok(value) = value.to_str() else { continue };
                    size += name.as_str().len() + value.len();
                    if size > 32768 {
                        evidence.error = Some("browser_headers_too_large".into());
                        break;
                    }
                    if [
                        "connection",
                        "transfer-encoding",
                        "content-length",
                        "alt-svc",
                    ]
                    .contains(&name.as_str())
                        || resource && name == reqwest::header::SET_COOKIE
                    {
                        continue;
                    }
                    headers.push((name.as_str().into(), value.into()));
                    if !input.login && RECORDED_HEADERS.contains(&name.as_str()) {
                        evidence.headers.insert(
                            name.as_str().into(),
                            self.access.redact_limited(value, 1024).0,
                        );
                    }
                }
                loop {
                    let chunk =
                        tokio::time::timeout_at(self.deadline.into(), response.chunk()).await;
                    match chunk {
                        Ok(Ok(Some(chunk))) if body.len() + chunk.len() <= MAX_BODY => {
                            body.extend_from_slice(&chunk)
                        }
                        Ok(Ok(None)) => break,
                        _ => {
                            evidence.error = Some("browser_response_incomplete".into());
                            evidence.truncated = true;
                            break;
                        }
                    }
                }
            }
        }
        {
            let mut state = self.browser.lock().map_err(|_| "browser_unavailable")?;
            state.bytes = state.bytes.saturating_add(body.len());
            if state.bytes > MAX_BYTES {
                evidence.error = Some("browser_budget_reached".into());
            }
        }
        // Login responses can carry a JavaScript token rather than Set-Cookie.
        // Register it before a browser tool can expose it to model/report text.
        // Anonymous dependencies cannot establish a target session. Their
        // public catalogs may be much wider than a bounded login response.
        // Known secrets are still redacted from all retained evidence below.
        if !resource {
            let inspected = match serde_json::from_slice::<Value>(&body) {
                Ok(value) => remember_tokens(&self.access, &value, 0),
                Err(_) if json_response && !body.is_empty() => Err("uninspectable_json_response"),
                Err(_) => Ok(()),
            };
            if let Err(error) = inspected {
                evidence.error = Some(error.into());
                body.clear();
                headers.clear();
            }
        }
        if !input.login {
            if let Some(data) = input.data {
                let redacted = self.access.redact(&data);
                evidence.request_body_sha256 =
                    Some(hex::encode(Sha256::digest(redacted.as_bytes())));
                evidence.request_body_excerpt = Some(redacted.chars().take(2048).collect());
            }
            let cleaned = self.access.redact(&String::from_utf8_lossy(&body));
            evidence.body_sha256 = Some(hex::encode(Sha256::digest(cleaned.as_bytes())));
            evidence.body_excerpt = if cleaned.contains('\0') {
                "[Binary response; see hash.]".into()
            } else {
                cleaned.chars().take(2048).collect()
            };
            evidence.truncated |= evidence.body_excerpt.len() < cleaned.len();
        } else {
            evidence.truncated = true;
        }
        let mut count = self.counters.lock().map_err(|_| "counter_unavailable")?;
        evidence.id = count.evidence.len() as u32 + 1;
        count.evidence_bytes += serde_json::to_vec(&evidence)
            .map_err(|_| "evidence_encoding_failed")?
            .len();
        count.evidence.push(evidence.clone());
        if evidence.error.is_some() {
            body.clear();
            headers.clear();
        }
        Ok(BrowserReply {
            evidence,
            headers,
            body,
        })
    }

    async fn browser_check(&self, input: Value) -> Result<Value, &'static str> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Check {
            url: String,
            #[serde(default)]
            headers: BTreeMap<String, String>,
            #[serde(default)]
            json_pointer: Option<String>,
        }
        let input: Check = serde_json::from_value(input).map_err(|_| "invalid_access_check")?;
        {
            let mut state = self.browser.lock().map_err(|_| "browser_unavailable")?;
            // Keep earlier paired evidence for the final report, but revoke the
            // live capability until this new check succeeds.
            state.verified_authorization = None;
            state.verified_origin = None;
        }
        if input.json_pointer.as_ref().is_some_and(|p| {
            p.len() > 256 || !p.starts_with('/') || p.chars().any(char::is_control)
        }) {
            return Err("invalid_identity_pointer");
        }
        let authorization = input
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| Zeroizing::new(value.clone()));
        let verified_origin = url::Url::parse(&input.url)
            .map_err(|_| "invalid_access_check")?
            .origin()
            .ascii_serialization();
        let signed = self
            .browser_exchange(BrowserRequest {
                method: "GET".into(),
                url: input.url.clone(),
                headers: input.headers,
                data: None,
                authenticated: true,
                login: false,
            })
            .await?;
        let anonymous = self
            .browser_exchange(BrowserRequest {
                method: "GET".into(),
                url: input.url,
                headers: BTreeMap::new(),
                data: None,
                authenticated: false,
                login: false,
            })
            .await?;
        let mut proof = BrowserAccessProof {
            authenticated_id: signed.evidence.id,
            anonymous_id: anonymous.evidence.id,
            check: BrowserAccessCheck::ProtectedResource,
        };
        if let Some(pointer) = input.json_pointer {
            let principal = if self.scope.authentication == Some(TestAuthKind::Wallet) {
                self.browser
                    .lock()
                    .map_err(|_| "browser_unavailable")?
                    .key
                    .as_ref()
                    .map(wallet::wallet_address)
            } else {
                self.access.browser_principal().map(str::to_owned)
            }
            .ok_or("identity_comparison_unavailable")?;
            let identity = |bytes: &[u8]| {
                serde_json::from_slice::<Value>(bytes).ok().and_then(|v| {
                    v.pointer(&pointer)
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
            };
            let normalize = |s: &str| {
                if self.scope.authentication == Some(TestAuthKind::Wallet) {
                    s.to_ascii_lowercase()
                } else {
                    s.to_owned()
                }
            };
            let hash = |s: &str| hex::encode(Sha256::digest(normalize(s).as_bytes()));
            let actual = identity(&signed.body).ok_or("authenticated_identity_missing")?;
            if normalize(&actual) != normalize(&principal) {
                return Err("authenticated_identity_mismatch");
            }
            proof.check = BrowserAccessCheck::AccountIdentity {
                json_pointer: pointer.clone(),
                principal_sha256: hash(&principal),
                authenticated_value_sha256: hash(&actual),
                anonymous_value_sha256: identity(&anonymous.body).map(|v| hash(&v)),
            };
        }
        let verified = proof.valid(
            &self.scope,
            &[signed.evidence.clone(), anonymous.evidence.clone()],
        );
        if verified {
            let mut state = self.browser.lock().map_err(|_| "browser_unavailable")?;
            state.proof = Some(proof.clone());
            state.verified_authorization = authorization;
            state.verified_origin = Some(verified_origin);
        }
        Ok(
            json!({"verified":verified,"proof":if verified {Some(proof)} else {None},"authenticated_evidence_id":signed.evidence.id,"anonymous_evidence_id":anonymous.evidence.id,
                "evidence":[signed.evidence,anonymous.evidence]}),
        )
    }

    fn browser_wallet(&self, input: Value) -> Result<Value, &'static str> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Signing {
            origin: String,
            method: String,
            #[serde(default)]
            address: Option<String>,
            #[serde(default)]
            message: Option<String>,
            #[serde(default)]
            approved: bool,
        }
        let input: Signing = serde_json::from_value(input).map_err(|_| "invalid_wallet_request")?;
        if self.scope.authentication != Some(TestAuthKind::Wallet)
            || !self.scope.origins.contains(&input.origin)
        {
            return Err("wallet_outside_scope");
        }
        if !matches!(input.method.as_str(), "eth_accounts" | "personal_sign") {
            return Err("wallet_method_not_supported");
        }
        let mut state = self.browser.lock().map_err(|_| "browser_unavailable")?;
        if state.key.is_none() {
            let mut seed = Zeroizing::new([0u8; 32]);
            getrandom::fill(seed.as_mut()).map_err(|_| "wallet_key_unavailable")?;
            state.key =
                Some(SigningKey::from_slice(seed.as_ref()).map_err(|_| "wallet_key_unavailable")?);
        }
        let key = state.key.as_ref().ok_or("wallet_key_unavailable")?;
        let address = wallet::wallet_address(key);
        if input.method == "eth_accounts" {
            return Ok(json!({"address":address}));
        }
        if !input.approved || state.signatures >= 4 {
            return Err("wallet_signature_not_approved");
        }
        if state
            .login_deadline
            .is_none_or(|deadline| Instant::now() >= deadline)
        {
            return Err("browser_login_not_active");
        }
        if input
            .address
            .as_ref()
            .is_none_or(|v| !v.eq_ignore_ascii_case(&address))
        {
            return Err("wallet_address_mismatch");
        }
        let message = input.message.ok_or("wallet_message_required")?;
        validate_browser_message(&message, &input.origin, &address)?;
        let signature = wallet::sign_login(key, &message);
        state.signatures += 1;
        self.access.remember_secret(signature.clone())?;
        Ok(json!({"signature":signature}))
    }
}

pub(super) fn remember_tokens(
    access: &access::Access,
    value: &Value,
    depth: usize,
) -> Result<(), &'static str> {
    if depth > 16 {
        return Err("browser_json_too_deep");
    }
    match value {
        Value::Object(fields) => {
            if fields.len() > 128 {
                return Err("browser_json_too_wide");
            }
            for (key, value) in fields {
                if safety::secret_field(key)
                    && let Some(secret) = value.as_str()
                    && !secret.is_empty()
                {
                    if secret.len() > 8192 {
                        return Err("browser_token_too_large");
                    }
                    access.remember_secret(secret.into())?;
                }
                remember_tokens(access, value, depth + 1)?;
            }
        }
        Value::Array(items) => {
            if items.len() > 256 {
                return Err("browser_json_too_wide");
            }
            for item in items {
                remember_tokens(access, item, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_browser_message(
    message: &str,
    origin: &str,
    address: &str,
) -> Result<(), &'static str> {
    if !(1..=4096).contains(&message.len()) || message.chars().any(|c| c.is_control() && c != '\n')
    {
        return Err("wallet_message_not_readable");
    }
    let lower = message.to_lowercase();
    if [
        "permit2",
        "permit(",
        "transferfrom",
        "setapprovalforall",
        "delegatecall",
        "approve spending",
        "sell order",
    ]
    .iter()
    .any(|word| lower.contains(word))
    {
        return Err("wallet_message_not_login");
    }
    if message.contains("wants you to sign in with your Ethereum account:") {
        let nonce = message
            .lines()
            .find_map(|s| s.strip_prefix("Nonce: "))
            .ok_or("wallet_challenge_not_login")?;
        let chain = message
            .lines()
            .find_map(|s| s.strip_prefix("Chain ID: "))
            .and_then(|s| s.parse().ok())
            .ok_or("wallet_challenge_not_login")?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "wallet_clock_unavailable")?
            .as_secs() as i64;
        wallet::validate_browser_siwe(message, nonce, origin, address, chain, now)?;
    }
    // Custom readable challenges need the agent's explicit review of the exact
    // message in its observed login context. This filter is not a proof that
    // arbitrary text has no off-chain authority. The key is always disposable.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[test]
    fn browser_siwe_accepts_optional_expiry_but_rejects_other_origins_and_resources() {
        let address = "0x1111111111111111111111111111111111111111";
        let now = chrono::DateTime::<chrono::Utc>::from(std::time::SystemTime::now()).to_rfc3339();
        let message = format!(
            "owned.example wants you to sign in with your Ethereum account:\n{address}\n\nSign in.\n\nURI: https://owned.example/login\nVersion: 1\nChain ID: 1\nNonce: challenge123\nIssued At: {now}\nRequest ID: fixture-1"
        );
        assert!(validate_browser_message(&message, "https://owned.example", address).is_ok());
        assert!(
            validate_browser_message(
                &message.replace("URI: https://owned.example", "URI: https://foreign.example"),
                "https://owned.example",
                address
            )
            .is_err()
        );
        assert!(
            validate_browser_message(
                &(message + "\nResources:\n- https://owned.example/delegate"),
                "https://owned.example",
                address
            )
            .is_err()
        );
    }

    #[test]
    fn javascript_tokens_are_redacted_and_secret_storage_is_bounded() {
        let broker = broker("session");
        let token = "synthetic-js-session-token";
        remember_tokens(&broker.access, &json!({"data":{"accessToken":token}}), 0).unwrap();
        assert_eq!(broker.access.redact(token), "REDACTED");
        for _ in 0..1000 {
            broker.access.remember_secret(token.into()).unwrap();
        }
        assert_eq!(
            broker.access.remember_secret("x".repeat(8193)),
            Err("credential_redaction_limit")
        );
        assert!(remember_tokens(&broker.access, &json!({"token":"x".repeat(8193)}), 0).is_err());
    }

    fn broker(kind: &str) -> Arc<LiveBroker> {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), "public-test-provider-placeholder").unwrap();
        let scope = serde_json::from_value::<LiveScope>(json!({
            "origins":["https://owned.example"],"methods":["GET","HEAD","OPTIONS"],
            "profile":"web_baseline_v1","tools":["authenticated_http_v1","browser_login_v1"],
            "authentication":kind,"browser_login":{}
        }))
        .unwrap()
        .normalized()
        .unwrap();
        let credentials = if kind == "wallet" {
            TestCredentials::Wallet {}
        } else {
            TestCredentials::Session {
                username: "fixture@example.com".into(),
                password: "only-synthetic-password".into(),
            }
        };
        LiveBroker::new_with_credentials(
            LiveProvider::Abliteration,
            file.path(),
            scope,
            Instant::now() + Duration::from_secs(60),
            Some(&credentials),
            None,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn password_changes_are_blocked_even_when_labeled_as_browser_login() {
        let mut broker = broker("session");
        let inner = Arc::get_mut(&mut broker).unwrap();
        inner.scope.methods.push("POST".into());
        inner.scope.profile = Some(AssessmentProfile::WebActiveV2);
        for login in [false, true] {
            assert_eq!(broker.browser_call("/patchriot/browser/http", json!({
                "method":"POST","url":"https://owned.example/api/auth/me/password",
                "headers":{"Content-Type":"application/json"},
                "data":r#"{"current_password":"only-synthetic-password","new_password":"fixture-change"}"#,
                "login":login
            })).await, Err("account_credential_changes_not_permitted"));
        }
        assert_eq!(broker.browser.lock().unwrap().requests, 0);
        assert!(broker.counters.lock().unwrap().evidence.is_empty());
    }

    #[tokio::test]
    async fn expired_login_is_visible_and_cannot_be_reopened_or_submit() {
        for kind in ["wallet", "session"] {
            let broker = broker(kind);
            let status = broker
                .browser_call("/patchriot/browser/status", json!({}))
                .await
                .unwrap();
            assert_eq!(status["login"]["state"], "not_started");
            assert!(status["login"]["seconds_remaining"].is_null());
            broker
                .browser_call("/patchriot/browser/begin", json!({}))
                .await
                .unwrap();
            let expired = Instant::now() - Duration::from_secs(1);
            {
                let mut state = broker.browser.lock().unwrap();
                state.login_deadline = Some(expired);
                state.posts = 3;
                state.signatures = 1;
            }
            let status = broker
                .browser_call("/patchriot/browser/status", json!({}))
                .await
                .unwrap();
            assert_eq!(
                status["login"],
                json!({"state":"expired","seconds_remaining":0,
                "submissions_remaining":5,"signatures_remaining":3})
            );
            assert_eq!(
                broker
                    .browser_call("/patchriot/browser/begin", json!({}))
                    .await
                    .unwrap_err(),
                "browser_login_expired"
            );
            assert_eq!(
                broker
                    .browser_call(
                        "/patchriot/browser/http",
                        json!({
                            "method":"POST","url":"https://owned.example/session","login":true,
                            "headers":{"content-type":"application/json"},"data":"{}"
                        })
                    )
                    .await
                    .unwrap_err(),
                "browser_login_submission_limit"
            );
            let state = broker.browser.lock().unwrap();
            assert_eq!(state.login_deadline, Some(expired));
            assert_eq!(state.posts, 3);
            assert!(broker.counters.lock().unwrap().evidence.is_empty());
        }
    }

    #[tokio::test]
    async fn active_login_status_distinguishes_consumed_submissions_without_resetting_them() {
        let broker = broker("wallet");
        broker
            .browser_call("/patchriot/browser/begin", json!({}))
            .await
            .unwrap();
        let status = broker
            .browser_call("/patchriot/browser/status", json!({}))
            .await
            .unwrap();
        assert_eq!(status["login"]["state"], "active");
        assert!(status["login"]["seconds_remaining"].as_u64().unwrap() <= 300);
        broker.browser.lock().unwrap().posts = MAX_LOGIN_POSTS;
        let status = broker
            .browser_call("/patchriot/browser/status", json!({}))
            .await
            .unwrap();
        assert_eq!(status["login"]["state"], "exhausted");
        assert_eq!(status["login"]["submissions_remaining"], 0);
        assert!(
            broker
                .browser_call("/patchriot/browser/begin", json!({}))
                .await
                .is_err()
        );
        assert_eq!(broker.browser.lock().unwrap().posts, MAX_LOGIN_POSTS);
    }

    async fn target() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let (head, body) = loop {
                    let mut chunk = [0; 8192];
                    let size = stream.read(&mut chunk).await.unwrap();
                    if size == 0 {
                        return;
                    }
                    bytes.extend_from_slice(&chunk[..size]);
                    if let Some(pos) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8(bytes[..pos].to_vec()).unwrap();
                        let length = head
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length: ")
                                    .and_then(|v| v.parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if bytes.len() >= pos + 4 + length {
                            break (head, String::from_utf8(bytes[pos + 4..].to_vec()).unwrap());
                        }
                    }
                };
                let reference_account =
                    head.contains("authorization: Bearer synthetic-reference-token");
                let logged_in = head.contains("cookie: session=synthetic-session")
                    || head.contains("authorization: Bearer synthetic-browser-token")
                    || reference_account;
                let (status, cookie, body) = if head.starts_with("POST /different/session ") {
                    assert_eq!(
                        serde_json::from_str::<Value>(&body).unwrap(),
                        json!({"login":"fixture@example.com","secret":"only-synthetic-password"})
                    );
                    (
                        200,
                        "Set-Cookie: session=synthetic-session; Path=/; Secure; HttpOnly\r\n",
                        json!({"ok":true}).to_string(),
                    )
                } else if head.starts_with("POST /api/auth/change-password ") {
                    assert!(!reference_account);
                    let change: Value = serde_json::from_str(&body).unwrap();
                    assert_eq!(change["current_password"], "only-synthetic-password");
                    assert!(change["new_password"].as_str().unwrap().len() >= 32);
                    assert!(!body.contains("PATCHRIOT_CURRENT_PASSWORD"));
                    (
                        200,
                        "",
                        json!({"password":change["new_password"]}).to_string(),
                    )
                } else if head.starts_with("GET /public ") {
                    (200, "", json!({"public":true}).to_string())
                } else if head.starts_with("GET /public-catalog ") {
                    (
                        200,
                        "",
                        json!({"items":vec!["public-item"; 300]}).to_string(),
                    )
                } else if ["GET /identity ", "GET /identity-401 ", "GET /identity-403 "]
                    .iter()
                    .any(|path| head.starts_with(path))
                {
                    (
                        if !logged_in && head.starts_with("GET /identity-401 ") { 401 }
                        else if !logged_in && head.starts_with("GET /identity-403 ") { 403 }
                        else { 200 },
                        "",
                        if logged_in {
                            json!({"account":{"email":if reference_account {"reference@example.com"} else {"fixture@example.com"}}})
                        } else {
                            json!({"account":null})
                        }
                        .to_string(),
                    )
                } else {
                    (
                        if logged_in { 200 } else { 401 },
                        "",
                        if logged_in {
                            "private-data"
                        } else {
                            "unauthenticated"
                        }
                        .into(),
                    )
                };
                let content_type = if serde_json::from_str::<Value>(&body).is_ok() {
                    "application/json"
                } else {
                    "text/plain"
                };
                stream.write_all(format!("HTTP/1.1 {status} Fixture\r\nContent-Type: {content_type}\r\n{cookie}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
            }
        });
        (address, task)
    }

    #[tokio::test]
    async fn discovery_http_reserve_keeps_browser_login_and_anonymous_controls() {
        let (address, server) = target().await;
        let mut broker = broker("session");
        let inner = Arc::get_mut(&mut broker).unwrap();
        inner.test_target = Some(address);
        inner.scope.tools.push(LiveToolProfile::ArtexEngineV1);
        let public = json!({"method":"GET","url":"https://owned.example/public"});
        broker.engine_http(public.clone()).await.unwrap();
        let saved_bytes = broker.counters.lock().unwrap().evidence_bytes;
        broker.counters.lock().unwrap().evidence_bytes = ENGINE_EVIDENCE_LIMIT;
        assert_eq!(
            broker.engine_http(public.clone()).await.unwrap_err(),
            "engine_http_budget_reached"
        );
        {
            let mut count = broker.counters.lock().unwrap();
            count.evidence_bytes = saved_bytes;
            let sample = count.evidence[0].clone();
            for id in 2..=ENGINE_HTTP_LIMIT {
                let mut record = sample.clone();
                record.id = id as u32;
                count.evidence.push(record);
            }
        }
        let (tx, mut rx) = mpsc::channel(4);
        broker
            .respond(
                Request {
                    id: 1,
                    method: "POST".into(),
                    path: ENGINE_HTTP.into(),
                    body: Some(public.clone()),
                },
                tx,
            )
            .await;
        assert!(matches!(
            rx.recv().await,
            Some(Frame::Start { status: 429, .. })
        ));
        assert_eq!(
            broker.counters.lock().unwrap().evidence.len(),
            ENGINE_HTTP_LIMIT
        );
        // The same hard role limit still allows independent probes and a real
        // browser login after discovery has consumed its smaller allowance.
        assert_eq!(
            broker.http(public).await.unwrap()["evidence"]["status"],
            200
        );
        let post = json!({"method":"POST","url":"https://owned.example/different/session","headers":{"content-type":"application/json"},
            "data":json!({"login":"fixture@example.com","secret":"only-synthetic-password"}).to_string(),"login":true});
        assert_eq!(
            broker
                .browser_call("/patchriot/browser/http", post.clone())
                .await
                .unwrap_err(),
            "browser_login_submission_limit"
        );
        broker
            .browser_call("/patchriot/browser/begin", json!({}))
            .await
            .unwrap();
        let reply = broker
            .browser_call("/patchriot/browser/http", post)
            .await
            .unwrap();
        assert_eq!(reply["evidence"]["status"], 200);
        assert_eq!(reply["evidence"]["body_excerpt"], "");
        let check = json!({"url":"https://owned.example/private","headers":{"cookie":"session=synthetic-session"}});
        let proof = broker
            .browser_call("/patchriot/browser/check", check)
            .await
            .unwrap();
        assert_eq!(proof["verified"], true);
        let returned: Vec<HttpEvidence> =
            serde_json::from_value(proof["evidence"].clone()).unwrap();
        assert_eq!(returned.len(), 2);
        assert_eq!(returned[0].id, proof["authenticated_evidence_id"]);
        assert_eq!(returned[1].id, proof["anonymous_evidence_id"]);
        assert_eq!(returned[0].status, Some(200));
        assert_eq!(returned[1].status, Some(401));
        {
            let authoritative = broker.counters.lock().unwrap();
            for record in &returned {
                assert_eq!(
                    serde_json::to_value(record).unwrap(),
                    serde_json::to_value(&authoritative.evidence[(record.id - 1) as usize])
                        .unwrap()
                );
            }
        }
        assert!(!proof.to_string().contains("synthetic-session"));
        assert!(!proof.to_string().contains("only-synthetic-password"));
        let retained = serde_json::to_value(&broker.counters.lock().unwrap().evidence)
            .unwrap()
            .to_string();
        assert!(!retained.contains("only-synthetic-password"));
        assert!(!retained.contains("synthetic-session"));
        // Subsequent ordinary HTTP tools can use the cookie saved by the broker.
        let continuation = broker
            .http(json!({"method":"GET","url":"https://owned.example/private"}))
            .await
            .unwrap();
        assert_eq!(continuation["evidence"]["authenticated"], true);
        assert_eq!(continuation["evidence"]["status"], 200);
        assert!(
            broker
                .browser_call("/patchriot/browser/begin", json!({}))
                .await
                .is_err()
        );
        server.abort();
    }

    #[tokio::test]
    async fn browser_dependencies_drop_account_headers_and_cannot_be_login_or_test_targets() {
        let (address, server) = target().await;
        let mut broker = broker("session");
        let inner = Arc::get_mut(&mut broker).unwrap();
        inner.test_target = Some(address);
        inner.scope.browser_login.as_mut().unwrap().resource_origins =
            vec!["https://cdn.example.com".into()];
        let url = "https://cdn.example.com/private";
        let reply = broker.browser_call("/patchriot/browser/http", json!({
            "method":"GET", "url":url, "authenticated":false,
            "headers":{"cookie":"session=synthetic-session", "authorization":"Bearer never-forward", "referer":"https://owned.example/private"}
        })).await.unwrap();
        assert_eq!(reply["evidence"]["status"], 401);
        let evidence: HttpEvidence = serde_json::from_value(reply["evidence"].clone()).unwrap();
        assert!(!evidence.authenticated);
        assert!(
            broker
                .http(json!({"method":"GET","url":url}))
                .await
                .is_err()
        );
        for change in [
            json!({"authenticated":true}),
            json!({"login":true}),
            json!({"method":"POST"}),
            json!({"data":"anything"}),
        ] {
            let mut request = json!({"method":"GET","url":url,"authenticated":false});
            for (key, value) in change.as_object().unwrap() {
                request[key] = value.clone();
            }
            assert!(
                broker
                    .browser_call("/patchriot/browser/http", request)
                    .await
                    .is_err()
            );
        }
        assert!(
            broker
                .browser_call("/patchriot/browser/check", json!({"url":url}))
                .await
                .is_err()
        );
        server.abort();
    }

    #[tokio::test]
    async fn browser_public_dependency_catalogs_do_not_use_session_token_limits() {
        let (address, server) = target().await;
        let mut broker = broker("session");
        let inner = Arc::get_mut(&mut broker).unwrap();
        inner.test_target = Some(address);
        inner.scope.browser_login.as_mut().unwrap().resource_origins =
            vec!["https://cdn.example.com".into()];
        let reply = broker.browser_call("/patchriot/browser/http", json!({
            "method":"GET", "url":"https://cdn.example.com/public-catalog", "authenticated":false
        })).await.unwrap();
        assert_eq!(reply["evidence"]["status"], 200);
        assert!(reply["evidence"]["error"].is_null());
        let bytes = STANDARD
            .decode(reply["body_base64"].as_str().unwrap())
            .unwrap();
        let catalog: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(catalog["items"].as_array().unwrap().len(), 300);
        let evidence: HttpEvidence = serde_json::from_value(reply["evidence"].clone()).unwrap();
        assert!(!evidence.authenticated);
        assert!(broker.browser.lock().unwrap().proof.is_none());
        // A target response may carry credentials, so its limit is unchanged.
        let reply = broker.browser_call("/patchriot/browser/http", json!({
            "method":"GET", "url":"https://owned.example/public-catalog", "authenticated":true
        })).await.unwrap();
        assert_eq!(reply["evidence"]["error"], "browser_json_too_wide");
        assert_eq!(reply["body_base64"], "");
        server.abort();
    }

    #[tokio::test]
    async fn browser_withholds_a_new_cookie_when_secret_tracking_is_full() {
        let (address, server) = target().await;
        let mut broker = broker("session");
        Arc::get_mut(&mut broker).unwrap().test_target = Some(address);
        for n in 0..600 {
            if broker
                .access
                .remember_secret(format!("synthetic-cookie-{n}"))
                .is_err()
            {
                break;
            }
        }
        broker
            .browser_call("/patchriot/browser/begin", json!({}))
            .await
            .unwrap();
        let result = broker.browser_call("/patchriot/browser/http", json!({
            "method":"POST", "url":"https://owned.example/different/session",
            "headers":{"content-type":"application/json"}, "login":true,
            "data":json!({"login":"fixture@example.com","secret":"only-synthetic-password"}).to_string()
        })).await;
        assert_eq!(result.unwrap_err(), "credential_redaction_limit");
        assert!(broker.counters.lock().unwrap().evidence.is_empty());
        assert!(
            !broker
                .access
                .authenticated(&public_url("https://owned.example/").unwrap(), true)
        );
        server.abort();
    }

    #[tokio::test]
    async fn two_accounts_isolate_access_and_require_explicit_verified_password_permission() {
        let (address, server) = target().await;
        let scope: LiveScope = serde_json::from_value(json!({"origins":["https://owned.example"],
            "methods":["GET","HEAD","OPTIONS","POST"], "profile":"web_active_v2",
            "tools":["active_web_v2","artex_engine_v1","authenticated_http_v1","browser_login_v1","multi_account_v1"],
            "authentication":"session","browser_login":{},"account_policy":{"allow_password_changes":true}})).unwrap();
        let key = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(key.path(), "synthetic-fixture-provider-key").unwrap();
        let credentials: TestCredentials =
            serde_json::from_value(json!({"kind":"session_accounts",
            "testing":{"username":"fixture@example.com","password":"only-synthetic-password"},
            "reference":{"username":"reference@example.com","password":"reference-password"}}))
            .unwrap();
        let mut broker = LiveBroker::new_with_credentials(
            LiveProvider::Abliteration,
            key.path(),
            scope.normalized().unwrap(),
            Instant::now() + Duration::from_secs(60),
            Some(&credentials),
            None,
        )
        .unwrap();
        let inner = Arc::get_mut(&mut broker).unwrap();
        inner.test_target = Some(address);
        Arc::get_mut(inner.reference.as_mut().unwrap())
            .unwrap()
            .test_target = Some(address);
        let reference = broker.reference.as_ref().unwrap();
        let change = json!({"method":"POST","url":"https://owned.example/api/auth/change-password",
            "headers":{"content-type":"application/json"},"authenticated":true,
            "data":json!({"current_password":"{{PATCHRIOT_CURRENT_PASSWORD}}","new_password":"{{PATCHRIOT_NEW_PASSWORD}}"}).to_string()});
        assert_eq!(
            broker.http(change.clone()).await.unwrap_err(),
            "account_credential_changes_not_permitted"
        );
        for path in ["identity", "identity-401", "identity-403"] {
            for (actor, token) in [
                (&broker, "synthetic-browser-token"),
                (reference, "synthetic-reference-token"),
            ] {
                let url = format!("https://owned.example/{path}");
                let headers = json!({"authorization":format!("Bearer {token}")});
                let invalid = actor
                    .browser_call(
                        "/patchriot/browser/check",
                        json!({"url":url,"headers":headers,"json_pointer":"/account/missing"}),
                    )
                    .await;
                assert_eq!(invalid.unwrap_err(), "authenticated_identity_missing");
                assert!(!broker.password_change_permitted());
                let proof = actor
                    .browser_call(
                        "/patchriot/browser/check",
                        json!({"url":url,"headers":headers,"json_pointer":"/account/email"}),
                    )
                    .await
                    .unwrap();
                assert_eq!(proof["verified"], true);
                assert_eq!(proof["proof"]["check"]["kind"], "account_identity");
            }
            assert!(broker.password_change_permitted(), "{path}");
        }
        let saved_reference_proof = reference.browser.lock().unwrap().proof.clone();
        reference.browser.lock().unwrap().proof = broker.browser.lock().unwrap().proof.clone();
        assert!(
            !broker.password_change_permitted(),
            "same identity cannot authorize account changes"
        );
        reference.browser.lock().unwrap().proof = saved_reference_proof;
        assert!(!reference.password_change_permitted());
        assert_eq!(
            reference.http(change.clone()).await.unwrap_err(),
            "account_credential_changes_not_permitted"
        );
        let mut reference_write = json!({"method":"POST","url":"https://owned.example/api/preferences",
            "headers":{"content-type":"application/json"},"authenticated":true,
            "data":json!({"display_name":"Synthetic fixture"}).to_string()});
        let evidence_count = broker.counters.lock().unwrap().evidence.len();
        assert_eq!(
            reference.http(reference_write.clone()).await.unwrap_err(),
            "protected_reference_read_only"
        );
        assert_eq!(
            reference
                .engine_http(reference_write.clone())
                .await
                .unwrap_err(),
            "protected_reference_read_only"
        );
        assert_eq!(
            reference
                .browser_call("/patchriot/browser/http", reference_write.clone())
                .await
                .unwrap_err(),
            "protected_reference_read_only"
        );
        assert_eq!(
            broker.counters.lock().unwrap().evidence.len(),
            evidence_count
        );
        let mut false_login = reference_write.clone();
        false_login["login"] = json!(true);
        assert_eq!(
            reference
                .browser_call("/patchriot/browser/http", false_login)
                .await
                .unwrap_err(),
            "browser_login_submission_limit"
        );
        assert!(broker.http(reference_write.clone()).await.is_ok());
        reference_write["authenticated"] = json!(false);
        assert!(reference.http(reference_write).await.is_ok());
        for method in ["GET", "POST"] {
            let logout = json!({"method":method,"url":"https://owned.example/api/auth/logout","authenticated":true});
            let count = broker.counters.lock().unwrap().evidence.len();
            assert_eq!(
                broker.http(logout.clone()).await.unwrap_err(),
                "session_revocation_not_permitted"
            );
            assert_eq!(
                broker.engine_http(logout.clone()).await.unwrap_err(),
                "session_revocation_not_permitted"
            );
            assert_eq!(
                broker
                    .browser_call("/patchriot/browser/http", logout)
                    .await
                    .unwrap_err(),
                "session_revocation_not_permitted"
            );
            assert_eq!(broker.counters.lock().unwrap().evidence.len(), count);
        }
        assert_eq!(reference.engine_http(json!({"method":"GET","url":"https://owned.example/sign-out","authenticated":true})).await.unwrap_err(), "session_revocation_not_permitted");
        assert!(broker.http(json!({"method":"POST","url":"https://owned.example/api/auth/logout","authenticated":false})).await.is_ok());
        let result = broker.http(change.clone()).await.unwrap();
        assert_eq!(result["evidence"]["status"], 200);
        assert_eq!(result["evidence"]["account"], "testing");
        let new_password = broker.access.current_browser_password().unwrap();
        assert_ne!(new_password.as_str(), "only-synthetic-password");
        assert!(!result.to_string().contains(new_password.as_str()));
        assert_eq!(
            reference
                .access
                .current_browser_password()
                .unwrap()
                .as_str(),
            "reference-password"
        );
        assert_eq!(
            broker.http(change).await.unwrap_err(),
            "password_change_already_attempted"
        );
        let result = reference
            .engine_http(
                json!({"method":"GET","url":"https://owned.example/identity","authenticated":true}),
            )
            .await
            .unwrap();
        assert_eq!(result["evidence"]["status"], 200);
        assert_eq!(result["evidence"]["account"], "reference");
        assert!(Arc::ptr_eq(&broker.counters, &reference.counters));
        assert_eq!(
            broker
                .access
                .redact("reference-password synthetic-reference-token"),
            "REDACTED REDACTED"
        );
        Arc::get_mut(&mut broker)
            .unwrap()
            .scope
            .account_policy
            .as_mut()
            .unwrap()
            .allow_password_changes = false;
        assert!(
            !broker.password_change_permitted(),
            "verified accounts still require explicit permission"
        );
        server.abort();
    }

    #[tokio::test]
    async fn engine_access_uses_verified_bearer_without_leaking_into_anonymous_controls() {
        let (address, server) = target().await;
        let mut broker = broker("session");
        let inner = Arc::get_mut(&mut broker).unwrap();
        inner.test_target = Some(address);
        inner.scope.tools.push(LiveToolProfile::ArtexEngineV1);
        assert!(broker.verified_access().is_none());
        let signed =
            json!({"method":"GET","url":"https://owned.example/private","authenticated":true});
        assert_eq!(
            broker.engine_http(signed.clone()).await.unwrap_err(),
            "authenticated_access_not_verified"
        );
        let verified = broker.browser_call("/patchriot/browser/check", json!({"url":"https://owned.example/private","headers":{"authorization":"Bearer synthetic-browser-token"}})).await.unwrap();
        assert_eq!(verified["verified"], true);
        assert_eq!(
            broker.verified_access().as_deref(),
            Some("https://owned.example/private")
        );
        let reply = broker.engine_http(signed.clone()).await.unwrap();
        assert_eq!(reply["evidence"]["status"], 200);
        assert_eq!(reply["evidence"]["authenticated"], true);
        assert!(!reply.to_string().contains("synthetic-browser-token"));
        let anonymous = broker
            .engine_http(
                json!({"method":"GET","url":"https://owned.example/private","authenticated":false}),
            )
            .await
            .unwrap();
        assert_eq!(anonymous["evidence"]["status"], 401);
        assert_ne!(anonymous["evidence"]["authenticated"], true);
        assert_eq!(broker.engine_http(json!({"method":"GET","url":"https://other.example/private","authenticated":true})).await.unwrap_err(), "authenticated_origin_mismatch");
        broker
            .browser_call(
                "/patchriot/browser/check",
                json!({"url":"https://owned.example/public"}),
            )
            .await
            .unwrap();
        assert!(broker.verified_access().is_none());
        assert!(
            broker.browser.lock().unwrap().proof.is_some(),
            "earlier paired evidence remains reportable"
        );
        assert_eq!(
            broker.engine_http(signed).await.unwrap_err(),
            "authenticated_access_not_verified"
        );
        server.abort();
    }

    #[tokio::test]
    async fn browser_access_requires_denial_or_the_actual_supplied_identity() {
        let (address, server) = target().await;
        let mut broker = broker("session");
        Arc::get_mut(&mut broker).unwrap().test_target = Some(address);
        let headers = json!({"cookie":"session=synthetic-session"});
        let public = broker
            .browser_call(
                "/patchriot/browser/check",
                json!({"url":"https://owned.example/public","headers":headers}),
            )
            .await
            .unwrap();
        assert_eq!(public["verified"], false);
        let wrong = broker.browser_call("/patchriot/browser/check",json!({"url":"https://owned.example/identity","headers":headers,"json_pointer":"/account/not_present"})).await;
        assert_eq!(wrong.unwrap_err(), "authenticated_identity_missing");
        let verified = broker.browser_call("/patchriot/browser/check",json!({"url":"https://owned.example/identity","headers":headers,"json_pointer":"/account/email"})).await.unwrap();
        assert_eq!(verified["verified"], true);
        assert_eq!(verified["proof"]["check"]["kind"], "account_identity");
        server.abort();
    }

    #[tokio::test]
    async fn browser_signs_exact_custom_login_bytes_with_one_unfunded_role_wallet() {
        use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
        use sha3::Keccak256;
        let broker = broker("wallet");
        let query = json!({"origin":"https://owned.example","method":"eth_accounts"});
        let account = broker
            .browser_call("/patchriot/browser/wallet", query.clone())
            .await
            .unwrap();
        assert_eq!(
            account,
            broker
                .browser_call("/patchriot/browser/wallet", query)
                .await
                .unwrap()
        );
        broker
            .browser_call("/patchriot/browser/begin", json!({}))
            .await
            .unwrap();
        let message = "Welcome! Log in to the owned fixture. Challenge 12345678.";
        let request = json!({"origin":"https://owned.example","method":"personal_sign","address":account["address"],"message":message,"approved":true});
        let signed = broker
            .browser_call("/patchriot/browser/wallet", request.clone())
            .await
            .unwrap();
        let bytes = hex::decode(
            signed["signature"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
        )
        .unwrap();
        let digest = Keccak256::digest(
            format!("\x19Ethereum Signed Message:\n{}{message}", message.len()).as_bytes(),
        );
        let recovered = VerifyingKey::recover_from_prehash(
            &digest,
            &Signature::from_slice(&bytes[..64]).unwrap(),
            RecoveryId::from_byte(bytes[64] - 27).unwrap(),
        )
        .unwrap();
        assert_eq!(
            recovered,
            *broker
                .browser
                .lock()
                .unwrap()
                .key
                .as_ref()
                .unwrap()
                .verifying_key()
        );
        for (field, value) in [
            ("origin", json!("https://foreign.example")),
            ("method", json!("eth_sendTransaction")),
            ("method", json!("eth_signTypedData_v4")),
            ("approved", json!(false)),
            ("message", json!("permit2 approve spending")),
            (
                "address",
                json!("0x0000000000000000000000000000000000000001"),
            ),
        ] {
            let mut invalid = request.clone();
            invalid[field] = value;
            assert!(
                broker
                    .browser_call("/patchriot/browser/wallet", invalid)
                    .await
                    .is_err(),
                "{field}"
            );
        }
    }

    #[tokio::test]
    async fn browser_cannot_expand_origins_or_run_after_the_deadline() {
        let mut broker = broker("session");
        for url in [
            "https://other.example/",
            "http://owned.example/",
            "https://127.0.0.1/",
            "https://owned.example:444/",
        ] {
            assert!(
                broker
                    .browser_call("/patchriot/browser/http", json!({"method":"GET","url":url}))
                    .await
                    .is_err()
            );
        }
        assert!(broker.counters.lock().unwrap().evidence.is_empty());
        Arc::get_mut(&mut broker).unwrap().deadline = Instant::now();
        assert_eq!(
            broker
                .browser_call("/patchriot/browser/status", json!({}))
                .await
                .unwrap_err(),
            "role_deadline_reached"
        );
    }
}
