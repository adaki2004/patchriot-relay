//! Login is performed by the broker, once, using the owner-selected endpoint.
//! Neither the agent nor the model receives the account, CSRF token or cookies.
use super::*;
use scraper::{Html, Selector};

impl LiveBroker {
    pub(super) async fn ensure_session(&self) -> Result<(), &'static str> {
        let Some(login) = &self.scope.session_login else {
            return Ok(());
        };
        let mut outcome = self.login_state.lock().await;
        if let Some(result) = *outcome {
            return result;
        }
        // Cancellation or a dropped connection must not trigger more password
        // submissions. A new assessment is needed to try a different account.
        *outcome = Some(Err("login_not_completed"));
        let result = self.start_session(login).await;
        *outcome = Some(result);
        result
    }

    async fn start_session(&self, login: &SessionLogin) -> Result<(), &'static str> {
        let origin = &self.scope.origins[0];
        let submit = public_url(&format!("{origin}{}", login.path))?;
        let mut fields = self.access.login_fields(login)?;
        if let Some(path) = &login.page_path {
            let page = public_url(&format!("{origin}{path}"))?;
            let reply = self
                .exchange(
                    Probe {
                        method: "GET".into(),
                        url: page.to_string(),
                        headers: BTreeMap::new(),
                        data: None,
                        authenticated: true,
                    },
                    true,
                )
                .await?;
            if reply["evidence"]["status"] != 200
                || !reply["evidence"]["error"].is_null()
                || reply["body_truncated"] == true
            {
                return Err("login_page_unavailable");
            }
            if let Some(name) = &login.csrf_field {
                let token = csrf_token(
                    login,
                    &page,
                    &submit,
                    reply["body"].as_str().unwrap_or(""),
                    name,
                )?;
                self.access.remember_secret(token.clone());
                fields.insert(name.clone(), token);
            }
        }
        let (content_type, body) = match login.format {
            LoginFormat::Form => (
                "application/x-www-form-urlencoded",
                url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(&fields)
                    .finish(),
            ),
            LoginFormat::Json => (
                "application/json",
                serde_json::to_string(&fields).map_err(|_| "invalid_login_fields")?,
            ),
        };
        let reply = self
            .exchange(
                Probe {
                    method: "POST".into(),
                    url: submit.to_string(),
                    headers: [
                        ("content-type".into(), content_type.into()),
                        ("origin".into(), origin.clone()),
                        (
                            "referer".into(),
                            format!(
                                "{origin}{}",
                                login.page_path.as_ref().unwrap_or(&login.path)
                            ),
                        ),
                    ]
                    .into(),
                    data: Some(body),
                    authenticated: true,
                },
                true,
            )
            .await?;
        let status = reply["evidence"]["status"].as_u64().unwrap_or(0);
        if !reply["evidence"]["error"].is_null()
            || !(200..300).contains(&status) && !matches!(status, 302 | 303)
        {
            return Err("login_rejected");
        }
        if let Some(location) = reply["login_redirect"].as_str() {
            let next = submit
                .join(location)
                .map_err(|_| "login_redirect_outside_scope")?;
            self.scope
                .permits("GET", next.as_str())
                .map_err(|_| "login_redirect_outside_scope")?;
            // No redirect is followed, even on the approved host. The next
            // ordinary request checks the declared protected resource instead.
        }
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
        Ok(())
    }
}

fn csrf_token(
    login: &SessionLogin,
    page: &url::Url,
    submit: &url::Url,
    html: &str,
    name: &str,
) -> Result<String, &'static str> {
    // Bound tree-building work as well as the HTTP body. Even a small page can
    // contain many unclosed tags; reject it before constructing a DOM.
    if html.len() > 256 * 1024
        || html.bytes().filter(|byte| *byte == b'<').take(8193).count() > 8192
    {
        return Err("login_page_too_complex");
    }
    let document = Html::parse_document(html);
    let forms = Selector::parse("form").map_err(|_| "login_form_unavailable")?;
    let inputs = Selector::parse("input").map_err(|_| "login_form_unavailable")?;
    let mut tokens = Vec::new();
    for form in document.select(&forms) {
        if !form
            .value()
            .attr("method")
            .is_some_and(|v| v.eq_ignore_ascii_case("post"))
            || page
                .join(form.value().attr("action").unwrap_or(page.as_str()))
                .ok()
                .as_ref()
                != Some(submit)
        {
            continue;
        }
        let fields: Vec<_> = form.select(&inputs).collect();
        if !fields
            .iter()
            .any(|i| i.value().attr("name") == Some(login.username_field.as_str()))
            || !fields
                .iter()
                .any(|i| i.value().attr("name") == Some(login.password_field.as_str()))
        {
            continue;
        }
        for input in fields {
            if input.value().attr("name") == Some(name)
                && input
                    .value()
                    .attr("type")
                    .is_some_and(|v| v.eq_ignore_ascii_case("hidden"))
            {
                let value = input.value().attr("value").ok_or("login_csrf_missing")?;
                if value.is_empty() || value.len() > 2048 || value.chars().any(char::is_control) {
                    return Err("login_csrf_invalid");
                }
                tokens.push(value.to_owned());
            }
        }
    }
    if tokens.len() != 1 {
        return Err("login_csrf_missing_or_ambiguous");
    }
    Ok(tokens.remove(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    fn response(status: &str, headers: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }
    async fn fixture(
        form: bool,
        replies: Vec<String>,
    ) -> (Arc<LiveBroker>, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();
            for reply in replies {
                let (mut stream, _) =
                    tokio::time::timeout(Duration::from_secs(5), listener.accept())
                        .await
                        .unwrap()
                        .unwrap();
                let mut bytes = Vec::new();
                loop {
                    let mut buf = [0; 4096];
                    let n = stream.read(&mut buf).await.unwrap();
                    assert!(n > 0 && bytes.len() < 32768);
                    bytes.extend_from_slice(&buf[..n]);
                    if let Some(pos) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&bytes[..pos]);
                        let body: usize = head
                            .lines()
                            .filter_map(|l| l.split_once(':'))
                            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                            .map(|(_, v)| v.trim().parse().unwrap())
                            .unwrap_or(0);
                        if bytes.len() >= pos + 4 + body {
                            break;
                        }
                    }
                }
                requests.push(String::from_utf8(bytes).unwrap());
                stream.write_all(reply.as_bytes()).await.unwrap();
            }
            requests
        });
        let mut raw = json!({"origins":["https://owned.example"],"methods":["GET","HEAD","OPTIONS"],"profile":"web_baseline_v1","tools":["authenticated_http_v1","session_login_v1"],"authentication":"session","auth_check_path":"/private","session_login":{"path":"/session","format":"json","username_field":"email","password_field":"password"}});
        if form {
            raw["session_login"]["format"] = json!("form");
            raw["session_login"]["page_path"] = json!("/login");
            raw["session_login"]["csrf_field"] = json!("csrf");
        }
        let scope = serde_json::from_value::<LiveScope>(raw)
            .unwrap()
            .normalized()
            .unwrap();
        let key = tempfile::NamedTempFile::new().unwrap();
        std::fs::set_permissions(key.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(key.path(), "synthetic-model-key-for-owned-test").unwrap();
        let credentials = TestCredentials::Session {
            username: "tester@example.com".into(),
            password: "fixture-password-only".into(),
        };
        let mut broker = LiveBroker::new_with_credentials(
            LiveProvider::Abliteration,
            key.path(),
            scope,
            Instant::now() + Duration::from_secs(60),
            Some(&credentials),
            None,
        )
        .unwrap();
        Arc::get_mut(&mut broker).unwrap().test_target = Some(address);
        (broker, server)
    }

    #[tokio::test]
    async fn form_login_uses_csrf_once_keeps_secrets_private_and_preserves_anonymous_controls() {
        let html = r#"<form method="post" action="/session"><input name="email"><input name="password" type="password"><input name="csrf" type="hidden" value="csrf&amp;fixture"></form>"#;
        let (broker, server) = fixture(true, vec![
            response("200 OK", "Set-Cookie: csrf_cookie=csrf-cookie-fixture; Path=/; Secure\r\n", html),
            response("303 See Other", "Location: /app\r\nSet-Cookie: session=session-cookie-fixture; Path=/; Secure; HttpOnly\r\n", "fixture-password-only"),
            response("200 OK", "", "fixture-password-only csrf&fixture session-cookie-fixture"),
            response("401 Unauthorized", "", "Account needed"),
            response("200 OK", "", "Private account page"),
        ]).await;
        let request = json!({"method":"GET","url":"https://owned.example/private"});
        let actual = broker.http(request.clone()).await.unwrap();
        assert_eq!(actual["evidence"]["authenticated"], true);
        assert_eq!(actual["body"], "REDACTED REDACTED REDACTED");
        let anonymous = broker
            .http(
                json!({"method":"GET","url":"https://owned.example/private","authenticated":false}),
            )
            .await
            .unwrap();
        assert_eq!(anonymous["evidence"]["status"], 401);
        assert!(
            !anonymous["evidence"]["authenticated"]
                .as_bool()
                .unwrap_or(false)
        );
        broker.http(request).await.unwrap();
        assert!(
            broker
                .http(json!({"method":"POST","url":"https://owned.example/other"}))
                .await
                .is_err()
        );
        assert!(
            broker
                .http(json!({"method":"GET","url":"https://other.example/private"}))
                .await
                .is_err()
        );
        let sent = server.await.unwrap();
        assert!(sent[1].starts_with("POST /session "));
        assert!(sent[1].contains("csrf=csrf%26fixture"));
        assert!(sent[1].contains("password=fixture-password-only"));
        assert!(sent[2].contains("session=session-cookie-fixture"));
        assert!(!sent[3].contains("cookie:") && !sent[3].contains("authorization:"));
        assert_eq!(sent.iter().filter(|r| r.starts_with("POST ")).count(), 1);
        let records = &broker.counters.lock().unwrap().evidence;
        assert_eq!(records.len(), 5);
        for record in &records[..2] {
            assert!(
                record.login
                    && record.body_excerpt.is_empty()
                    && record.request_body_excerpt.is_none()
            );
            assert!(record.headers.is_empty() && record.request_headers.is_empty());
        }
        let saved = serde_json::to_string(records).unwrap();
        for secret in [
            "fixture-password-only",
            "csrf&fixture",
            "session-cookie-fixture",
            "csrf-cookie-fixture",
        ] {
            assert!(!saved.contains(secret));
        }
        let result: PentestResult = serde_json::from_value(json!({
            "kind":"pentest_agent_v1","scope_sha256":broker.scope.hash().unwrap(),
            "execution":{"state":"completed","provider":"abliteration.ai","model":MODEL,"image_digest":"owned-fixture","duration_ms":10,"inference_calls":1,"http_requests":records.len(),"cost_upper_microusd":0,"cleanup_confirmed":true},
            "assessment":{"summary":"Owned fixture account and anonymous control were compared.","findings":[],"limitations":[]},"evidence":records,"raw_summary":""
        })).unwrap();
        assert!(result.evidence_complete(&broker.scope));
        let mut changed = result.clone();
        changed.evidence[1].login = false;
        assert!(
            !changed.valid(&broker.scope),
            "a login exception cannot become arbitrary POST evidence"
        );
        let mut changed = result;
        changed.evidence[1].body_excerpt = "accidentally retained login content".into();
        assert!(!changed.valid(&broker.scope));
    }

    #[tokio::test]
    async fn json_login_uses_session_cookies_without_inventing_a_bearer_token() {
        let (broker, server) = fixture(
            false,
            vec![
                response(
                    "200 OK",
                    "Set-Cookie: session=json-fixture-session; Path=/; Secure\r\n",
                    "{}",
                ),
                response("200 OK", "", "Signed in"),
            ],
        )
        .await;
        let actual = broker
            .http(json!({"method":"GET","url":"https://owned.example/private"}))
            .await
            .unwrap();
        assert_eq!(actual["evidence"]["authenticated"], true);
        let sent = server.await.unwrap();
        let body: Value = serde_json::from_str(sent[0].split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(
            body,
            json!({"email":"tester@example.com","password":"fixture-password-only"})
        );
        assert!(sent[1].contains("session=json-fixture-session"));
        assert!(!sent[1].contains("authorization:"));
    }

    #[tokio::test]
    async fn failed_login_and_off_scope_redirect_never_retry_the_password() {
        for (response, reason) in [
            (
                response("401 Unauthorized", "", "Wrong password"),
                "login_rejected",
            ),
            (
                response(
                    "302 Found",
                    "Location: https://elsewhere.example/app\r\nSet-Cookie: session=fixture-cookie; Path=/\r\n",
                    "",
                ),
                "login_redirect_outside_scope",
            ),
            (
                response(
                    "200 OK",
                    "",
                    "{\"token\":\"unsupported-token-only-response\"}",
                ),
                "login_session_missing",
            ),
        ] {
            let (broker, server) = fixture(false, vec![response]).await;
            for _ in 0..2 {
                assert_eq!(
                    broker
                        .http(json!({"method":"GET","url":"https://owned.example/private"}))
                        .await
                        .unwrap_err(),
                    reason
                );
            }
            assert_eq!(server.await.unwrap().len(), 1);
            assert_eq!(broker.counters.lock().unwrap().evidence.len(), 1);
        }
    }

    #[tokio::test]
    async fn foreign_or_ambiguous_csrf_forms_cannot_trigger_a_login_post() {
        let form = r#"<form method="post" action="/session"><input name="email"><input name="password"><input type="hidden" name="csrf" value="fixture-csrf"></form>"#;
        for html in [
            form.replace("/session", "https://elsewhere.example/session"),
            format!("{form}{form}"),
        ] {
            let (broker, server) = fixture(true, vec![response("200 OK", "", &html)]).await;
            assert_eq!(
                broker
                    .http(json!({"method":"GET","url":"https://owned.example/private"}))
                    .await
                    .unwrap_err(),
                "login_csrf_missing_or_ambiguous"
            );
            let requests = server.await.unwrap();
            assert_eq!(requests.len(), 1);
            assert!(requests[0].starts_with("GET /login "));
        }
    }

    #[tokio::test]
    async fn dense_login_markup_is_rejected_before_parsing_or_submitting_credentials() {
        let html = "<b>".repeat(8193);
        let (broker, server) = fixture(true, vec![response("200 OK", "", &html)]).await;
        assert_eq!(
            broker
                .http(json!({"method":"GET","url":"https://owned.example/private"}))
                .await
                .unwrap_err(),
            "login_page_too_complex"
        );
        let sent = server.await.unwrap();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].starts_with("GET /login "));
    }
}
