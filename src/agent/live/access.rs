//! The model gets a scoped HTTP helper, never credentials or session cookies.
use base64::{Engine, engine::general_purpose::STANDARD};
use patchriot_protocol::pentests::{LiveScope, SessionLogin, TestCredentials};
use reqwest::{
    cookie::{CookieStore, Jar},
    header::{HeaderMap, HeaderValue, SET_COOKIE},
};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

pub(super) struct Access {
    authorization: Option<Zeroizing<String>>,
    login_account: Option<(Zeroizing<String>, Zeroizing<String>)>,
    replacement_password: Mutex<Option<Zeroizing<String>>>,
    secrets: Arc<Mutex<Vec<Zeroizing<String>>>>,
    supplied_secret_count: usize,
    cookies: Jar,
    cookie_bytes: Mutex<usize>,
    sessions: bool,
}
impl Access {
    /// Delivered to the isolated browser controller for filling the supplied
    /// account. Never include this response in a model transcript or report.
    pub fn share_redactions(&mut self, other: &mut Self) {
        let mut combined = self.secrets.lock().expect("secret store poisoned").clone();
        combined.extend(
            other
                .secrets
                .lock()
                .expect("secret store poisoned")
                .iter()
                .cloned(),
        );
        self.supplied_secret_count = combined.len();
        other.supplied_secret_count = combined.len();
        self.secrets = Arc::new(Mutex::new(combined));
        other.secrets = self.secrets.clone();
    }
    /// Fresh cookie jar sharing only redaction knowledge with the current role.
    pub(super) fn fresh_session(&self) -> Result<Self, &'static str> {
        let password = self.replacement_password()?;
        Ok(Self {
            authorization: None,
            login_account: self
                .login_account
                .as_ref()
                .map(|(name, _)| (name.clone(), password)),
            replacement_password: Mutex::new(None),
            secrets: self.secrets.clone(),
            supplied_secret_count: self.supplied_secret_count,
            cookies: Jar::default(),
            cookie_bytes: Mutex::new(0),
            sessions: true,
        })
    }
    pub fn browser_credentials(&self) -> Result<serde_json::Value, &'static str> {
        let (username, password) = self
            .login_account
            .as_ref()
            .ok_or("test_account_unavailable")?;
        let replacement = self
            .replacement_password
            .lock()
            .map_err(|_| "credential_unavailable")?;
        Ok(
            serde_json::json!({"username":username.as_str(),"password":replacement.as_deref().map(String::as_str).unwrap_or(password.as_str())}),
        )
    }
    pub fn current_browser_password(&self) -> Result<Zeroizing<String>, &'static str> {
        let replacement = self
            .replacement_password
            .lock()
            .map_err(|_| "credential_unavailable")?;
        replacement
            .clone()
            .or_else(|| {
                self.login_account
                    .as_ref()
                    .map(|(_, password)| password.clone())
            })
            .ok_or("test_account_unavailable")
    }
    pub fn replace_browser_password(
        &self,
        password: Zeroizing<String>,
    ) -> Result<(), &'static str> {
        self.remember_secret(password.to_string())?;
        *self
            .replacement_password
            .lock()
            .map_err(|_| "credential_unavailable")? = Some(password);
        Ok(())
    }
    pub fn replacement_password(&self) -> Result<Zeroizing<String>, &'static str> {
        self.replacement_password
            .lock()
            .map_err(|_| "credential_unavailable")?
            .clone()
            .ok_or("password_change_not_accepted")
    }
    pub fn browser_principal(&self) -> Option<&str> {
        self.login_account
            .as_ref()
            .map(|(username, _)| username.as_str())
    }
    pub fn redact_limited(&self, value: &str, limit: usize) -> (String, bool) {
        Self::limit_text(self.redact(value), limit)
    }
    /// Tool receipts contain typed counters and flags as well as untrusted
    /// strings. Redacting their serialized bytes can turn `1` into bare
    /// `REDACTED`, making an otherwise complete receipt unreadable.
    pub fn redact_tool_excerpt(&self, value: &str, limit: usize) -> (String, bool) {
        let Ok(mut parsed) = serde_json::from_str(value) else {
            return self.redact_limited(value, limit);
        };
        self.redact_tool_json(&mut parsed);
        Self::limit_text(serde_json::to_string(&parsed).expect("JSON receipt"), limit)
    }
    fn redact_tool_json(&self, value: &mut serde_json::Value) {
        use serde_json::Value;
        match value {
            Value::String(text) => *text = self.redact(text),
            Value::Array(items) => items
                .iter_mut()
                .for_each(|item| self.redact_tool_json(item)),
            Value::Object(fields) => {
                for (key, mut child) in std::mem::take(fields) {
                    self.redact_tool_json(&mut child);
                    let mut key = self.redact(&key);
                    // Two private keys may redact to the same marker. Retain
                    // both values without restoring either original key.
                    let mut suffix = 2;
                    while fields.contains_key(&key) {
                        key = format!("REDACTED_{suffix}");
                        suffix += 1;
                    }
                    fields.insert(key, child);
                }
            }
            _ => {
                let raw = value.to_string();
                // Discovered short cookie flags such as "1" and "true" do
                // not make every typed counter/boolean a credential. Supplied
                // credentials and longer discovered secrets stay protected,
                // even if a tool echoes them as a JSON scalar rather than text.
                let sensitive = self
                    .secrets
                    .lock()
                    .expect("redaction state poisoned")
                    .iter()
                    .enumerate()
                    .any(|(index, secret)| {
                        !secret.is_empty()
                            && (index < self.supplied_secret_count || secret.chars().count() >= 8)
                            && raw.contains(secret.as_str())
                    });
                if sensitive {
                    *value = Value::String(self.redact(&raw));
                }
            }
        }
    }
    fn limit_text(mut text: String, limit: usize) -> (String, bool) {
        let shortened = text.len() > limit;
        if shortened {
            let mut end = limit;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
        }
        (text, shortened)
    }
    pub fn apply(
        &self,
        mut request: reqwest::RequestBuilder,
        url: &url::Url,
        enabled: bool,
    ) -> reqwest::RequestBuilder {
        if let Some(header) = self.authorization(enabled) {
            request = request.header("authorization", header);
        }
        if let Some(header) = self.cookies(url, enabled) {
            request = request.header("cookie", header);
        }
        request
    }
    pub fn new(
        scope: &LiveScope,
        credentials: Option<&TestCredentials>,
    ) -> Result<Self, &'static str> {
        if matches!(credentials, Some(TestCredentials::SessionAccounts { .. }))
            || scope.authentication != credentials.map(TestCredentials::kind)
            || credentials.is_some_and(|c| !c.valid())
        {
            return Err("invalid_test_credentials");
        }
        let mut secrets = Vec::new();
        let authorization = credentials.and_then(|c| match c {
            TestCredentials::Basic { username, password } => {
                secrets.push(Zeroizing::new(password.clone()));
                let joined = Zeroizing::new(format!("{username}:{password}"));
                Some(format!("Basic {}", STANDARD.encode(joined.as_bytes())))
            }
            TestCredentials::Bearer { token } => {
                secrets.push(Zeroizing::new(token.clone()));
                Some(format!("Bearer {token}"))
            }
            TestCredentials::Wallet {} | TestCredentials::SessionAccounts { .. } => None,
            TestCredentials::Session { password, .. } => {
                secrets.push(Zeroizing::new(password.clone()));
                None
            }
        });
        if let Some(header) = &authorization {
            secrets.push(Zeroizing::new(header.clone()));
            secrets.push(Zeroizing::new(header.split_once(' ').unwrap().1.to_owned()));
        }
        Ok(Self {
            replacement_password: Mutex::new(None),
            authorization: authorization.map(Zeroizing::new),
            login_account: match credentials {
                Some(TestCredentials::Session { username, password }) => Some((
                    Zeroizing::new(username.clone()),
                    Zeroizing::new(password.clone()),
                )),
                _ => None,
            },
            supplied_secret_count: secrets.len(),
            secrets: Arc::new(Mutex::new(secrets)),
            cookies: Jar::default(),
            cookie_bytes: Mutex::new(0),
            sessions: scope.methods.iter().any(|m| m == "POST") || credentials.is_some(),
        })
    }
    pub fn login_fields(
        &self,
        login: &SessionLogin,
    ) -> Result<std::collections::BTreeMap<String, String>, &'static str> {
        let (username, password) = self
            .login_account
            .as_ref()
            .ok_or("invalid_test_credentials")?;
        Ok([
            (login.username_field.clone(), username.to_string()),
            (login.password_field.clone(), password.to_string()),
        ]
        .into())
    }
    pub fn remember_supplied_secret(&mut self, value: String) -> Result<(), &'static str> {
        self.remember_secret(value)?;
        self.supplied_secret_count = self
            .secrets
            .lock()
            .map_err(|_| "redaction_unavailable")?
            .len();
        Ok(())
    }
    pub fn remember_secret(&self, value: String) -> Result<(), &'static str> {
        let value = Zeroizing::new(value);
        let mut secrets = self.secrets.lock().map_err(|_| "redaction_unavailable")?;
        if value.is_empty() || secrets.iter().any(|old| **old == *value) {
            return Ok(());
        }
        if value.len() > 8192
            || secrets.len() >= 512
            || secrets.iter().map(|v| v.len()).sum::<usize>() + value.len() > 256 * 1024
        {
            return Err("credential_redaction_limit");
        }
        secrets.push(value);
        Ok(())
    }
    pub fn authenticated(&self, url: &url::Url, enabled: bool) -> bool {
        self.authorization(enabled).is_some() || self.cookies(url, enabled).is_some()
    }
    pub fn authorization(&self, enabled: bool) -> Option<&str> {
        if enabled {
            self.authorization.as_deref().map(String::as_str)
        } else {
            None
        }
    }
    pub fn cookies(&self, url: &url::Url, enabled: bool) -> Option<HeaderValue> {
        if !self.sessions || !enabled {
            return None;
        }
        self.cookies
            .cookies(url)
            .filter(|h| h.as_bytes().len() <= 8192)
    }
    pub fn remember(&self, url: &url::Url, headers: &HeaderMap, enabled: bool) {
        if !self.sessions || !enabled {
            return;
        }
        let mut total = self.cookie_bytes.lock().expect("cookie counter poisoned");
        for header in headers.get_all(SET_COOKIE) {
            if header.as_bytes().len() > 4096 || *total + header.as_bytes().len() > 32768 {
                continue;
            }
            let Ok(value) = header.to_str() else { continue };
            if let Some((_, secret)) = value.split(';').next().unwrap_or("").split_once('=')
                && !secret.is_empty()
                && self
                    .remember_secret(secret.trim_matches('"').to_owned())
                    .is_err()
            {
                continue;
            }
            *total += header.as_bytes().len();
            self.cookies.set_cookies(&mut std::iter::once(header), url);
        }
    }
    pub fn redact(&self, value: &str) -> String {
        let secrets = self.secrets.lock().expect("redaction state poisoned");
        // Match only the original text. Replacing successively would reprocess
        // the marker itself when a server sets short cookies such as R or E,
        // allowing a small response to expand repeatedly during redaction.
        let mut covered = vec![false; value.len()];
        for (index, secret) in secrets.iter().enumerate().filter(|(_, s)| !s.is_empty()) {
            // Supplied credentials always receive substring protection. Short
            // discovered values can instead be invalid probe inputs or cookie
            // flags (e.g. "x" or "1"). Hiding them inside unrelated words
            // corrupts source code, paths and the next model's instructions.
            let whole_value = index >= self.supplied_secret_count && secret.chars().count() < 8;
            // Echoed HTML/JSON/form values cannot smuggle the supplied secret
            // into a model prompt, evidence file or report.
            let json = serde_json::to_string(secret.as_str()).expect("string is JSON");
            for pattern in [
                secret.to_string(),
                url::form_urlencoded::byte_serialize(secret.as_bytes()).collect(),
                json[1..json.len() - 1].to_owned(),
            ] {
                if !pattern.is_empty() {
                    for (start, _) in value.match_indices(&pattern) {
                        let end = start + pattern.len();
                        let identifier = |c: char| c.is_alphanumeric() || c == '_';
                        if whole_value
                            && (value[..start].chars().next_back().is_some_and(identifier)
                                || value[end..].chars().next().is_some_and(identifier))
                        {
                            continue;
                        }
                        covered[start..end].fill(true);
                    }
                }
            }
        }
        let mut result = String::with_capacity(value.len());
        let mut start = 0;
        while start < value.len() {
            let hidden = covered[start];
            let end = covered[start..]
                .iter()
                .position(|value| *value != hidden)
                .map_or(value.len(), |offset| start + offset);
            if hidden {
                result.push_str("REDACTED");
            } else {
                // Match boundaries are UTF-8 boundaries; merging matches keeps
                // the untouched spans valid too.
                result.push_str(&value[start..end]);
            }
            start = end;
        }
        result
    }
    pub fn redact_json(&self, value: &mut serde_json::Value) {
        match value {
            serde_json::Value::String(v) => *v = self.redact(v),
            serde_json::Value::Array(v) => v.iter_mut().for_each(|v| self.redact_json(v)),
            serde_json::Value::Object(v) => v.values_mut().for_each(|v| self.redact_json(v)),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn redaction_never_reprocesses_markers_and_preserves_unicode() {
        let scope: LiveScope = serde_json::from_value(serde_json::json!({
            "origins":["https://owned.example"], "methods":["GET"]
        }))
        .unwrap();
        let access = Access::new(&scope, None).unwrap();
        for secret in ["x", "R", "E", "D", "A", "C", "T", "é\"&"] {
            access.remember_secret(secret.into()).unwrap();
        }
        assert_eq!(access.redact(&"x".repeat(8192)), "x".repeat(8192));
        assert_eq!(access.redact("x ☃ x"), "REDACTED ☃ REDACTED");
        assert_eq!(
            access.redact("é\"& é\\\"& %C3%A9%22%26"),
            "REDACTED REDACTED REDACTED"
        );
        let (bounded, shortened) = access.redact_limited("x ☃ x", 11);
        assert_eq!(bounded, "REDACTED ");
        assert!(shortened);
    }
    #[test]
    fn structured_receipts_keep_flags_while_redacting_private_keys_and_scalar_echoes() {
        use serde_json::{Value, json};
        let scope: LiveScope = serde_json::from_value(json!({
            "origins":["https://owned.example"], "methods":["GET"], "authentication":"basic"
        }))
        .unwrap();
        let access = Access::new(
            &scope,
            Some(&TestCredentials::Basic {
                username: "fixture-account".into(),
                password: "246813".into(),
            }),
        )
        .unwrap();
        for secret in ["1", "true", "fixture-session-key", "876543210"] {
            access.remember_secret(secret.into()).unwrap();
        }
        let receipt = json!({
            "receipt_schema":1, "coverage_complete":true, "failure":null,
            "findings_returned":1, "private": {
                "fixture-session-key":"cookie=1 password=246813",
                "REDACTED":"second value", "password_echo":246813,
                "session_echo":876543210, "nested":["fixture-session-key",true]
            }
        })
        .to_string();
        assert!(serde_json::from_str::<Value>(&access.redact(&receipt)).is_err());
        let (cleaned, shortened) = access.redact_tool_excerpt(&receipt, 24 * 1024);
        assert!(!shortened);
        assert!(
            !cleaned.contains("246813")
                && !cleaned.contains("876543210")
                && !cleaned.contains("fixture-session-key")
        );
        let parsed: Value = serde_json::from_str(&cleaned).unwrap();
        assert_eq!(parsed["receipt_schema"], 1);
        assert_eq!(parsed["coverage_complete"], true);
        assert_eq!(parsed["failure"], Value::Null);
        assert_eq!(parsed["findings_returned"], 1);
        assert_eq!(parsed["private"].as_object().unwrap().len(), 5);
        assert_eq!(parsed["private"]["password_echo"], "REDACTED");
        assert_eq!(parsed["private"]["session_echo"], "REDACTED");
        assert_eq!(parsed["private"]["nested"], json!(["REDACTED", true]));
        let (bounded, shortened) =
            access.redact_tool_excerpt(&json!({"text":"é".repeat(100)}).to_string(), 31);
        assert!(shortened && bounded.len() <= 31);
        assert_eq!(
            access.redact_tool_excerpt("plain cookie=1", 100),
            ("plain cookie=REDACTED".into(), false)
        );
    }
    #[test]
    fn short_observed_values_do_not_corrupt_code_but_supplied_credentials_stay_private() {
        let scope: LiveScope = serde_json::from_value(serde_json::json!({
            "origins":["https://owned.example"], "methods":["GET"]
        }))
        .unwrap();
        let access = Access::new(&scope, None).unwrap();
        super::super::safety::remember_body_secrets(&access, r#"{"password":"x"}"#).unwrap();
        let code = "except Exception: print('/work/example.txt')";
        assert_eq!(access.redact(code), code);
        assert_eq!(
            access.redact(r#"{"password":"x"} password=x; 'x'"#),
            r#"{"password":"REDACTED"} password=REDACTED; 'REDACTED'"#
        );
        access
            .remember_secret("fixture-generated-secret".into())
            .unwrap();
        assert_eq!(
            access.redact("prefixfixture-generated-secretsuffix"),
            "prefixREDACTEDsuffix"
        );

        let scope: LiveScope = serde_json::from_value(serde_json::json!({
            "origins":["https://owned.example"], "methods":["GET"], "authentication":"basic"
        }))
        .unwrap();
        let access = Access::new(
            &scope,
            Some(&TestCredentials::Basic {
                username: "fixture".into(),
                password: "éééé".into(),
            }),
        )
        .unwrap();
        assert_eq!(access.redact("prefixéééésuffix"), "prefixREDACTEDsuffix");
    }
    #[tokio::test]
    async fn a_real_session_keeps_cookies_out_of_anonymous_controls_and_does_not_follow_redirects()
    {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();
            for index in 0..3 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut bytes = vec![0; 8192];
                let count = socket.read(&mut bytes).await.unwrap();
                requests.push(String::from_utf8_lossy(&bytes[..count]).into_owned());
                let reply = if index == 2 {
                    "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                } else {
                    "HTTP/1.1 200 OK\r\nSet-Cookie: session=fixture-session-cookie; Path=/; HttpOnly\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                };
                socket.write_all(reply.as_bytes()).await.unwrap();
            }
            requests
        });
        let scope:LiveScope=serde_json::from_value(serde_json::json!({"origins":["https://owned.example"],"methods":["GET","HEAD","OPTIONS"],"profile":"web_baseline_v1","tools":["authenticated_http_v1"],"authentication":"basic","auth_check_path":"/private"})).unwrap();
        let input = TestCredentials::Basic {
            username: "test-user".into(),
            password: "fixture-password".into(),
        };
        let access = Access::new(&scope, Some(&input)).unwrap();
        // Transport fixture only. Production resolves and validates public HTTPS
        // before applying this helper; no localhost exception exists there.
        let url = url::Url::parse(&format!("http://{address}/private")).unwrap();
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();
        for enabled in [true, false, true] {
            let response = access
                .apply(client.get(url.clone()), &url, enabled)
                .send()
                .await
                .unwrap();
            access.remember(&url, response.headers(), enabled);
        }
        let requests = server.await.unwrap();
        assert!(requests[0].contains("authorization: Basic "));
        assert!(!requests[1].contains("authorization:") && !requests[1].contains("cookie:"));
        assert!(requests[2].contains("cookie: session=fixture-session-cookie"));
        assert_eq!(
            access.redact("fixture-password fixture-session-cookie"),
            "REDACTED REDACTED"
        );
    }
    #[test]
    fn credentials_and_cookie_echoes_are_redacted_and_anonymous_controls_send_neither() {
        let scope = LiveScope {
            check_groups: None,
            origins: vec!["https://owned.example".into()],
            objective: "fixture".into(),
            methods: vec!["GET".into()],
            profile: None,
            tools: vec![],
            authentication: Some(patchriot_protocol::pentests::TestAuthKind::Bearer),
            auth_check_path: Some("/private".into()),
            session_login: None,
            wallet_login: None,
            browser_login: None,
            browser_entry_origin: None,
            browser_resource_origins: vec![],
            account_policy: None,
        };
        let credentials = TestCredentials::Bearer {
            token: "synthetic-bearer-for-tests".into(),
        };
        let access = Access::new(&scope, Some(&credentials)).unwrap();
        let url = url::Url::parse("https://owned.example/private").unwrap();
        assert!(
            access
                .authorization(true)
                .unwrap()
                .contains("synthetic-bearer")
        );
        assert!(access.authorization(false).is_none());
        let mut headers = HeaderMap::new();
        headers.insert(
            SET_COOKIE,
            HeaderValue::from_static("session=synthetic-cookie-value; Path=/; Secure; HttpOnly"),
        );
        access.remember(&url, &headers, true);
        assert!(access.cookies(&url, true).is_some());
        assert!(access.cookies(&url, false).is_none());
        assert!(
            access
                .cookies(
                    &url::Url::parse("https://elsewhere.example/").unwrap(),
                    true
                )
                .is_none()
        );
        assert_eq!(
            access.redact("synthetic-bearer-for-tests synthetic-cookie-value"),
            "REDACTED REDACTED"
        );
        let mut short = HeaderMap::new();
        short.insert(
            SET_COOKIE,
            HeaderValue::from_static("short=x; Path=/; Secure"),
        );
        access.remember(&url, &short, true);
        let (bounded, shortened) = access.redact_limited(&"x ☃ ".repeat(3000), 2048);
        assert!(shortened && bounded.len() <= 2048 && !bounded.contains('x'));
        assert!(std::str::from_utf8(bounded.as_bytes()).is_ok());
        let mut value = serde_json::json!({"summary":"synthetic-cookie-value","evidence":["synthetic-bearer-for-tests"]});
        access.redact_json(&mut value);
        assert!(!value.to_string().contains("synthetic-"));
    }
}
