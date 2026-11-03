//! The model gets a scoped HTTP helper, never credentials or session cookies.
use base64::{Engine, engine::general_purpose::STANDARD};
use patchriot_protocol::pentests::{LiveScope, TestCredentials};
use reqwest::{
    cookie::{CookieStore, Jar},
    header::{HeaderMap, HeaderValue, SET_COOKIE},
};
use std::sync::Mutex;
use zeroize::Zeroizing;

pub(super) struct Access {
    authorization: Option<Zeroizing<String>>,
    secrets: Mutex<Vec<Zeroizing<String>>>,
    cookies: Jar,
    cookie_bytes: Mutex<usize>,
    sessions: bool,
}
impl Access {
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
        if scope.authentication != credentials.map(TestCredentials::kind)
            || credentials.is_some_and(|c| !c.valid())
        {
            return Err("invalid_test_credentials");
        }
        let mut secrets = Vec::new();
        let authorization = credentials.map(|c| match c {
            TestCredentials::Basic { username, password } => {
                secrets.push(Zeroizing::new(password.clone()));
                let joined = Zeroizing::new(format!("{username}:{password}"));
                format!("Basic {}", STANDARD.encode(joined.as_bytes()))
            }
            TestCredentials::Bearer { token } => {
                secrets.push(Zeroizing::new(token.clone()));
                format!("Bearer {token}")
            }
        });
        if let Some(header) = &authorization {
            secrets.push(Zeroizing::new(header.clone()));
            secrets.push(Zeroizing::new(header.split_once(' ').unwrap().1.to_owned()));
        }
        Ok(Self {
            authorization: authorization.map(Zeroizing::new),
            secrets: Mutex::new(secrets),
            cookies: Jar::default(),
            cookie_bytes: Mutex::new(0),
            sessions: scope.methods.iter().any(|m| m == "POST") || credentials.is_some(),
        })
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
            {
                self.secrets
                    .lock()
                    .expect("redaction state poisoned")
                    .push(Zeroizing::new(secret.trim_matches('"').to_owned()));
            }
            *total += header.as_bytes().len();
            self.cookies.set_cookies(&mut std::iter::once(header), url);
        }
    }
    pub fn redact(&self, value: &str) -> String {
        let secrets = self.secrets.lock().expect("redaction state poisoned");
        let mut result = value.to_owned();
        for secret in secrets.iter().filter(|s| !s.is_empty()) {
            // Echoed HTML/JSON/form values cannot smuggle the supplied secret
            // into a model prompt, evidence file or report.
            for pattern in [
                secret.to_string(),
                url::form_urlencoded::byte_serialize(secret.as_bytes()).collect(),
                serde_json::to_string(secret.as_str())
                    .unwrap_or_default()
                    .trim_matches('"')
                    .to_owned(),
            ] {
                if !pattern.is_empty() {
                    result = result.replace(&pattern, "REDACTED");
                }
            }
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
            origins: vec!["https://owned.example".into()],
            objective: "fixture".into(),
            methods: vec!["GET".into()],
            profile: None,
            tools: vec![],
            authentication: Some(patchriot_protocol::pentests::TestAuthKind::Bearer),
            auth_check_path: Some("/private".into()),
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
        let mut value = serde_json::json!({"summary":"synthetic-cookie-value","evidence":["synthetic-bearer-for-tests"]});
        access.redact_json(&mut value);
        assert!(!value.to_string().contains("synthetic-"));
    }
}
