//! A password-change permission is scoped to one verified testing identity.
//! The protected reference account never receives this exception.
use super::*;
use std::sync::atomic::Ordering;
use zeroize::Zeroizing;

const CURRENT: &str = "{{PATCHRIOT_CURRENT_PASSWORD}}";
const NEXT: &str = "{{PATCHRIOT_NEW_PASSWORD}}";

/// A private replay of an observed login, with its password replaced by a
/// marker. Models cannot choose the destination or submit replacement fields.
#[derive(Clone)]
pub(super) struct PasswordLogin {
    url: String,
    content_type: String,
    headers: BTreeMap<String, String>,
    data: Zeroizing<String>,
}

impl PasswordLogin {
    pub(super) fn learn(
        access: &access::Access,
        method: &str,
        url: &str,
        headers: &BTreeMap<String, String>,
        data: Option<&str>,
    ) -> Option<Self> {
        let raw = data?;
        if method != "POST" || raw.contains("PATCHRIOT_") || public_url(url).ok()?.query().is_some()
        {
            return None;
        }
        let content_type = headers.get("content-type")?.split(';').next()?.trim();
        let mut fields: Value = match content_type {
            "application/json" => serde_json::from_str(raw).ok()?,
            "application/x-www-form-urlencoded" => {
                let pairs: Vec<_> = url::form_urlencoded::parse(raw.as_bytes())
                    .into_owned()
                    .collect();
                let fields: BTreeMap<String, String> = pairs.iter().cloned().collect();
                if fields.len() != pairs.len() {
                    return None;
                }
                serde_json::to_value(fields).ok()?
            }
            _ => return None,
        };
        let principal = access.browser_principal()?;
        let password = access.current_browser_password().ok()?;
        let mut principals = 0;
        let mut passwords = 0;
        replace_login_password(
            &mut fields,
            principal,
            &password,
            &mut principals,
            &mut passwords,
            0,
        )?;
        if principals == 0 || passwords != 1 {
            return None;
        }
        let data = if content_type == "application/json" {
            serde_json::to_string(&fields).ok()?
        } else {
            url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(
                    fields
                        .as_object()?
                        .iter()
                        .map(|(k, v)| (k, v.as_str().unwrap_or(""))),
                )
                .finish()
        };
        let headers = headers
            .iter()
            .filter(|(key, _)| {
                matches!(
                    key.as_str(),
                    "content-type"
                        | "origin"
                        | "referer"
                        | "x-csrf-token"
                        | "x-xsrf-token"
                        | "csrf-token"
                )
            })
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        Some(Self {
            url: url.into(),
            content_type: content_type.into(),
            headers,
            data: Zeroizing::new(data),
        })
    }

    fn needs_csrf(&self) -> bool {
        self.headers.keys().any(|key| csrf_name(key))
            || if self.content_type == "application/json" {
                serde_json::from_str::<Value>(&self.data).is_ok_and(|value| csrf_in_value(&value))
            } else {
                url::form_urlencoded::parse(self.data.as_bytes()).any(|(name, _)| csrf_name(&name))
            }
    }

    fn refreshed_probe(
        &self,
        password: &str,
        html: &str,
        cookies: &str,
    ) -> Result<Probe, &'static str> {
        use scraper::{Html, Selector};
        if html.len() > 256 * 1024 || html.matches('<').count() > 4096 {
            return Err("fresh_login_csrf_page_too_large");
        }
        let document = Html::parse_document(html);
        let selector =
            Selector::parse("input[type=hidden][name][value], meta[name][content]").unwrap();
        let mut tokens = BTreeMap::<String, Vec<String>>::new();
        for element in document.select(&selector) {
            let name = element.value().attr("name").unwrap();
            if csrf_name(name) {
                let value = element
                    .value()
                    .attr("value")
                    .or_else(|| element.value().attr("content"))
                    .unwrap();
                tokens
                    .entry(normalized(name))
                    .or_default()
                    .push(value.into());
            }
        }
        for pair in cookies.split(';') {
            if let Some((name, value)) = pair.trim().split_once('=')
                && csrf_name(name)
            {
                tokens
                    .entry(normalized(name))
                    .or_default()
                    .push(value.into());
            }
        }
        let resolve = |name: &str| -> Result<String, &'static str> {
            let key = normalized(name).trim_start_matches('x').to_owned();
            let mut values: Vec<_> = tokens
                .iter()
                .filter(|(k, _)| k.trim_start_matches('x') == key)
                .flat_map(|(_, v)| v.iter())
                .collect();
            values.sort();
            values.dedup();
            if values.len() != 1 || values[0].is_empty() || values[0].len() > 2048 {
                return Err("fresh_login_csrf_missing_or_ambiguous");
            }
            Ok(values[0].clone())
        };
        let mut probe = self.probe(password);
        for (name, value) in &mut probe.headers {
            if csrf_name(name) {
                *value = resolve(name)?;
            }
        }
        if self.content_type == "application/json" {
            let mut body: Value = serde_json::from_str(probe.data.as_deref().unwrap())
                .map_err(|_| "invalid_login_fields")?;
            refresh_csrf_fields(&mut body, &resolve)?;
            probe.data = Some(body.to_string());
        } else {
            let mut fields: BTreeMap<String, String> =
                url::form_urlencoded::parse(probe.data.as_deref().unwrap().as_bytes())
                    .into_owned()
                    .collect();
            for (name, value) in &mut fields {
                if csrf_name(name) {
                    *value = resolve(name)?;
                }
            }
            probe.data = Some(
                url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(fields)
                    .finish(),
            );
        }
        Ok(probe)
    }

    fn probe(&self, password: &str) -> Probe {
        // Generated passwords contain only ASCII alphanumerics and '!'. Both
        // encodings are produced through their serializers before substitution.
        let (marker, replacement) = if self.content_type == "application/json" {
            (NEXT.to_owned(), password.to_owned())
        } else {
            let encode = |value: &str| {
                url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>()
            };
            (encode(NEXT), encode(password))
        };
        Probe {
            method: "POST".into(),
            url: self.url.clone(),
            headers: self.headers.clone(),
            data: Some(self.data.replace(&marker, &replacement)),
            authenticated: false,
            account_change: false,
        }
    }
}

fn replace_login_password(
    value: &mut Value,
    principal: &str,
    password: &str,
    principals: &mut usize,
    passwords: &mut usize,
    depth: usize,
) -> Option<()> {
    if depth > 16 {
        return None;
    }
    match value {
        Value::String(text) => {
            if text == principal {
                *principals += 1;
            }
            if text == password {
                *passwords += 1;
                *text = NEXT.into();
            }
        }
        Value::Object(fields) => {
            for child in fields.values_mut() {
                replace_login_password(
                    child,
                    principal,
                    password,
                    principals,
                    passwords,
                    depth + 1,
                )?;
            }
        }
        Value::Array(fields) => {
            for child in fields {
                replace_login_password(
                    child,
                    principal,
                    password,
                    principals,
                    passwords,
                    depth + 1,
                )?;
            }
        }
        _ => {}
    }
    Some(())
}

fn csrf_in_value(value: &Value) -> bool {
    match value {
        Value::Object(fields) => fields
            .iter()
            .any(|(name, value)| csrf_name(name) || csrf_in_value(value)),
        Value::Array(values) => values.iter().any(csrf_in_value),
        _ => false,
    }
}

fn csrf_name(name: &str) -> bool {
    let name = normalized(name);
    name.contains("csrf") || name.contains("xsrf")
}

fn refresh_csrf_fields(
    value: &mut Value,
    resolve: &impl Fn(&str) -> Result<String, &'static str>,
) -> Result<(), &'static str> {
    match value {
        Value::Object(fields) => {
            for (name, value) in fields {
                if csrf_name(name) {
                    *value = Value::String(resolve(name)?);
                } else {
                    refresh_csrf_fields(value, resolve)?;
                }
            }
        }
        Value::Array(items) => {
            for value in items {
                refresh_csrf_fields(value, resolve)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn fresh_access_token(value: &Value) -> Option<&str> {
    let mut candidates = Vec::new();
    fn collect<'a>(value: &'a Value, found: &mut Vec<&'a str>, depth: usize) {
        if depth > 16 {
            return;
        }
        if let Value::Object(fields) = value {
            for (name, child) in fields {
                if matches!(normalized(name).as_str(), "accesstoken" | "token") {
                    if let Some(token) = child.as_str().filter(|v| !v.is_empty()) {
                        found.push(token);
                    }
                } else {
                    collect(child, found, depth + 1);
                }
            }
        }
    }
    collect(value, &mut candidates, 0);
    candidates.sort_unstable();
    candidates.dedup();
    (candidates.len() == 1).then(|| candidates[0])
}

fn normalized(value: &str) -> String {
    value
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect()
}

fn self_service_path(url: &url::Url) -> bool {
    if url.query().is_some() || url.path().contains('%') {
        return false;
    }
    let parts: Vec<_> = url
        .path()
        .split('/')
        .filter(|s| !s.is_empty())
        .map(normalized)
        .collect();
    parts
        .iter()
        .any(|p| matches!(p.as_str(), "auth" | "account" | "profile" | "me" | "self"))
        && parts.iter().any(|p| p.contains("password"))
        && parts.iter().all(|p| {
            matches!(
                p.as_str(),
                "api"
                    | "auth"
                    | "account"
                    | "accounts"
                    | "profile"
                    | "me"
                    | "self"
                    | "user"
                    | "users"
                    | "settings"
                    | "security"
                    | "password"
                    | "changepassword"
                    | "passwordchange"
                    | "updatepassword"
                    | "passwordupdate"
                    | "change"
                    | "update"
            ) || p
                .strip_prefix('v')
                .is_some_and(|v| !v.is_empty() && v.bytes().all(|c| c.is_ascii_digit()))
        })
}

impl LiveBroker {
    pub(super) fn password_change_control(&self) -> Value {
        let accepted = self.password_change_evidence.load(Ordering::SeqCst);
        let login = self.password_login_evidence.load(Ordering::SeqCst);
        json!({"attempted":self.password_change_attempted.load(Ordering::SeqCst),
            "accepted_evidence_id":(accepted > 0).then_some(accepted),
            "login_control_evidence_id":(login > 0).then_some(login),
            "fresh_session_proof":self.browser.lock().ok().and_then(|state| state.password_login_proof.clone())})
    }

    /// One isolated login control after an accepted authorized change. The
    /// existing session remains available for the separate revocation check.
    pub(super) async fn verify_changed_password(&self) -> Result<Value, &'static str> {
        if !self.password_change_permitted() {
            return Err("account_credential_changes_not_permitted");
        }
        let password = self.access.replacement_password()?;
        let (login, proof) = {
            let mut state = self.browser.lock().map_err(|_| "browser_unavailable")?;
            let login = state
                .password_login
                .as_ref()
                .ok_or("password_login_replay_unavailable")?
                .clone();
            let origin = public_url(&login.url)?.origin().ascii_serialization();
            if state.verified_origin.as_deref() != Some(origin.as_str()) {
                return Err("authenticated_origin_mismatch");
            }
            self.probe_url(&login.probe(&password), false)?;
            if state.password_login_attempted {
                return Err("password_login_already_attempted");
            }
            let proof = state
                .proof
                .clone()
                .ok_or("authenticated_identity_missing")?;
            state.password_login_attempted = true;
            (login, proof)
        };
        let session = self.fresh_password_session()?;
        session
            .browser_call("/patchriot/browser/begin", json!({}))
            .await?;
        let mut probe = login.probe(&password);
        if login.needs_csrf() {
            let page = login.headers.get("referer").cloned().unwrap_or_else(|| {
                format!(
                    "{}{}",
                    self.scope.origins[0],
                    self.scope
                        .browser_login
                        .as_ref()
                        .and_then(|b| b.entry_path.as_deref())
                        .unwrap_or("/")
                )
            });
            self.scope.permits("GET", &page)?;
            let bootstrap = session
                .browser_exchange(browser::BrowserRequest {
                    method: "GET".into(),
                    url: page,
                    headers: BTreeMap::new(),
                    data: None,
                    authenticated: true,
                    login: true,
                })
                .await?;
            if bootstrap.evidence.error.is_some() || bootstrap.evidence.status != Some(200) {
                return Err("fresh_login_csrf_page_unavailable");
            }
            let cookies = session.access.cookies(&public_url(&login.url)?, true);
            probe = login.refreshed_probe(
                &password,
                &String::from_utf8_lossy(&bootstrap.body),
                cookies.as_ref().and_then(|v| v.to_str().ok()).unwrap_or(""),
            )?;
            if let Some(cookie) = cookies {
                probe.headers.insert(
                    "cookie".into(),
                    cookie
                        .to_str()
                        .map_err(|_| "invalid_session_cookie")?
                        .into(),
                );
            }
        }
        let reply = session
            .browser_exchange(browser::BrowserRequest {
                method: probe.method,
                url: probe.url,
                headers: probe.headers,
                data: probe.data,
                authenticated: true,
                login: true,
            })
            .await?;
        self.password_login_evidence
            .store(reply.evidence.id, Ordering::SeqCst);
        let body = self.access.redact(&String::from_utf8_lossy(&reply.body));
        let mut result = json!({"evidence":reply.evidence,"body":body,
            "password_login_control":{"account":"testing","fresh_session":true,"verified":false}});
        if reply.evidence.error.is_some()
            || !reply
                .evidence
                .status
                .is_some_and(|s| (200..400).contains(&s))
        {
            result["password_login_control"]["reason"] = json!("fresh_login_rejected");
            return Ok(result);
        }
        let (resource, pointer) = {
            let count = self.counters.lock().map_err(|_| "counter_unavailable")?;
            let resource = count
                .evidence
                .iter()
                .find(|e| e.id == proof.authenticated_id)
                .ok_or("authenticated_resource_unavailable")?
                .url
                .clone();
            let BrowserAccessCheck::AccountIdentity { json_pointer, .. } = proof.check else {
                return Err("authenticated_identity_missing");
            };
            (resource, json_pointer)
        };
        let mut headers = BTreeMap::new();
        if let Some(cookie) = session.access.cookies(&public_url(&resource)?, true) {
            headers.insert(
                "cookie",
                cookie
                    .to_str()
                    .map_err(|_| "invalid_session_cookie")?
                    .to_owned(),
            );
        }
        if let Ok(value) = serde_json::from_slice::<Value>(&reply.body)
            && let Some(token) = fresh_access_token(&value)
        {
            headers.insert("authorization", format!("Bearer {token}"));
        }
        let check = session
            .browser_check(json!({"url":resource,"headers":headers,"json_pointer":pointer}))
            .await;
        match check {
            Ok(check) => {
                result["password_login_control"]["verified"] = check["verified"].clone();
                result["password_login_control"]["proof"] = check["proof"].clone();
                if check["verified"] == true {
                    self.browser
                        .lock()
                        .map_err(|_| "browser_unavailable")?
                        .password_login_proof = serde_json::from_value(check["proof"].clone()).ok();
                }
                result["verification_evidence"] = check["evidence"].clone();
            }
            Err(reason) => result["password_login_control"]["reason"] = json!(reason),
        }
        Ok(result)
    }

    fn fresh_password_session(&self) -> Result<Self, &'static str> {
        Ok(Self {
            provider: self.provider,
            client: self.client.clone(),
            near: None,
            key: self.key.clone(),
            fallback_key: None,
            fallback_provider: None,
            scope: self.scope.clone(),
            deadline: self.deadline,
            final_report_reserve: self.final_report_reserve,
            counters: self.counters.clone(),
            account: self.account,
            reference: None,
            password_change_attempted: std::sync::atomic::AtomicBool::new(true),
            password_change_evidence: std::sync::atomic::AtomicU32::new(0),
            password_login_evidence: std::sync::atomic::AtomicU32::new(0),
            workflow: Mutex::new(None),
            access: self.access.fresh_session()?,
            login_state: tokio::sync::Mutex::new(None),
            browser: Mutex::new(browser::BrowserState::default()),
            #[cfg(test)]
            test_target: self.test_target,
        })
    }

    pub(super) fn password_change_permitted(&self) -> bool {
        if self.account != Some(AccountSlot::Testing)
            || !self
                .scope
                .account_policy
                .as_ref()
                .is_some_and(|p| p.allow_password_changes)
            || self.scope.profile != Some(AssessmentProfile::WebActiveV2)
            || self.verified_access().is_none()
        {
            return false;
        }
        let Some(reference) = &self.reference else {
            return false;
        };
        if reference.verified_access().is_none() {
            return false;
        }
        let identity =
            |broker: &LiveBroker| match broker.browser.lock().ok()?.proof.as_ref()?.check.clone() {
                BrowserAccessCheck::AccountIdentity {
                    authenticated_value_sha256,
                    ..
                } => Some(authenticated_value_sha256),
                _ => None,
            };
        identity(self)
            .zip(identity(reference))
            .is_some_and(|(first, second)| first != second)
    }

    /// Substitute private passwords only for the one permitted self-service
    /// request. Engines receive markers and redacted evidence, never passwords.
    pub(super) fn prepare_password_change(
        &self,
        probe: &mut Probe,
    ) -> Result<Option<Zeroizing<String>>, &'static str> {
        let Some(raw) = probe.data.as_ref() else {
            return Ok(None);
        };
        if !raw.contains("PATCHRIOT_CURRENT_PASSWORD") && !raw.contains("PATCHRIOT_NEW_PASSWORD") {
            return Ok(None);
        }
        if probe.method != "POST" || !probe.authenticated || !self.password_change_permitted() {
            return Err("account_credential_changes_not_permitted");
        }
        let url = self.scope.permits(&probe.method, &probe.url)?;
        if !self_service_path(&url) {
            return Err("password_change_self_service_path_required");
        }
        let content = probe
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.split(';').next().unwrap_or("").trim())
            .unwrap_or("");
        let mut fields: BTreeMap<String, String> = match content {
            "application/json" => {
                serde_json::from_str(raw).map_err(|_| "password_change_flat_fields_required")?
            }
            "application/x-www-form-urlencoded" => {
                let pairs: Vec<_> = url::form_urlencoded::parse(raw.as_bytes())
                    .into_owned()
                    .collect();
                let map: BTreeMap<_, _> = pairs.iter().cloned().collect();
                if map.len() != pairs.len() {
                    return Err("password_change_flat_fields_required");
                }
                map
            }
            _ => return Err("unsupported_probe_body"),
        };
        let mut current = 0;
        let mut next = 0;
        for (key, value) in &fields {
            match normalized(key).as_str() {
                "currentpassword" | "oldpassword" if value == CURRENT => current += 1,
                "newpassword" if value == NEXT => next += 1,
                "confirmpassword" | "passwordconfirmation" | "passwordconfirm" if value == NEXT => {
                }
                "csrf" | "csrftoken" | "xsrf" | "xsrftoken" if !value.contains("PATCHRIOT_") => {}
                _ => return Err("password_change_flat_fields_required"),
            }
        }
        if current != 1 || next != 1 {
            return Err("password_change_markers_required");
        }
        let old = self.access.current_browser_password()?;
        let password = Zeroizing::new(format!(
            "Pr!{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        ));
        self.access.remember_secret(password.to_string())?;
        self.password_change_attempted
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| "password_change_already_attempted")?;
        for value in fields.values_mut() {
            if value == CURRENT {
                *value = old.to_string();
            } else if value == NEXT {
                *value = password.to_string();
            }
        }
        probe.data = Some(if content == "application/json" {
            serde_json::to_string(&fields).expect("string map")
        } else {
            url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(fields)
                .finish()
        });
        probe.account_change = true;
        Ok(Some(password))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nested_login_refreshes_csrf_and_retains_other_json_types() {
        let scope: LiveScope = serde_json::from_value(json!({"origins":["https://owned.example"],
            "methods":["GET","POST"],"authentication":"session","browser_login":{},
            "tools":["authenticated_http_v1","browser_login_v1"]}))
        .unwrap();
        let credentials = TestCredentials::Session {
            username: "fixture@example.com".into(),
            password: "synthetic-password".into(),
        };
        let access = access::Access::new(&scope, Some(&credentials)).unwrap();
        let headers = BTreeMap::from([
            ("content-type".into(), "application/json".into()),
            ("origin".into(), "https://owned.example".into()),
            ("x-csrf-token".into(), "old-csrf".into()),
        ]);
        let login = PasswordLogin::learn(&access, "POST", "https://owned.example/session", &headers,
            Some(r#"{"credentials":{"email":"fixture@example.com","secret":"synthetic-password"},"remember":true,"csrf_token":"old-csrf"}"#)).unwrap();
        assert!(login.needs_csrf());
        let probe = login
            .refreshed_probe(
                "Pr!fresh",
                r#"<meta name="csrf-token" content="fresh-csrf">"#,
                "",
            )
            .unwrap();
        let body: Value = serde_json::from_str(probe.data.as_deref().unwrap()).unwrap();
        assert_eq!(body["credentials"]["secret"], "Pr!fresh");
        assert_eq!(body["remember"], true);
        assert_eq!(body["csrf_token"], "fresh-csrf");
        assert_eq!(probe.headers["x-csrf-token"], "fresh-csrf");
        assert_eq!(probe.headers["origin"], "https://owned.example");
        assert!(login.refreshed_probe("Pr!fresh", "", "").is_err());
        assert!(login.refreshed_probe("Pr!fresh", r#"<meta name="csrf-token" content="one"><meta name="csrf-token" content="two">"#, "").is_err());
        assert_eq!(
            fresh_access_token(&json!({"token":"one","data":{"access_token":"two"}})),
            None
        );
        assert_eq!(
            fresh_access_token(&json!({"refresh_token":"refresh","data":{"access_token":"one"}})),
            Some("one")
        );
    }

    #[test]
    fn password_login_replays_only_observed_flat_credentials() {
        let scope: LiveScope = serde_json::from_value(json!({"origins":["https://owned.example"],
            "methods":["GET","POST"],"profile":"web_active_v2", "authentication":"session",
            "browser_login":{},"tools":["active_web_v2","browser_login_v1"]}))
        .unwrap();
        let credentials: TestCredentials = serde_json::from_value(json!({"kind":"session",
            "username":"fixture@example.com","password":"synthetic-password"}))
        .unwrap();
        let access = access::Access::new(&scope, Some(&credentials)).unwrap();
        for (content, body) in [
            (
                "application/json",
                r#"{"email":"fixture@example.com","password":"synthetic-password"}"#,
            ),
            (
                "application/x-www-form-urlencoded",
                "user=fixture%40example.com&pwd=synthetic-password",
            ),
        ] {
            let headers = BTreeMap::from([("content-type".into(), content.into())]);
            let login = PasswordLogin::learn(
                &access,
                "POST",
                "https://owned.example/signin",
                &headers,
                Some(body),
            )
            .unwrap();
            assert!(!login.data.contains("synthetic-password"));
            let probe = login.probe("Pr!replacement123");
            let fields: BTreeMap<String, String> = if content == "application/json" {
                serde_json::from_str(probe.data.as_ref().unwrap()).unwrap()
            } else {
                url::form_urlencoded::parse(probe.data.as_ref().unwrap().as_bytes())
                    .into_owned()
                    .collect()
            };
            assert!(fields.values().any(|v| v == "Pr!replacement123"));
            assert!(!probe.authenticated);
            assert_eq!(probe.headers.len(), 1);
            assert!(
                PasswordLogin::learn(
                    &access,
                    "GET",
                    "https://owned.example/signin",
                    &headers,
                    Some(body)
                )
                .is_none()
            );
            assert!(
                PasswordLogin::learn(
                    &access,
                    "POST",
                    "https://owned.example/signin?next=/",
                    &headers,
                    Some(body)
                )
                .is_none()
            );
        }
        let headers = BTreeMap::from([("content-type".into(), "application/json".into())]);
        for body in [
            r#"{"email":"other@example.com","password":"synthetic-password"}"#,
            r#"{"email":"fixture@example.com","password":"wrong-password"}"#,
            r#"{"email":"fixture@example.com","password":"synthetic-password","confirmation":"synthetic-password"}"#,
        ] {
            assert!(
                PasswordLogin::learn(
                    &access,
                    "POST",
                    "https://owned.example/signin",
                    &headers,
                    Some(body)
                )
                .is_none()
            );
        }
    }
    #[test]
    fn self_service_exception_excludes_recovery_admin_targets_and_account_ids() {
        for path in [
            "/api/auth/change-password",
            "/v1/users/me/password",
            "/account/password/change",
        ] {
            assert!(self_service_path(
                &url::Url::parse(&format!("https://owned.example{path}")).unwrap()
            ));
        }
        for path in [
            "/api/auth/password-reset",
            "/admin/users/42/password",
            "/users/42/password",
            "/auth/password?user=other",
            "/auth/%70assword",
        ] {
            assert!(!self_service_path(
                &url::Url::parse(&format!("https://owned.example{path}")).unwrap()
            ));
        }
    }
}
