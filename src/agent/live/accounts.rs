//! A password-change permission is scoped to one verified testing identity.
//! The protected reference account never receives this exception.
use super::*;
use std::sync::atomic::Ordering;
use zeroize::Zeroizing;

const CURRENT: &str = "{{PATCHRIOT_CURRENT_PASSWORD}}";
const NEXT: &str = "{{PATCHRIOT_NEW_PASSWORD}}";

/// A private replay of an observed login, with its password replaced by a
/// marker. Models cannot choose the destination or submit replacement fields.
pub(super) struct PasswordLogin {
    url: String,
    content_type: String,
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
        let mut fields: BTreeMap<String, String> = match content_type {
            "application/json" => serde_json::from_str(raw).ok()?,
            "application/x-www-form-urlencoded" => {
                let pairs: Vec<_> = url::form_urlencoded::parse(raw.as_bytes())
                    .into_owned()
                    .collect();
                let fields: BTreeMap<_, _> = pairs.iter().cloned().collect();
                if fields.len() != pairs.len() {
                    return None;
                }
                fields
            }
            _ => return None,
        };
        let principal = access.browser_principal()?;
        let password = access.current_browser_password().ok()?;
        if !fields.values().any(|v| v == principal)
            || fields
                .values()
                .filter(|v| v.as_str() == password.as_str())
                .count()
                != 1
        {
            return None;
        }
        for value in fields.values_mut() {
            if value == password.as_str() {
                *value = NEXT.into();
            }
        }
        let data = if content_type == "application/json" {
            serde_json::to_string(&fields).ok()?
        } else {
            url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(fields)
                .finish()
        };
        Some(Self {
            url: url.into(),
            content_type: content_type.into(),
            data: Zeroizing::new(data),
        })
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
            headers: BTreeMap::from([("content-type".into(), self.content_type.clone())]),
            data: Some(self.data.replace(&marker, &replacement)),
            authenticated: false,
            account_change: false,
        }
    }
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
            "login_control_evidence_id":(login > 0).then_some(login)})
    }

    /// One isolated login control after an accepted authorized change. The
    /// existing session remains available for the separate revocation check.
    pub(super) async fn verify_changed_password(&self) -> Result<Value, &'static str> {
        if !self.password_change_permitted() {
            return Err("account_credential_changes_not_permitted");
        }
        let password = self.access.replacement_password()?;
        let probe = {
            let mut state = self.browser.lock().map_err(|_| "browser_unavailable")?;
            let login = state
                .password_login
                .as_ref()
                .ok_or("password_login_not_observed")?;
            let origin = public_url(&login.url)?.origin().ascii_serialization();
            if state.verified_origin.as_deref() != Some(origin.as_str()) {
                return Err("authenticated_origin_mismatch");
            }
            let probe = login.probe(&password);
            self.probe_url(&probe, false)?;
            if state.password_login_attempted {
                return Err("password_login_already_attempted");
            }
            state.password_login_attempted = true;
            probe
        };
        // An anonymous exchange sends no prior cookie or bearer token and does
        // not install its new session. Only redacted evidence leaves the relay.
        let mut result = self.exchange(probe, false).await?;
        self.password_login_evidence.store(
            result["evidence"]["id"]
                .as_u64()
                .expect("recorded HTTP evidence") as u32,
            Ordering::SeqCst,
        );
        result["password_login_control"] = json!({"account":"testing","fresh_session":true,
            "interpretation":"Compare the observed login response with the original successful login. HTTP success alone does not establish authentication."});
        Ok(result)
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
            r#"{"credentials":{"email":"fixture@example.com","password":"synthetic-password"}}"#,
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
