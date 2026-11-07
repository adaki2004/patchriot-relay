//! A password-change permission is scoped to one verified testing identity.
//! The protected reference account never receives this exception.
use super::*;
use std::sync::atomic::Ordering;
use zeroize::Zeroizing;

const CURRENT: &str = "{{PATCHRIOT_CURRENT_PASSWORD}}";
const NEXT: &str = "{{PATCHRIOT_NEW_PASSWORD}}";

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
