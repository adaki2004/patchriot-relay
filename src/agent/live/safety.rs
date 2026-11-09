//! Account credentials are not disposable probe data. These checks apply to
//! HTTP, discovery and browser traffic before any request is sent. Semantic
//! checks cannot identify every application-specific mutation; agents must
//! also leave account/security changes untested and report that limitation.
use super::{Value, access, browser};

fn normalized(value: &str) -> String {
    value
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect()
}

pub(super) fn secret_field(key: &str) -> bool {
    let key = normalized(key);
    key.contains("password")
        || key.contains("passwd")
        || matches!(
            key.as_str(),
            "pwd"
                | "token"
                | "accesstoken"
                | "refreshtoken"
                | "idtoken"
                | "resettoken"
                | "recoverytoken"
                | "jwt"
                | "secret"
                | "clientsecret"
                | "apikey"
                | "sessionkey"
                | "sessiontoken"
                | "authorization"
        )
}

/// Common browser session headers. These are retained only in the broker,
/// stripped from anonymous controls and never sent to another origin.
pub(super) fn session_header(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    let key = key.strip_prefix("x-").unwrap_or(&key);
    secret_field(key) || matches!(normalized(key).as_str(), "authtoken" | "auth")
}

fn mutation_field(key: &str) -> bool {
    let key = normalized(key);
    matches!(
        key.as_str(),
        "currentpassword"
            | "oldpassword"
            | "newpassword"
            | "confirmpassword"
            | "passwordconfirmation"
            | "passwordconfirm"
            | "password1"
            | "password2"
            | "newpasswd"
            | "oldpasswd"
            | "newpwd"
            | "oldpwd"
            | "resettoken"
            | "recoverytoken"
    ) || [
        "changepassword",
        "resetpassword",
        "updatepassword",
        "setpassword",
        "changepasswd",
    ]
    .iter()
    .any(|term| key.contains(term))
}

fn mutation_json(value: &Value) -> bool {
    match value {
        Value::Object(fields) => fields
            .iter()
            .any(|(k, v)| mutation_field(k) || mutation_json(v)),
        Value::Array(items) => items.iter().any(mutation_json),
        // Also covers GraphQL operations and action=change_password forms.
        Value::String(value) => [
            "changepassword",
            "resetpassword",
            "updatepassword",
            "setpassword",
            "newpassword",
        ]
        .iter()
        .any(|term| normalized(value).contains(term)),
        _ => false,
    }
}

pub(super) fn check_session_preservation(url: &url::Url) -> Result<(), &'static str> {
    let action = |value: &str| {
        matches!(
            normalized(value).as_str(),
            "logout"
                | "logoff"
                | "signout"
                | "signoff"
                | "endsession"
                | "destroysession"
                | "revokesession"
                | "revokesessions"
                | "invalidatesession"
                | "invalidatesessions"
        )
    };
    let path = url::form_urlencoded::parse(format!("path={}", url.path()).as_bytes())
        .next()
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default();
    // GET logout routes also destroy access. Keep anonymous controls available,
    // but never send the prepared account session to recognizable revocation.
    if path.split('/').any(action)
        || [
            "sessionrevoke",
            "sessionsrevoke",
            "sessiondestroy",
            "sessionsinvalidate",
        ]
        .iter()
        .any(|suffix| normalized(&path).ends_with(suffix))
        || url.query_pairs().any(|(key, value)| {
            matches!(normalized(&key).as_str(), "action" | "operation") && action(&value)
        })
    {
        return Err("session_revocation_not_permitted");
    }
    Ok(())
}

pub(super) fn check_account_write(
    url: &url::Url,
    method: &str,
    data: Option<&str>,
) -> Result<(), &'static str> {
    if matches!(method, "GET" | "HEAD" | "OPTIONS") {
        return Ok(());
    }
    let path = url::form_urlencoded::parse(format!("path={}", url.path()).as_bytes())
        .next()
        .map(|(_, v)| normalized(&v))
        .unwrap_or_default();
    // Includes initiating recovery: no unsolicited recovery emails or account
    // lockouts as part of an ordinary production assessment.
    if [
        "password",
        "passwd",
        "credential",
        "accountrecovery",
        "resetpwd",
        "changepwd",
    ]
    .iter()
    .any(|term| path.contains(term))
    {
        return Err("account_credential_changes_not_permitted");
    }
    if url
        .query_pairs()
        .any(|(k, v)| mutation_field(&k) || mutation_json(&Value::String(v.into_owned())))
    {
        return Err("account_credential_changes_not_permitted");
    }
    if let Some(data) = data {
        let forbidden = match serde_json::from_str::<Value>(data) {
            Ok(value) => mutation_json(&value),
            Err(_) => url::form_urlencoded::parse(data.as_bytes())
                .any(|(k, v)| mutation_field(&k) || mutation_json(&Value::String(v.into_owned()))),
        };
        if forbidden {
            return Err("account_credential_changes_not_permitted");
        }
    }
    Ok(())
}

pub(super) fn remember_body_secrets(
    access: &access::Access,
    data: &str,
) -> Result<(), &'static str> {
    if let Ok(value) = serde_json::from_str::<Value>(data) {
        browser::remember_tokens(access, &value, 0)
    } else {
        for (key, value) in url::form_urlencoded::parse(data.as_bytes()) {
            if secret_field(&key) {
                access.remember_secret(value.into_owned())?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn session_preservation_covers_encoded_routes_and_explicit_actions() {
        for path in [
            "/api/auth/logout",
            "/sign-out",
            "/api/%6cogout",
            "/logoff/confirm",
            "/api/sessions/revoke",
            "/account?action=sign_out",
            "/api/revoke-sessions",
        ] {
            assert_eq!(
                check_session_preservation(
                    &format!("https://owned.example{path}").parse().unwrap()
                ),
                Err("session_revocation_not_permitted"),
                "{path}"
            );
        }
        for path in [
            "/login",
            "/api/session",
            "/api/account/password",
            "/docs?topic=logout",
        ] {
            assert!(
                check_session_preservation(
                    &format!("https://owned.example{path}").parse().unwrap()
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn credential_mutations_are_blocked_without_blocking_login_or_public_form_controls() {
        for (path, body) in [
            (
                "/api/auth/me/password",
                r#"{"current_password":"fixture-old","new_password":"fixture-new"}"#,
            ),
            (
                "/api/auth/password-reset/request",
                r#"{"email":"test@example.invalid"}"#,
            ),
            (
                "/api/auth/%70assword-reset/confirm",
                "token=fixture&password=fixture",
            ),
            ("/api/profile", r#"{"data":{"newPassword":"fixture"}}"#),
            (
                "/api/profile",
                "current_password=fixture&new_password=fixture",
            ),
            (
                "/graphql",
                r#"{"query":"mutation { changePassword(value: \"fixture\") }"}"#,
            ),
            ("/action", "action=change_password&value=fixture"),
        ] {
            assert_eq!(
                check_account_write(
                    &format!("https://owned.example{path}").parse().unwrap(),
                    "POST",
                    Some(body)
                ),
                Err("account_credential_changes_not_permitted")
            );
        }
        for (method, path, body) in [
            (
                "POST",
                "/api/auth/login",
                r#"{"email":"test@example.invalid","password":"fixture"}"#,
            ),
            (
                "POST",
                "/contact",
                r#"{"name":"Authorized security test","message":"Test only"}"#,
            ),
            ("GET", "/password-reset", ""),
        ] {
            assert!(
                check_account_write(
                    &format!("https://owned.example{path}").parse().unwrap(),
                    method,
                    Some(body)
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn newly_generated_secrets_are_removed_from_later_model_and_evidence_text() {
        let scope = serde_json::from_value(
            json!({"origins":["https://owned.example"],"methods":["GET","HEAD","OPTIONS"]}),
        )
        .unwrap();
        let access = access::Access::new(&scope, None).unwrap();
        remember_body_secrets(
            &access,
            r#"{"data":{"new_password":"fixture-generated","clientSecret":"fixture-client"}}"#,
        )
        .unwrap();
        remember_body_secrets(&access, "password=fixture%26form").unwrap();
        browser::remember_tokens(
            &access,
            &json!({"accessToken":"fixture-session", "nested":{"refresh_token":"fixture-refresh"}}),
            0,
        )
        .unwrap();
        let mut transcript = json!({"content":"fixture-generated fixture-client fixture&form fixture-session fixture-refresh"});
        access.redact_json(&mut transcript);
        assert_eq!(
            transcript["content"],
            "REDACTED REDACTED REDACTED REDACTED REDACTED"
        );
    }
}
