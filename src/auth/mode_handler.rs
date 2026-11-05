use axum::{http::StatusCode, response::Json};
use serde::Serialize;

use crate::auth::AuthMode;

/// The sign-in button's provider name, shown in OIDC mode.
#[derive(Debug, Clone)]
pub struct SignInLabel(pub String);

/// Response for auth mode query
#[derive(Debug, Serialize)]
pub struct AuthModeResponse {
    pub mode: String,
    pub label: Option<String>,
}

/// Get the current authentication mode
pub async fn get_auth_mode(
    auth_mode: axum::Extension<AuthMode>,
    label: Option<axum::Extension<SignInLabel>>,
) -> Result<Json<AuthModeResponse>, StatusCode> {
    Ok(Json(AuthModeResponse {
        mode: auth_mode.as_str().to_string(),
        label: label.map(|axum::Extension(SignInLabel(label))| label),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_mode_answer_carries_the_sign_in_label_only_when_there_is_one() {
        let oidc = get_auth_mode(
            axum::Extension(AuthMode::Oidc),
            Some(axum::Extension(SignInLabel("Example IdP".to_string()))),
        )
        .await
        .unwrap();
        assert_eq!(oidc.mode, "oidc");
        assert_eq!(oidc.label.as_deref(), Some("Example IdP"));

        let saml = get_auth_mode(axum::Extension(AuthMode::Saml), None)
            .await
            .unwrap();
        assert_eq!(saml.mode, "saml");
        assert_eq!(saml.label, None);
    }
}
