use axum::Json;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tracing::debug;

const MAX_CONCURRENT_POLICY_VALIDATIONS: usize = 4;
static POLICY_VALIDATION_SLOTS: Semaphore = Semaphore::const_new(MAX_CONCURRENT_POLICY_VALIDATIONS);

/// Request body for validating OPA policy
#[derive(Debug, Deserialize)]
pub struct ValidatePolicyRequest {
    pub policy: String,
}

/// Response for policy validation
#[derive(Debug, Serialize)]
pub struct ValidatePolicyResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Validate OPA/Rego policy syntax under the same admission limits used by the
/// persistence and runtime paths.
pub async fn validate_policy(Json(payload): Json<ValidatePolicyRequest>) -> (StatusCode, Json<ValidatePolicyResponse>) {
    debug!("Validating OPA policy (length: {} bytes)", payload.policy.len());

    if payload
        .policy
        .trim()
        .is_empty()
    {
        return (
            StatusCode::OK,
            Json(ValidatePolicyResponse {
                valid: false,
                error: Some("An enabled policy definition must contain Rego source".to_string()),
            }),
        );
    }

    let Ok(_permit) = POLICY_VALIDATION_SLOTS.try_acquire() else {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ValidatePolicyResponse {
                valid: false,
                error: Some("Too many policy validations are already running".to_string()),
            }),
        );
    };

    let policy = payload.policy;
    let result = tokio::task::spawn_blocking(move || {
        let test_engine = crate::policies::OpaEngine::new();
        crate::policies::validate_policy_inputs(&policy)
            .and_then(|()| test_engine.load_policy("test_validation", &policy))
    })
    .await;

    match result {
        Ok(Ok(())) => {
            debug!("Policy validation successful");
            (StatusCode::OK, Json(ValidatePolicyResponse { valid: true, error: None }))
        }
        Ok(Err(error)) => {
            debug!("Policy validation failed: {}", error);
            (
                StatusCode::OK,
                Json(ValidatePolicyResponse {
                    valid: false,
                    error: Some(error),
                }),
            )
        }
        Err(error) => {
            debug!("Policy validation worker failed: {}", error);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ValidatePolicyResponse {
                    valid: false,
                    error: Some("Policy validation failed".to_string()),
                }),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_policy_is_invalid() {
        let (status, Json(response)) = validate_policy(Json(ValidatePolicyRequest { policy: "  ".to_string() })).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!response.valid);
    }

    #[tokio::test]
    async fn a_policy_reading_an_unpopulated_input_is_invalid() {
        let policy = "package llm.policy\ndefault allow := true\ndeny if input.mcp.tool_name == \"delete_repo\"";
        let (status, Json(response)) =
            validate_policy(Json(ValidatePolicyRequest { policy: policy.to_string() })).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!response.valid);
        assert!(
            response
                .error
                .unwrap()
                .contains("input.mcp")
        );
    }

    #[tokio::test]
    async fn unsafe_builtin_is_invalid() {
        let policy = "package llm.policy\ndefault allow = false\nallow if { numbers.range(1, 1000) }";
        let (status, Json(response)) =
            validate_policy(Json(ValidatePolicyRequest { policy: policy.to_string() })).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!response.valid);
        assert!(
            response
                .error
                .unwrap()
                .contains("numbers.range")
        );
    }
}
