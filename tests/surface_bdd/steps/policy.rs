use super::support::*;
use crate::world::SurfaceWorld;
use cucumber::{given, then, when};
use serde_json::json;

#[given(expr = "LLM Surface {string} policy allows caller access tier {string}")]
async fn llm_surface_policy_allows_caller_access_tier(
    world: &mut SurfaceWorld,
    surface_name: String,
    access_tier: String,
) {
    world.ensure_operator().await;
    let policy_id = policy_id(&surface_name);
    let access_tier_literal = serde_json::to_string(&access_tier).expect("access tier should serialize");
    let policy = format!(
        r#"package llm.policy
import rego.v1
default allow := false
allow if input.http.headers["x-access-tier"] == {access_tier_literal}
"#
    );
    let now = chrono::Utc::now().to_rfc3339();
    let create_response = world
        .admin_client()
        .create_policy_definition(json!({
            "id": policy_id,
            "name": format!("{surface_name} access policy"),
            "description": "Allows one caller access tier",
            "policy_type": "llm",
            "policy": policy,
            "enabled": true,
            "created_at": now
        }))
        .await;
    assert_eq!(
        create_response.status, 201,
        "expected policy definition creation to succeed, got {}: {}",
        create_response.status, create_response.text
    );

    configure_llm_surface_policy(world, &surface_name, &policy_id).await;
}

#[given(expr = "IDE Surface {string} policy allows caller access tier {string}")]
async fn ide_surface_policy_allows_caller_access_tier(
    world: &mut SurfaceWorld,
    surface_name: String,
    access_tier: String,
) {
    world.ensure_operator().await;
    let policy_id = policy_id(&surface_name);
    let access_tier_literal = serde_json::to_string(&access_tier).expect("access tier should serialize");
    let policy = format!(
        r#"package ide.policy
import rego.v1
default allow := false
allow if input.http.headers["x-access-tier"] == {access_tier_literal}
"#
    );
    let response = world
        .admin_client()
        .create_policy_definition(json!({
            "id": policy_id,
            "name": format!("{surface_name} access policy"),
            "description": "Allows one caller access tier",
            "policy_type": "ide",
            "policy": policy,
            "enabled": true,
            "created_at": chrono::Utc::now().to_rfc3339()
        }))
        .await;
    assert_eq!(
        response.status, 201,
        "expected IDE policy creation to succeed, got {}: {}",
        response.status, response.text
    );
    update_surface(
        world,
        &surface_name,
        |pipe| pipe["opa_policy"] = json!({ "enabled": true, "policy_definition_id": policy_id }),
        "policy",
    )
    .await;
}

#[given(expr = "the appliance-wide LLM policy allows caller access tier {string}")]
async fn appliance_wide_llm_policy_allows_caller_access_tier(
    world: &mut SurfaceWorld,
    access_tier: String,
) {
    world.ensure_operator().await;
    let policy_id = "bdd-appliance-llm-policy";
    let access_tier_literal = serde_json::to_string(&access_tier).expect("access tier should serialize");
    let policy = format!(
        r#"package llm.policy
import rego.v1
default allow := false
allow if input.http.headers["x-access-tier"] == {access_tier_literal}
"#
    );
    let created = world
        .admin_client()
        .create_policy_definition(json!({
            "id": policy_id,
            "name": "Appliance-wide LLM access policy",
            "description": "Allows one caller access tier on every LLM Surface",
            "policy_type": "llm",
            "policy": policy,
            "enabled": true,
            "created_at": chrono::Utc::now().to_rfc3339()
        }))
        .await;
    assert_eq!(
        created.status, 201,
        "expected policy definition creation to succeed, got {}: {}",
        created.status, created.text
    );
    let assigned = world
        .admin_client()
        .put_admin_json(
            "/v1/policy-assignments",
            json!({ "assignments": { "llm": [{ "policy_id": policy_id, "monitor_only": false }] } }),
        )
        .await;
    assert_eq!(
        assigned.status, 200,
        "expected the appliance-wide policy assignment to succeed, got {}: {}",
        assigned.status, assigned.text
    );
}

#[given(expr = "LLM Surface {string} requires a verifiable presentation from its callers")]
async fn llm_surface_requires_verifiable_presentation(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    world.ensure_operator().await;
    update_surface(
        world,
        &surface_name,
        |pipe| {
            pipe["vp_evidence"] = required_vp_evidence();
        },
        "verifiable presentation",
    )
    .await;
}

#[when(expr = "the operator requires a verifiable presentation from the callers of IDE Surface {string}")]
async fn operator_requires_verifiable_presentation_on_ide_surface(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    world.ensure_operator().await;
    world.admin_response = Some(
        submit_surface_update(world, &surface_name, |pipe| {
            pipe["vp_evidence"] = required_vp_evidence();
        })
        .await,
    );
}

fn required_vp_evidence() -> serde_json::Value {
    json!({ "enabled": true, "require_present": true, "source": "header" })
}

#[when(expr = "the caller asks LLM Surface {string} for a VP challenge")]
async fn caller_asks_for_vp_challenge(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    request_vp_challenge(world, &surface_name).await;
}

#[when(expr = "the caller asks LLM Surface {string} for a VP challenge without caller credentials")]
async fn caller_asks_for_vp_challenge_without_caller_credentials(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    request_vp_challenge(world, &surface_name).await;
}

#[when(expr = "the operator assigns an unavailable policy definition to LLM Surface {string}")]
async fn operator_assigns_unavailable_policy_definition(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    world.ensure_operator().await;
    let policy_definition_id = format!("{}-unavailable", policy_id(&surface_name));
    world.admin_response = Some(
        submit_surface_update(world, &surface_name, |pipe| {
            pipe["opa_policy"] = json!({
                "enabled": true,
                "policy_definition_id": policy_definition_id
            });
        })
        .await,
    );
}

async fn configure_llm_surface_policy(
    world: &mut SurfaceWorld,
    surface_name: &str,
    policy_definition_id: &str,
) {
    update_surface(
        world,
        surface_name,
        |pipe| {
            pipe["opa_policy"] = json!({
                "enabled": true,
                "policy_definition_id": policy_definition_id
            });
        },
        "policy",
    )
    .await;
}

#[when(expr = "the caller sends a chat completion request to LLM Surface {string} with access tier {string}")]
async fn caller_sends_chat_completion_with_access_tier(
    world: &mut SurfaceWorld,
    surface_name: String,
    access_tier: String,
) {
    let route = route_for_surface(world, &surface_name);
    let path = format!("{}/v1/chat/completions", route.trim_end_matches('/'));
    let response = world
        .admin_client()
        .post_caller_json_with_access_tier(&path, chat_completion_body(DEFAULT_CALLER_PROMPT), &access_tier)
        .await;
    world.last_caller_prompt = Some(DEFAULT_CALLER_PROMPT.to_string());
    world.caller_response = Some(response);
}

#[when(
    expr = "the caller sends a chat completion request to the discovery path of LLM Surface {string} with access tier {string}"
)]
async fn caller_sends_chat_completion_to_discovery_path_with_access_tier(
    world: &mut SurfaceWorld,
    surface_name: String,
    access_tier: String,
) {
    send_chat_completion_to_discovery_path(world, &surface_name, Some(("X-Access-Tier", &access_tier))).await;
}

#[when(expr = "the caller sends a {string} request to LLM Surface {string} with access tier {string}")]
async fn caller_sends_provider_operation_with_access_tier(
    world: &mut SurfaceWorld,
    operation: String,
    surface_name: String,
    access_tier: String,
) {
    send_provider_operation(world, &operation, &surface_name, Some(("X-Access-Tier", &access_tier))).await;
}

#[then(expr = "the caller is rejected by LLM Surface policy")]
async fn caller_is_rejected_by_llm_surface_policy(world: &mut SurfaceWorld) {
    assert_policy_response(world, "policy_denied");
}

#[then(expr = "the caller is rejected by the appliance-wide policy")]
async fn caller_is_rejected_by_appliance_wide_policy(world: &mut SurfaceWorld) {
    assert_policy_response(world, "policy_denied");
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(
        response.body["error"]["message"], "Request denied by appliance-wide policy",
        "expected the appliance-wide policy to refuse the request, got {}",
        response.text
    );
}

#[then(expr = "the caller is rejected because a verifiable presentation is required")]
async fn caller_is_rejected_for_missing_verifiable_presentation(world: &mut SurfaceWorld) {
    assert_policy_response(world, "vp_required");
}

#[then(expr = "the caller receives a VP challenge for the appliance that expires within {int} minutes")]
async fn caller_receives_vp_challenge(
    world: &mut SurfaceWorld,
    minutes: i64,
) {
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(response.status, 200, "expected a VP challenge, got {}: {}", response.status, response.text);
    let challenge = response.body["challenge"]
        .as_str()
        .unwrap_or_default();
    assert_eq!(challenge.len(), 43, "expected a 256-bit base64url challenge, got {}", response.text);
    let domain = response.body["domain"]
        .as_str()
        .unwrap_or_default();
    assert!(domain.starts_with("did:"), "expected the appliance DID as the challenge domain, got {}", response.text);
    let expires_at: chrono::DateTime<chrono::Utc> = response.body["expires_at"]
        .as_str()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("expected the challenge expiry, got {}", response.text));
    let now = chrono::Utc::now();
    assert!(
        expires_at > now && expires_at <= now + chrono::TimeDelta::minutes(minutes),
        "expected the challenge to expire within {minutes} minutes, got {expires_at}"
    );
    assert_eq!(
        response
            .headers
            .get("cache-control")
            .map(String::as_str),
        Some("no-store"),
        "expected the challenge response to forbid caching, got {:?}",
        response.headers
    );
}

#[then(expr = "the caller is rejected by IDE Surface policy")]
async fn caller_is_rejected_by_ide_surface_policy(world: &mut SurfaceWorld) {
    assert_policy_response(world, "policy_denied");
}

#[then(expr = "the IDE Surface update is rejected because VP evidence belongs on its member LLM Surfaces")]
async fn ide_surface_update_is_rejected_for_vp_evidence(world: &mut SurfaceWorld) {
    let response = world
        .admin_response
        .as_ref()
        .expect("Surface update response should be recorded");
    assert_eq!(response.status, 400, "expected Surface update rejection, got {}: {}", response.status, response.text);
    assert!(
        response.body["error"]
            .as_str()
            .is_some_and(|message| message.contains("enable it on its member LLM Surfaces")),
        "expected the IDE Surface VP evidence refusal, got {}",
        response.text
    );
}

#[then(expr = "the LLM Surface update is rejected because the policy definition is unavailable")]
async fn surface_update_is_rejected_for_unavailable_policy(world: &mut SurfaceWorld) {
    let response = world
        .admin_response
        .as_ref()
        .expect("Surface update response should be recorded");
    assert_eq!(response.status, 400, "expected Surface update rejection, got {}: {}", response.status, response.text);
    assert_eq!(
        response.body["error"], "Policy definition reference is not accessible",
        "expected inaccessible policy definition error, got {}",
        response.text
    );
}

fn assert_policy_response(
    world: &SurfaceWorld,
    expected_code: &str,
) {
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(response.status, 403, "expected policy rejection, got {}: {}", response.status, response.text);
    assert_eq!(
        response.body["error"]["type"], "permission_error",
        "expected policy permission error, got {}",
        response.text
    );
    assert_eq!(
        response.body["error"]["code"], expected_code,
        "expected policy error code {expected_code:?}, got {}",
        response.text
    );
}
