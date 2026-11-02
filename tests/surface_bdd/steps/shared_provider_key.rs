use super::support::*;
use crate::world::SurfaceWorld;
use cucumber::{given, then};

#[given(expr = "secret {string} holds a provider key for the whole appliance")]
async fn secret_holds_appliance_provider_key(
    world: &mut SurfaceWorld,
    secret_id: String,
) {
    world.ensure_operator().await;
    let response = world
        .admin_client()
        .create_secret(&secret_id, &secret_id, &provider_key_value(&secret_id))
        .await;
    assert_eq!(
        response.status, 201,
        "expected the appliance-wide provider key to be stored, got {}: {}",
        response.status, response.text
    );
}

#[given(expr = "the operator has deleted secret {string}")]
async fn operator_has_deleted_secret(
    world: &mut SurfaceWorld,
    secret_id: String,
) {
    world.ensure_operator().await;
    let secrets = world
        .admin_client()
        .list_secrets()
        .await;
    assert_eq!(secrets.status, 200, "expected secrets to be listed, got {}: {}", secrets.status, secrets.text);
    let id = secrets
        .body
        .as_array()
        .and_then(|secrets| {
            secrets
                .iter()
                .find(|secret| secret["secret_id"] == secret_id.as_str())
        })
        .and_then(|secret| secret["id"].as_str())
        .unwrap_or_else(|| panic!("expected secret {secret_id:?} to exist, got: {}", secrets.text))
        .to_string();
    let response = world
        .admin_client()
        .delete_secret(&id)
        .await;
    assert!(
        response.status == 200 || response.status == 204,
        "expected secret {secret_id:?} to be deleted, got {}: {}",
        response.status,
        response.text
    );
}

#[given(expr = "secret {string} holds a provider key for tenant {string}")]
async fn secret_holds_tenant_provider_key(
    world: &mut SurfaceWorld,
    secret_id: String,
    tenant_id: String,
) {
    world.ensure_operator().await;
    let response = world
        .admin_client()
        .create_tenant_secret(&secret_id, &provider_key_value(&secret_id), &tenant_id)
        .await;
    assert_eq!(
        response.status, 201,
        "expected tenant {tenant_id:?}'s provider key to be stored, got {}: {}",
        response.status, response.text
    );
}

#[given(
    expr = "the operator has published LLM Surface {string} for route {string} for tenant {string} spending provider key {string}"
)]
async fn operator_has_published_tenant_llm_surface(
    world: &mut SurfaceWorld,
    surface_name: String,
    route: String,
    tenant_id: String,
    secret_id: String,
) {
    publish_tenant_llm_surface(world, surface_name, route, &tenant_id, &secret_id).await;
}

#[then(expr = "the {string} request is refused because the provider key is shared with other tenants")]
async fn request_is_refused_for_shared_provider_key(
    world: &mut SurfaceWorld,
    operation_name: String,
) {
    let expected_code = match provider_operation(&operation_name) {
        ProviderOperation { method: "GET", .. } => "shared_credential_read_refused",
        ProviderOperation {
            body: OperationBody::Multipart, ..
        } => "shared_credential_upload_refused",
        _ => "shared_credential_call_refused",
    };
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(
        response.status, 403,
        "expected the {operation_name:?} request to be refused, got {}: {}",
        response.status, response.text
    );
    assert_eq!(
        response.body["error"]["type"], "permission_error",
        "expected a permission error, got {}",
        response.text
    );
    assert_eq!(
        response.body["error"]["code"], expected_code,
        "expected error code {expected_code:?}, got {}",
        response.text
    );
}
