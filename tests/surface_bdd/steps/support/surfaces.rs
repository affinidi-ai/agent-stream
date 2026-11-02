use crate::bdd_support::admin_client::{AdminClient, RecordedResponse};
use crate::world::SurfaceWorld;
use serde_json::json;

pub(crate) async fn update_surface<F>(
    world: &mut SurfaceWorld,
    surface_name: &str,
    mutate: F,
    change: &str,
) where
    F: FnOnce(&mut serde_json::Value),
{
    let response = submit_surface_update(world, surface_name, mutate).await;
    assert_eq!(
        response.status, 200,
        "expected Surface {change} update to succeed, got {}: {}",
        response.status, response.text
    );
    world.admin_response = Some(response);
}

pub(crate) async fn submit_surface_update<F>(
    world: &SurfaceWorld,
    surface_name: &str,
    mutate: F,
) -> RecordedResponse
where
    F: FnOnce(&mut serde_json::Value),
{
    submit_surface_update_as(world.admin_client(), surface_name, mutate).await
}

/// Read the Surface and save it back changed by `mutate`, both as `client`.
pub(crate) async fn submit_surface_update_as<F>(
    client: &AdminClient,
    surface_name: &str,
    mutate: F,
) -> RecordedResponse
where
    F: FnOnce(&mut serde_json::Value),
{
    let pipe_id = surface_id(surface_name);
    let get_response = client
        .get_pipe(&pipe_id)
        .await;
    assert_eq!(
        get_response.status, 200,
        "expected Surface lookup to succeed, got {}: {}",
        get_response.status, get_response.text
    );
    let mut pipe = get_response.body;
    mutate(&mut pipe);
    client
        .update_pipe(&pipe_id, pipe)
        .await
}

pub(crate) async fn change_llm_surface_provider(
    world: &mut SurfaceWorld,
    surface_name: &str,
    provider_name: &str,
) {
    let base_url = world
        .provider(provider_name)
        .server
        .base_url()
        .to_string();
    update_surface(world, surface_name, |pipe| pipe["pipe_type"]["provider"]["base_url"] = json!(base_url), "provider")
        .await;
}

pub(crate) async fn disable_llm_surface(
    world: &mut SurfaceWorld,
    surface_name: &str,
) {
    update_surface(world, surface_name, |pipe| pipe["status"] = json!("disabled"), "disable").await;
}

pub(crate) async fn publish_llm_surface(
    world: &mut SurfaceWorld,
    surface_name: String,
    route: String,
    provider_name: &str,
) {
    let provider = mock_openai_provider(world, provider_name);
    publish_llm_surface_with_provider(world, surface_name, route, provider, json!({}), None).await;
}

/// Publish an LLM Surface targeting `provider_name` as `publisher` instead of
/// the operator, so the Surface is theirs.
pub(crate) async fn publish_llm_surface_as(
    world: &mut SurfaceWorld,
    publisher: AdminClient,
    surface_name: String,
    route: String,
    provider_name: &str,
) {
    publish_llm_surface_as_with(world, publisher, surface_name, route, provider_name, json!({})).await;
}

/// [`publish_llm_surface_as`], with `extra_fields` (a JSON object) added to
/// the create body.
pub(crate) async fn publish_llm_surface_as_with(
    world: &mut SurfaceWorld,
    publisher: AdminClient,
    surface_name: String,
    route: String,
    provider_name: &str,
    extra_fields: serde_json::Value,
) {
    let provider = mock_openai_provider(world, provider_name);
    publish_llm_surface_with_provider(world, surface_name, route, provider, extra_fields, Some(publisher)).await;
}

/// Publish an empty IDE Surface as `publisher`, or as the operator when `None`.
pub(crate) async fn publish_ide_surface(
    world: &mut SurfaceWorld,
    publisher: Option<AdminClient>,
    surface_name: String,
    route: String,
) {
    let pipe = json!({
        "id": surface_id(&surface_name),
        "name": surface_name,
        "description": "BDD IDE Surface",
        "pipe_type": {
            "type": "ide_catalog",
            "config": { "members": [] }
        },
        "route": route,
        "request_timeout_seconds": 10,
        "created_at": chrono::Utc::now().to_rfc3339(),
        "test_surface": true
    });
    let response = publisher
        .as_ref()
        .unwrap_or_else(|| world.admin_client())
        .create_pipe(pipe)
        .await;
    assert_eq!(
        response.status, 200,
        "expected IDE Surface creation to succeed, got {}: {}",
        response.status, response.text
    );
    world
        .surface_routes
        .insert(surface_name, route);
    world.admin_response = Some(response);
}

fn mock_openai_provider(
    world: &SurfaceWorld,
    provider_name: &str,
) -> serde_json::Value {
    json!({
        "provider_type": "openai",
        "model": "mock-small",
        "base_url": world.provider(provider_name).server.base_url()
    })
}

/// Publish an LLM Surface owned by `tenant_id` whose OpenAI-compatible provider
/// is `provider_name`, spending the provider key in secret `secret_id`, for a
/// model the catalog prices.
pub(crate) async fn publish_tenant_llm_surface(
    world: &mut SurfaceWorld,
    surface_name: String,
    route: String,
    tenant_id: &str,
    secret_id: &str,
) {
    let provider = json!({
        "provider_type": "openai",
        "model": "gpt-4o",
        "base_url": world.provider("bravo").server.base_url(),
        "api_key_secret": secret_id
    });
    publish_llm_surface_with_provider(world, surface_name, route, provider, json!({ "tenant_id": tenant_id }), None)
        .await;
}

/// Publish an LLM Surface whose provider is a Custom OpenAI-compatible
/// endpoint: the provider's chat completions URL, used as-is whatever path the
/// caller sent after the Surface route.
pub(crate) async fn publish_llm_surface_at_custom_endpoint(
    world: &mut SurfaceWorld,
    surface_name: String,
    route: String,
    provider_name: &str,
) {
    let endpoint = format!(
        "{}/v1/chat/completions",
        world
            .provider(provider_name)
            .server
            .base_url()
    );
    let provider = json!({
        "provider_type": "custom",
        "name": "mock-small",
        "endpoint": endpoint
    });
    publish_llm_surface_with_provider(world, surface_name, route, provider, json!({}), None).await;
}

async fn publish_llm_surface_with_provider(
    world: &mut SurfaceWorld,
    surface_name: String,
    route: String,
    provider: serde_json::Value,
    extra_fields: serde_json::Value,
    publisher: Option<AdminClient>,
) {
    world.ensure_operator().await;
    let now = chrono::Utc::now().to_rfc3339();
    let pipe_id = surface_id(&surface_name);
    let mut pipe = json!({
        "id": pipe_id,
        "name": surface_name,
        "description": "BDD LLM Surface",
        "pipe_type": {
            "type": "llm",
            "provider": provider
        },
        "route": route,
        "cost_tracking": { "enabled": true },
        "enable_metrics": true,
        "metrics_enabled": true,
        "request_timeout_seconds": 10,
        "created_at": now,
        "test_surface": true
    });
    for (field, value) in extra_fields
        .as_object()
        .into_iter()
        .flatten()
    {
        pipe[field] = value.clone();
    }

    let publisher = publisher.unwrap_or_else(|| world.admin_client().clone());
    let response = publisher
        .create_pipe(pipe)
        .await;
    assert_eq!(
        response.status, 200,
        "expected LLM Surface creation to succeed, got {}: {}",
        response.status, response.text
    );
    world
        .surface_routes
        .insert(surface_name, route);
    world.admin_response = Some(response);
}

pub(crate) fn surface_id(name: &str) -> String {
    format!("bdd-{}", name.replace(|c: char| !c.is_ascii_alphanumeric(), "-"))
}

pub(crate) fn policy_id(surface_name: &str) -> String {
    format!("{}-policy", surface_id(surface_name))
}
