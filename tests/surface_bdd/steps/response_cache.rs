use super::support::*;
use crate::world::SurfaceWorld;
use cucumber::{given, then, when};
use serde_json::json;

#[given(expr = "embedding provider {string} returns the same meaning for similar prompts")]
async fn embedding_provider_returns_same_meaning(
    world: &mut SurfaceWorld,
    provider_name: String,
) {
    world
        .ensure_provider(&provider_name)
        .await;
}

#[given(expr = "LLM Surface {string} uses an exact response cache for {int} seconds")]
async fn llm_surface_uses_exact_response_cache(
    world: &mut SurfaceWorld,
    surface_name: String,
    ttl_seconds: u64,
) {
    configure_llm_surface_cache(world, &surface_name, ttl_seconds, "exact", None).await;
}

#[given(expr = "LLM Surface {string} uses an exact response cache for {int} second")]
async fn llm_surface_uses_exact_response_cache_for_one_second(
    world: &mut SurfaceWorld,
    surface_name: String,
    ttl_seconds: u64,
) {
    configure_llm_surface_cache(world, &surface_name, ttl_seconds, "exact", None).await;
}

#[given(expr = "LLM Surface {string} uses a semantic response cache with embedding provider {string}")]
async fn llm_surface_uses_semantic_response_cache(
    world: &mut SurfaceWorld,
    surface_name: String,
    provider_name: String,
) {
    let endpoint = format!(
        "{}/v1/embeddings",
        world
            .provider(&provider_name)
            .server
            .base_url()
    );
    configure_llm_surface_cache(world, &surface_name, 60, "semantic", Some(endpoint)).await;
}

#[given(expr = "the caller has cached chat prompt {string} through LLM Surface {string}")]
async fn caller_has_cached_chat_prompt(
    world: &mut SurfaceWorld,
    prompt: String,
    surface_name: String,
) {
    let route = route_for_surface(world, &surface_name);
    send_chat_prompt(world, &route, &prompt).await;
    let response = world
        .caller_response
        .as_ref()
        .expect("cache-populating response should be recorded");
    assert_eq!(
        response.status, 200,
        "expected cache-populating request to succeed, got {}: {}",
        response.status, response.text
    );
    assert_eq!(
        response
            .headers
            .get("x-agent-stream-cache")
            .map(String::as_str),
        Some("miss"),
        "expected cache-populating request to report a miss"
    );
}

#[given(expr = "the cache entry has expired")]
async fn cache_entry_has_expired(_world: &mut SurfaceWorld) {
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
}

async fn configure_llm_surface_cache(
    world: &mut SurfaceWorld,
    surface_name: &str,
    ttl_seconds: u64,
    mode: &str,
    embedder_endpoint: Option<String>,
) {
    let mut cache = json!({
        "enabled": true,
        "ttl_seconds": ttl_seconds,
        "max_entries": 100,
        "mode": mode
    });
    if let Some(endpoint_url) = embedder_endpoint {
        cache["similarity_threshold"] = json!(0.9);
        cache["embedder"] = json!({
            "endpoint_url": endpoint_url,
            "model": "mock-embedding"
        });
    }
    update_surface(world, surface_name, |pipe| pipe["cache"] = cache, "cache").await;
}

#[then(expr = "the response reports a cache miss")]
async fn response_reports_cache_miss(world: &mut SurfaceWorld) {
    assert_cache_status(world, "miss");
}

#[then(expr = "the response reports a cache hit")]
async fn response_reports_cache_hit(world: &mut SurfaceWorld) {
    assert_cache_status(world, "hit");
}

fn assert_cache_status(
    world: &SurfaceWorld,
    expected: &str,
) {
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(
        response
            .headers
            .get("x-agent-stream-cache")
            .map(String::as_str),
        Some(expected),
        "expected response cache status {expected:?}, got headers {:?}",
        response.headers
    );
}

/// The issuer and audience of the JWT source auth these steps' Surfaces use.
const JWT_ISSUER: &str = "https://issuer.example.test";
const JWT_AUDIENCE: &str = "agent-stream";

#[given(expr = "LLM Surface {string} forwards caller tokens to its provider")]
async fn llm_surface_forwards_caller_tokens(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    update_surface(world, &surface_name, |pipe| pipe["forward_caller_token"] = json!(true), "identity pass-through")
        .await;
}

#[given(expr = "caller {string} has sent chat prompt {string} to LLM Surface {string} with their own JWT")]
async fn named_caller_has_sent_chat_prompt(
    world: &mut SurfaceWorld,
    caller: String,
    prompt: String,
    surface_name: String,
) {
    send_chat_prompt_with_own_jwt(world, &caller, &prompt, &surface_name, false).await;
    assert_populated_cache_entry(world, &caller);
}

#[given(expr = "caller {string} has streamed chat prompt {string} from LLM Surface {string} with their own JWT")]
async fn named_caller_has_streamed_chat_prompt(
    world: &mut SurfaceWorld,
    caller: String,
    prompt: String,
    surface_name: String,
) {
    send_chat_prompt_with_own_jwt(world, &caller, &prompt, &surface_name, true).await;
    assert_populated_cache_entry(world, &caller);
}

#[when(expr = "caller {string} sends chat prompt {string} to LLM Surface {string} with their own JWT")]
async fn named_caller_sends_chat_prompt(
    world: &mut SurfaceWorld,
    caller: String,
    prompt: String,
    surface_name: String,
) {
    send_chat_prompt_with_own_jwt(world, &caller, &prompt, &surface_name, false).await;
}

#[when(expr = "caller {string} requests streamed chat prompt {string} from LLM Surface {string} with their own JWT")]
async fn named_caller_requests_streamed_chat_prompt(
    world: &mut SurfaceWorld,
    caller: String,
    prompt: String,
    surface_name: String,
) {
    send_chat_prompt_with_own_jwt(world, &caller, &prompt, &surface_name, true).await;
}

async fn send_chat_prompt_with_own_jwt(
    world: &mut SurfaceWorld,
    caller: &str,
    prompt: &str,
    surface_name: &str,
    stream: bool,
) {
    let token = world
        .caller_jwts
        .entry(caller.to_string())
        .or_insert_with(|| crate::bdd_support::jwt::signed_token_for(JWT_ISSUER, JWT_AUDIENCE, caller))
        .clone();
    let route = route_for_surface(world, surface_name);
    let path = format!("{}/v1/chat/completions", route.trim_end_matches('/'));
    let mut body = chat_completion_body(prompt);
    if stream {
        body["stream"] = json!(true);
    }
    let authorization = format!("Bearer {token}");
    let response = world
        .admin_client()
        .post_caller_json_with_headers(&path, body, [("Authorization", authorization.as_str())])
        .await;
    world.last_caller_prompt = Some(prompt.to_string());
    world.caller_response = Some(response);
}

/// The request succeeded and missed the cache, so it stored a new entry.
fn assert_populated_cache_entry(
    world: &SurfaceWorld,
    caller: &str,
) {
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(
        response.status, 200,
        "expected caller {caller:?} request to succeed, got {}: {}",
        response.status, response.text
    );
    assert_cache_status(world, "miss");
}
