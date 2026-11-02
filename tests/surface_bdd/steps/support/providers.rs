use crate::world::SurfaceWorld;

/// The value a provider-key secret holds, distinct per secret so a provider
/// can prove which stored key it received.
pub(crate) fn provider_key_value(secret_id: &str) -> String {
    format!("sk-{secret_id}")
}

pub(crate) async fn make_chat_completions_unavailable(
    world: &mut SurfaceWorld,
    provider_name: &str,
) {
    world
        .ensure_provider(provider_name)
        .await;
    world
        .provider(provider_name)
        .server
        .make_chat_completions_unavailable()
        .await;
}
