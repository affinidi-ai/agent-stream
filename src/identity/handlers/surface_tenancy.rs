use crate::config::agent_surface::AgentSurface;
use crate::config::types::TargetAuthMethod;
use crate::identity::handlers::pipe_tenancy::PipeReferenceKey;
use crate::source_auth::{ManagedIdentityConfig, SourceAuthConfig, models::MtlsTrust};
use crate::tenancy::ResourceKind;

pub(crate) fn collect_surface_reference_keys(surface: &AgentSurface) -> Result<Vec<PipeReferenceKey>, String> {
    let mut references = Vec::new();
    for effective in resolved_views(surface)? {
        collect_effective_references(&effective, &mut references);
    }
    references.sort_by(|left, right| {
        left.kind
            .as_str()
            .cmp(right.kind.as_str())
            .then_with(|| left.id.cmp(&right.id))
    });
    references.dedup_by(|left, right| left.kind == right.kind && left.id == right.id);
    Ok(references)
}

fn resolved_views(surface: &AgentSurface) -> Result<Vec<AgentSurface>, String> {
    let mut views = vec![surface.clone()];
    for variant in &surface.variants {
        let mut resolvable = surface.clone();
        if let Some(candidate) = resolvable
            .variants
            .iter_mut()
            .find(|candidate| candidate.id == variant.id)
        {
            candidate.enabled = true;
        }
        views.push(
            resolvable
                .resolve_variant(Some(&variant.alias))
                .map_err(|error| format!("Variant '{}' references could not be resolved: {}", variant.alias, error))?,
        );
    }
    Ok(views)
}

fn collect_effective_references(
    surface: &AgentSurface,
    references: &mut Vec<PipeReferenceKey>,
) {
    if let Some(authentication) = &surface
        .access_point
        .caller_authentication
    {
        for method in &authentication.methods {
            collect_source_auth(method, references);
        }
    }
    for policy in [
        surface
            .access_point
            .inbound_policy
            .as_ref(),
        surface.target.policy.as_ref(),
        surface
            .target
            .response_policy
            .as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        push(references, ResourceKind::PolicyDefinitions, &policy.policy_definition_id);
    }
    if let Some(auth) = &surface.target.auth
        && let TargetAuthMethod::StaticSecret { secret_id, .. } = &auth.method
    {
        push(references, ResourceKind::Secrets, secret_id);
    }
    if let Some(gateway_id) = surface
        .target
        .endpoint
        .strip_prefix("fabric://")
        .and_then(|value| value.split('/').next())
    {
        push(references, ResourceKind::Gateways, gateway_id);
    }
    if let Some(id) = &surface
        .target
        .identity_injection
        .api_key_id
    {
        push(references, ResourceKind::ApiKeys, id);
    }
    if let Some(id) = &surface
        .target
        .identity_injection
        .certificate_id
    {
        push(references, ResourceKind::Certificates, id);
    }
    for binding in &surface.outbound_credentials {
        push(references, ResourceKind::CredentialProviders, &binding.credential_provider_id);
    }
    for identity in [
        surface
            .identity_slots
            .inbound
            .as_ref(),
        surface
            .identity_slots
            .protected
            .as_ref(),
        surface
            .identity_slots
            .external
            .as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        collect_managed_identity(identity, references);
    }
}

fn collect_source_auth(
    config: &SourceAuthConfig,
    references: &mut Vec<PipeReferenceKey>,
) {
    match config {
        SourceAuthConfig::JwtBearer(config) => {
            push(references, ResourceKind::JwtVerificationStrategies, &config.jwt_verification_strategy_id)
        }
        SourceAuthConfig::ApiKey(config) => push(references, ResourceKind::Secrets, &config.secret_id),
        SourceAuthConfig::ApiKeyProvider(config) => push(references, ResourceKind::Surfaces, &config.agent_id),
        SourceAuthConfig::Mtls(config) => match &config.trust {
            MtlsTrust::Pinned { certificate_ids } => {
                for id in certificate_ids {
                    push(references, ResourceKind::Certificates, id);
                }
            }
            MtlsTrust::Ca { ca_certificate_ids, .. } => {
                for id in ca_certificate_ids {
                    push(references, ResourceKind::Certificates, id);
                }
            }
        },
    }
}

fn collect_managed_identity(
    config: &ManagedIdentityConfig,
    references: &mut Vec<PipeReferenceKey>,
) {
    match config {
        ManagedIdentityConfig::FromApiKey { api_key_id } => push(references, ResourceKind::ApiKeys, api_key_id),
        ManagedIdentityConfig::FromMtls { certificate_id } => {
            push(references, ResourceKind::Certificates, certificate_id)
        }
        ManagedIdentityConfig::PayloadExtraction(_) | ManagedIdentityConfig::Static { .. } => {}
    }
}

fn push(
    references: &mut Vec<PipeReferenceKey>,
    kind: ResourceKind,
    id: &str,
) {
    let id = id.trim();
    if !id.is_empty() {
        references.push(PipeReferenceKey { kind, id: id.to_string() });
    }
}
