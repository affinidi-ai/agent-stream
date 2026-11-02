use axum::{
    Extension, Json, Router,
    extract::Path,
    http::StatusCode,
    routing::{delete, get, post, put},
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::sync::Arc;

use crate::auth_manager::middleware::{AuthGuardOk, RbacGuard, maybe_gate};
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::config::GatewayConfig;
use crate::integrations::audit_integration_triggers::{AUDIT_CATEGORY, is_audit_integration};
use crate::integrations::destinations;
use crate::rbac::Feature;
use crate::secrets::{RevealSecretValues, SecretsStore};
use crate::storage::integration_credentials::{
    IntegrationView, NewCredentials, PINNED_DESTINATION, apply_credential_rules, authorize_secret_references,
    hide_url_refusal, keeps_signing_secret, pairs_secret_with_new_destination, pin_destination,
    references_only_addresses, resolve_secret_references, same_destination,
};
use crate::storage::{Integration, IntegrationStorage};
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, scope_allows_resource, tenant_for_create};

/// The integration management routes, with every extension their handlers
/// extract. `rbac_guard` is `None` only for test-only unguarded composition.
pub fn integration_api_router(
    storage: Arc<IntegrationStorage>,
    config: Arc<GatewayConfig>,
    bootstrap_config: Arc<crate::config::BootstrapConfig>,
    secrets_store: Option<Arc<dyn SecretsStore>>,
    reveal_secret_values: RevealSecretValues,
    rbac_guard: Option<&RbacGuard>,
) -> Router {
    let mut router = Router::new()
        .route("/v1/integrations", maybe_gate(rbac_guard, get(list_notifiers), Feature::IntegrationsView))
        .route("/v1/integrations", maybe_gate(rbac_guard, post(create_notifier), Feature::IntegrationsEdit))
        // Specific routes must come before parameterized routes
        .route("/v1/integrations/config", get(get_notifier_config))
        .route("/v1/integrations/runtime-variables", get(get_runtime_variables))
        .route(
            "/v1/integrations/test",
            maybe_gate(
                rbac_guard,
                post(crate::storage::integration_trigger_handlers::test_notifier_handler),
                Feature::IntegrationsEdit,
            ),
        )
        .route(
            "/v1/integrations/trigger-multiple",
            maybe_gate(
                rbac_guard,
                post(crate::storage::integration_trigger_handlers::trigger_multiple_notifiers_handler),
                Feature::IntegrationsEdit,
            ),
        )
        // Parameterized routes come after specific ones
        .route("/v1/integrations/{id}", maybe_gate(rbac_guard, get(get_notifier), Feature::IntegrationsView))
        .route("/v1/integrations/{id}", maybe_gate(rbac_guard, put(update_notifier), Feature::IntegrationsEdit))
        .route("/v1/integrations/{id}", maybe_gate(rbac_guard, delete(delete_notifier), Feature::IntegrationsDelete))
        .route(
            "/v1/integrations/{id}/trigger",
            maybe_gate(
                rbac_guard,
                post(crate::storage::integration_trigger_handlers::trigger_integration_handler),
                Feature::IntegrationsEdit,
            ),
        )
        .layer(Extension(storage))
        .layer(Extension(secrets_store))
        .layer(Extension(reveal_secret_values))
        .layer(Extension(config))
        .layer(Extension(bootstrap_config));

    if let Some(guard) = rbac_guard {
        router = router.layer(Extension(guard.clone()));
    }

    router
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateIntegrationRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub name: String,
    pub description: String,
    #[serde(rename = "type")]
    pub integration_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    pub configuration: JsonValue,
    pub content: JsonValue,
    pub status: String,
}

/// The authenticated caller of an integration route. Governance audit
/// integrations receive audit evidence (VP JWTs, principals), so only a caller
/// holding `audit.view` may see or manage them, and only one holding
/// `secrets.view` may choose where a stored secret is sent; a request without
/// an authenticated caller or RBAC guard is refused.
pub(crate) struct AuditCaller<'a> {
    guard: Option<&'a RbacGuard>,
    user_id: Option<&'a str>,
    pat: Option<&'a PatContext>,
}

impl<'a> AuditCaller<'a> {
    pub(crate) fn new(
        guard: &'a Option<Extension<RbacGuard>>,
        caller: &'a Option<Extension<AuthGuardOk>>,
        pat: &'a Option<Extension<PatContext>>,
    ) -> Self {
        Self {
            guard: guard
                .as_ref()
                .map(|Extension(guard)| guard),
            user_id: caller
                .as_ref()
                .map(|Extension(AuthGuardOk(user_id))| user_id.as_str()),
            pat: pat
                .as_ref()
                .map(|Extension(pat)| pat),
        }
    }

    async fn holds(
        &self,
        feature: Feature,
    ) -> Result<bool, (StatusCode, String)> {
        let (Some(guard), Some(user_id)) = (self.guard, self.user_id) else {
            return Ok(false);
        };
        guard
            .allows(user_id, self.pat, feature)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to check permissions: {}", e)))
    }

    pub(crate) async fn may_access_audit(&self) -> Result<bool, (StatusCode, String)> {
        self.holds(Feature::AuditView)
            .await
    }

    /// Choosing where a stored secret is sent reveals it to that destination,
    /// so it needs `secrets.view` and, while `secrets.reveal_values` is off, is
    /// refused for everyone unless every reference is the URL this type of
    /// integration delivers to; a caller who can edit integrations cannot
    /// otherwise send any secret to a host of their own.
    pub(crate) async fn require_secret_pairing_access(
        &self,
        RevealSecretValues(reveal_values): RevealSecretValues,
        integration_type: &str,
        configuration: &JsonValue,
        stored: Option<&Integration>,
    ) -> Result<(), (StatusCode, String)> {
        if !pairs_secret_with_new_destination(integration_type, configuration, stored) {
            return Ok(());
        }
        self.require_choosing_secret_destination(
            RevealSecretValues(reveal_values),
            integration_type,
            configuration,
            PAIRING_REFUSAL,
        )
        .await
    }

    /// The pairing check on the request alone, before the credentials
    /// `stored` keeps are merged in, so a caller without `secrets.view` gets
    /// the same answer whether or not the saved integration keeps one.
    pub(crate) async fn require_secret_pairing_view(
        &self,
        integration_type: &str,
        configuration: &JsonValue,
        stored: &Integration,
        new_credentials: NewCredentials,
    ) -> Result<(), (StatusCode, String)> {
        let mut requested = configuration.clone();
        apply_credential_rules(integration_type, &mut requested, None, new_credentials)?;
        if pairs_secret_with_new_destination(integration_type, &requested, Some(stored)) {
            self.require_secrets_view(PAIRING_REFUSAL)
                .await?;
        }
        Ok(())
    }

    /// A referenced secret that now resolves somewhere other than the pinned
    /// destination moves where the integration's secrets go, so confirming it
    /// needs the same access as choosing a new destination. While values are
    /// hidden, the saved signing secret never follows the move: it would sign
    /// whatever the new destination is sent.
    pub(crate) async fn require_moved_destination_access(
        &self,
        RevealSecretValues(reveal_values): RevealSecretValues,
        integration_type: &str,
        configuration: &JsonValue,
        stored: &Integration,
    ) -> Result<(), (StatusCode, String)> {
        self.require_moved_destination_view()
            .await?;
        if !reveal_values
            && (keeps_signing_secret(configuration, stored)
                || !references_only_addresses(integration_type, configuration))
        {
            return Err(values_hidden_refusal());
        }
        Ok(())
    }

    /// Where a saved reference now resolves, why its value is refused, and
    /// whether its secret still exists are answered only to a caller holding
    /// `secrets.view`; anyone else gets this one refusal whatever the secret
    /// now holds.
    pub(crate) async fn require_moved_destination_view(&self) -> Result<(), (StatusCode, String)> {
        self.require_secrets_view(CHANGED_REFERENCE_REFUSAL)
            .await
    }

    /// Whether an answer may say why a referenced secret's value was refused
    /// or why a delivery that used one failed: only while values are revealed
    /// and to a caller holding `secrets.view`, who may read the value anyway.
    pub(crate) async fn reveals_secret_detail(
        &self,
        RevealSecretValues(reveal_values): RevealSecretValues,
    ) -> Result<bool, (StatusCode, String)> {
        if !reveal_values {
            return Ok(false);
        }
        self.holds(Feature::SecretsView)
            .await
    }

    async fn require_choosing_secret_destination(
        &self,
        RevealSecretValues(reveal_values): RevealSecretValues,
        integration_type: &str,
        configuration: &JsonValue,
        refusal: &str,
    ) -> Result<(), (StatusCode, String)> {
        self.require_secrets_view(refusal)
            .await?;
        if !reveal_values && !references_only_addresses(integration_type, configuration) {
            return Err(values_hidden_refusal());
        }
        Ok(())
    }

    /// Checked before anything the configuration holds, so a caller without
    /// `secrets.view` gets the same answer whatever it holds, including the
    /// credentials a save or test keeps from the stored integration.
    async fn require_secrets_view(
        &self,
        refusal: &str,
    ) -> Result<(), (StatusCode, String)> {
        if self
            .holds(Feature::SecretsView)
            .await?
        {
            Ok(())
        } else {
            Err((StatusCode::FORBIDDEN, refusal.to_string()))
        }
    }

    pub(crate) async fn require_audit_access(&self) -> Result<(), (StatusCode, String)> {
        if self
            .may_access_audit()
            .await?
        {
            Ok(())
        } else {
            Err((StatusCode::FORBIDDEN, "Governance audit integrations require the audit.view permission".to_string()))
        }
    }
}

const PAIRING_REFUSAL: &str = "Choosing where an integration sends a stored secret needs secrets.view";

const CHANGED_REFERENCE_REFUSAL: &str =
    "A secret this integration references changed; confirming it needs secrets.view";

fn values_hidden_refusal() -> (StatusCode, String) {
    (
        StatusCode::FORBIDDEN,
        "Secret values are not revealed on this appliance, so an integration cannot send a stored secret to a new destination".to_string(),
    )
}

/// Audit records are appliance-wide evidence, so an audit integration is never tenant-owned.
fn ensure_audit_integration_is_global(
    category: Option<&str>,
    tenant_id: Option<&str>,
) -> Result<(), (StatusCode, String)> {
    if category == Some(AUDIT_CATEGORY) && tenant_id.is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Governance audit integrations are appliance-wide and cannot belong to a tenant".to_string(),
        ));
    }
    Ok(())
}

fn tenant_context(context: &Option<Extension<PatTenantContext>>) -> Option<&PatTenantContext> {
    context
        .as_ref()
        .map(|Extension(context)| context)
}

fn resource_scope(scope: &Option<Extension<PatResourceScope>>) -> Option<&PatResourceScope> {
    scope
        .as_ref()
        .map(|Extension(scope)| scope)
}

fn integration_allowed(
    integration: &Integration,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> bool {
    can_access(
        integration
            .tenant_id
            .as_deref(),
        tenant_context(context),
    ) && scope_allows_resource(
        resource_scope(scope),
        tenant_context(context),
        ResourceKind::Integrations,
        &integration.id,
    )
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UpdateIntegrationRequest {
    pub name: String,
    pub description: String,
    #[serde(rename = "type")]
    pub integration_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    pub configuration: JsonValue,
    pub content: JsonValue,
    pub status: String,
}

/// List all integrations
pub async fn list_notifiers(
    Extension(storage): Extension<Arc<IntegrationStorage>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    guard: Option<Extension<RbacGuard>>,
    caller: Option<Extension<AuthGuardOk>>,
    pat: Option<Extension<PatContext>>,
) -> Result<Json<Vec<IntegrationView>>, (StatusCode, String)> {
    let mut integrations = storage
        .list()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list integrations: {}", e)))?;
    integrations.retain(|integration| integration_allowed(integration, &context, &scope));
    if integrations
        .iter()
        .any(is_audit_integration)
        && !AuditCaller::new(&guard, &caller, &pat)
            .may_access_audit()
            .await?
    {
        integrations.retain(|integration| !is_audit_integration(integration));
    }
    Ok(Json(
        integrations
            .into_iter()
            .map(IntegrationView::from)
            .collect(),
    ))
}

/// Get a specific integration by ID
pub async fn get_notifier(
    Extension(storage): Extension<Arc<IntegrationStorage>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    guard: Option<Extension<RbacGuard>>,
    caller: Option<Extension<AuthGuardOk>>,
    pat: Option<Extension<PatContext>>,
) -> Result<Json<IntegrationView>, (StatusCode, String)> {
    let integration = storage
        .load(&id)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Integration not found".to_string()))?;
    if !integration_allowed(&integration, &context, &scope) {
        return Err((StatusCode::NOT_FOUND, "Integration not found".to_string()));
    }
    if is_audit_integration(&integration)
        && !AuditCaller::new(&guard, &caller, &pat)
            .may_access_audit()
            .await?
    {
        return Err((StatusCode::NOT_FOUND, "Integration not found".to_string()));
    }
    Ok(Json(integration.into()))
}

/// Create a new integration
pub async fn create_notifier(
    Extension(storage): Extension<Arc<IntegrationStorage>>,
    Extension(config): Extension<Arc<GatewayConfig>>,
    Extension(secrets_store): Extension<Option<Arc<dyn SecretsStore>>>,
    Extension(reveal_secret_values): Extension<RevealSecretValues>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    guard: Option<Extension<RbacGuard>>,
    caller: Option<Extension<AuthGuardOk>>,
    Json(mut req): Json<CreateIntegrationRequest>,
) -> Result<(StatusCode, Json<IntegrationView>), (StatusCode, String)> {
    if req.category.as_deref() == Some(AUDIT_CATEGORY) {
        AuditCaller::new(&guard, &caller, &pat)
            .require_audit_access()
            .await?;
    }
    req.tenant_id = tenant_for_create(req.tenant_id.take(), pat.is_some(), tenant_context(&context))
        .map_err(|message| (StatusCode::FORBIDDEN, message.to_string()))?;
    ensure_audit_integration_is_global(req.category.as_deref(), req.tenant_id.as_deref())?;
    // Validate name
    if req.name.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Integration name is required".to_string()));
    }

    // Enforce the appliance integrations limit before persisting.
    if let Err(e) = crate::config::enforce_add("integrations").await {
        return Err((StatusCode::FORBIDDEN, e.message()));
    }

    // Validate type using config
    let valid_types: Vec<&str> = config
        .integration
        .types
        .iter()
        .map(|t| t.enum_value.as_str())
        .collect();
    if !valid_types.contains(&req.integration_type.as_str()) {
        return Err((StatusCode::BAD_REQUEST, format!("Invalid integration type. Must be one of: {:?}", valid_types)));
    }

    // Validate status
    let valid_statuses = ["active", "disabled"];
    if !valid_statuses.contains(&req.status.as_str()) {
        return Err((StatusCode::BAD_REQUEST, format!("Invalid status. Must be one of: {:?}", valid_statuses)));
    }

    // Validate configuration is an object
    if !req.configuration.is_object() {
        return Err((StatusCode::BAD_REQUEST, "Configuration must be a JSON object".to_string()));
    }

    // Validate content is an object
    if !req.content.is_object() {
        return Err((StatusCode::BAD_REQUEST, "Content must be a JSON object".to_string()));
    }

    // Validate category if provided
    if let Some(ref category) = req.category {
        let valid_categories: Vec<&str> = config
            .integration
            .categories
            .iter()
            .map(|c| c.enum_value.as_str())
            .collect();
        if !valid_categories.contains(&category.as_str()) {
            return Err((StatusCode::BAD_REQUEST, format!("Invalid category. Must be one of: {:?}", valid_categories)));
        }

        // Validate that content template variables match the category
        let content_str = serde_json::to_string(&req.content)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Failed to serialize content: {}", e)))?;

        let invalid_vars = crate::integrations::validate_template_variables(&content_str, category);
        if !invalid_vars.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "Invalid runtime variables for category '{}': {}. These variables are not available for this category. Use variables from the allowed list, or prefix custom variables with underscore (e.g., ${{_MY_VAR}})",
                    category,
                    invalid_vars.join(", ")
                ),
            ));
        }
    }

    apply_credential_rules(&req.integration_type, &mut req.configuration, None, NewCredentials::ReferencesOnly)?;
    // Before any reference is resolved, so a caller without secrets.view cannot
    // tell from the answer which secrets exist.
    AuditCaller::new(&guard, &caller, &pat)
        .require_secret_pairing_access(reveal_secret_values, &req.integration_type, &req.configuration, None)
        .await?;
    authorize_secret_references(
        &req.configuration,
        secrets_store.as_ref(),
        req.tenant_id.as_deref(),
        tenant_context(&context),
        resource_scope(&scope),
    )
    .await?;
    let pinned = pin_destination(&mut req.configuration, req.tenant_id.as_deref(), secrets_store.clone()).await;
    pinned.map_err(|refusal| hide_url_refusal(reveal_secret_values.0, &req.configuration, refusal))?;

    // Create the integration
    let mut integration = Integration::new(
        req.name,
        req.description,
        req.integration_type,
        req.configuration,
        req.content,
        req.status,
        req.category,
    );
    integration.tenant_id = req.tenant_id;
    if !integration_allowed(&integration, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Integration is outside this token's permitted scope".into()));
    }
    check_destination(
        &integration.integration_type,
        &integration.configuration,
        integration
            .tenant_id
            .as_deref(),
        secrets_store.clone(),
    )
    .await
    .map_err(|refusal| hide_url_refusal(reveal_secret_values.0, &integration.configuration, refusal))?;

    storage
        .save(&integration)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save integration: {}", e)))?;

    tracing::info!("Created integration '{}' ({})", integration.name, integration.id);

    Ok((StatusCode::CREATED, Json(integration.into())))
}

/// Refuse a new or changed destination the strict outbound policy does not
/// allow, resolving the secret references among its destination settings the
/// way a delivery would. A destination already saved is not checked here;
/// every delivery checks it again.
async fn check_destination(
    integration_type: &str,
    configuration: &JsonValue,
    owner_tenant_id: Option<&str>,
    secrets_store: Option<Arc<dyn SecretsStore>>,
) -> Result<(), (StatusCode, String)> {
    let mut destination = destinations::destination_settings(integration_type, configuration);
    resolve_secret_references(&mut destination, owner_tenant_id, secrets_store)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    destinations::check(integration_type, &destination)
        .await
        .map_err(|refused| (StatusCode::BAD_REQUEST, refused.to_string()))
}

/// Update an existing integration
pub async fn update_notifier(
    Extension(storage): Extension<Arc<IntegrationStorage>>,
    Extension(config): Extension<Arc<GatewayConfig>>,
    Extension(secrets_store): Extension<Option<Arc<dyn SecretsStore>>>,
    Extension(reveal_secret_values): Extension<RevealSecretValues>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    guard: Option<Extension<RbacGuard>>,
    caller: Option<Extension<AuthGuardOk>>,
    pat: Option<Extension<PatContext>>,
    Json(mut req): Json<UpdateIntegrationRequest>,
) -> Result<Json<IntegrationView>, (StatusCode, String)> {
    // Validate name
    if req.name.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Integration name is required".to_string()));
    }

    // Validate type using config
    let valid_types: Vec<&str> = config
        .integration
        .types
        .iter()
        .map(|t| t.enum_value.as_str())
        .collect();
    if !valid_types.contains(&req.integration_type.as_str()) {
        return Err((StatusCode::BAD_REQUEST, format!("Invalid integration type. Must be one of: {:?}", valid_types)));
    }

    // Validate status
    let valid_statuses = ["active", "disabled"];
    if !valid_statuses.contains(&req.status.as_str()) {
        return Err((StatusCode::BAD_REQUEST, format!("Invalid status. Must be one of: {:?}", valid_statuses)));
    }

    // Validate configuration is an object
    if !req.configuration.is_object() {
        return Err((StatusCode::BAD_REQUEST, "Configuration must be a JSON object".to_string()));
    }

    // Validate content is an object
    if !req.content.is_object() {
        return Err((StatusCode::BAD_REQUEST, "Content must be a JSON object".to_string()));
    }

    // Validate category if provided
    if let Some(ref category) = req.category {
        let valid_categories: Vec<&str> = config
            .integration
            .categories
            .iter()
            .map(|c| c.enum_value.as_str())
            .collect();
        if !valid_categories.contains(&category.as_str()) {
            return Err((StatusCode::BAD_REQUEST, format!("Invalid category. Must be one of: {:?}", valid_categories)));
        }

        // Validate that content template variables match the category
        let content_str = serde_json::to_string(&req.content)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Failed to serialize content: {}", e)))?;

        let invalid_vars = crate::integrations::validate_template_variables(&content_str, category);
        if !invalid_vars.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "Invalid runtime variables for category '{}': {}. These variables are not available for this category. Use variables from the allowed list, or prefix custom variables with underscore (e.g., ${{_MY_VAR}})",
                    category,
                    invalid_vars.join(", ")
                ),
            ));
        }
    }

    // Load existing integration to preserve created_at
    let existing = storage
        .load(&id)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Integration not found".to_string()))?;
    if !integration_allowed(&existing, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Integration is outside this token's permitted scope".into()));
    }
    if is_audit_integration(&existing) || req.category.as_deref() == Some(AUDIT_CATEGORY) {
        AuditCaller::new(&guard, &caller, &pat)
            .require_audit_access()
            .await?;
    }
    ensure_audit_integration_is_global(req.category.as_deref(), existing.tenant_id.as_deref())?;
    let audit_caller = AuditCaller::new(&guard, &caller, &pat);
    audit_caller
        .require_secret_pairing_view(
            &req.integration_type,
            &req.configuration,
            &existing,
            NewCredentials::ReferencesOnly,
        )
        .await?;
    apply_credential_rules(
        &req.integration_type,
        &mut req.configuration,
        Some(&existing),
        NewCredentials::ReferencesOnly,
    )?;
    // Before any reference is resolved, as on create.
    audit_caller
        .require_secret_pairing_access(reveal_secret_values, &req.integration_type, &req.configuration, Some(&existing))
        .await?;
    let authorized = authorize_secret_references(
        &req.configuration,
        secrets_store.as_ref(),
        existing.tenant_id.as_deref(),
        tenant_context(&context),
        resource_scope(&scope),
    )
    .await;
    if let Err(refusal) = authorized {
        if refusal.0 == StatusCode::BAD_REQUEST {
            audit_caller
                .require_moved_destination_view()
                .await?;
        }
        return Err(refusal);
    }
    if !same_destination(&req.integration_type, &req.configuration, &existing) {
        check_destination(
            &req.integration_type,
            &req.configuration,
            existing.tenant_id.as_deref(),
            secrets_store.clone(),
        )
        .await
        .map_err(|refusal| hide_url_refusal(reveal_secret_values.0, &req.configuration, refusal))?;
    }
    let pinned = pin_destination(&mut req.configuration, existing.tenant_id.as_deref(), secrets_store.clone()).await;
    if let Err(refusal) = pinned {
        audit_caller
            .require_moved_destination_view()
            .await?;
        return Err(hide_url_refusal(reveal_secret_values.0, &req.configuration, refusal));
    }
    let repinned = req
        .configuration
        .get(PINNED_DESTINATION)
        .is_some_and(|pin| {
            existing
                .configuration
                .get(PINNED_DESTINATION)
                != Some(pin)
        });
    if repinned {
        audit_caller
            .require_moved_destination_access(
                reveal_secret_values,
                &req.integration_type,
                &req.configuration,
                &existing,
            )
            .await?;
    }

    // Create updated integration
    let now = chrono::Utc::now().to_rfc3339();
    let updated = Integration {
        id: existing.id,
        name: req.name,
        description: req.description,
        integration_type: req.integration_type,
        category: req.category,
        configuration: req.configuration,
        content: req.content,
        status: req.status,
        tenant_id: existing.tenant_id,
        created_at: existing.created_at,
        updated_at: now,
    };

    storage
        .update(&id, &updated)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update integration: {}", e)))?;

    tracing::info!("Updated integration '{}' ({})", updated.name, updated.id);

    Ok(Json(updated.into()))
}

/// Delete a integration
pub async fn delete_notifier(
    Extension(storage): Extension<Arc<IntegrationStorage>>,
    Extension(config): Extension<Arc<crate::config::BootstrapConfig>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    guard: Option<Extension<RbacGuard>>,
    caller: Option<Extension<AuthGuardOk>>,
    pat: Option<Extension<PatContext>>,
) -> Result<StatusCode, (StatusCode, String)> {
    let integration = storage
        .load(&id)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Integration not found".to_string()))?;
    if !integration_allowed(&integration, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Integration is outside this token's permitted scope".into()));
    }
    if is_audit_integration(&integration) {
        AuditCaller::new(&guard, &caller, &pat)
            .require_audit_access()
            .await?;
    }
    storage
        .delete(&id)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("not found") {
                (StatusCode::NOT_FOUND, msg)
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to delete integration: {}", msg))
            }
        })?;

    tracing::info!("Deleted integration {}", id);

    // Clean up integration from all trigger mapping files
    let triggers_path = std::path::PathBuf::from(
        &config
            .storage_paths
            .integration_triggers,
    );

    // Remove from user integrations
    if let Ok(user_storage) = crate::integrations::UserIntegrationsStorage::new(triggers_path.join("users")).await
        && let Err(e) = user_storage
            .remove_integration(&id)
            .await
    {
        tracing::warn!("Failed to remove integration {} from user triggers: {}", id, e);
    }

    // Remove from gateway integrations
    if let Ok(gateway_storage) =
        crate::integrations::GatewayIntegrationsStorage::new(triggers_path.join("gateways")).await
        && let Err(e) = gateway_storage
            .remove_integration(&id)
            .await
    {
        tracing::warn!("Failed to remove integration {} from gateway triggers: {}", id, e);
    }

    // Remove from identity integrations
    if let Ok(identity_storage) =
        crate::integrations::IdentityIntegrationsStorage::new(triggers_path.join("identities")).await
        && let Err(e) = identity_storage
            .remove_integration(&id)
            .await
    {
        tracing::warn!("Failed to remove integration {} from identity triggers: {}", id, e);
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Get runtime variables available for integration templates
pub async fn get_runtime_variables() -> Result<Json<crate::integrations::RuntimeVariablesResponse>, (StatusCode, String)>
{
    let variables = crate::integrations::get_runtime_variables();
    Ok(Json(variables))
}

/// Get integration configuration (types and categories with metadata)
pub async fn get_notifier_config(
    Extension(config): Extension<Arc<GatewayConfig>>
) -> Result<Json<crate::config::IntegrationConfig>, (StatusCode, String)> {
    Ok(Json(config.integration.clone()))
}

#[cfg(test)]
pub(crate) mod test_caller {
    use super::*;
    use crate::auth::storage::{PasskeyStorage, UserData};
    use crate::auth::types::{UserRole, UserStatus};

    /// A signed-in caller with `role` and the RBAC guard that checks it.
    pub(crate) struct TestCaller {
        _dir: tempfile::TempDir,
        pub(crate) guard: Option<Extension<RbacGuard>>,
        pub(crate) caller: Option<Extension<AuthGuardOk>>,
    }

    impl TestCaller {
        pub(crate) fn audit_caller(&self) -> AuditCaller<'_> {
            AuditCaller::new(&self.guard, &self.caller, &None)
        }
    }

    pub(crate) async fn signed_in(role: UserRole) -> TestCaller {
        let dir = tempfile::tempdir().unwrap();
        let path = |name: &str| {
            dir.path()
                .join(name)
                .to_string_lossy()
                .into_owned()
        };
        let storage = Arc::new(
            PasskeyStorage::new(path("users"), path("avatars"))
                .await
                .unwrap(),
        );
        let now = chrono::Utc::now();
        storage
            .save_user(&UserData {
                user_id: "caller-1".to_string(),
                username: "caller".to_string(),
                passkeys: Vec::new(),
                role,
                status: UserStatus::Approved,
                is_primary: false,
                first_name: None,
                last_name: None,
                email: None,
                department: None,
                job_title: None,
                avatar_path: None,
                created_at: now,
                updated_at: now,
                last_logged_in: None,
                saml_id: None,
            })
            .await
            .unwrap();
        TestCaller {
            _dir: dir,
            guard: Some(Extension(RbacGuard::new(storage, Arc::new(crate::rbac::RbacConfig::default())))),
            caller: Some(Extension(AuthGuardOk("caller-1".to_string()))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_caller::{TestCaller, signed_in};
    use super::*;
    use crate::auth::types::UserRole;

    async fn unguarded_storage() -> (tempfile::TempDir, Arc<IntegrationStorage>, Arc<GatewayConfig>) {
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            IntegrationStorage::new(dir.path().to_path_buf())
                .await
                .unwrap(),
        );
        (dir, storage, Arc::new(GatewayConfig::default_config()))
    }

    async fn seed(
        storage: &IntegrationStorage,
        category: &str,
    ) -> Integration {
        let integration = Integration::new(
            format!("{category} integration"),
            String::new(),
            "stream".to_string(),
            serde_json::json!({}),
            serde_json::json!({}),
            "active".to_string(),
            Some(category.to_string()),
        );
        storage
            .save(&integration)
            .await
            .unwrap();
        integration
    }

    #[tokio::test]
    async fn audit_integrations_are_hidden_and_refused_without_an_rbac_guard() {
        let (_dir, storage, config) = unguarded_storage().await;
        let audit = seed(&storage, "audit").await;
        seed(&storage, "general").await;

        let Json(listed) = list_notifiers(Extension(storage.clone()), None, None, None, None, None)
            .await
            .unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|i| i.integration().name.as_str())
                .collect::<Vec<_>>(),
            vec!["general integration"]
        );

        let got = get_notifier(Extension(storage.clone()), Path(audit.id.clone()), None, None, None, None, None).await;
        assert_eq!(got.unwrap_err().0, StatusCode::NOT_FOUND);

        let update = update_notifier(
            Extension(storage.clone()),
            Extension(config.clone()),
            secrets(),
            Extension(RevealSecretValues(true)),
            Path(audit.id.clone()),
            None,
            None,
            None,
            None,
            None,
            Json(UpdateIntegrationRequest {
                name: "edited".to_string(),
                description: String::new(),
                integration_type: "stream".to_string(),
                category: Some("audit".to_string()),
                configuration: serde_json::json!({}),
                content: serde_json::json!({}),
                status: "active".to_string(),
            }),
        )
        .await;
        assert_eq!(update.unwrap_err().0, StatusCode::FORBIDDEN);

        let create = create_notifier(
            Extension(storage.clone()),
            Extension(config),
            secrets(),
            Extension(RevealSecretValues(true)),
            None,
            None,
            None,
            None,
            None,
            Json(CreateIntegrationRequest {
                tenant_id: None,
                name: "audit sink".to_string(),
                description: String::new(),
                integration_type: "stream".to_string(),
                category: Some("audit".to_string()),
                configuration: serde_json::json!({}),
                content: serde_json::json!({}),
                status: "active".to_string(),
            }),
        )
        .await;
        assert_eq!(create.unwrap_err().0, StatusCode::FORBIDDEN);
        assert_eq!(
            storage
                .list()
                .await
                .unwrap()
                .len(),
            2
        );
    }

    const SMTP_PASSWORD: &str = "smtp-pass-123";
    const AUTH_HEADER: &str = "Bearer header-token-789";
    const REDIS_URL: &str = "redis://:redis-pass@93.184.216.34:6379";

    fn secrets() -> Extension<Option<Arc<dyn SecretsStore>>> {
        use crate::secrets::store::memory::{MemorySecretsStore, secret};
        Extension(Some(Arc::new(MemorySecretsStore::with(vec![
            secret("id-global", "smtp-global", "global-pass", None),
            secret("id-other", "smtp-other", "other-pass", None),
            secret("id-tenant-b", "smtp-b", "tenant-b-pass", Some("tenant-b")),
            secret("id-hook", "hook-url", "https://hooks.example.com/in", None),
            secret("id-moved", "moved-hook", "https://attacker.example/in", None),
            secret("id-redis", "redis-url", "redis://93.184.216.34:6379", None),
            secret("id-internal-redis", "internal-redis", "redis://10.0.0.5:6379", None),
            secret("id-private-hook", "private-hook", "http://10.0.0.5/in", None),
            secret("id-credentialed-hook", "credentialed-hook", "https://user:pw@hooks.example.com/in", None),
        ]))))
    }

    fn credential_configuration() -> JsonValue {
        serde_json::json!({
            "smtp_host": "smtp.example.com",
            "smtp_username": "mailer",
            "smtp_password": SMTP_PASSWORD,
            "signing_secret": "whsec-456",
            "headers": { "Authorization": AUTH_HEADER, "X-Trace": "abc", "X-Surface": "${SURFACE_ID}" },
            "redis_url": REDIS_URL,
            "public_key": "pk-public",
            "secret_key": "sk-langfuse",
            "sasl_password": "sasl-pass",
            "webhook_url": "https://hooks.slack.com/services/T/B/X",
            "url": "https://outlook.office.com/webhook/teams-token",
        })
    }

    async fn seed_integration(
        storage: &IntegrationStorage,
        integration_type: &str,
        configuration: JsonValue,
    ) -> Integration {
        let integration = Integration::new(
            "credentialed".to_string(),
            String::new(),
            integration_type.to_string(),
            configuration,
            serde_json::json!({}),
            "active".to_string(),
            Some("general".to_string()),
        );
        storage
            .save(&integration)
            .await
            .unwrap();
        integration
    }

    fn assert_no_credentials(view: &IntegrationView) {
        let json = serde_json::to_string(view).unwrap();
        for secret in [
            SMTP_PASSWORD,
            "whsec-456",
            AUTH_HEADER,
            REDIS_URL,
            "sk-langfuse",
            "sasl-pass",
            "hooks.slack.com",
            "teams-token",
        ] {
            assert!(!json.contains(secret), "response leaked {secret}: {json}");
        }
        let configuration = &view
            .integration()
            .configuration;
        for key in ["smtp_password", "signing_secret", "redis_url", "secret_key", "sasl_password", "webhook_url", "url"]
        {
            assert!(
                configuration
                    .get(key)
                    .is_none(),
                "{key} present: {json}"
            );
        }
        assert!(
            configuration["headers"]
                .get("Authorization")
                .is_none()
        );
        assert_eq!(configuration["headers"]["X-Trace"], "abc");
        assert_eq!(configuration["headers"]["X-Surface"], "${SURFACE_ID}");
        assert_eq!(configuration["smtp_host"], "smtp.example.com");
        assert_eq!(configuration["public_key"], "pk-public");
    }

    fn create_request(
        integration_type: &str,
        configuration: JsonValue,
    ) -> Json<CreateIntegrationRequest> {
        Json(CreateIntegrationRequest {
            tenant_id: None,
            name: "credentialed".to_string(),
            description: String::new(),
            integration_type: integration_type.to_string(),
            category: Some("general".to_string()),
            configuration,
            content: serde_json::json!({}),
            status: "active".to_string(),
        })
    }

    fn update_request(
        integration_type: &str,
        configuration: JsonValue,
    ) -> Json<UpdateIntegrationRequest> {
        Json(UpdateIntegrationRequest {
            name: "renamed".to_string(),
            description: String::new(),
            integration_type: integration_type.to_string(),
            category: Some("general".to_string()),
            configuration,
            content: serde_json::json!({}),
            status: "active".to_string(),
        })
    }

    async fn create(
        storage: &Arc<IntegrationStorage>,
        config: &Arc<GatewayConfig>,
        integration_type: &str,
        configuration: JsonValue,
    ) -> Result<(StatusCode, Json<IntegrationView>), (StatusCode, String)> {
        create_as(&signed_in(UserRole::Administrator).await, storage, config, integration_type, configuration).await
    }

    async fn create_as(
        caller: &TestCaller,
        storage: &Arc<IntegrationStorage>,
        config: &Arc<GatewayConfig>,
        integration_type: &str,
        configuration: JsonValue,
    ) -> Result<(StatusCode, Json<IntegrationView>), (StatusCode, String)> {
        create_revealing(true, caller, storage, config, integration_type, configuration).await
    }

    async fn create_revealing(
        reveal_values: bool,
        caller: &TestCaller,
        storage: &Arc<IntegrationStorage>,
        config: &Arc<GatewayConfig>,
        integration_type: &str,
        configuration: JsonValue,
    ) -> Result<(StatusCode, Json<IntegrationView>), (StatusCode, String)> {
        create_notifier(
            Extension(storage.clone()),
            Extension(config.clone()),
            secrets(),
            Extension(RevealSecretValues(reveal_values)),
            None,
            None,
            None,
            caller.guard.clone(),
            caller.caller.clone(),
            create_request(integration_type, configuration),
        )
        .await
    }

    async fn update(
        storage: &Arc<IntegrationStorage>,
        config: &Arc<GatewayConfig>,
        id: &str,
        integration_type: &str,
        configuration: JsonValue,
    ) -> Result<Json<IntegrationView>, (StatusCode, String)> {
        update_as(&signed_in(UserRole::Administrator).await, storage, config, id, integration_type, configuration).await
    }

    async fn update_as(
        caller: &TestCaller,
        storage: &Arc<IntegrationStorage>,
        config: &Arc<GatewayConfig>,
        id: &str,
        integration_type: &str,
        configuration: JsonValue,
    ) -> Result<Json<IntegrationView>, (StatusCode, String)> {
        update_revealing(true, caller, storage, config, id, integration_type, configuration).await
    }

    async fn update_revealing(
        reveal_values: bool,
        caller: &TestCaller,
        storage: &Arc<IntegrationStorage>,
        config: &Arc<GatewayConfig>,
        id: &str,
        integration_type: &str,
        configuration: JsonValue,
    ) -> Result<Json<IntegrationView>, (StatusCode, String)> {
        update_notifier(
            Extension(storage.clone()),
            Extension(config.clone()),
            secrets(),
            Extension(RevealSecretValues(reveal_values)),
            Path(id.to_string()),
            None,
            None,
            caller.guard.clone(),
            caller.caller.clone(),
            None,
            update_request(integration_type, configuration),
        )
        .await
    }

    async fn view_of(
        storage: &Arc<IntegrationStorage>,
        id: &str,
    ) -> JsonValue {
        let Json(view) = get_notifier(Extension(storage.clone()), Path(id.to_string()), None, None, None, None, None)
            .await
            .unwrap();
        view.integration()
            .configuration
            .clone()
    }

    async fn saved_configuration(
        storage: &IntegrationStorage,
        id: &str,
    ) -> JsonValue {
        storage
            .load(id)
            .await
            .unwrap()
            .configuration
    }

    #[tokio::test]
    async fn list_and_get_leave_every_stored_credential_out() {
        let (_dir, storage, _config) = unguarded_storage().await;
        let stored = seed_integration(&storage, "email", credential_configuration()).await;

        let Json(listed) = list_notifiers(Extension(storage.clone()), None, None, None, None, None)
            .await
            .unwrap();
        assert_eq!(listed.len(), 1);
        assert_no_credentials(&listed[0]);

        let Json(got) = get_notifier(Extension(storage.clone()), Path(stored.id.clone()), None, None, None, None, None)
            .await
            .unwrap();
        assert_no_credentials(&got);

        assert_eq!(saved_configuration(&storage, &stored.id).await, credential_configuration());
    }

    #[tokio::test]
    async fn create_stores_a_secret_reference_and_answers_it() {
        let (_dir, storage, config) = unguarded_storage().await;

        let (status, Json(created)) = create(
            &storage,
            &config,
            "email",
            serde_json::json!({ "smtp_host": "93.184.216.34", "smtp_password_secret_id": "smtp-global" }),
        )
        .await
        .unwrap();

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(
            created
                .integration()
                .configuration["smtp_password_secret_id"],
            "smtp-global"
        );
        let saved = saved_configuration(&storage, &created.integration().id).await;
        assert_eq!(saved["smtp_password_secret_id"], "smtp-global");
        assert!(
            saved
                .get("smtp_password")
                .is_none()
        );
    }

    #[tokio::test]
    async fn create_refuses_inline_credentials_placeholders_and_unusable_references() {
        let (_dir, storage, config) = unguarded_storage().await;
        let cases = [
            ("inline password", serde_json::json!({ "smtp_host": "h", "smtp_password": SMTP_PASSWORD })),
            ("inline auth header", serde_json::json!({ "headers": { "Authorization": AUTH_HEADER } })),
            ("old placeholder", serde_json::json!({ "smtp_host": "h", "smtp_password": "********" })),
            ("nested placeholder", serde_json::json!({ "headers": { "X-Trace": "********" } })),
            ("another tenant's secret", serde_json::json!({ "smtp_host": "h", "smtp_password_secret_id": "smtp-b" })),
            ("unknown secret", serde_json::json!({ "smtp_host": "h", "smtp_password_secret_id": "missing" })),
            (
                "inline and by reference",
                serde_json::json!({ "smtp_host": "h", "smtp_password": "x", "smtp_password_secret_id": "smtp-global" }),
            ),
        ];

        for (case, configuration) in cases {
            let refused = create(&storage, &config, "email", configuration)
                .await
                .unwrap_err();
            assert_eq!(refused.0, StatusCode::BAD_REQUEST, "{case}: {}", refused.1);
        }
        assert!(
            storage
                .list()
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn create_takes_a_url_reference_and_a_generated_signing_secret_and_pins_the_host() {
        let (_dir, storage, config) = unguarded_storage().await;
        let signing_secret = "3f2c1a9e-7b4d-4e8a-9c61-0d5f2b7e8a14";

        let refused = create(
            &storage,
            &config,
            "webhook",
            serde_json::json!({ "url": "https://hooks.example.com/in", "signing_secret": signing_secret }),
        )
        .await
        .unwrap_err();
        assert_eq!(refused.0, StatusCode::BAD_REQUEST);
        assert!(
            refused
                .1
                .contains("url_secret_id"),
            "{}",
            refused.1
        );

        let (_, Json(created)) = create(
            &storage,
            &config,
            "webhook",
            serde_json::json!({ "url_secret_id": "hook-url", "signing_secret": signing_secret, "headers": { "X-Trace": "abc" } }),
        )
        .await
        .unwrap();

        let saved = saved_configuration(&storage, &created.integration().id).await;
        assert_eq!(saved["url_secret_id"], "hook-url");
        assert!(saved.get("url").is_none());
        assert_eq!(saved["signing_secret"], signing_secret);
        assert_eq!(saved["pinned_destination"], serde_json::json!({ "url": "hooks.example.com:443" }));
        let answered = &created
            .integration()
            .configuration;
        assert!(
            answered
                .get("signing_secret")
                .is_none()
        );
        assert_eq!(answered["pinned_destination"]["url"], "hooks.example.com:443");
    }

    #[tokio::test]
    async fn a_rename_only_edit_keeps_every_stored_credential() {
        let (_dir, storage, config) = unguarded_storage().await;
        let stored = seed_integration(&storage, "email", credential_configuration()).await;
        let view = view_of(&storage, &stored.id).await;

        let Json(updated) = update(&storage, &config, &stored.id, "email", view)
            .await
            .unwrap();

        assert_no_credentials(&updated);
        assert_eq!(saved_configuration(&storage, &stored.id).await, credential_configuration());
    }

    #[tokio::test]
    async fn an_edit_clears_with_null_and_replaces_with_a_reference() {
        let (_dir, storage, config) = unguarded_storage().await;
        let stored = seed_integration(&storage, "email", credential_configuration()).await;
        let mut edited = view_of(&storage, &stored.id).await;
        edited["sasl_password"] = JsonValue::Null;
        edited["headers"]["authorization"] = JsonValue::Null;
        edited["smtp_password_secret_id"] = serde_json::json!("smtp-global");

        let Json(_) = update(&storage, &config, &stored.id, "email", edited)
            .await
            .unwrap();

        let saved = saved_configuration(&storage, &stored.id).await;
        assert!(
            saved
                .get("sasl_password")
                .is_none()
        );
        assert!(
            saved["headers"]
                .get("Authorization")
                .is_none()
        );
        assert!(
            saved
                .get("smtp_password")
                .is_none()
        );
        assert_eq!(saved["smtp_password_secret_id"], "smtp-global");
        assert_eq!(saved["secret_key"], "sk-langfuse");
    }

    #[tokio::test]
    async fn an_edit_refuses_a_new_inline_credential() {
        let (_dir, storage, config) = unguarded_storage().await;
        let stored = seed_integration(&storage, "email", credential_configuration()).await;
        let mut edited = view_of(&storage, &stored.id).await;
        edited["smtp_password"] = serde_json::json!("typed-again");

        let refused = update(&storage, &config, &stored.id, "email", edited)
            .await
            .unwrap_err();

        assert_eq!(refused.0, StatusCode::BAD_REQUEST);
        assert!(
            refused
                .1
                .contains("smtp_password_secret_id"),
            "{}",
            refused.1
        );
        assert_eq!(saved_configuration(&storage, &stored.id).await, credential_configuration());
    }

    #[tokio::test]
    async fn update_refuses_to_send_stored_credentials_to_a_new_destination() {
        let (_dir, storage, config) = unguarded_storage().await;
        let stored = seed_integration(&storage, "email", credential_configuration()).await;
        let mut edited = view_of(&storage, &stored.id).await;
        edited["smtp_host"] = serde_json::json!("smtp.attacker.example");

        let refused = update(&storage, &config, &stored.id, "email", edited)
            .await
            .unwrap_err();

        assert_eq!(refused.0, StatusCode::BAD_REQUEST);
        assert_eq!(saved_configuration(&storage, &stored.id).await, credential_configuration());
    }

    /// The stream configuration the edit page sends when only the name changes:
    /// every field it loads, blank where the response left a credential out.
    fn dashboard_stream_payload(stored: &JsonValue) -> JsonValue {
        let field = |key: &str, default: &str| {
            stored
                .get(key)
                .cloned()
                .unwrap_or_else(|| serde_json::json!(default))
        };
        serde_json::json!({
            "platform": field("platform", "kafka"),
            "topic": field("topic", ""),
            "brokers": field("brokers", ""),
            "region": field("region", ""),
            "redis_url": "",
            "redis_url_secret_id": field("redis_url_secret_id", ""),
            "auth_type": field("auth_type", "none"),
            "sasl_username": field("sasl_username", ""),
            "sasl_password_secret_id": field("sasl_password_secret_id", ""),
        })
    }

    #[tokio::test]
    async fn a_rename_only_edit_of_a_stream_from_the_dashboard_is_accepted() {
        let platforms = [
            serde_json::json!({
                "platform": "kafka",
                "topic": "events",
                "brokers": "kafka:9092",
                "auth_type": "sasl",
                "sasl_username": "svc",
                "sasl_password": "sasl-pass",
            }),
            serde_json::json!({
                "platform": "pulsar",
                "topic": "events",
                "brokers": "pulsar://pulsar:6650",
                "auth_type": "sasl",
                "sasl_username": "svc",
                "sasl_password": "pulsar-pass",
            }),
            serde_json::json!({
                "platform": "kinesis",
                "topic": "events",
                "region": "eu-west-1",
                "access_key": "AKIA-legacy",
                "secret_key": "aws-legacy",
            }),
            serde_json::json!({ "platform": "redis", "topic": "events", "redis_url": REDIS_URL }),
            serde_json::json!({
                "platform": "redis",
                "topic": "events",
                "redis_url_secret_id": "redis-url",
                "pinned_destination": { "redis_url": "93.184.216.34:6379" },
            }),
        ];

        for stored_configuration in platforms {
            let (_dir, storage, config) = unguarded_storage().await;
            let stored = seed_integration(&storage, "stream", stored_configuration.clone()).await;
            let dashboard_payload = dashboard_stream_payload(&view_of(&storage, &stored.id).await);

            let Json(_) = update(&storage, &config, &stored.id, "stream", dashboard_payload)
                .await
                .unwrap_or_else(|refused| panic!("{stored_configuration}: {refused:?}"));

            let saved = saved_configuration(&storage, &stored.id).await;
            for (key, value) in stored_configuration
                .as_object()
                .unwrap()
            {
                assert_eq!(&saved[key], value, "{stored_configuration}: {key}");
            }
        }
    }

    #[tokio::test]
    async fn a_save_confirming_a_moved_destination_needs_secrets_view() {
        let (_dir, storage, config) = unguarded_storage().await;
        let pinned = serde_json::json!({ "url": "hooks.example.com:443" });
        let stored = seed_integration(
            &storage,
            "webhook",
            serde_json::json!({
                "url_secret_id": "moved-hook",
                "signing_secret": "3f2c1a9e-7b4d-4e8a-9c61-0d5f2b7e8a14",
                "pinned_destination": pinned,
            }),
        )
        .await;
        let rename = view_of(&storage, &stored.id).await;
        let poweruser = signed_in(UserRole::PowerUser).await;
        let administrator = signed_in(UserRole::Administrator).await;

        let refused = update_as(&poweruser, &storage, &config, &stored.id, "webhook", rename.clone())
            .await
            .unwrap_err();
        assert_eq!(refused.0, StatusCode::FORBIDDEN, "{}", refused.1);
        assert_eq!(refused.1, CHANGED_REFERENCE_REFUSAL);
        assert!(!refused.1.contains("attacker"), "{}", refused.1);
        assert_eq!(saved_configuration(&storage, &stored.id).await["pinned_destination"], pinned);

        let Json(_) = update_as(&administrator, &storage, &config, &stored.id, "webhook", rename)
            .await
            .unwrap();
        assert_eq!(
            saved_configuration(&storage, &stored.id).await["pinned_destination"],
            serde_json::json!({ "url": "attacker.example:443" })
        );
    }

    #[tokio::test]
    async fn with_values_hidden_a_moved_address_is_confirmed_unless_another_secret_follows_it() {
        let (_dir, storage, config) = unguarded_storage().await;
        let pinned = serde_json::json!({ "url": "hooks.example.com:443" });
        let administrator = signed_in(UserRole::Administrator).await;
        let address_only = seed_integration(
            &storage,
            "webhook",
            serde_json::json!({ "url_secret_id": "moved-hook", "pinned_destination": pinned }),
        )
        .await;
        let with_header = seed_integration(
            &storage,
            "webhook",
            serde_json::json!({
                "url_secret_id": "moved-hook",
                "headers_secret_id": { "Authorization": "smtp-global" },
                "pinned_destination": pinned,
            }),
        )
        .await;

        let rename = view_of(&storage, &with_header.id).await;
        let unrevealed = update_revealing(false, &administrator, &storage, &config, &with_header.id, "webhook", rename)
            .await
            .unwrap_err();
        assert_eq!(unrevealed.0, StatusCode::FORBIDDEN, "{}", unrevealed.1);
        assert!(
            unrevealed
                .1
                .contains("not revealed"),
            "{}",
            unrevealed.1
        );
        assert_eq!(saved_configuration(&storage, &with_header.id).await["pinned_destination"], pinned);

        let with_inline_header = seed_integration(
            &storage,
            "webhook",
            serde_json::json!({
                "url_secret_id": "moved-hook",
                "headers": { "Authorization": "Bearer saved-inline-token" },
                "pinned_destination": pinned,
            }),
        )
        .await;
        let rename = view_of(&storage, &with_inline_header.id).await;
        let unrevealed =
            update_revealing(false, &administrator, &storage, &config, &with_inline_header.id, "webhook", rename)
                .await
                .unwrap_err();
        assert_eq!(unrevealed.0, StatusCode::FORBIDDEN, "{}", unrevealed.1);
        assert_eq!(saved_configuration(&storage, &with_inline_header.id).await["pinned_destination"], pinned);

        let rename = view_of(&storage, &address_only.id).await;
        let Json(_) = update_revealing(false, &administrator, &storage, &config, &address_only.id, "webhook", rename)
            .await
            .unwrap();
        assert_eq!(
            saved_configuration(&storage, &address_only.id).await["pinned_destination"],
            serde_json::json!({ "url": "attacker.example:443" })
        );
    }

    #[tokio::test]
    async fn with_values_hidden_the_saved_signing_secret_never_follows_a_moved_address() {
        let (_dir, storage, config) = unguarded_storage().await;
        let pinned = serde_json::json!({ "url": "hooks.example.com:443" });
        let signing_secret = "whsec-saved-3f2c1a9e-7b4d-4e8a-9c61-0d5f";
        let administrator = signed_in(UserRole::Administrator).await;
        let moved = seed_integration(
            &storage,
            "webhook",
            serde_json::json!({ "url_secret_id": "moved-hook", "signing_secret": signing_secret, "pinned_destination": pinned }),
        )
        .await;
        let unmoved = seed_integration(
            &storage,
            "webhook",
            serde_json::json!({ "url_secret_id": "hook-url", "signing_secret": signing_secret, "pinned_destination": pinned }),
        )
        .await;

        let rename = view_of(&storage, &moved.id).await;
        let refused = update_revealing(false, &administrator, &storage, &config, &moved.id, "webhook", rename)
            .await
            .unwrap_err();
        assert_eq!(refused.0, StatusCode::FORBIDDEN, "{}", refused.1);
        assert!(
            refused
                .1
                .contains("not revealed"),
            "{}",
            refused.1
        );
        assert_eq!(saved_configuration(&storage, &moved.id).await["pinned_destination"], pinned);

        let rename = view_of(&storage, &unmoved.id).await;
        let Json(_) = update_revealing(false, &administrator, &storage, &config, &unmoved.id, "webhook", rename)
            .await
            .unwrap();
        let saved = saved_configuration(&storage, &unmoved.id).await;
        assert_eq!(saved["pinned_destination"], pinned);
        assert_eq!(saved["signing_secret"], signing_secret);
    }

    #[tokio::test]
    async fn with_values_hidden_every_refusal_of_a_referenced_url_gets_one_answer_per_key() {
        let (_dir, storage, config) = unguarded_storage().await;
        let administrator = signed_in(UserRole::Administrator).await;

        for (integration_type, key, extra, references) in [
            (
                "webhook",
                "url",
                serde_json::json!({}),
                ["smtp-global", "internal-redis", "private-hook", "credentialed-hook"],
            ),
            (
                "stream",
                "redis_url",
                serde_json::json!({ "platform": "redis", "topic": "events" }),
                ["smtp-global", "hook-url", "internal-redis", "private-hook"],
            ),
        ] {
            let mut answers = std::collections::BTreeSet::new();
            for reference in references {
                let mut configuration = extra.clone();
                configuration[format!("{key}_secret_id")] = serde_json::json!(reference);
                let refused =
                    create_revealing(false, &administrator, &storage, &config, integration_type, configuration)
                        .await
                        .unwrap_err();
                assert_eq!(refused.0, StatusCode::BAD_REQUEST, "{integration_type} {reference}: {}", refused.1);
                answers.insert(refused.1);
            }
            assert_eq!(
                answers
                    .into_iter()
                    .collect::<Vec<_>>(),
                [format!("{key}_secret_id does not name a destination this integration may send to")],
                "{integration_type}"
            );
        }
        assert!(
            storage
                .list()
                .await
                .unwrap()
                .is_empty()
        );

        let revealed = create_revealing(
            true,
            &administrator,
            &storage,
            &config,
            "webhook",
            serde_json::json!({ "url_secret_id": "private-hook" }),
        )
        .await
        .unwrap_err();
        assert!(
            revealed
                .1
                .contains("may not send to"),
            "{}",
            revealed.1
        );
    }

    #[tokio::test]
    async fn a_rename_keeping_the_pinned_destination_needs_no_secrets_view() {
        let (_dir, storage, config) = unguarded_storage().await;
        let pinned = serde_json::json!({ "url": "hooks.example.com:443" });
        let stored = seed_integration(
            &storage,
            "webhook",
            serde_json::json!({ "url_secret_id": "hook-url", "pinned_destination": pinned }),
        )
        .await;
        let rename = view_of(&storage, &stored.id).await;

        let Json(_) =
            update_as(&signed_in(UserRole::PowerUser).await, &storage, &config, &stored.id, "webhook", rename)
                .await
                .unwrap();

        assert_eq!(saved_configuration(&storage, &stored.id).await["pinned_destination"], pinned);
    }

    #[tokio::test]
    async fn choosing_where_a_stored_secret_is_sent_needs_secrets_view() {
        let (_dir, storage, config) = unguarded_storage().await;
        let poweruser = signed_in(UserRole::PowerUser).await;
        let reference = serde_json::json!({ "smtp_host": "93.184.216.34", "smtp_password_secret_id": "smtp-global" });

        let refused = create_as(&poweruser, &storage, &config, "email", reference.clone())
            .await
            .unwrap_err();
        assert_eq!(refused.0, StatusCode::FORBIDDEN, "{}", refused.1);
        assert!(
            storage
                .list()
                .await
                .unwrap()
                .is_empty()
        );

        let (_, Json(created)) = create(&storage, &config, "email", reference.clone())
            .await
            .unwrap();
        let id = created
            .integration()
            .id
            .clone();

        let Json(_) = update_as(&poweruser, &storage, &config, &id, "email", reference)
            .await
            .unwrap();

        for (case, configuration) in [
            (
                "a new host",
                serde_json::json!({ "smtp_host": "smtp.attacker.example", "smtp_password_secret_id": "smtp-global" }),
            ),
            (
                "another secret",
                serde_json::json!({ "smtp_host": "93.184.216.34", "smtp_password_secret_id": "smtp-other" }),
            ),
        ] {
            let refused = update_as(&poweruser, &storage, &config, &id, "email", configuration)
                .await
                .unwrap_err();
            assert_eq!(refused.0, StatusCode::FORBIDDEN, "{case}: {}", refused.1);
        }
        assert_eq!(saved_configuration(&storage, &id).await["smtp_host"], "93.184.216.34");
    }

    #[tokio::test]
    async fn with_values_hidden_an_integration_may_reference_only_its_address() {
        let (_dir, storage, config) = unguarded_storage().await;
        let administrator = signed_in(UserRole::Administrator).await;
        let signing_secret = "3f2c1a9e-7b4d-4e8a-9c61-0d5f2b7e8a14";

        for (case, integration_type, configuration) in [
            (
                "an address and a header",
                "webhook",
                serde_json::json!({
                    "url_secret_id": "hook-url",
                    "headers_secret_id": { "Authorization": "smtp-global" },
                    "signing_secret": signing_secret,
                }),
            ),
            (
                "a password",
                "email",
                serde_json::json!({ "smtp_host": "93.184.216.34", "smtp_password_secret_id": "smtp-global" }),
            ),
            (
                "an address and a routing header",
                "webhook",
                serde_json::json!({
                    "url_secret_id": "hook-url",
                    "headers": { "Host": "attacker.example" },
                    "signing_secret": signing_secret,
                }),
            ),
        ] {
            let refused = create_revealing(false, &administrator, &storage, &config, integration_type, configuration)
                .await
                .unwrap_err();
            assert_eq!(refused.0, StatusCode::FORBIDDEN, "{case}: {}", refused.1);
            assert!(
                refused
                    .1
                    .contains("not revealed"),
                "{case}: {}",
                refused.1
            );
        }
        assert!(
            storage
                .list()
                .await
                .unwrap()
                .is_empty()
        );

        let address_only = serde_json::json!({ "url_secret_id": "hook-url", "signing_secret": signing_secret });
        let refused = create_revealing(
            false,
            &signed_in(UserRole::PowerUser).await,
            &storage,
            &config,
            "webhook",
            address_only.clone(),
        )
        .await
        .unwrap_err();
        assert_eq!(refused.0, StatusCode::FORBIDDEN, "{}", refused.1);
        assert!(
            refused
                .1
                .contains("secrets.view"),
            "{}",
            refused.1
        );

        let (status, Json(created)) =
            create_revealing(false, &administrator, &storage, &config, "webhook", address_only)
                .await
                .unwrap();
        assert_eq!(status, StatusCode::CREATED);
        let saved = saved_configuration(&storage, &created.integration().id).await;
        assert_eq!(saved["url_secret_id"], "hook-url");
        assert_eq!(saved["pinned_destination"], serde_json::json!({ "url": "hooks.example.com:443" }));
    }

    #[tokio::test]
    async fn with_values_hidden_a_url_the_type_does_not_deliver_to_is_refused_alike_for_every_secret() {
        let (_dir, storage, config) = unguarded_storage().await;
        let administrator = signed_in(UserRole::Administrator).await;
        let mut answers = std::collections::BTreeSet::new();

        for (integration_type, key, extra) in [
            ("webhook", "redis_url_secret_id", serde_json::json!({})),
            ("email", "redis_url_secret_id", serde_json::json!({ "smtp_host": "93.184.216.34" })),
            ("slack", "url_secret_id", serde_json::json!({})),
            ("webhook", "webhook_url_secret_id", serde_json::json!({})),
            (
                "stream",
                "redis_url_secret_id",
                serde_json::json!({ "platform": "kafka", "brokers": "93.184.216.34:9092" }),
            ),
        ] {
            for reference in ["redis-url", "hook-url", "smtp-global", "missing"] {
                let mut configuration = extra.clone();
                configuration[key] = serde_json::json!(reference);
                let refused =
                    create_revealing(false, &administrator, &storage, &config, integration_type, configuration)
                        .await
                        .unwrap_err();
                assert_eq!(refused.0, StatusCode::FORBIDDEN, "{integration_type} {key} {reference}: {}", refused.1);
                answers.insert(refused.1);
            }
        }
        assert_eq!(answers.len(), 1, "{answers:?}");
        assert!(
            answers
                .iter()
                .all(|answer| answer.contains("not revealed")),
            "{answers:?}"
        );
        assert!(
            storage
                .list()
                .await
                .unwrap()
                .is_empty()
        );

        let (status, Json(created)) = create_revealing(
            false,
            &administrator,
            &storage,
            &config,
            "stream",
            serde_json::json!({ "platform": "redis", "topic": "events", "redis_url_secret_id": "redis-url" }),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::CREATED);
        let saved = saved_configuration(&storage, &created.integration().id).await;
        assert_eq!(saved["pinned_destination"], serde_json::json!({ "redis_url": "93.184.216.34:6379" }));
    }

    #[tokio::test]
    async fn without_secrets_view_a_missing_and_an_existing_secret_get_the_same_answer() {
        let (_dir, storage, config) = unguarded_storage().await;
        let poweruser = signed_in(UserRole::PowerUser).await;

        let mut answers = Vec::new();
        for reference in ["smtp-global", "no-such-secret"] {
            let configuration =
                serde_json::json!({ "smtp_host": "93.184.216.34", "smtp_password_secret_id": reference });
            answers.push(
                create_as(&poweruser, &storage, &config, "email", configuration)
                    .await
                    .unwrap_err(),
            );
        }
        assert_eq!(answers[0].0, StatusCode::FORBIDDEN, "{}", answers[0].1);
        assert_eq!(answers[0], answers[1]);

        let (_, Json(created)) = create(
            &storage,
            &config,
            "email",
            serde_json::json!({ "smtp_host": "93.184.216.34", "smtp_password_secret_id": "smtp-global" }),
        )
        .await
        .unwrap();
        let id = created
            .integration()
            .id
            .clone();
        let mut answers = Vec::new();
        for reference in ["smtp-other", "no-such-secret"] {
            let configuration =
                serde_json::json!({ "smtp_host": "93.184.216.34", "smtp_password_secret_id": reference });
            answers.push(
                update_as(&poweruser, &storage, &config, &id, "email", configuration)
                    .await
                    .unwrap_err(),
            );
        }
        assert_eq!(answers[0].0, StatusCode::FORBIDDEN, "{}", answers[0].1);
        assert_eq!(answers[0], answers[1]);
    }

    #[tokio::test]
    async fn with_values_hidden_a_caller_without_secrets_view_cannot_tell_whether_a_credential_is_kept() {
        let (_dir, storage, config) = unguarded_storage().await;
        let poweruser = signed_in(UserRole::PowerUser).await;
        let pinned = serde_json::json!({ "url": "hooks.example.com:443" });

        let mut answers = Vec::new();
        for kept in [
            serde_json::json!({}),
            serde_json::json!({ "headers": { "Authorization": "Bearer saved-inline-token" } }),
            serde_json::json!({ "signing_secret": "whsec-saved-3f2c1a9e-7b4d-4e8a-9c61-0d5f" }),
        ] {
            let mut configuration = serde_json::json!({ "url_secret_id": "moved-hook", "pinned_destination": pinned });
            configuration
                .as_object_mut()
                .unwrap()
                .extend(
                    kept.as_object()
                        .unwrap()
                        .clone(),
                );
            let stored = seed_integration(&storage, "webhook", configuration.clone()).await;
            let rename = view_of(&storage, &stored.id).await;
            answers.push(
                update_revealing(false, &poweruser, &storage, &config, &stored.id, "webhook", rename)
                    .await
                    .unwrap_err(),
            );
            assert_eq!(saved_configuration(&storage, &stored.id).await, configuration);
        }
        assert_eq!(answers[0].0, StatusCode::FORBIDDEN, "{}", answers[0].1);
        assert!(
            answers[0]
                .1
                .contains("secrets.view"),
            "{}",
            answers[0].1
        );
        assert!(
            answers
                .iter()
                .all(|answer| answer == &answers[0]),
            "{answers:?}"
        );

        let mut answers = Vec::new();
        for configuration in [
            serde_json::json!({ "url_secret_id": "hook-url" }),
            serde_json::json!({ "url_secret_id": "hook-url", "headers_secret_id": { "Authorization": "smtp-global" } }),
        ] {
            answers.push(
                create_revealing(false, &poweruser, &storage, &config, "webhook", configuration)
                    .await
                    .unwrap_err(),
            );
        }
        assert_eq!(answers[0].0, StatusCode::FORBIDDEN, "{}", answers[0].1);
        assert_eq!(answers[0], answers[1]);
    }

    #[tokio::test]
    async fn with_values_hidden_every_refusal_of_a_referenced_url_on_update_gets_one_answer() {
        let (_dir, storage, config) = unguarded_storage().await;
        let administrator = signed_in(UserRole::Administrator).await;
        let stored_configuration = serde_json::json!({
            "url_secret_id": "hook-url",
            "pinned_destination": { "url": "hooks.example.com:443" },
        });
        let stored = seed_integration(&storage, "webhook", stored_configuration.clone()).await;

        let mut answers = std::collections::BTreeSet::new();
        for reference in ["smtp-global", "internal-redis", "private-hook", "credentialed-hook"] {
            let refused = update_revealing(
                false,
                &administrator,
                &storage,
                &config,
                &stored.id,
                "webhook",
                serde_json::json!({ "url_secret_id": reference }),
            )
            .await
            .unwrap_err();
            assert_eq!(refused.0, StatusCode::BAD_REQUEST, "{reference}: {}", refused.1);
            answers.insert(refused.1);
        }
        assert_eq!(
            answers
                .into_iter()
                .collect::<Vec<_>>(),
            ["url_secret_id does not name a destination this integration may send to"]
        );
        assert_eq!(saved_configuration(&storage, &stored.id).await, stored_configuration);

        let revealed =
            update(&storage, &config, &stored.id, "webhook", serde_json::json!({ "url_secret_id": "private-hook" }))
                .await
                .unwrap_err();
        assert!(
            revealed
                .1
                .contains("may not send to"),
            "{}",
            revealed.1
        );
    }

    #[tokio::test]
    async fn a_rename_without_secrets_view_gets_one_answer_whatever_a_moved_url_secret_now_holds() {
        let (_dir, storage, config) = unguarded_storage().await;
        let poweruser = signed_in(UserRole::PowerUser).await;
        let administrator = signed_in(UserRole::Administrator).await;

        for reveal_values in [true, false] {
            let mut answers = std::collections::BTreeSet::new();
            for reference in ["moved-hook", "private-hook", "credentialed-hook", "smtp-global", "no-such-secret"] {
                let configuration = serde_json::json!({
                    "url_secret_id": reference,
                    "pinned_destination": { "url": "hooks.example.com:443" },
                });
                let stored = seed_integration(&storage, "webhook", configuration.clone()).await;
                let rename = view_of(&storage, &stored.id).await;
                let refused =
                    update_revealing(reveal_values, &poweruser, &storage, &config, &stored.id, "webhook", rename)
                        .await
                        .unwrap_err();
                assert_eq!(refused.0, StatusCode::FORBIDDEN, "{reveal_values} {reference}: {}", refused.1);
                answers.insert(refused.1);
                assert_eq!(saved_configuration(&storage, &stored.id).await, configuration);
            }
            assert_eq!(
                answers
                    .into_iter()
                    .collect::<Vec<_>>(),
                [CHANGED_REFERENCE_REFUSAL],
                "{reveal_values}"
            );
        }

        let stored = seed_integration(
            &storage,
            "webhook",
            serde_json::json!({
                "url_secret_id": "no-such-secret",
                "pinned_destination": { "url": "hooks.example.com:443" },
            }),
        )
        .await;
        let rename = view_of(&storage, &stored.id).await;
        let revealed = update_revealing(true, &administrator, &storage, &config, &stored.id, "webhook", rename)
            .await
            .unwrap_err();
        assert_eq!(
            revealed,
            (StatusCode::BAD_REQUEST, "url_secret_id does not name a secret this integration may use".to_string())
        );

        let stored = seed_integration(
            &storage,
            "webhook",
            serde_json::json!({
                "url_secret_id": "private-hook",
                "pinned_destination": { "url": "hooks.example.com:443" },
            }),
        )
        .await;
        let rename = view_of(&storage, &stored.id).await;
        let revealed = update_revealing(true, &administrator, &storage, &config, &stored.id, "webhook", rename)
            .await
            .unwrap_err();
        assert_eq!(revealed.0, StatusCode::BAD_REQUEST, "{}", revealed.1);
        assert!(
            revealed
                .1
                .contains("may not send to"),
            "{}",
            revealed.1
        );
    }

    #[tokio::test]
    async fn without_secrets_view_a_new_destination_gets_one_answer_whether_a_credential_is_kept() {
        let (_dir, storage, config) = unguarded_storage().await;
        let poweruser = signed_in(UserRole::PowerUser).await;
        let administrator = signed_in(UserRole::Administrator).await;

        let mut answers = Vec::new();
        let mut kept_signing_secret = None;
        for kept in [
            serde_json::json!({}),
            serde_json::json!({ "headers": { "Authorization": "Bearer saved-inline-token" } }),
            serde_json::json!({ "signing_secret": "whsec-saved-3f2c1a9e-7b4d-4e8a-9c61-0d5f" }),
        ] {
            let mut configuration = serde_json::json!({
                "url_secret_id": "hook-url",
                "pinned_destination": { "url": "hooks.example.com:443" },
            });
            configuration
                .as_object_mut()
                .unwrap()
                .extend(
                    kept.as_object()
                        .unwrap()
                        .clone(),
                );
            let stored = seed_integration(&storage, "webhook", configuration.clone()).await;
            for reveal_values in [true, false] {
                answers.push(
                    update_revealing(
                        reveal_values,
                        &poweruser,
                        &storage,
                        &config,
                        &stored.id,
                        "webhook",
                        serde_json::json!({ "url_secret_id": "moved-hook" }),
                    )
                    .await
                    .unwrap_err(),
                );
            }
            assert_eq!(saved_configuration(&storage, &stored.id).await, configuration);
            kept_signing_secret = Some(stored.id);
        }
        assert_eq!(answers[0], (StatusCode::FORBIDDEN, PAIRING_REFUSAL.to_string()));
        assert!(
            answers
                .iter()
                .all(|answer| answer == &answers[0]),
            "{answers:?}"
        );

        let locked = update_as(
            &administrator,
            &storage,
            &config,
            &kept_signing_secret.unwrap(),
            "webhook",
            serde_json::json!({ "url_secret_id": "moved-hook" }),
        )
        .await
        .unwrap_err();
        assert_eq!(locked.0, StatusCode::BAD_REQUEST, "{}", locked.1);
        assert!(
            locked
                .1
                .contains("Re-enter the credentials"),
            "{}",
            locked.1
        );
    }

    #[tokio::test]
    async fn with_values_hidden_a_slack_integration_may_reference_its_webhook_url() {
        let (_dir, storage, config) = unguarded_storage().await;
        let administrator = signed_in(UserRole::Administrator).await;

        let (status, Json(created)) = create_revealing(
            false,
            &administrator,
            &storage,
            &config,
            "slack",
            serde_json::json!({ "webhook_url_secret_id": "hook-url" }),
        )
        .await
        .unwrap();

        assert_eq!(status, StatusCode::CREATED);
        let saved = saved_configuration(&storage, &created.integration().id).await;
        assert_eq!(saved["webhook_url_secret_id"], "hook-url");
        assert!(
            saved
                .get("webhook_url")
                .is_none()
        );
        assert_eq!(saved["pinned_destination"], serde_json::json!({ "webhook_url": "hooks.example.com:443" }));
    }

    #[test]
    fn audit_integrations_cannot_be_tenant_owned() {
        assert!(ensure_audit_integration_is_global(Some("audit"), Some("tenant-a")).is_err());
        assert!(ensure_audit_integration_is_global(Some("audit"), None).is_ok());
        assert!(ensure_audit_integration_is_global(Some("general"), Some("tenant-a")).is_ok());
    }

    #[test]
    fn canonical_integration_access_combines_tenant_kind_and_id() {
        let context = Some(Extension(PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: "tenant-a".into(),
        }));
        let scope = Some(Extension(PatResourceScope(Arc::new(
            regex::Regex::new(r"\ATENANT:tenant-a:integrations:integration-1\z").unwrap(),
        ))));
        let mut integration = Integration::new(
            "Integration".into(),
            String::new(),
            "webhook".into(),
            serde_json::json!({}),
            serde_json::json!({}),
            "active".into(),
            None,
        );
        integration.id = "integration-1".into();

        integration.tenant_id = Some("tenant-a".into());
        assert!(integration_allowed(&integration, &context, &scope));

        integration.tenant_id = None;
        // Untenanted (legacy) record now denied to a tenant PAT (fail-closed hardening).
        assert!(!integration_allowed(&integration, &context, &scope));

        integration.tenant_id = Some("tenant-b".into());
        assert!(!integration_allowed(&integration, &context, &scope));

        let wrong_kind = Some(Extension(PatResourceScope(Arc::new(
            regex::Regex::new(r"\ATENANT:tenant-a:gateways:integration-1\z").unwrap(),
        ))));
        integration.tenant_id = Some("tenant-a".into());
        assert!(!integration_allowed(&integration, &context, &wrong_kind));
    }

    #[tokio::test]
    async fn deleting_an_integration_through_the_router_has_every_extension_its_handler_needs() {
        use tower::ServiceExt;

        let (_dir, storage, config) = unguarded_storage().await;
        let triggers = tempfile::tempdir().unwrap();
        let bootstrap: crate::config::BootstrapConfig = serde_json::from_value(serde_json::json!({
            "tls": { "cert_path": "cert.pem", "key_path": "key.pem" },
            "storage_paths": { "integration_triggers": triggers.path().to_str().unwrap() },
        }))
        .unwrap();
        let integration = seed(&storage, "general").await;

        let router =
            integration_api_router(storage.clone(), config, Arc::new(bootstrap), None, RevealSecretValues(true), None);
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/integrations/{}", integration.id))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(
            storage
                .list()
                .await
                .unwrap()
                .is_empty()
        );
    }

    fn not_public() -> (StatusCode, String) {
        (StatusCode::BAD_REQUEST, destinations::DestinationError::NotPublic.to_string())
    }

    #[tokio::test]
    async fn test_creating_an_integration_checks_its_destination() {
        let (_dir, storage, config) = unguarded_storage().await;

        let internal =
            create(&storage, &config, "email", serde_json::json!({ "smtp_host": "10.0.0.5", "smtp_port": 25 })).await;
        assert_eq!(internal.map(|(status, _)| status), Err(not_public()));
        assert!(
            storage
                .list()
                .await
                .unwrap()
                .is_empty()
        );

        let public =
            create(&storage, &config, "email", serde_json::json!({ "smtp_host": "93.184.216.34", "smtp_port": 587 }))
                .await;
        assert_eq!(public.map(|(status, _)| status), Ok(StatusCode::CREATED));
    }

    #[tokio::test]
    async fn test_a_destination_behind_a_secret_reference_is_checked_on_save() {
        use crate::secrets::store::memory::{MemorySecretsStore, secret};
        let (_dir, storage, config) = unguarded_storage().await;
        let store: Option<Arc<dyn SecretsStore>> = Some(Arc::new(MemorySecretsStore::with(vec![secret(
            "id-cache",
            "cache-url",
            "redis://:cache-pass@10.0.0.5:6379",
            None,
        )])));

        let administrator = signed_in(UserRole::Administrator).await;
        let refused = create_notifier(
            Extension(storage.clone()),
            Extension(config),
            Extension(store),
            Extension(RevealSecretValues(true)),
            None,
            None,
            None,
            administrator.guard.clone(),
            administrator.caller.clone(),
            create_request("stream", serde_json::json!({ "platform": "redis", "redis_url_secret_id": "cache-url" })),
        )
        .await;

        assert_eq!(refused.map(|(status, _)| status), Err(not_public()));
    }

    #[tokio::test]
    async fn test_updating_keeps_a_saved_destination_and_checks_a_changed_one() {
        let (_dir, storage, config) = unguarded_storage().await;
        let saved = seed_integration(
            &storage,
            "email",
            serde_json::json!({ "smtp_host": "10.0.0.5", "smtp_port": 25, "smtp_password": "old" }),
        )
        .await;

        let kept = update(
            &storage,
            &config,
            &saved.id,
            "email",
            serde_json::json!({ "smtp_host": "10.0.0.5", "smtp_port": 25 }),
        )
        .await;
        assert!(kept.is_ok(), "{:?}", kept.err());
        assert_eq!(saved_configuration(&storage, &saved.id).await["smtp_password"], "old");

        let moved = update(
            &storage,
            &config,
            &saved.id,
            "email",
            serde_json::json!({ "smtp_host": "10.0.0.6", "smtp_port": 25, "smtp_password": null }),
        )
        .await;
        assert_eq!(moved.map(|_| ()), Err(not_public()));

        let retyped = update(
            &storage,
            &config,
            &saved.id,
            "stream",
            serde_json::json!({ "platform": "redis", "redis_url_secret_id": "internal-redis", "smtp_password": null }),
        )
        .await;
        assert_eq!(retyped.map(|_| ()), Err(not_public()));
        assert_eq!(saved_configuration(&storage, &saved.id).await["smtp_host"], "10.0.0.5");
    }

    #[tokio::test]
    async fn test_a_create_outside_the_tokens_scope_is_refused_before_its_destination_is_checked() {
        let (_dir, storage, config) = unguarded_storage().await;
        let context = Some(Extension(PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: "tenant-a".into(),
        }));
        let other_kind =
            Some(Extension(PatResourceScope(Arc::new(regex::Regex::new(r"\ATENANT:tenant-a:gateways:.*\z").unwrap()))));

        let refused = create_notifier(
            Extension(storage.clone()),
            Extension(config),
            secrets(),
            Extension(RevealSecretValues(true)),
            None,
            context,
            other_kind,
            None,
            None,
            create_request("email", serde_json::json!({ "smtp_host": "10.0.0.5", "smtp_port": 25 })),
        )
        .await;

        assert_eq!(
            refused
                .map(|(status, _)| status)
                .map_err(|(status, _)| status),
            Err(StatusCode::FORBIDDEN)
        );
    }

    #[tokio::test]
    async fn test_a_secret_changed_after_save_is_checked_when_it_delivers() {
        use crate::secrets::store::memory::{MemorySecretsStore, secret};
        use crate::storage::integration_trigger_handlers::{TestNotifierRequest, test_notifier_handler};
        let (_dir, storage, config) = unguarded_storage().await;
        let configuration =
            serde_json::json!({ "platform": "redis", "topic": "events", "redis_url_secret_id": "cache-url" });
        let holding = |redis_url: &str| -> Option<Arc<dyn SecretsStore>> {
            Some(Arc::new(MemorySecretsStore::with(vec![secret("id-cache", "cache-url", redis_url, None)])))
        };

        let administrator = signed_in(UserRole::Administrator).await;
        let (status, Json(created)) = create_notifier(
            Extension(storage.clone()),
            Extension(config),
            Extension(holding("redis://93.184.216.34:6379")),
            Extension(RevealSecretValues(true)),
            None,
            None,
            None,
            administrator.guard.clone(),
            administrator.caller.clone(),
            create_request("stream", configuration.clone()),
        )
        .await
        .expect("a public destination passes the save-time check");
        assert_eq!(status, StatusCode::CREATED);

        // The secret is edited after the save to name an internal address.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a loopback listener");
        listener
            .set_nonblocking(true)
            .expect("make the listener non-blocking");
        let port = listener
            .local_addr()
            .expect("listener address")
            .port();
        let request = TestNotifierRequest {
            integration_type: "stream".to_string(),
            configuration,
            content: serde_json::json!({}),
            variables: Default::default(),
            integration_id: Some(
                created
                    .integration()
                    .id
                    .clone(),
            ),
        };
        let answer = test_notifier_handler(
            Extension(storage),
            Extension(holding(&format!("redis://127.0.0.1:{port}"))),
            Extension(RevealSecretValues(true)),
            None,
            None,
            administrator.guard.clone(),
            administrator.caller.clone(),
            None,
            Json(request),
        )
        .await
        .map(|_| ());

        assert_eq!(answer, Err(not_public()));
        match listener.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            other => panic!("the edited secret's address was dialled: {other:?}"),
        }
    }
}
