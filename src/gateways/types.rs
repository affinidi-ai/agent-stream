use crate::storage::filesystem::StorableEntity;
use serde::{Deserialize, Serialize};

/// Represents the type of gateway
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum GatewayType {
    /// The local gateway (this instance)
    #[serde(rename = "self")]
    SelfGateway,
    /// A remote gateway
    #[default]
    Remote,
}

/// Represents the status of a gateway
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum GatewayStatus {
    #[default]
    Active,
    Pending,
    #[serde(rename = "awaiting-approval")]
    AwaitingApproval,
    Disabled,
    Failed,
}

/// Represents how the gateway record was created
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum GatewayCreationType {
    /// Created by user accepting an OOB invitation
    #[default]
    User,
    /// Created automatically when remote accepted our connection point
    System,
}

/// Gateway-level OPA policy configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GatewayOpaPolicyConfig {
    /// Whether the gateway-level OPA policy is enabled
    pub enabled: bool,

    /// Legacy / hand-authored inline Rego. A gateway that references a policy
    /// definition (below) resolves its Rego from that definition at compile time
    /// and stores nothing here; this is kept only for gateways authored inline
    /// before reusable definitions existed.
    #[serde(default)]
    pub policy: String,

    /// Id of the reusable policy definition this gateway enforces. This is the
    /// single source of truth: the Rego is resolved from the definition at
    /// compile time (never copied into the gateway), so editing the definition
    /// updates enforcement without touching the gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_definition_id: Option<String>,

    /// Additional reusable policy definitions this gateway enforces. Evaluated
    /// together with `policy_definition_id` under deny-overrides (any deny
    /// blocks). Reference-only, like the single id above.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_definition_ids: Vec<String>,
}

impl GatewayOpaPolicyConfig {
    /// The ordered, deduped set of policy-definition ids enforced on this
    /// gateway: the legacy single `policy_definition_id` first, then any in
    /// `policy_definition_ids`. Empty when the gateway references no reusable
    /// definition (it may still carry legacy inline Rego). Evaluated under
    /// deny-overrides.
    pub fn all_policy_definition_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = Vec::new();
        if let Some(id) = self
            .policy_definition_id
            .as_deref()
            .filter(|id| !id.is_empty())
        {
            ids.push(id.to_string());
        }
        for id in &self.policy_definition_ids {
            if !id.is_empty() && !ids.contains(id) {
                ids.push(id.clone());
            }
        }
        ids
    }
}

/// Represents a gateway record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gateway {
    /// Unique identifier for this gateway
    pub id: String,

    /// Gateway name
    pub name: String,

    /// Gateway description
    pub description: String,

    /// Decentralized Identifier (DID) for this gateway
    pub did: String,

    /// Type of gateway (self or remote)
    pub gateway_type: GatewayType,

    /// Status of the gateway
    pub status: GatewayStatus,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    /// How this gateway record was created (user or system)
    #[serde(default)]
    pub creation_type: GatewayCreationType,

    /// Timestamp when this record was created
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// Timestamp when this record was last updated
    pub updated_at: chrono::DateTime<chrono::Utc>,

    /// List of channel config IDs to expose to this remote gateway
    /// If empty, all active channels will be exposed
    #[serde(default)]
    pub exposed_channels: Vec<String>,

    /// Gateway-level OPA policy configuration
    /// For self gateway: enforced on ALL inbound traffic
    /// For remote gateways: enforced on outbound traffic to that gateway
    #[serde(default)]
    pub opa_policy_config: Option<GatewayOpaPolicyConfig>,
}

impl Gateway {
    pub fn new(
        name: String,
        description: String,
        did: String,
        gateway_type: GatewayType,
    ) -> Self {
        Self::new_with_creation_type(name, description, did, gateway_type, GatewayCreationType::User)
    }

    pub fn new_with_creation_type(
        name: String,
        description: String,
        did: String,
        gateway_type: GatewayType,
        creation_type: GatewayCreationType,
    ) -> Self {
        let now = chrono::Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            description,
            did,
            gateway_type,
            status: GatewayStatus::Active,
            tenant_id: None,
            creation_type,
            created_at: now,
            updated_at: now,
            exposed_channels: Vec::new(),
            opa_policy_config: None,
        }
    }
}

impl StorableEntity for Gateway {
    fn id(&self) -> &str {
        &self.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_and_legacy_gateways_are_global() {
        let gateway =
            Gateway::new("Remote".into(), String::new(), "did:web:remote.example".into(), GatewayType::Remote);
        assert_eq!(gateway.tenant_id, None);

        let mut value = serde_json::to_value(gateway).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("tenant_id");
        let legacy: Gateway = serde_json::from_value(value).unwrap();
        assert_eq!(legacy.tenant_id, None);
    }
}
