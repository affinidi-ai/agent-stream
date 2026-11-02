use crate::storage::filesystem::StorableEntity;
use serde::{Deserialize, Serialize};

/// A marketplace model that has been purchased and stored in the gateway.
/// Persisted as `{id}.json` under the `marketplace_models` storage directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplaceModel {
    /// UUID for this record
    pub id: String,

    /// Marketplace model id (e.g. "openai-gpt-4o")
    pub model_id: String,

    /// Human-readable name (e.g. "GPT-4o")
    pub name: String,

    /// Provider display name (e.g. "OpenAI")
    pub provider: String,

    /// Logo URL
    #[serde(default)]
    pub logo: String,

    /// Category (e.g. "General Purpose")
    #[serde(default)]
    pub category: String,

    /// Short description
    #[serde(default)]
    pub description: String,

    /// Pricing label (e.g. "$2.50 / 1M input · $10 / 1M output")
    #[serde(default)]
    pub pricing: String,

    /// Context window label (e.g. "128k tokens")
    #[serde(default)]
    pub context_window: String,

    /// Capability tags (e.g. ["chat", "vision", "function_calling"])
    #[serde(default)]
    pub capabilities: Vec<String>,

    /// Name of the gateway that serves this model (for multi-gateway marketplace)
    #[serde(default)]
    pub gateway_name: String,

    /// Connection metadata for the LLM provider
    pub metadata: MarketplaceModelMetadata,

    /// Purchase information
    pub purchase: PurchaseInfo,
}

/// Connection / provider metadata from the marketplace catalogue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplaceModelMetadata {
    pub api_schema: String,
    pub provider: String,
    pub model: String,
    pub default_base_url: String,
    #[serde(default)]
    pub api_version_prefix: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub cost_per_1k_input: f64,
    #[serde(default)]
    pub cost_per_1k_output: f64,
    #[serde(default)]
    pub api_key_required: bool,
    #[serde(default)]
    pub api_key_label: String,
    #[serde(default)]
    pub purchase_price: u64,
}

/// Information about the purchase / API key provisioning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurchaseInfo {
    /// ISO-8601 timestamp of when the key was purchased
    pub purchased_at: String,

    /// ISO-8601 timestamp of when the key expires
    pub expires_at: String,

    /// The secret_id in the gateway secrets store where the API key is saved
    pub api_key_secret_id: String,
}

#[allow(dead_code)]
impl MarketplaceModel {
    pub fn new(
        model_id: String,
        name: String,
        provider: String,
        metadata: MarketplaceModelMetadata,
        purchase: PurchaseInfo,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            model_id,
            name,
            provider,
            logo: String::new(),
            category: String::new(),
            description: String::new(),
            pricing: String::new(),
            context_window: String::new(),
            capabilities: Vec::new(),
            gateway_name: String::new(),
            metadata,
            purchase,
        }
    }

    /// Returns true if the key has expired
    pub fn is_expired(&self) -> bool {
        if let Ok(expires) = chrono::DateTime::parse_from_rfc3339(&self.purchase.expires_at) {
            expires < chrono::Utc::now()
        } else {
            false
        }
    }
}

impl StorableEntity for MarketplaceModel {
    fn id(&self) -> &str {
        &self.id
    }
}
