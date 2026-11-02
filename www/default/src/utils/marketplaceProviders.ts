import { apiClient } from '../api';

/** Shape of a purchased model record from the gateway storage API */
export interface PurchasedMarketplaceModel {
  id: string;
  model_id: string;
  name: string;
  provider: string;
  logo: string;
  category: string;
  description: string;
  pricing: string;
  context_window: string;
  capabilities: string[];
  gateway_name?: string;
  metadata: {
    api_schema: string;
    provider: string;
    model: string;
    default_base_url: string;
    api_version_prefix: string;
    endpoint: string;
    cost_per_1k_input: number;
    cost_per_1k_output: number;
    api_key_required: boolean;
    api_key_label: string;
    purchase_price?: number;
  };
  purchase: {
    purchased_at: string;
    expires_at: string;
    api_key_secret_id: string;
  };
}

/** Extra metadata attached to marketplace-sourced LLM providers */
export interface MarketplaceProviderMeta {
  purchased_id: string;
  model_id: string;
  real_provider_type: string;
  base_url: string;
  api_schema: string;
  api_version_prefix: string;
  endpoint: string;
  api_key_secret_id: string;
  expires_at: string;
}

/**
 * Convert a purchased marketplace model into an LLMProvider-shaped object
 * that can be merged into provider dropdowns.
 *
 * The returned object has a `_marketplace` field carrying the real connection
 * details, and an `enum_value` prefixed with `mp_` so the save handler can
 * detect marketplace-sourced providers.
 */
export function purchasedToProvider(pm: PurchasedMarketplaceModel): any {
  const isExpired = pm.purchase.expires_at ? new Date(pm.purchase.expires_at) < new Date() : false;

  return {
    name: pm.gateway_name ? `${pm.gateway_name}: ${pm.name}` : pm.name,
    enum_value: `mp_${pm.id}`,
    enabled: !isExpired,
    default_base_url: pm.metadata.default_base_url,
    api_version_prefix: pm.metadata.api_version_prefix,
    api_schema: pm.metadata.api_schema,
    endpoints: [
      {
        name: 'Chat Completions',
        path: pm.metadata.endpoint,
        description: `${pm.name} via marketplace`,
        is_default: true,
        capabilities: ['chat_completions'],
      },
    ],
    icon: 'fa-store',
    api_key_label: pm.metadata.api_key_label || 'API Key',
    models: [
      {
        name: pm.metadata.model,
        value: pm.metadata.model,
        cost_per_1k_input: pm.metadata.cost_per_1k_input || 0,
        cost_per_1k_output: pm.metadata.cost_per_1k_output || 0,
      },
    ],
    _marketplace: {
      purchased_id: pm.id,
      model_id: pm.model_id,
      real_provider_type: pm.metadata.provider,
      base_url: pm.metadata.default_base_url,
      api_schema: pm.metadata.api_schema,
      api_version_prefix: pm.metadata.api_version_prefix,
      endpoint: pm.metadata.endpoint,
      api_key_secret_id: pm.purchase.api_key_secret_id,
      expires_at: pm.purchase.expires_at,
    } as MarketplaceProviderMeta,
  };
}

/**
 * Fetch purchased marketplace models and convert them to LLMProvider objects.
 * Returns only non-expired models.
 */
export async function fetchMarketplaceProviders(): Promise<any[]> {
  try {
    const res = await apiClient.get<PurchasedMarketplaceModel[]>('/marketplace/purchased');
    const purchased = res.data || [];
    return purchased.map(purchasedToProvider);
  } catch {
    return [];
  }
}
