export type EndpointParamType = 'string' | 'number' | 'boolean' | 'select' | 'object' | 'array';
export type ModelParamType = 'number' | 'select';

export interface ProviderHero {
  logo_path: string;
  width: number;
  height: number;
}

export interface EndpointParameter {
  name: string;
  label: string;
  type: EndpointParamType;
  default: string;
  options: string[];
  description: string;
  applies_to_models: string[];
}

export interface LlmEndpoint {
  name: string;
  path: string;
  description: string;
  is_default: boolean;
  capabilities: string[];
  endpoint_parameters: EndpointParameter[];
  moderation_models: string[];
  moderation_categories: string[];
}

export interface ModelParameter {
  name: string;
  label: string;
  type: ModelParamType;
  default: string;
  min?: number;
  max?: number;
  step?: number;
  options: string[];
  description: string;
}

export interface RateLimitRange {
  min: number;
  max: number;
  default: number;
}

export interface RateLimiting {
  can_disable: boolean;
  can_change: boolean;
  requests_per_minute: RateLimitRange;
  tokens_per_minute: RateLimitRange;
}

export interface CapabilityFlag {
  key: string;
  value: boolean;
}

export interface LlmModel {
  name: string;
  value: string;
  enabled: boolean;
  cost_per_1k_input: number;
  cost_per_1k_output: number;
  model_parameters: ModelParameter[];
  rate_limiting: RateLimiting | null;
  capabilities: CapabilityFlag[];
}

export interface LlmProviderForm {
  name: string;
  enum_value: string;
  default_base_url: string;
  api_version_prefix: string;
  enabled: boolean;
  api_key_label: string;
  filter_tag: string;
  api_key_required: boolean;
  /** Three-state key policy (`mandatory` | `optional` | `none`). */
  api_key_validation: 'mandatory' | 'optional' | 'none';
  api_schema: string;
  icon: string;
  description: string;
  hero: ProviderHero;
  provider_capabilities: string[];
  endpoints: LlmEndpoint[];
  models: LlmModel[];
}

export interface LlmProviderSummary {
  name: string;
  enum_value: string;
  api_schema: string;
  enabled: boolean;
  icon?: string;
  description?: string;
  default_base_url?: string;
  endpoints?: unknown[];
  models?: unknown[];
  provider_capabilities?: string[];
}
