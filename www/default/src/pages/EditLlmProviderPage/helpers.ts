import type {
  CapabilityFlag,
  EndpointParameter,
  LlmEndpoint,
  LlmModel,
  LlmProviderForm,
  ModelParameter,
  ProviderHero,
  RateLimiting,
} from './types';

// Hero logos are rendered at a fixed square size; the dimensions are not
// user-editable. Uploaded images should be 512x512.
export const HERO_SIZE = 512;

const num = (value: unknown, fallback = 0): number => {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
};

const optNum = (value: unknown): number | undefined => {
  if (value === null || value === undefined || value === '') return undefined;
  const n = Number(value);
  return Number.isFinite(n) ? n : undefined;
};

const strList = (value: unknown): string[] =>
  Array.isArray(value) ? value.map(v => String(v)) : [];

const emptyHero = (): ProviderHero => ({ logo_path: '', width: HERO_SIZE, height: HERO_SIZE });

export const emptyProvider = (): LlmProviderForm => ({
  name: '',
  enum_value: '',
  default_base_url: '',
  api_version_prefix: '',
  enabled: true,
  api_key_label: '',
  filter_tag: '',
  api_key_required: true,
  api_key_validation: 'mandatory',
  api_schema: 'openai',
  icon: '',
  description: '',
  hero: emptyHero(),
  provider_capabilities: [],
  endpoints: [],
  models: [],
});

const normalizeEndpointParameter = (raw: Record<string, unknown>): EndpointParameter => ({
  name: String(raw.name ?? ''),
  label: String(raw.label ?? ''),
  type: (raw.type as EndpointParameter['type']) ?? 'string',
  default: raw.default === undefined || raw.default === null ? '' : String(raw.default),
  options: strList(raw.options),
  description: String(raw.description ?? ''),
  applies_to_models: strList(raw.applies_to_models),
});

const normalizeEndpoint = (raw: Record<string, unknown>): LlmEndpoint => ({
  name: String(raw.name ?? ''),
  path: String(raw.path ?? ''),
  description: String(raw.description ?? ''),
  is_default: raw.is_default === true,
  capabilities: strList(raw.capabilities),
  endpoint_parameters: Array.isArray(raw.endpoint_parameters)
    ? raw.endpoint_parameters.map(p => normalizeEndpointParameter(p as Record<string, unknown>))
    : [],
  moderation_models: strList(raw.moderation_models),
  moderation_categories: strList(raw.moderation_categories),
});

const normalizeModelParameter = (raw: Record<string, unknown>): ModelParameter => ({
  name: String(raw.name ?? ''),
  label: String(raw.label ?? ''),
  type: (raw.type as ModelParameter['type']) ?? 'number',
  default: raw.default === undefined || raw.default === null ? '' : String(raw.default),
  min: optNum(raw.min),
  max: optNum(raw.max),
  step: optNum(raw.step),
  options: strList(raw.options),
  description: String(raw.description ?? ''),
});

const normalizeRange = (raw: unknown) => {
  const r = (raw ?? {}) as Record<string, unknown>;
  return { min: num(r.min), max: num(r.max), default: num(r.default) };
};

const normalizeRateLimiting = (raw: Record<string, unknown>): RateLimiting => ({
  can_disable: raw.can_disable === true,
  can_change: raw.can_change !== false,
  requests_per_minute: normalizeRange(raw.requests_per_minute),
  tokens_per_minute: normalizeRange(raw.tokens_per_minute),
});

const normalizeCapabilities = (raw: unknown): CapabilityFlag[] => {
  if (!raw || typeof raw !== 'object') return [];
  return Object.entries(raw as Record<string, unknown>).map(([key, value]) => ({
    key,
    value: value === true,
  }));
};

const normalizeModel = (raw: Record<string, unknown>): LlmModel => ({
  name: String(raw.name ?? ''),
  value: String(raw.value ?? ''),
  enabled: raw.enabled !== false,
  cost_per_1k_input: num(raw.cost_per_1k_input),
  cost_per_1k_output: num(raw.cost_per_1k_output),
  model_parameters: Array.isArray(raw.model_parameters)
    ? raw.model_parameters.map(p => normalizeModelParameter(p as Record<string, unknown>))
    : [],
  rate_limiting: raw.rate_limiting
    ? normalizeRateLimiting(raw.rate_limiting as Record<string, unknown>)
    : null,
  capabilities: normalizeCapabilities(raw.capabilities),
});

export const normalizeProvider = (raw: Record<string, unknown>): LlmProviderForm => {
  const hero = (raw.hero ?? {}) as Record<string, unknown>;
  return {
    name: String(raw.name ?? ''),
    enum_value: String(raw.enum_value ?? ''),
    default_base_url: String(raw.default_base_url ?? ''),
    api_version_prefix: String(raw.api_version_prefix ?? ''),
    enabled: raw.enabled !== false,
    api_key_label: String(raw.api_key_label ?? ''),
    filter_tag: String(raw.filter_tag ?? ''),
    api_key_required: raw.api_key_required !== false,
    api_key_validation:
      raw.api_key_validation === 'mandatory' ||
      raw.api_key_validation === 'optional' ||
      raw.api_key_validation === 'none'
        ? raw.api_key_validation
        : raw.api_key_required === false
          ? 'none'
          : 'mandatory',
    api_schema: String(raw.api_schema ?? 'openai'),
    icon: String(raw.icon ?? ''),
    description: String(raw.description ?? ''),
    hero: {
      logo_path: String(hero.logo_path ?? ''),
      width: HERO_SIZE,
      height: HERO_SIZE,
    },
    provider_capabilities: strList(raw.provider_capabilities),
    endpoints: Array.isArray(raw.endpoints)
      ? raw.endpoints.map(e => normalizeEndpoint(e as Record<string, unknown>))
      : [],
    models: Array.isArray(raw.models)
      ? raw.models.map(m => normalizeModel(m as Record<string, unknown>))
      : [],
  };
};
