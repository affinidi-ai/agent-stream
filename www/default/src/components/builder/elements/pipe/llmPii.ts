// Shared types + presets for the Prompt Guard model-backed PII detectors.
// Mirrors the backend `LlmPiiConfig` (src/pipes/prompt_guard/config.rs). Kept in
// its own module so the panel and the per-detector card share one definition.

export interface RejectionConfig {
  status_code: number;
  body: string;
  content_type: string;
}

export const DEFAULT_REJECTION: RejectionConfig = {
  status_code: 403,
  body: '{"error":{"message":"Request rejected: content violates prompt guard policy","type":"prompt_guard_violation","code":"content_policy_violation"}}',
  content_type: 'application/json',
};

/** Model-backed PII detector config (mirrors backend `LlmPiiConfig`). */
export interface LlmPiiConfig {
  enabled?: boolean;
  /** Provider enum (e.g. "openai", "ollama") used to resolve the endpoint. */
  provider_type?: string;
  endpoint_url?: string;
  model?: string;
  api_key_secret?: string | null;
  entity_types?: string[];
  action?: 'mask' | 'reject';
  mask_mode?: 'redact' | 'pseudonymize';
  rejection?: RejectionConfig | null;
  restore_in_response?: boolean;
  link_coreferences?: boolean;
  cache_detection?: boolean;
  timeout_secs?: number;
  fail_closed?: boolean;
}

export const DEFAULT_LLM_PII: LlmPiiConfig = {
  enabled: true,
  provider_type: '',
  endpoint_url: '',
  model: '',
  entity_types: ['PERSON', 'ORGANIZATION', 'LOCATION', 'ADDRESS', 'EMAIL_ADDRESS', 'PHONE_NUMBER'],
  action: 'mask',
  mask_mode: 'pseudonymize',
  fail_closed: true,
};

/**
 * Preset entity types offered as pills. Free-form: the operator can add their
 * own (stored per-detector in the surface config), so the model is told exactly
 * which entities to return for this surface.
 */
export const ENTITY_TYPE_PRESETS: string[] = [
  'PERSON',
  'ORGANIZATION',
  'LOCATION',
  'ADDRESS',
  'EMAIL_ADDRESS',
  'PHONE_NUMBER',
  'DATE_OF_BIRTH',
  'NATIONALITY',
  'CREDIT_CARD',
  'IBAN',
  'SSN',
  'PASSPORT',
  'DRIVER_LICENSE',
  'IP_ADDRESS',
  'MEDICAL_LICENSE',
];

/** Normalise the prompt-guard config's `llm_pii` (list, single object, or absent) to a list. */
export function toLlmPiiList(value: unknown): LlmPiiConfig[] {
  if (Array.isArray(value)) return value as LlmPiiConfig[];
  if (value && typeof value === 'object') return [value as LlmPiiConfig];
  return [];
}
