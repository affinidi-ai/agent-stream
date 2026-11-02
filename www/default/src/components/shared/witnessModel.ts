/**
 * Expert-witness domain model — mirrors the backend `ExpertWitnessConfig`
 * (`src/pipes/prompt_guard/config.rs`), whose `guardrail: ExternalGuardrailConfig`
 * is `#[serde(flatten)]`ed, so the wire shape is a single flat object. An
 * expert witness is an external, purpose-trained safety classifier consulted
 * in addition to the local regex/PII guards — a first-class role sibling to the
 * Judge and Jury.
 *
 * The canvas exposes witnesses as two seam nodes — `pipe-witness-request` and
 * `pipe-witness-response` — each owning a list of witnesses for its seam. A
 * request-seam witness serializes `check_request=true / check_response=false`;
 * a response-seam witness the inverse. The same provider on both seams is two
 * separate entries (one per circle).
 */

export type WitnessProvider =
  | 'enkryptai'
  | 'enkryptai_guardrail'
  | 'enkryptai_ai_proxy'
  | 'enkryptai_policy_detect'
  | 'generic'
  | 'lakera'
  | 'azure_prompt_shields'
  | 'azure_content_safety';

export type WitnessSeam = 'request' | 'response';

/** Flat wire shape of one expert witness (matches the flattened backend type). */
export interface WitnessConfig {
  id: string;
  name: string;
  enabled: boolean;
  provider: WitnessProvider;
  endpoint_url: string;
  api_key_secret?: string | null;
  timeout_secs: number;
  fail_open: boolean;
  check_request: boolean;
  check_response: boolean;
  /**
   * Arbitrary static headers sent on every provider call (e.g. EnkryptAI's
   * `X-Enkrypt-Deployment`, or any header a `generic` endpoint requires).
   * `{key}` in a value is substituted with the resolved API key.
   */
  headers?: Record<string, string>;
  /**
   * Optional `model` injected into the request body. Required by the EnkryptAI
   * AI Proxy (the deployment selects the policy; the body still carries the
   * model saved-name); unused by providers that take no model.
   */
  model?: string | null;
}

/** Provider options shown in the witness editor select. */
export const WITNESS_PROVIDERS: ReadonlyArray<{ value: WitnessProvider; label: string }> = [
  { value: 'enkryptai', label: 'EnkryptAI (Detect API)' },
  { value: 'enkryptai_guardrail', label: 'EnkryptAI (Guardrail)' },
  { value: 'enkryptai_ai_proxy', label: 'EnkryptAI (AI Proxy)' },
  { value: 'enkryptai_policy_detect', label: 'EnkryptAI (Policy — Legacy)' },
  { value: 'lakera', label: 'Lakera Guard' },
  { value: 'azure_prompt_shields', label: 'Azure Prompt Shields (request)' },
  { value: 'azure_content_safety', label: 'Azure Content Safety (response)' },
  { value: 'generic', label: 'Generic (OpenAI-moderation shape)' },
];

/** Endpoint hint shown per provider preset to guide the operator. */
export const WITNESS_ENDPOINT_PLACEHOLDERS: Record<WitnessProvider, string> = {
  enkryptai: 'https://api.enkryptai.com/guardrails/detect',
  enkryptai_guardrail: 'https://api.enkryptai.com/guardrails/guardrail/detect',
  enkryptai_policy_detect: 'https://api.enkryptai.com/guardrails/policy/detect',
  enkryptai_ai_proxy: 'https://api.enkryptai.com/ai-proxy/chat/completions',
  generic: 'https://your-provider.example/moderate',
  lakera: 'https://api.lakera.ai/v2/guard',
  azure_prompt_shields:
    'https://<resource>.cognitiveservices.azure.com/contentsafety/text:shieldPrompt?api-version=2024-09-01',
  azure_content_safety:
    'https://<resource>.cognitiveservices.azure.com/contentsafety/text:analyze?api-version=2024-09-01',
};

/**
 * Concrete, ready-to-use endpoint URL per provider, where one exists. Used to
 * auto-fill the Endpoint URL when a provider is picked so the operator doesn't
 * have to type a fixed cloud URL by hand. Providers whose endpoint is
 * resource/region-specific (Azure) or fully bespoke (generic) have no default
 * and keep the placeholder template.
 */
export const WITNESS_DEFAULT_ENDPOINT: Partial<Record<WitnessProvider, string>> = {
  enkryptai: 'https://api.enkryptai.com/guardrails/detect',
  enkryptai_guardrail: 'https://api.enkryptai.com/guardrails/guardrail/detect',
  enkryptai_policy_detect: 'https://api.enkryptai.com/guardrails/policy/detect',
  enkryptai_ai_proxy: 'https://api.enkryptai.com/ai-proxy/chat/completions',
  lakera: 'https://api.lakera.ai/v2/guard',
};

const DEFAULT_ENDPOINT_VALUES: ReadonlySet<string> = new Set(
  Object.values(WITNESS_DEFAULT_ENDPOINT)
);

/**
 * Pick the endpoint to show when switching to `next`. Auto-fills the provider's
 * known default when the field is empty or still holds another provider's
 * auto-filled default; preserves an endpoint the operator typed themselves.
 */
export function endpointForProviderChange(current: string, next: WitnessProvider): string {
  const trimmed = current.trim();
  const isUntouched = trimmed === '' || DEFAULT_ENDPOINT_VALUES.has(trimmed);
  if (isUntouched && WITNESS_DEFAULT_ENDPOINT[next]) return WITNESS_DEFAULT_ENDPOINT[next]!;
  return current;
}

/** The HTTP header the gateway sends the API key in, per provider. */
export const WITNESS_AUTH_HEADER: Record<WitnessProvider, string> = {
  enkryptai: 'apikey',
  enkryptai_guardrail: 'apikey',
  enkryptai_policy_detect: 'apikey',
  enkryptai_ai_proxy: 'apikey',
  lakera: 'Authorization: Bearer …',
  azure_prompt_shields: 'Ocp-Apim-Subscription-Key',
  azure_content_safety: 'Ocp-Apim-Subscription-Key',
  generic: 'Authorization: Bearer …',
};

/** One-line guidance shown beneath the provider select. */
export const WITNESS_PROVIDER_HELP: Record<WitnessProvider, string> = {
  enkryptai:
    'Runs EnkryptAI detectors directly on the text and returns a verdict. Choose this for pure screening — no model call, no deployment needed.',
  enkryptai_guardrail:
    'Runs a named guardrail you saved in the EnkryptAI dashboard, screening the text directly. Pure screening — no model call. Set the Guardrail name below; it is sent as the X-Enkrypt-Guardrail header. The required X-Enkrypt-Mode header (prompt/response) is set automatically from the seam. This is EnkryptAI’s current named-config endpoint — prefer it over Policy (Legacy).',
  enkryptai_policy_detect:
    'Legacy: EnkryptAI has deprecated saved “policies” in favour of guardrails — use EnkryptAI (Guardrail) instead. Runs a named policy you saved in the EnkryptAI dashboard, screening the text directly. Set the Policy name below; it is sent as the X-Enkrypt-Policy header and binds the detectors.',
  enkryptai_ai_proxy:
    'Use this when you configured a named deployment in the EnkryptAI dashboard. The deployment selects both the guardrail policy and the underlying model. It runs its own model completion (extra latency + a model charge the witness discards).',
  lakera: 'Lakera Guard screens the text and returns a flagged verdict.',
  azure_prompt_shields:
    'Azure Content Safety Prompt Shields — request-side jailbreak/prompt-injection detection.',
  azure_content_safety:
    'Azure Content Safety harm categories — response-side moderation by severity.',
  generic: 'Any OpenAI-moderation-shaped endpoint. Set auth/routing via Custom headers below.',
};

/** Vertical rise (px) of a witness circle above the spine edge it points to. */
export const WITNESS_RISE = 104;

const PROVIDER_SET: ReadonlySet<string> = new Set(WITNESS_PROVIDERS.map(p => p.value));

/** Coerce an unknown blob into a `{ string: string }` header map. */
function normalizeHeaders(raw: unknown): Record<string, string> {
  if (!raw || typeof raw !== 'object') return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (typeof k === 'string' && k.trim() && typeof v === 'string') out[k] = v;
  }
  return out;
}

/** A fresh witness seeded for the given seam, with seam-correct check flags. */
export function makeDefaultWitness(seam: WitnessSeam, index: number): WitnessConfig {
  return {
    id: `witness-${seam}-${index + 1}`,
    name: `Witness ${index + 1}`,
    enabled: true,
    provider: 'enkryptai',
    endpoint_url: WITNESS_DEFAULT_ENDPOINT.enkryptai ?? '',
    api_key_secret: null,
    timeout_secs: 10,
    fail_open: false,
    check_request: seam === 'request',
    check_response: seam === 'response',
    headers: {},
  };
}

/** Coerce an unknown blob into a well-formed witness, or `null` if unusable. */
export function normalizeWitness(raw: unknown, seam: WitnessSeam, index: number): WitnessConfig {
  const o = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {};
  const provider =
    typeof o.provider === 'string' && PROVIDER_SET.has(o.provider)
      ? (o.provider as WitnessProvider)
      : 'enkryptai';
  return {
    id: typeof o.id === 'string' && o.id ? o.id : `witness-${seam}-${index + 1}`,
    name: typeof o.name === 'string' && o.name ? o.name : `Witness ${index + 1}`,
    enabled: o.enabled !== false,
    provider,
    endpoint_url: typeof o.endpoint_url === 'string' ? o.endpoint_url : '',
    api_key_secret: typeof o.api_key_secret === 'string' ? o.api_key_secret : null,
    timeout_secs: typeof o.timeout_secs === 'number' && o.timeout_secs > 0 ? o.timeout_secs : 10,
    fail_open: o.fail_open === true,
    check_request: seam === 'request',
    check_response: seam === 'response',
    headers: normalizeHeaders(o.headers),
    model: typeof o.model === 'string' && o.model ? o.model : null,
  };
}

/**
 * Partition a backend `expert_witnesses` list into the two canvas seam nodes.
 * A witness goes to the request circle when `check_request` is set, else to the
 * response circle when `check_response` is set; an ambiguous entry defaults to
 * the request seam. Each returned witness has seam-correct, mutually-exclusive
 * check flags so the single-seam-per-node model round-trips cleanly.
 */
export function partitionWitnesses(list: unknown): {
  request: WitnessConfig[];
  response: WitnessConfig[];
} {
  const arr = Array.isArray(list) ? list : [];
  const request: WitnessConfig[] = [];
  const response: WitnessConfig[] = [];
  for (const raw of arr) {
    const o = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {};
    const onResponse = o.check_response === true && o.check_request !== true;
    const seam: WitnessSeam = onResponse ? 'response' : 'request';
    const bucket = onResponse ? response : request;
    bucket.push(normalizeWitness(raw, seam, bucket.length));
  }
  return { request, response };
}

/** Re-stamp a witness list with seam-correct check flags before serialization. */
export function stampSeam(witnesses: WitnessConfig[], seam: WitnessSeam): WitnessConfig[] {
  return witnesses.map(w => ({
    ...w,
    check_request: seam === 'request',
    check_response: seam === 'response',
  }));
}
