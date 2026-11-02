import type { integrationIntegration } from '../../components/connection-points/IntegrationsStep';
import { buildCanvasBlob, type CanvasBlob } from '../../components/builder/elements';
import {
  flattenSourceAuth,
  readSourceAuthFromNode,
} from '../../components/builder/elements/caller-auth/sourceAuthMapping';
import type { PipeConfigLike } from '../../components/builder/elements/pipe';
import type { PipeUsageLimitEntry } from '../../components/builder/PipeBuilderPanel';
import type { CanvasNode } from '../../components/builder/SurfaceCanvas';
import { llmToolSlotPosition } from '../../components/builder/elements/pipe/definitions';
import { readDecider, readExpertWitnesses, readJury } from './pipeBuilderHelpers';
import type {
  CallerIdentitySourceForm,
  ContextManagementForm,
  DocumentIngestionForm,
  DriftForm,
  LLMProvider,
  PipeConfig,
  PipeFormData,
  ProviderUrlForm,
  ServerToolsWire,
  TeamAttributionForm,
  UpstreamHeaderForm,
  UsageLimitWire,
} from './types';
import type { SourceAuthConfig } from '../../types';
import { EMPTY_PIPE_FORM } from './types';

/**
 * Derive the Decider config from a persisted/live canvas blob. The canvas is
 * the source of truth for "decider mode" (its on/off state IS whether a
 * `pipe-decider` node exists), so the structured `decider` field must be
 * reassembled from the decider + candidate nodes. Returns `null` when the blob
 * carries no `pipe-decider` node. Used on load to heal a config whose canvas
 * has a decider but whose structured `decider` was dropped, and on save to
 * keep the structured `decider` in lock-step with the serialized canvas.
 */
export function deciderFromCanvas(canvas: unknown): Record<string, unknown> | null {
  const blob =
    canvas && typeof canvas === 'object' && Array.isArray((canvas as CanvasBlob).nodes)
      ? (canvas as CanvasBlob)
      : null;
  if (!blob) return null;
  if (!blob.nodes.some(n => n?.type === 'pipe-decider')) return null;
  const result = readDecider(blob.nodes as unknown as CanvasNode[]);
  return result.present ? (result.decider as Record<string, unknown>) : null;
}

/**
 * Derive the Jury config from a persisted/live canvas blob. Like the Decider,
 * the canvas is the source of truth: jury-level settings live on the `pipe-jury`
 * node and each juror (with its required `llm`) is a first-class `pipe-juror`
 * sibling, so the structured `jury` — including every juror's `llm` — is
 * reassembled from them (`readJury`). Returns `null` when the blob carries no
 * `pipe-jury` node, so callers fall back to the form value. Using this on save
 * keeps the payload's jurors in lock-step with the canvas and stops a drifted
 * `formData.jury` from sending a juror stripped of its `llm` (a 400 on save).
 */
export function juryFromCanvas(canvas: unknown): Record<string, unknown> | null {
  const blob =
    canvas && typeof canvas === 'object' && Array.isArray((canvas as CanvasBlob).nodes)
      ? (canvas as CanvasBlob)
      : null;
  if (!blob) return null;
  if (!blob.nodes.some(n => n?.type === 'pipe-jury')) return null;
  const result = readJury(blob.nodes as unknown as CanvasNode[]);
  return result.present ? (result.jury as Record<string, unknown>) : null;
}

/**
 * Derive the flat `expert_witnesses` list from a persisted/live canvas blob.
 * The two witness seam nodes (`pipe-witness-request`/`pipe-witness-response`)
 * are the source of truth for the roster, so the structured list must be
 * reassembled from them. Returns `null` when the blob carries neither witness
 * node or every roster is empty — letting callers fall back to the form value.
 * Used on load to heal a config whose canvas carries witnesses but whose
 * structured `expert_witnesses` was dropped, and on save to keep the two in
 * lock-step with the serialized canvas.
 */
export function expertWitnessesFromCanvas(canvas: unknown): unknown[] | null {
  const blob =
    canvas && typeof canvas === 'object' && Array.isArray((canvas as CanvasBlob).nodes)
      ? (canvas as CanvasBlob)
      : null;
  if (!blob) return null;
  const hasWitnessNode = blob.nodes.some(
    n => n?.type === 'pipe-witness-request' || n?.type === 'pipe-witness-response'
  );
  if (!hasWitnessNode) return null;
  const result = readExpertWitnesses(blob.nodes as unknown as CanvasNode[]);
  return result.present ? result.witnesses : null;
}

/**
 * Derive the wire `source_auth` from a persisted/live canvas blob. The
 * `pipe-caller-auth` node is the sole source of truth for caller-context on
 * the LLM Surface (mirroring `ide-caller-auth` on the IDE Surface), so the
 * structured `source_auth` field is reassembled from it on save. Returns
 * `null` when no `pipe-caller-auth` node is present OR when its config is
 * incomplete (e.g. JWT bearer with no strategy selected) — the surface then
 * saves without `source_auth` so the element stays incomplete and the
 * surface stays open until it is configured. `surfaceId` is required by
 * `api_key_provider` (which addresses the API-key provider by the surface's
 * own id) and unused by every other method.
 */
export function sourceAuthFromCanvas(canvas: unknown, surfaceId?: string): SourceAuthConfig | null {
  const blob =
    canvas && typeof canvas === 'object' && Array.isArray((canvas as CanvasBlob).nodes)
      ? (canvas as CanvasBlob)
      : null;
  if (!blob) return null;
  const node = blob.nodes.find(n => n?.type === 'pipe-caller-auth') as CanvasNode | undefined;
  return readSourceAuthFromNode(node, surfaceId);
}

/**
 * Derive the wire `server_tools` from a persisted/live canvas blob. The two
 * Tools-palette nodes (`pipe-web-search`, `pipe-web-fetch`) are the source of
 * truth for governed server tools, so the structured `server_tools` field is
 * reassembled from them on save. Returns `null` when neither node is present
 * (or both are disabled) so callers fall back to the form value. The
 * frontend's `engine_secret_id` is mapped to the backend's `engine_secret`,
 * and comma-edited domain arrays are passed through verbatim.
 */
export function serverToolsFromCanvas(canvas: unknown): Record<string, unknown> | null {
  const blob =
    canvas && typeof canvas === 'object' && Array.isArray((canvas as CanvasBlob).nodes)
      ? (canvas as CanvasBlob)
      : null;
  if (!blob) return null;
  const searchNode = blob.nodes.find(n => n?.type === 'pipe-web-search');
  const fetchNode = blob.nodes.find(n => n?.type === 'pipe-web-fetch');
  if (!searchNode && !fetchNode) return null;

  const str = (v: unknown): string => (typeof v === 'string' ? v.trim() : '');
  const num = (v: unknown, fallback: number): number =>
    typeof v === 'number' && Number.isFinite(v) ? v : fallback;
  const domains = (v: unknown): string[] =>
    Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x.trim() !== '') : [];
  const policy = (v: unknown): 'allow_all' | 'block_all' =>
    v === 'block_all' ? 'block_all' : 'allow_all';

  const searchOn = !!searchNode && searchNode.config?.enabled !== false;
  const fetchOn = !!fetchNode && fetchNode.config?.enabled !== false;

  const web_search = searchOn
    ? {
        enabled: true,
        engine: str(searchNode!.config?.engine) || 'tavily',
        engine_secret: str(searchNode!.config?.engine_secret_id) || undefined,
        max_results: num(searchNode!.config?.max_results, 5),
        google_cse_id: str(searchNode!.config?.google_cse_id) || undefined,
        domain_policy: policy(searchNode!.config?.domain_policy),
        domain_exceptions: domains(searchNode!.config?.domain_exceptions),
      }
    : undefined;

  const web_fetch = fetchOn
    ? {
        enabled: true,
        max_content_bytes: num(fetchNode!.config?.max_content_bytes, 60000),
        domain_policy: policy(fetchNode!.config?.domain_policy),
        domain_exceptions: domains(fetchNode!.config?.domain_exceptions),
      }
    : undefined;

  if (!web_search && !web_fetch) return null;

  const max_iterations = num(
    searchNode?.config?.max_iterations ?? fetchNode?.config?.max_iterations,
    3
  );
  return { enabled: true, max_iterations, web_search, web_fetch };
}

/** The config of a pipe node on a canvas blob, by node type, or null. */
function pipeNodeConfig(canvas: unknown, type: string): Record<string, unknown> | null {
  const blob =
    canvas && typeof canvas === 'object' && Array.isArray((canvas as CanvasBlob).nodes)
      ? (canvas as CanvasBlob)
      : null;
  const node = blob?.nodes.find(n => n?.type === type);
  return node && node.config && typeof node.config === 'object'
    ? (node.config as Record<string, unknown>)
    : null;
}

const strList = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x.trim() !== '') : [];
const posNum = (v: unknown, fallback: number): number =>
  typeof v === 'number' && Number.isFinite(v) && v > 0 ? v : fallback;

/**
 * Derive the wire `audio_input` from the `pipe-audio-input` "Audio File" Inputs
 * node (the source of truth for inline `input_audio` files). `null` when the
 * node is absent or disabled, so the surface rejects audio files (strict
 * opt-in). Realtime voice (Mode C) lives on the separate Audio Stream element.
 */
export function audioInputFromCanvas(canvas: unknown): Record<string, unknown> | null {
  const c = pipeNodeConfig(canvas, 'pipe-audio-input');
  if (!c || c.enabled === false) return null;
  return {
    enabled: true,
    allowed_formats: strList(c.allowed_formats),
    max_bytes: posNum(c.max_bytes, 25 * 1024 * 1024),
  };
}

/** Derive the wire `image_input` from the `pipe-image-input` node, or null. */
export function imageInputFromCanvas(canvas: unknown): Record<string, unknown> | null {
  const c = pipeNodeConfig(canvas, 'pipe-image-input');
  if (!c || c.enabled === false) return null;
  return {
    enabled: true,
    allowed_formats: strList(c.allowed_formats),
    max_bytes: posNum(c.max_bytes, 20 * 1024 * 1024),
  };
}

/**
 * Derive the wire `realtime` (Mode C) block from the `pipe-audio-stream` Inputs
 * node (the source of truth). Realtime voice is the streaming form of audio, so
 * it has its own **Audio Stream** element (distinct from the file-based **Audio
 * File** element). `null` when the node is absent or disabled (strict opt-in),
 * so the surface refuses a `/v1/realtime` upgrade.
 */
export function realtimeFromCanvas(canvas: unknown): Record<string, unknown> | null {
  const rt = pipeNodeConfig(canvas, 'pipe-audio-stream') as {
    enabled?: boolean;
    max_session_secs?: number;
    voice?: string;
    safety?: {
      enabled?: boolean;
      mode?: string;
      refusal_message?: string;
    };
    audio_streams?: {
      filler_guard_band_ms?: number;
      filler_tiers?: Array<{ after_ms?: number; clips?: unknown }>;
      refusal_buckets?: Array<{ category?: string; clips?: unknown }>;
      on_fail?: unknown;
    };
  } | null;
  if (!rt || rt.enabled !== true) return null;
  const out: Record<string, unknown> = {
    enabled: true,
    max_session_secs: posNum(rt.max_session_secs, 600),
  };
  if (typeof rt.voice === 'string' && rt.voice.trim() !== '') out.voice = rt.voice.trim();
  const s = rt.safety;
  if (s && s.enabled === true) {
    const safety: Record<string, unknown> = {
      enabled: true,
      mode: s.mode === 'barge_in' ? 'barge_in' : 'gated',
    };
    if (typeof s.refusal_message === 'string' && s.refusal_message.trim() !== '')
      safety.refusal_message = s.refusal_message.trim();
    out.safety = safety;
  }
  const streams = rt.audio_streams;
  if (streams) {
    const fillerGuardBandMs = posNum(streams.filler_guard_band_ms, 2000);
    const fillerTiers = Array.isArray(streams.filler_tiers)
      ? streams.filler_tiers
          .map(t => ({ after_ms: posNum(t?.after_ms, 0), clips: strList(t?.clips) }))
          .filter(t => t.clips.length > 0)
      : [];
    const refusalBuckets = Array.isArray(streams.refusal_buckets)
      ? streams.refusal_buckets
          .map(b => ({
            category: typeof b?.category === 'string' ? b.category.trim() : '',
            clips: strList(b?.clips),
          }))
          .filter(b => b.clips.length > 0)
      : [];
    const onFail = strList(streams.on_fail);
    if (
      fillerGuardBandMs !== 2000 ||
      fillerTiers.length > 0 ||
      refusalBuckets.length > 0 ||
      onFail.length > 0
    ) {
      out.audio_streams = {
        ...(fillerGuardBandMs !== 2000 ? { filler_guard_band_ms: fillerGuardBandMs } : {}),
        ...(fillerTiers.length > 0 ? { filler_tiers: fillerTiers } : {}),
        ...(refusalBuckets.length > 0 ? { refusal_buckets: refusalBuckets } : {}),
        ...(onFail.length > 0 ? { on_fail: onFail } : {}),
      };
    }
  }
  return out;
}

/** Derive the wire `document_ingestion` from the `pipe-document-input` node, or null. */
export function documentInputFromCanvas(canvas: unknown): Record<string, unknown> | null {
  const c = pipeNodeConfig(canvas, 'pipe-document-input');
  if (!c || c.enabled === false) return null;
  const mode = c.mode === 'extract' || c.mode === 'passthrough' ? c.mode : 'auto';
  const allowed = strList(c.allowed_types);
  return {
    enabled: true,
    allowed_types: allowed.length > 0 ? allowed : [...DEFAULT_DOCUMENT_TYPES],
    mode,
    max_file_bytes: posNum(c.max_file_bytes, 5 * 1024 * 1024),
    max_extracted_chars: posNum(c.max_extracted_chars, 100000),
  };
}

/**
 * Whether the surface's attribute-based routing is enforced, per the canvas
 * `pipe-router` node (the Router element's enable flag). `null` when the node is
 * absent, so the caller falls back to the form value. The rules themselves are a
 * base-pipe field on the form (shared with variant-catalog sync), not the node
 * config.
 */
export function routerEnabledFromCanvas(canvas: unknown): boolean | null {
  const c = pipeNodeConfig(canvas, 'pipe-router');
  if (!c) return null;
  return c.enabled !== false;
}

/**
 * Whether the surface's drift monitoring is enabled, per the canvas
 * `pipe-drift-harness` node (the Drift Harness element's enable flag). `null`
 * when the node is absent, so the caller falls back to the form value. The full
 * `drift` config (sampling, thresholds, replay eval, alerting) is a base-pipe
 * field on the form, not the node config.
 */
export function driftHarnessEnabledFromCanvas(canvas: unknown): boolean | null {
  const c = pipeNodeConfig(canvas, 'pipe-drift-harness');
  if (!c) return null;
  return c.enabled !== false;
}

/**
 * Reconcile the base-pipe `drift` block with the canvas Drift Harness node on
 * save. The form block (written through the surface meta by both the sidebar
 * toggle and the full-page editor) is the single source of truth for every
 * field, including enable — so the sidebar and full-page enable switches can
 * never diverge. The node is only consulted for the fresh-drop case: a harness
 * dropped and enabled but not yet otherwise configured (no form block) still
 * persists, so it survives a reload.
 */
function buildDriftFromCanvas(
  drift: DriftForm | null | undefined,
  canvas: unknown
): DriftForm | undefined {
  if (drift) return drift;
  return driftHarnessEnabledFromCanvas(canvas) === true ? { enabled: true } : undefined;
}

const SYSTEM_FIELDS = [
  'provider',
  'provider_type',
  'model',
  // The `custom` provider carries its model id in `name` (the backend's
  // `LLMProvider::Custom` requires it). It is an identity field, not a tunable
  // parameter, so exclude it from the model-parameter sweep below.
  'name',
  'deployment_name',
  'endpoint',
  'endpoint_url',
  'base_url',
  'api_key_secret',
  'api_key_secret_id',
  'api_version',
  'api_schema',
  '_marketplace_source',
];

/** Providers whose provider URL is `endpoint` rather than `base_url`. */
const ENDPOINT_URL_PROVIDERS = ['mistral', 'huggingface', 'custom'];

function providerUrlField(providerType: string): 'endpoint' | 'base_url' {
  return ENDPOINT_URL_PROVIDERS.includes(providerType) ? 'endpoint' : 'base_url';
}

/**
 * The provider URL a saved provider config carries, for `provider` (the
 * editor's enum value). Azure keeps its endpoint in the form and marketplace
 * models take theirs from the purchase, so neither has one here.
 */
export function storedProviderUrl(
  providerConfig: Record<string, unknown> | undefined,
  provider: string
): ProviderUrlForm | null {
  if (!providerConfig || provider === 'azure_openai' || providerConfig._marketplace_source) {
    return null;
  }
  const url = providerConfig[providerUrlField(provider)];
  return typeof url === 'string' && url ? { provider, url } : null;
}

/** Project the backend `context_management` block into editor form fields. */
function mapContextManagement(raw: unknown): ContextManagementForm | null {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as Record<string, unknown>;
  return {
    enabled: r.enabled === true,
    context_window_tokens:
      typeof r.context_window_tokens === 'number' ? r.context_window_tokens : null,
    keep_recent_messages: typeof r.keep_recent_messages === 'number' ? r.keep_recent_messages : 4,
    reserve_output_tokens:
      typeof r.reserve_output_tokens === 'number' ? r.reserve_output_tokens : 1024,
  };
}

/** Build the wire `context_management`, or `undefined` when effectively off. */
function buildContextManagement(
  cm: ContextManagementForm | null
): Record<string, unknown> | undefined {
  if (!cm) return undefined;
  const window =
    cm.context_window_tokens && cm.context_window_tokens > 0 ? cm.context_window_tokens : undefined;
  if (!cm.enabled && window === undefined) return undefined;
  return {
    enabled: cm.enabled === true,
    context_window_tokens: window,
    keep_recent_messages: cm.keep_recent_messages > 0 ? cm.keep_recent_messages : 4,
    reserve_output_tokens: cm.reserve_output_tokens >= 0 ? cm.reserve_output_tokens : 1024,
  };
}

const DEFAULT_DOCUMENT_TYPES = ['text', 'markdown', 'csv', 'json', 'docx'];

/**
 * Build the wire `upstream_headers`, or `undefined` when none are usable. A row
 * missing either half is dropped rather than saved: an in-progress edit must
 * not fail the whole surface save, and a half-filled row would be refused by
 * the backend anyway.
 */
export function buildUpstreamHeaders(
  headers: UpstreamHeaderForm[] | undefined
): UpstreamHeaderForm[] | undefined {
  const usable = (headers ?? [])
    .map(h => ({ name: (h.name ?? '').trim(), secret_id: (h.secret_id ?? '').trim() }))
    .filter(h => h.name !== '' && h.secret_id !== '');
  return usable.length > 0 ? usable : undefined;
}

/** Project the backend `document_ingestion` block into editor form fields. */
function mapDocumentIngestion(raw: unknown): DocumentIngestionForm | null {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as Record<string, unknown>;
  const mode = r.mode === 'extract' || r.mode === 'passthrough' ? r.mode : 'auto';
  return {
    enabled: r.enabled === true,
    allowed_types: Array.isArray(r.allowed_types)
      ? (r.allowed_types.filter(t => typeof t === 'string') as string[])
      : [...DEFAULT_DOCUMENT_TYPES],
    max_file_bytes: typeof r.max_file_bytes === 'number' ? r.max_file_bytes : 5 * 1024 * 1024,
    max_extracted_chars: typeof r.max_extracted_chars === 'number' ? r.max_extracted_chars : 100000,
    mode,
  };
}

/** Build the wire `document_ingestion`, or `undefined` when effectively off. */
function buildDocumentIngestion(
  di: DocumentIngestionForm | null
): Record<string, unknown> | undefined {
  if (!di || !di.enabled) return undefined;
  return {
    enabled: true,
    allowed_types: di.allowed_types.length > 0 ? di.allowed_types : [...DEFAULT_DOCUMENT_TYPES],
    max_file_bytes: di.max_file_bytes > 0 ? di.max_file_bytes : 5 * 1024 * 1024,
    max_extracted_chars: di.max_extracted_chars > 0 ? di.max_extracted_chars : 100000,
    mode: di.mode,
  };
}

export interface MappedPipe {
  formData: PipeFormData;
  integrations: integrationIntegration[] | null;
}

/**
 * Normalise a usage limit's scope + stage. A stage-scoped limit always names a
 * concrete stage (defaulting to `llm`); a cumulative limit names none.
 */
function normalizeUsageScope(
  rawScope: unknown,
  rawStage: unknown
): { scope: 'cumulative' | 'stage'; stage: 'llm' | 'judge' | 'jury' | null } {
  const scope = rawScope === 'cumulative' ? 'cumulative' : 'stage';
  if (scope === 'cumulative') return { scope, stage: null };
  const stage = rawStage === 'judge' || rawStage === 'jury' ? rawStage : 'llm';
  return { scope, stage };
}

/** Project the backend `usage_limits` wire array into editor form entries. */
function mapUsageLimitsToForm(raw: unknown): PipeUsageLimitEntry[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .filter(
      (l): l is Record<string, any> => !!l && typeof l === 'object' && typeof l.id === 'string'
    )
    .map(l => {
      const { scope, stage } = normalizeUsageScope(l.scope, l.stage);
      const entry: PipeUsageLimitEntry = {
        id: l.id,
        enabled: l.enabled !== false,
        scope,
        stage,
        monthly_budget_usd: typeof l.monthly_budget_usd === 'number' ? l.monthly_budget_usd : null,
        monthly_token_cap: typeof l.monthly_token_cap === 'number' ? l.monthly_token_cap : null,
      };
      if (scope === 'stage' && stage === 'jury' && typeof l.juror_index === 'number') {
        entry.juror_index = l.juror_index;
      }
      return entry;
    });
}

/** Canvas-owned usage limits: per-stage and per-juror, excluding the cumulative total. */
function mapStageUsageLimits(raw: unknown): PipeUsageLimitEntry[] {
  return mapUsageLimitsToForm(raw).filter(l => l.scope !== 'cumulative');
}

/** The surface-wide cumulative usage limit, edited on the surface property sidebar. */
function mapSurfaceUsageLimit(raw: unknown): PipeUsageLimitEntry | null {
  return mapUsageLimitsToForm(raw).find(l => l.scope === 'cumulative') ?? null;
}

/** Parse one backend caller-identity-source object into the form union. */
function parseCallerSource(src: Record<string, unknown> | undefined): CallerIdentitySourceForm {
  switch (src?.type) {
    case 'header':
      return { type: 'header', name: typeof src.name === 'string' ? src.name : '' };
    case 'jwt_claim':
      return { type: 'jwt_claim', claim: typeof src.claim === 'string' ? src.claim : '' };
    case 'body_json_path':
      return { type: 'body_json_path', path: typeof src.path === 'string' ? src.path : '' };
    case 'mtls':
      return { type: 'mtls', binding: src.binding === 'subject_cn' ? 'subject_cn' : 'email_san' };
    case 'api_key':
      return { type: 'api_key' };
    default:
      return { type: 'header', name: '' };
  }
}

/**
 * Normalise a backend `team_attribution` blob into the editor form shape.
 * Surface-type agnostic: describes the ordered caller-identity sources, the
 * auto-provision opt-in, and the enforcement flags. Reads either the new
 * `caller_identity_sources` array or the legacy singular `caller_email_source`.
 * Returns `null` when absent or malformed.
 */
function mapTeamAttribution(raw: unknown): TeamAttributionForm | null {
  if (!raw || typeof raw !== 'object') return null;
  const obj = raw as Record<string, unknown>;
  let sources: CallerIdentitySourceForm[];
  if (Array.isArray(obj.caller_identity_sources)) {
    sources = obj.caller_identity_sources.map(s =>
      parseCallerSource(s as Record<string, unknown> | undefined)
    );
  } else if (obj.caller_email_source && typeof obj.caller_email_source === 'object') {
    sources = [parseCallerSource(obj.caller_email_source as Record<string, unknown>)];
  } else {
    sources = [];
  }
  return {
    enabled: obj.enabled === true,
    caller_identity_sources: sources,
    auto_provision: obj.auto_provision === true,
    enforce: obj.enforce === true,
    allow_individual_overage: obj.allow_individual_overage === true,
    allowed_teams: Array.isArray(obj.allowed_teams)
      ? obj.allowed_teams.filter((t): t is string => typeof t === 'string')
      : [],
  };
}

/**
 * Shape the editor's usage-limit entries into the backend wire array. Drops
 * limits that set neither a budget nor a token cap (the backend rejects them)
 * so a half-configured drag-on never blocks a save.
 */
function buildUsageLimitsPayload(
  limits: PipeUsageLimitEntry[] | undefined
): UsageLimitWire[] | undefined {
  if (!Array.isArray(limits)) return undefined;
  const wire = limits
    .filter(l => {
      const hasBudget = typeof l.monthly_budget_usd === 'number' && l.monthly_budget_usd > 0;
      const hasTokens = typeof l.monthly_token_cap === 'number' && l.monthly_token_cap > 0;
      return hasBudget || hasTokens;
    })
    .map(l => {
      const { scope, stage } = normalizeUsageScope(l.scope, l.stage);
      const out: UsageLimitWire = { id: l.id, enabled: l.enabled !== false, scope };
      if (scope === 'stage') out.stage = stage;
      if (scope === 'stage' && stage === 'jury' && typeof l.juror_index === 'number') {
        out.juror_index = l.juror_index;
      }
      if (typeof l.monthly_budget_usd === 'number' && l.monthly_budget_usd > 0) {
        out.monthly_budget_usd = l.monthly_budget_usd;
      }
      if (typeof l.monthly_token_cap === 'number' && l.monthly_token_cap > 0) {
        out.monthly_token_cap = l.monthly_token_cap;
      }
      return out;
    });
  return wire.length > 0 ? wire : undefined;
}

/**
 * Project the wire variant catalog into the editor's catalog metadata.
 * The behavioural snapshot for each variant is resolved separately by
 * the page's snapshot manager (`parsePipeVariants`); this only carries
 * the identity fields the catalog UI renders.
 */
function mapVariantsToFormData(raw: unknown): PipeFormData['variants'] {
  if (!Array.isArray(raw)) return [];
  return raw.map((v: any) => ({
    id: v.id ?? (typeof crypto !== 'undefined' ? crypto.randomUUID() : `${Date.now()}`),
    alias: v.alias ?? '',
    name: v.name ?? '',
    description: v.description || undefined,
    enabled: v.enabled !== false,
  }));
}

/**
 * Backend guard blocks (rate limit, OPA policy) are first-class on the pipe
 * record but only surface on the canvas as drag-on decoration nodes. A pipe
 * configured through the form, API, import, or a template carries the block
 * with no matching canvas node, so the decoration is invisible AND the canvas
 * read-seam reports it absent — silently disabling the backend block on the
 * next save. Synthesize the missing decoration from backend truth so the
 * canvas faithfully reflects an enabled rate limit / OPA gate and the block
 * round-trips instead of being dropped. Existing nodes (the user dragged one
 * on) and disabled / unset blocks are left untouched.
 */
export function reconcilePipeCanvasGuards(canvas: unknown, pipe: PipeConfig): unknown {
  const blob =
    canvas && typeof canvas === 'object' && Array.isArray((canvas as CanvasBlob).nodes)
      ? (canvas as CanvasBlob)
      : null;
  const existingTypes = new Set((blob?.nodes ?? []).map(n => n?.type));

  const additions: Array<{
    id: string;
    type: string;
    label: string;
    parentId?: string;
    position: { x: number; y: number };
    config: Record<string, unknown>;
  }> = [];

  // Inbound governance gates must parent to `pipe-source`; `deriveEdges` only
  // binds a gate onto the AP→LLM edge when it is a child of the Access Point,
  // so a parentless reconstruction floats free instead of snapping to the edge.
  const rl = pipe.rate_limit;
  if (rl && rl.enabled === true && !existingTypes.has('pipe-rate-limit')) {
    additions.push({
      id: 'pipe-rate-limit',
      type: 'pipe-rate-limit',
      label: 'Rate Limit',
      parentId: 'pipe-source',
      position: { x: -120, y: 110 },
      config: {
        enabled: true,
        requests_per_minute:
          typeof rl.requests_per_minute === 'number' ? rl.requests_per_minute : 60,
        tokens_per_minute: typeof rl.tokens_per_minute === 'number' ? rl.tokens_per_minute : 100000,
      },
    });
  }

  const opa = pipe.opa_policy;
  if (opa && opa.enabled === true && !existingTypes.has('pipe-opa-policy')) {
    additions.push({
      id: 'pipe-opa-policy',
      type: 'pipe-opa-policy',
      label: 'OPA Policy',
      parentId: 'pipe-source',
      position: { x: 120, y: 110 },
      config: {
        enabled: true,
        policy_definition_id:
          typeof opa.policy_definition_id === 'string' ? opa.policy_definition_id : '',
        log_decisions: opa.log_decisions === true,
      },
    });
  }

  const sa = pipe.source_auth;
  if (sa && !existingTypes.has('pipe-caller-auth')) {
    const cfg = flattenSourceAuth(sa);
    if (cfg) {
      additions.push({
        id: 'pipe-caller-auth',
        type: 'pipe-caller-auth',
        label: 'Caller Context',
        parentId: 'pipe-source',
        position: { x: 0, y: 110 },
        config: cfg,
      });
    }
  }

  // Router: rebuild the inbound-edge Router element from the base-pipe
  // `routing_rules` / `routing_enabled` so a surface configured via the API,
  // JSON, or an older canvas (routing used to live in the surface config) still
  // shows the draggable element. The rules stay on the form; the node only
  // carries the enable flag and seeds leftmost on the inbound edge.
  const routingRules = Array.isArray((pipe as any).routing_rules)
    ? (pipe as any).routing_rules
    : [];
  const routingEnabled = (pipe as any).routing_enabled === true;
  if ((routingEnabled || routingRules.length > 0) && !existingTypes.has('pipe-router')) {
    additions.push({
      id: 'pipe-router',
      type: 'pipe-router',
      label: 'Router',
      position: { x: -200, y: 110 },
      config: { enabled: routingEnabled },
    });
  }

  // Drift Harness: rebuild the LLM-bound monitoring element from the base-pipe
  // `drift` block so a surface configured via the API, JSON, or an older canvas
  // (drift used to live in the surface config panel) still shows the draggable
  // element. The full `drift` config stays on the form; the node only carries
  // the enable flag and sits in the LLM tool row (parented to the LLM).
  const drift = (pipe as any).drift;
  if (drift && typeof drift === 'object' && !existingTypes.has('pipe-drift-harness')) {
    additions.push({
      id: 'pipe-drift-harness',
      type: 'pipe-drift-harness',
      label: 'Drift Harness',
      parentId: 'pipe-upstream',
      position: llmToolSlotPosition(6),
      config: { enabled: drift.enabled === true },
    });
  }

  // Governed server tools: rebuild the two Tools-palette nodes from the
  // structured `server_tools` so a config authored via JSON (or an older
  // canvas) still shows the draggable elements. `engine_secret` (backend) maps
  // back to the panel's `engine_secret_id`.
  const st = pipe.server_tools as ServerToolsWire | undefined;
  const ws = st?.web_search;
  if (ws && ws.enabled === true && !existingTypes.has('pipe-web-search')) {
    additions.push({
      id: 'pipe-web-search',
      type: 'pipe-web-search',
      label: 'Web Search',
      parentId: 'pipe-upstream',
      position: llmToolSlotPosition(0),
      config: {
        enabled: true,
        engine: typeof ws.engine === 'string' ? ws.engine : 'tavily',
        engine_secret_id: typeof ws.engine_secret === 'string' ? ws.engine_secret : '',
        max_results: typeof ws.max_results === 'number' ? ws.max_results : 5,
        max_iterations: typeof st?.max_iterations === 'number' ? st.max_iterations : 3,
        google_cse_id: typeof ws.google_cse_id === 'string' ? ws.google_cse_id : '',
        domain_policy: ws.domain_policy === 'block_all' ? 'block_all' : 'allow_all',
        domain_exceptions: Array.isArray(ws.domain_exceptions) ? ws.domain_exceptions : [],
      },
    });
  }
  const wf = st?.web_fetch;
  if (wf && wf.enabled === true && !existingTypes.has('pipe-web-fetch')) {
    additions.push({
      id: 'pipe-web-fetch',
      type: 'pipe-web-fetch',
      label: 'Web Fetch',
      parentId: 'pipe-upstream',
      position: llmToolSlotPosition(1),
      config: {
        enabled: true,
        max_content_bytes: typeof wf.max_content_bytes === 'number' ? wf.max_content_bytes : 60000,
        domain_policy: wf.domain_policy === 'block_all' ? 'block_all' : 'allow_all',
        domain_exceptions: Array.isArray(wf.domain_exceptions) ? wf.domain_exceptions : [],
      },
    });
  }

  // Inbound modality nodes: rebuild the three Inputs-palette elements from the
  // structured `audio_input` / `image_input` / `document_ingestion` so a config
  // authored via JSON (or an older canvas) still shows the draggable elements.
  // They sit in the LLM tool row after the two server-tool slots.
  const ai = (pipe as any).audio_input as
    | { enabled?: boolean; allowed_formats?: string[]; max_bytes?: number }
    | undefined;
  const rt = (pipe as any).realtime as
    | {
        enabled?: boolean;
        max_session_secs?: number;
        voice?: string;
        safety?: Record<string, unknown>;
        audio_streams?: Record<string, unknown>;
      }
    | undefined;
  // Audio File (Mode A inline `input_audio`) and Audio Stream (Mode C realtime
  // voice) are distinct Inputs elements; each rebuilds from its own backend
  // block so a config authored via JSON still shows the draggable element.
  if (ai?.enabled === true && !existingTypes.has('pipe-audio-input')) {
    additions.push({
      id: 'pipe-audio-input',
      type: 'pipe-audio-input',
      label: 'Audio File',
      parentId: 'pipe-upstream',
      position: llmToolSlotPosition(2),
      config: {
        enabled: true,
        allowed_formats: Array.isArray(ai.allowed_formats) ? ai.allowed_formats : [],
        max_bytes: typeof ai.max_bytes === 'number' ? ai.max_bytes : 25 * 1024 * 1024,
      },
    });
  }
  if (rt?.enabled === true && !existingTypes.has('pipe-audio-stream')) {
    additions.push({
      id: 'pipe-audio-stream',
      type: 'pipe-audio-stream',
      label: 'Audio Stream',
      parentId: 'pipe-upstream',
      position: llmToolSlotPosition(3),
      config: {
        enabled: true,
        max_session_secs: typeof rt.max_session_secs === 'number' ? rt.max_session_secs : 600,
        ...(typeof rt.voice === 'string' && rt.voice ? { voice: rt.voice } : {}),
        ...(rt.safety && typeof rt.safety === 'object' ? { safety: rt.safety } : {}),
        ...(rt.audio_streams && typeof rt.audio_streams === 'object'
          ? { audio_streams: rt.audio_streams }
          : {}),
      },
    });
  }
  const ii = (pipe as any).image_input as
    | { enabled?: boolean; allowed_formats?: string[]; max_bytes?: number }
    | undefined;
  if (ii && ii.enabled === true && !existingTypes.has('pipe-image-input')) {
    additions.push({
      id: 'pipe-image-input',
      type: 'pipe-image-input',
      label: 'Image File',
      parentId: 'pipe-upstream',
      position: llmToolSlotPosition(4),
      config: {
        enabled: true,
        allowed_formats: Array.isArray(ii.allowed_formats) ? ii.allowed_formats : [],
        max_bytes: typeof ii.max_bytes === 'number' ? ii.max_bytes : 20 * 1024 * 1024,
      },
    });
  }
  const di = (pipe as any).document_ingestion as
    | {
        enabled?: boolean;
        allowed_types?: string[];
        mode?: string;
        max_file_bytes?: number;
        max_extracted_chars?: number;
      }
    | undefined;
  if (di && di.enabled === true && !existingTypes.has('pipe-document-input')) {
    additions.push({
      id: 'pipe-document-input',
      type: 'pipe-document-input',
      label: 'Document File',
      parentId: 'pipe-upstream',
      position: llmToolSlotPosition(5),
      config: {
        enabled: true,
        allowed_types: Array.isArray(di.allowed_types)
          ? di.allowed_types
          : [...DEFAULT_DOCUMENT_TYPES],
        mode: di.mode === 'extract' || di.mode === 'passthrough' ? di.mode : 'auto',
        max_file_bytes: typeof di.max_file_bytes === 'number' ? di.max_file_bytes : 5 * 1024 * 1024,
        max_extracted_chars:
          typeof di.max_extracted_chars === 'number' ? di.max_extracted_chars : 100000,
      },
    });
  }

  if (additions.length === 0) return canvas;

  const built = buildCanvasBlob(additions);
  if (!blob) return built;
  return { ...blob, nodes: [...blob.nodes, ...built.nodes] };
}

/**
 * Parse a backend pipe record into the flat editor form shape. Pure — the
 * caller owns React state. `llmProviders` is only consulted for endpoint
 * defaulting and may legitimately be empty on first load (a dedicated
 * effect fills the default endpoint once providers arrive).
 */
export function mapPipeToFormData(pipe: PipeConfig, llmProviders: LLMProvider[]): MappedPipe {
  const llmConfig = (pipe.pipe_type as any).provider;

  let providerEnumValue = '';
  let modelValue = '';
  let endpointUrl = '';
  let apiKeySecretId = '';

  if (llmConfig) {
    const providerConfig = llmConfig as any;

    if (providerConfig._marketplace_source?.purchased_id) {
      providerEnumValue = `mp_${providerConfig._marketplace_source.purchased_id}`;
    } else {
      providerEnumValue = providerConfig.provider_type || providerConfig.provider || '';
    }

    if (providerEnumValue === 'azure_openai') {
      modelValue = providerConfig.deployment_name || '';
      endpointUrl = providerConfig.endpoint || '';
      apiKeySecretId = providerConfig.api_key_secret || '';
    } else {
      // The `custom` provider stores its model id in `name` (per the backend's
      // `LLMProvider::Custom`); every other provider uses `model`. Fall back to
      // `name` so a custom surface shows its configured model instead of blank.
      modelValue = providerConfig.model || providerConfig.name || '';
      endpointUrl = '';
      apiKeySecretId = providerConfig.api_key_secret || providerConfig.api_key_secret_id || '';
    }
  }

  const modelParameters: Record<string, any> = {};
  if (llmConfig) {
    Object.keys(llmConfig).forEach(key => {
      if (!SYSTEM_FIELDS.includes(key)) {
        modelParameters[key] = (llmConfig as any)[key];
      }
    });
  }

  if (!endpointUrl && llmProviders.length > 0) {
    const provider = llmProviders.find(p => p.enum_value === providerEnumValue);
    if (provider?.endpoints) {
      const chatEndpoints = provider.endpoints.filter(e =>
        e.capabilities?.includes('chat_completions')
      );
      const defaultEndpoint =
        chatEndpoints.find(e => e.is_default) ||
        chatEndpoints[0] ||
        provider.endpoints.find(e => e.is_default) ||
        provider.endpoints[0];
      if (defaultEndpoint) {
        endpointUrl = defaultEndpoint.path;
      }
    }
  }

  const formData: PipeFormData = {
    ...EMPTY_PIPE_FORM,
    id: pipe.id,
    name: pipe.name,
    description: pipe.description || '',
    enabled: pipe.status === 'enabled',
    listen_address: (pipe as any).listen_address || '',
    route: (pipe as any).route || '',
    provider: providerEnumValue,
    model: modelValue,
    endpoint_url: endpointUrl,
    provider_url: storedProviderUrl(llmConfig, providerEnumValue),
    api_key_secret_id: apiKeySecretId,
    model_parameters: modelParameters,
    rate_limit_enabled: pipe.rate_limit?.enabled ?? false,
    requests_per_minute: pipe.rate_limit?.requests_per_minute || 60,
    tokens_per_minute: pipe.rate_limit?.tokens_per_minute || 100000,
    cost_tracking_enabled: pipe.cost_tracking?.enabled || false,
    input_price_per_1k: pipe.cost_tracking?.input_price_per_1k || 0,
    output_price_per_1k: pipe.cost_tracking?.output_price_per_1k || 0,
    override_policy: pipe.override_policy || {},
    opa_policy: (pipe as any).opa_policy || null,
    prompt_guard: (pipe as any).prompt_guard || null,
    judge: (pipe as any).judge || null,
    jury: (pipe as any).jury || null,
    decider: (pipe as any).decider || deciderFromCanvas((pipe as any).canvas) || null,
    expert_witnesses: Array.isArray((pipe as any).expert_witnesses)
      ? (pipe as any).expert_witnesses
      : (expertWitnessesFromCanvas((pipe as any).canvas) ?? []),
    source_auth: (pipe as any).source_auth ?? null,
    server_tools: (pipe as any).server_tools ?? null,
    context_management: mapContextManagement((pipe as any).context_management),
    document_ingestion: mapDocumentIngestion((pipe as any).document_ingestion),
    usage_limits: mapStageUsageLimits(pipe.usage_limits),
    surface_usage_limit: mapSurfaceUsageLimit(pipe.usage_limits),
    team_attribution: mapTeamAttribution((pipe as any).team_attribution),
    governance_recording: (pipe as any).governance_recording ?? null,
    drift: (pipe as any).drift ?? null,
    vp_evidence: (pipe as any).vp_evidence ?? null,
    streaming_enabled: (pipe as any).streaming?.enabled ?? true,
    forward_caller_token: (pipe as any).forward_caller_token ?? false,
    upstream_headers: Array.isArray((pipe as any).upstream_headers)
      ? (pipe as any).upstream_headers
      : [],
    upstream_pricing: (pipe as any).upstream_pricing ?? null,
    accepted_ingress_schemas: Array.isArray((pipe as any).accepted_ingress_schemas)
      ? (pipe as any).accepted_ingress_schemas
      : ['openai_chat', 'anthropic_messages', 'openai_responses'],
    max_reasoning_tokens:
      typeof (pipe as any).max_reasoning_tokens === 'number'
        ? (pipe as any).max_reasoning_tokens
        : null,
    sandbox_auth: (pipe as any).sandbox_auth ?? null,
    sandbox_oauth_identifier_id: (pipe as any).sandbox_oauth_identifier_id ?? null,
    cache: (pipe as any).cache ?? null,
    canary: (pipe as any).canary ?? null,
    routing_rules: Array.isArray((pipe as any).routing_rules) ? (pipe as any).routing_rules : [],
    // Back-compat: a config predating the flag but carrying rules is enforced.
    routing_enabled:
      (pipe as any).routing_enabled ?? ((pipe as any).routing_rules?.length ?? 0) > 0,
    failover: (pipe as any).failover || null,
    load_balancing: (pipe as any).load_balancing || null,
    usage_alerts: Array.isArray((pipe as any).usage_alerts) ? (pipe as any).usage_alerts : [],
    usage_alerts_enabled:
      (pipe as any).usage_alerts_enabled ?? ((pipe as any).usage_alerts?.length ?? 0) > 0,
    variants: mapVariantsToFormData((pipe as any).variants),
    default_variant_id: (pipe as any).default_variant_id || null,
    created_at: pipe.created_at || '',
  };

  (formData as any).canvas = reconcilePipeCanvasGuards((pipe as any).canvas, pipe);
  (formData as any).auto_canvas = (pipe as any).auto_canvas === true;

  const integrations = (pipe as any).integrations
    ? ((pipe as any).integrations as integrationIntegration[])
    : null;

  return { formData, integrations };
}

export interface BuildPipePayloadArgs {
  formData: PipeFormData;
  integrations: integrationIntegration[];
  llmProviders: LLMProvider[];
  isNew: boolean;
  pipeId?: string;
  /**
   * Precomputed full-snapshot variant catalog from the page's snapshot
   * manager. When supplied, the base pipe's behavioural fields are taken
   * from `baseSnapshot` (so saving while a variant is active never writes
   * that variant's config as the base) and the wire `variants[]` /
   * `default_variant_id` come from the slice. Omitted by template-apply
   * round-trips, which carry no variants.
   */
  variantsSlice?: {
    variants: unknown[];
    defaultVariantId: string | null;
    baseSnapshot: Partial<PipeFormData> & { canvas?: unknown };
  };
}

/**
 * Build the wire `pipe_type` (LLM upstream) from the flat upstream
 * fields. Shared by the base pipe and each variant override so both
 * produce an identical shape; a variant simply supplies the base fields
 * overlaid with its own non-empty overrides.
 */
export function buildLlmPipeType(
  upstream: {
    provider: string;
    model: string;
    endpoint_url: string;
    provider_url?: ProviderUrlForm | null;
    api_key_secret_id: string;
    model_parameters?: Record<string, any>;
  },
  llmProviders: LLMProvider[]
): Record<string, any> {
  const selectedProv = llmProviders.find(p => p.enum_value === upstream.provider);
  const mpMeta = selectedProv?._marketplace;
  const { _marketplace, ...cleanModelParams } = upstream.model_parameters || {};

  const providerConfig: any = {
    provider_type: mpMeta ? mpMeta.real_provider_type : upstream.provider,
    model: upstream.model,
    ...cleanModelParams,
  };

  if (mpMeta) {
    providerConfig.api_key_secret = upstream.api_key_secret_id;
    providerConfig.base_url = mpMeta.base_url;
    providerConfig.api_schema = mpMeta.api_schema;
    providerConfig._marketplace_source = {
      purchased_id: mpMeta.purchased_id,
      provider: mpMeta.real_provider_type,
      model_id: mpMeta.model_id,
      base_url: mpMeta.base_url,
      api_schema: mpMeta.api_schema,
    };
  } else if (upstream.provider === 'azure_openai') {
    providerConfig.endpoint = upstream.endpoint_url;
    providerConfig.api_key_secret = upstream.api_key_secret_id;
    providerConfig.api_version = '2024-02-15-preview';
  } else {
    providerConfig.api_key_secret = upstream.api_key_secret_id;
    const savedUrl =
      upstream.provider_url?.provider === upstream.provider ? upstream.provider_url.url : '';
    const baseUrl = selectedProv?.default_base_url;
    if (savedUrl) {
      providerConfig[providerUrlField(upstream.provider)] = savedUrl;
    } else if (baseUrl) {
      providerConfig.base_url = baseUrl;
    }
  }

  return {
    type: 'llm',
    provider: providerConfig,
    endpoint_path: (() => {
      const versionPrefix = mpMeta
        ? mpMeta.api_version_prefix || ''
        : selectedProv?.api_version_prefix || '';
      const path = upstream.endpoint_url;
      // Mirror the backend's resolve_endpoint_url guard: never double the
      // version prefix if it is already present. Keeps variant saves
      // idempotent so repeated edits cannot accumulate `/v1/v1/...`.
      return versionPrefix && path.startsWith(versionPrefix) ? path : `${versionPrefix}${path}`;
    })(),
  };
}

/**
 * Assemble the backend pipe payload from the editor form. Pure — the caller
 * performs the request and owns toasts/navigation.
 */
export function buildPipePayload(args: BuildPipePayloadArgs): Record<string, any> {
  const { formData, integrations, llmProviders, isNew, pipeId, variantsSlice } = args;

  // When a variant snapshot slice is supplied, the pipe's behavioural
  // fields (upstream / rate limit / cost / policies / canvas) come from
  // the base snapshot, not from `formData` (which mirrors whatever
  // variant is currently active on the canvas). Identity / routing
  // fields always come from `formData`.
  const baseSnap = variantsSlice?.baseSnapshot;
  const provider = baseSnap?.provider ?? formData.provider;
  const model = baseSnap?.model ?? formData.model;
  const endpoint_url = baseSnap?.endpoint_url ?? formData.endpoint_url;
  const provider_url = baseSnap ? (baseSnap.provider_url ?? null) : formData.provider_url;
  const api_key_secret_id = baseSnap?.api_key_secret_id ?? formData.api_key_secret_id;
  const model_parameters = baseSnap?.model_parameters ?? formData.model_parameters;
  const rate_limit_enabled = baseSnap?.rate_limit_enabled ?? formData.rate_limit_enabled;
  const requests_per_minute = baseSnap?.requests_per_minute ?? formData.requests_per_minute;
  const tokens_per_minute = baseSnap?.tokens_per_minute ?? formData.tokens_per_minute;
  const cost_tracking_enabled = baseSnap?.cost_tracking_enabled ?? formData.cost_tracking_enabled;
  const input_price_per_1k = baseSnap?.input_price_per_1k ?? formData.input_price_per_1k;
  const output_price_per_1k = baseSnap?.output_price_per_1k ?? formData.output_price_per_1k;
  const override_policy = baseSnap?.override_policy ?? formData.override_policy;
  const opa_policy = baseSnap ? baseSnap.opa_policy : formData.opa_policy;
  const prompt_guard = baseSnap ? baseSnap.prompt_guard : formData.prompt_guard;
  const judge = baseSnap ? baseSnap.judge : formData.judge;
  const usage_limits = baseSnap ? baseSnap.usage_limits : formData.usage_limits;
  const surface_usage_limit = baseSnap
    ? ((baseSnap.surface_usage_limit ?? null) as PipeUsageLimitEntry | null)
    : formData.surface_usage_limit;
  const canvas = baseSnap ? baseSnap.canvas : (formData as any).canvas;
  // The Jury, like the Decider, is canvas-sourced: each juror (carrying its
  // required `llm`) is a first-class `pipe-juror` node, so reassemble the jury
  // from the canvas to keep the payload's jurors in lock-step and never send a
  // juror stripped of its `llm`. Fall back to the form/snapshot value only when
  // the canvas has no `pipe-jury` node to read from.
  const jury = juryFromCanvas(canvas) ?? (baseSnap ? baseSnap.jury : formData.jury);
  // The Decider is a base-pipe field (not a per-variant override) and its
  // source of truth is the canvas (its on/off state IS whether a
  // `pipe-decider` node exists). Snapshots intentionally don't carry it, so
  // derive it from the same canvas blob being saved — that keeps the
  // structured `decider` in lock-step with the canvas and stops it silently
  // dropping to `undefined` on save. Fall back to the form/snapshot value only
  // when the canvas has no decider node to read from.
  const decider = deciderFromCanvas(canvas) ?? (baseSnap ? baseSnap.decider : formData.decider);

  // Expert witnesses are a base-pipe field (not a per-variant override) and
  // their source of truth is the canvas (the two witness seam nodes). Snapshots
  // don't carry them, so derive from the same canvas blob being saved to keep
  // the structured list in lock-step with the canvas. Fall back to the
  // form/snapshot value only when the canvas has no witness node to read from.
  const expert_witnesses =
    expertWitnessesFromCanvas(canvas) ??
    (baseSnap ? baseSnap.expert_witnesses : formData.expert_witnesses);

  // Caller-context (`source_auth`) is a base-pipe field (not a per-variant
  // override) and its source of truth is the canvas `pipe-caller-auth` node
  // (edge-bound on the inbound edge, mirroring the IDE Surface). Falls back
  // to the base snapshot when editing a variant so the base's caller-context
  // is preserved.
  const source_auth =
    sourceAuthFromCanvas(canvas, isNew ? undefined : pipeId) ??
    (baseSnap ? baseSnap.source_auth : formData.source_auth);

  // Governed server tools (`web_search` / `web_fetch`) are a base-pipe field
  // whose source of truth is the canvas (the two Tools-palette nodes). Derive
  // from the same canvas blob being saved so the structured `server_tools`
  // stays in lock-step with the canvas; fall back to the form value only when
  // the canvas carries no tool node.
  const server_tools =
    serverToolsFromCanvas(canvas) ?? (baseSnap ? undefined : formData.server_tools);

  // Inbound modality gates are canvas-sourced (the three Inputs-palette nodes).
  // Documents keep a form fallback for back-compat; audio/image are canvas-only.
  const audio_input = audioInputFromCanvas(canvas);
  const image_input = imageInputFromCanvas(canvas);
  const realtime = realtimeFromCanvas(canvas);
  const document_ingestion =
    documentInputFromCanvas(canvas) ??
    (baseSnap ? undefined : buildDocumentIngestion(formData.document_ingestion));

  const pipe_type_config = buildLlmPipeType(
    {
      provider,
      model,
      endpoint_url,
      provider_url,
      api_key_secret_id,
      model_parameters,
    },
    llmProviders
  );

  const variantsWire = variantsSlice?.variants ?? [];

  return {
    id: isNew ? crypto.randomUUID() : pipeId,
    name: formData.name,
    description: formData.description,
    status: formData.enabled ? 'enabled' : 'disabled',
    listen_address: formData.listen_address || undefined,
    route: formData.route || undefined,
    pipe_type: pipe_type_config,
    rate_limit: {
      // Coerce to a strict boolean: the backend's `RateLimit.enabled` defaults
      // to `true` when the field is absent (`serde(default = "default_true")`),
      // so an `undefined` here would silently enable rate limiting on save.
      enabled: rate_limit_enabled === true,
      requests_per_minute,
      tokens_per_minute,
    },
    cost_tracking: {
      enabled: cost_tracking_enabled,
      input_price_per_1k:
        input_price_per_1k !== undefined && input_price_per_1k !== null
          ? input_price_per_1k
          : undefined,
      output_price_per_1k:
        output_price_per_1k !== undefined && output_price_per_1k !== null
          ? output_price_per_1k
          : undefined,
    },
    override_policy: Object.keys(override_policy || {}).length > 0 ? override_policy : undefined,
    opa_policy: opa_policy || undefined,
    prompt_guard: prompt_guard || undefined,
    judge: judge || undefined,
    jury: jury || undefined,
    decider: decider || undefined,
    expert_witnesses:
      expert_witnesses && expert_witnesses.length > 0 ? expert_witnesses : undefined,
    source_auth: source_auth || undefined,
    usage_limits: buildUsageLimitsPayload([
      ...(usage_limits ?? []),
      ...(surface_usage_limit ? [surface_usage_limit] : []),
    ]),
    team_attribution: formData.team_attribution || undefined,
    // Base-pipe field (not variant-overridable, not in the variant snapshot):
    // always read from the form so a variant-active save can't drop it.
    governance_recording: formData.governance_recording || undefined,
    drift: buildDriftFromCanvas(formData.drift, canvas),
    vp_evidence: formData.vp_evidence || undefined,
    streaming: { enabled: formData.streaming_enabled },
    forward_caller_token: formData.forward_caller_token,
    // Drop half-filled rows so an in-progress edit can't fail the save; a row
    // needs both a name and the secret its value comes from.
    upstream_headers: buildUpstreamHeaders(formData.upstream_headers),
    upstream_pricing: formData.upstream_pricing ?? undefined,
    accepted_ingress_schemas: formData.accepted_ingress_schemas?.length
      ? formData.accepted_ingress_schemas
      : ['openai_chat', 'anthropic_messages', 'openai_responses'],
    max_reasoning_tokens:
      formData.max_reasoning_tokens && formData.max_reasoning_tokens > 0
        ? formData.max_reasoning_tokens
        : undefined,
    server_tools: server_tools || undefined,
    context_management: buildContextManagement(formData.context_management),
    document_ingestion: document_ingestion || undefined,
    audio_input: audio_input || undefined,
    image_input: image_input || undefined,
    realtime: realtime || undefined,
    sandbox_auth: formData.sandbox_auth || undefined,
    sandbox_oauth_identifier_id: formData.sandbox_oauth_identifier_id || undefined,
    cache: formData.cache || undefined,
    canary: formData.canary || undefined,
    routing_rules: formData.routing_rules?.length ? formData.routing_rules : undefined,
    // Enable-first list controls: if the list is empty, force the switch off on
    // save so an empty configuration can never persist in an "enabled" state.
    // The canvas Router element is the source of truth for the enable flag
    // (delete/toggle it off to stop enforcement); fall back to the form value
    // when no Router node is on the canvas (e.g. an API-authored config).
    routing_enabled:
      (routerEnabledFromCanvas(canvas) ?? formData.routing_enabled) &&
      (formData.routing_rules?.length ?? 0) > 0,
    failover: formData.failover || undefined,
    load_balancing: formData.load_balancing || undefined,
    usage_alerts:
      formData.usage_alerts && formData.usage_alerts.length > 0 ? formData.usage_alerts : undefined,
    usage_alerts_enabled: formData.usage_alerts_enabled && (formData.usage_alerts?.length ?? 0) > 0,
    integrations,
    canvas: canvas || undefined,
    // Dashboard-only hint; the builder clears it after the first Auto Layout, so
    // a normal open+save drops it (omitted here when false).
    auto_canvas: (formData as any).auto_canvas ? true : undefined,
    variants: variantsWire.length > 0 ? variantsWire : undefined,
    default_variant_id: variantsSlice?.defaultVariantId || undefined,
    created_at: isNew ? new Date().toISOString() : formData.created_at,
  };
}

/**
 * Project the flat editor form into the canvas pipe snapshot.
 *
 * @param routePrefixResolved Whether route→prefix parsing has been attempted
 * (see `PipeConfigLike.route_prefix_resolved`). Defaults to `false` — the
 * safe default is "not yet resolved" (a reseed gate waiting on this keeps
 * waiting) rather than risking a premature reseed from an unresolved prefix.
 */
export function buildPipeForCanvas(
  formData: PipeFormData,
  selectedPrefix: string,
  customPath: string,
  routePrefixResolved = false
): PipeConfigLike {
  return {
    id: formData.id,
    name: formData.name,
    description: formData.description,
    enabled: formData.enabled,
    rate_limit: {
      enabled: formData.rate_limit_enabled,
      requests_per_minute: formData.requests_per_minute,
      tokens_per_minute: formData.tokens_per_minute,
    },
    cost_tracking: {
      enabled: formData.cost_tracking_enabled,
      input_price_per_1k: formData.input_price_per_1k,
      output_price_per_1k: formData.output_price_per_1k,
    },
    override_policy: formData.override_policy,
    model_parameters: formData.model_parameters,
    opa_policy: formData.opa_policy,
    prompt_guard: formData.prompt_guard,
    judge: formData.judge,
    jury: formData.jury,
    decider: formData.decider,
    expert_witnesses: formData.expert_witnesses,
    source_auth: formData.source_auth,
    usage_limits: formData.usage_limits,
    failover: formData.failover,
    load_balancing: formData.load_balancing,
    provider: formData.provider,
    model: formData.model,
    api_key_secret_id: formData.api_key_secret_id,
    listen_address: formData.listen_address,
    route: formData.route,
    route_prefix: selectedPrefix,
    route_prefix_resolved: routePrefixResolved,
    custom_path: customPath,
    canvas: (formData as any).canvas || undefined,
    pipe_type: {
      type: 'llm',
      provider: { endpoint: formData.endpoint_url },
    },
  };
}

/**
 * Merge a pasted/edited configuration into the current pipe form, importing
 * the incoming behavioural config (including name + description) while
 * preserving THIS surface's identity and routing (`id`, `route`,
 * `listen_address`) so copying a config between surfaces can never introduce a
 * duplicate listener/route or clobber the surface id. Accepts either a
 * `formData`-shaped payload (what the Config tab renders) or a full backend
 * wire config (carrying `pipe_type`), which is first mapped back to form shape.
 * Pure — the caller owns React state and the canvas reseed. Returns the merged
 * form on success or an error string surfaced inline by the Config editor.
 */
export function mergeImportedPipeConfig(
  current: PipeFormData,
  parsed: unknown,
  llmProviders: LLMProvider[]
): PipeFormData | string {
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return 'Configuration must be a JSON object';
  }
  const obj = parsed as Record<string, unknown>;
  const incoming: Partial<PipeFormData> =
    obj.pipe_type && typeof obj.pipe_type === 'object'
      ? mapPipeToFormData(obj as unknown as PipeConfig, llmProviders).formData
      : (obj as Partial<PipeFormData>);
  return {
    ...current,
    ...incoming,
    id: current.id,
    route: current.route,
    listen_address: current.listen_address,
  } as PipeFormData;
}
