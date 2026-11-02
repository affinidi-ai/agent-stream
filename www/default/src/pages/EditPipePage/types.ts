import type { MarketplaceProviderMeta } from '../../utils/marketplaceProviders';
import type { EntityStatus } from '../../generated/EntityStatus';
import type { SourceAuthConfig } from '../../types';
import type { PromptGuardConfig } from './tabs/promptGuardTypes';
import type { JudgeConfig } from './tabs/JudgeTab';
import type { JuryConfig } from './tabs/JuryTab';
import type { DeciderConfig } from '../../components/shared/deciderModel';
import type { WitnessConfig } from '../../components/shared/witnessModel';
import type { FailoverConfig, LoadBalancingConfig } from '../../components/shared/resilienceModel';
import type { PipeUsageLimitEntry } from '../../components/builder/PipeBuilderPanel';

export interface ModelParameter {
  name: string;
  label: string;
  type: 'number' | 'string' | 'boolean' | 'select' | 'array' | 'object' | 'text' | 'multi-select';
  default: any;
  min?: number;
  max?: number;
  step?: number;
  description?: string;
  options?: string[];
  applies_to_models?: string[];
}

export interface LLMModel {
  name: string;
  value: string;
  enabled?: boolean;
  cost_per_1k_input: number;
  cost_per_1k_output: number;
  model_parameters?: ModelParameter[];
  rate_limiting?: {
    can_disable: boolean;
    can_change: boolean;
    requests_per_minute: {
      min: number;
      max: number;
      default: number;
    };
    tokens_per_minute: {
      min: number;
      max: number;
      default: number;
    };
  };
}

export interface LLMEndpoint {
  name: string;
  path: string;
  description: string;
  is_default?: boolean;
  capabilities?: string[];
  endpoint_parameters?: ModelParameter[];
}

export interface LLMProvider {
  name: string;
  enum_value: string;
  enabled?: boolean;
  default_base_url?: string;
  api_version_prefix?: string;
  api_schema?: string;
  marketplace_url?: string;
  endpoints: LLMEndpoint[];
  icon: string;
  api_key_label: string;
  api_key_required?: boolean;
  /** Three-state key policy (`mandatory` | `optional` | `none`). */
  api_key_validation?: string;
  filter_tag?: string;
  models: LLMModel[];
  _marketplace?: MarketplaceProviderMeta;
}

export interface Secret {
  id: string;
  name: string;
  secret_id?: string;
  secret_type?: string;
  tags?: string[];
}

/**
 * Per-pipe OPA gate. Mirrors the backend `PipeOpaConfig`
 * (`src/pipes/config.rs`): when `enabled`, the gateway evaluates the
 * referenced policy definition against each inbound request and denies
 * (403) on a `false` result. Fail-closed when enabled without a definition.
 */
export interface PipeOpaPolicy {
  enabled: boolean;
  policy_definition_id?: string;
  log_decisions?: boolean;
}

/**
 * Backend wire shape of a `UsageLimit` (`src/pipes/config.rs`): a monthly
 * spend / token ceiling for a stage (or the pipe-wide cumulative total) that
 * blocks calls (429) once reached.
 */
export interface UsageLimitWire {
  id: string;
  enabled?: boolean;
  scope?: 'cumulative' | 'stage';
  stage?: 'llm' | 'judge' | 'jury' | null;
  /** Index of the targeted juror in `jury.jurors` (Jury stage only). */
  juror_index?: number | null;
  monthly_budget_usd?: number | null;
  monthly_token_cap?: number | null;
}

export interface PipesConfig {
  llm?: {
    paths?: Array<{ id: string; name: string; prefix: string }>;
    providers?: LLMProvider[];
  };
  mcp_proxies?: {
    paths?: Array<{ id: string; name: string; prefix: string }>;
  };
  input_modalities?: import('../../components/builder/elements/pipe/pipePanelData').InputModalitySupport;
  audio_streams?: import('../../components/builder/elements/pipe/pipePanelData').AudioStreamsCatalog;
}

/** Wire shape of a surface's governed server-tools config. */
export interface ServerToolsWire {
  enabled?: boolean;
  max_iterations?: number;
  web_search?: {
    enabled?: boolean;
    engine?: string;
    engine_secret?: string;
    max_results?: number;
    google_cse_id?: string;
    domain_policy?: 'allow_all' | 'block_all';
    domain_exceptions?: string[];
  } | null;
  web_fetch?: {
    enabled?: boolean;
    max_content_bytes?: number;
    domain_policy?: 'allow_all' | 'block_all';
    domain_exceptions?: string[];
  } | null;
}

/** Per-surface context-window management (middle-out compression). */
export interface ContextManagementForm {
  enabled: boolean;
  context_window_tokens: number | null;
  keep_recent_messages: number;
  reserve_output_tokens: number;
}

/** Per-surface inbound document ingestion (parse attached documents to text). */
export interface DocumentIngestionForm {
  enabled: boolean;
  allowed_types: string[];
  max_file_bytes: number;
  max_extracted_chars: number;
  mode: 'auto' | 'extract' | 'passthrough';
}

export interface PipeConfig {
  id: string;
  name: string;
  description?: string;
  status: EntityStatus;
  pipe_type: {
    LLM?: {
      provider: string;
      model: string;
      endpoint_url: string;
      api_key_secret_id?: string;
      max_tokens?: number;
      temperature?: number;
    };
  };
  rate_limit?: {
    enabled?: boolean;
    requests_per_minute?: number;
    tokens_per_minute?: number;
  };
  cost_tracking?: {
    enabled: boolean;
    input_price_per_1k?: number;
    output_price_per_1k?: number;
  };
  override_policy?: Record<string, string>;
  opa_policy?: PipeOpaPolicy | null;
  prompt_guard?: PromptGuardConfig | null;
  judge?: JudgeConfig | null;
  jury?: JuryConfig | null;
  decider?: DeciderConfig | null;
  /** Monthly spend / token ceilings enforced per stage or cumulatively. */
  usage_limits?: UsageLimitWire[];
  /**
   * SSE streaming passthrough opt-out. Mirrors the backend `StreamingConfig`
   * (`src/pipes/config.rs`): when `enabled` is false the surface never streams
   * even if the client requests it. Base-pipe-level (not variant-overridable).
   */
  streaming?: { enabled: boolean } | null;
  /**
   * Cross-provider failover (`FailoverConfig`, `src/pipes/config.rs`). Ordered
   * backup providers tried on a transport/upstream failure of the primary.
   * Base-pipe-level (not variant-overridable).
   */
  failover?: FailoverConfig | null;
  /**
   * Weighted load-balancing pool (`LoadBalancingConfig`). Distributes requests
   * across the primary and weighted backups. Base-pipe-level; takes precedence
   * over `failover` at runtime when both are set.
   */
  load_balancing?: LoadBalancingConfig | null;
  /**
   * Breach / anomaly alerts (`Vec<UsageAlert>`). Fire through the pipe
   * integration / notification system. Variant-overridable, but edited as the
   * base-pipe value on the surface sidebar.
   */
  usage_alerts?: UsageAlertForm[];
  /**
   * Inbound caller authentication (`source_auth`). Base-pipe-level (not
   * variant-overridable in v1). Edited via the `pipe-caller-auth` edge-bound
   * anchor on the LLM Surface canvas — the same panel component the IDE
   * Surface uses. Absent when no caller-context element is configured; the
   * surface then falls back to whatever gateway-wide auth applies.
   */
  source_auth?: SourceAuthConfig | null;
  /**
   * Governed server tools (`web_search` / `web_fetch`) the gateway executes on
   * the surface's behalf. Off by default. Edited via the `pipe-web-search` /
   * `pipe-web-fetch` nodes in the Tools palette; assembled on save from the
   * canvas (`serverToolsFromCanvas`). See `src/pipes/server_tools.rs`.
   */
  server_tools?: ServerToolsWire | null;
  /**
   * Context-window guard + `middle-out` compression
   * (`src/pipes/context_transform.rs`). Off by default; when enabled an
   * over-window prompt is compressed before the upstream call.
   */
  context_management?: ContextManagementForm | null;
  /**
   * Inbound document ingestion (`src/pipes/document_ingestion.rs`). Off by
   * default; when enabled, inline document parts are gated + extracted to
   * prompt text.
   */
  document_ingestion?: DocumentIngestionForm | null;
  /**
   * Signed governance recording (`GovernanceRecordingConfig`,
   * `src/governance/config.rs`). Off by default; when present and enabled,
   * every interaction on the surface is captured as a signed, chained VC.
   * Base-pipe-level (not variant-overridable).
   */
  governance_recording?: GovernanceRecordingForm | null;
  /**
   * Per-surface LLM drift monitoring (`DriftConfig`, `src/drift/config.rs`).
   * Off by default; when enabled a sampled fraction of live traffic feeds the
   * surface's drift dimensions. Base-pipe-level (not variant-overridable).
   */
  drift?: DriftForm | null;
  /**
   * Per-surface verifiable-presentation evidence (`VpEvidenceConfig`,
   * `src/pipes/config.rs`). Off by default; when enabled an inbound VP is
   * verified and injected as `input.identity_binding` for the surface policy.
   */
  vp_evidence?: VpEvidenceForm | null;
  /** Opaque management-dashboard canvas blob (node positions, viewport). */
  canvas?: any;
  /**
   * Dashboard-only hint: run Auto Layout the first time the surface opens (then
   * clear it on save). Set on a machine-generated surface with no hand-authored
   * canvas. The runtime never reads it.
   */
  auto_canvas?: boolean;
  /** Upstream-only variant catalog addressed by `$alias`. */
  variants?: PipeVariant[];
  /** Id of the variant selected when a request carries no `$alias`. */
  default_variant_id?: string;
  created_at: string;
  updated_at?: string;
}

/**
 * Catalog metadata for a `$alias`-addressable pipe variant. Mirrors the
 * identity fields of the backend `PipeVariant` (`src/pipes/pipe_variants.rs`).
 *
 * A variant's full behavioural snapshot (upstream, rate limit, policies,
 * prompt guard, judge, jury, canvas) lives in the page's snapshot
 * manager (`usePipeVariantSnapshots`), keyed by `id` — it is NOT stored
 * inline here. {@link buildPipePayload} folds each snapshot into the
 * wire `overrides` and the loader resolves them back. Switching a
 * variant re-renders the whole pipe canvas from that snapshot.
 */
export interface PipeVariant {
  /** Stable UUID. Survives renames of `alias` / `name`. */
  id: string;
  /** URL-safe alias used in `/route$alias/...`. Grammar `^[a-z0-9-]{1,32}$`. */
  alias: string;
  name: string;
  description?: string;
  /** Whether this variant accepts traffic. Defaults to true. */
  enabled?: boolean;
}

export interface RoutingConfig {
  available_listen_addresses: string[];
  pipe_path_prefix: Array<{ id: string; name: string; prefix: string }>;
}

/** Which field of an mTLS client certificate carries the caller identity. */
export type MtlsCallerBinding = 'email_san' | 'subject_cn';

/**
 * Where the caller's identity lives in an inbound request. Mirrors the backend
 * `CallerIdentitySource` tagged enum (snake_case `type` discriminant). This is
 * surface-type agnostic so any future surface type can reuse it.
 */
export type CallerIdentitySourceForm =
  | { type: 'header'; name: string }
  | { type: 'jwt_claim'; claim: string }
  | { type: 'body_json_path'; path: string }
  | { type: 'mtls'; binding: MtlsCallerBinding }
  | { type: 'api_key' };

/** Breach / anomaly alert kind. Mirrors the backend `AlertType` (lowercase). */
export type UsageAlertType = 'cost_threshold' | 'token_threshold' | 'error_rate' | 'cost_spike';

/**
 * A single breach / anomaly alert (`UsageAlert`, `src/pipes/config.rs`). The
 * `threshold` meaning is per-type: per-execution USD (`cost_threshold`),
 * per-execution total tokens (`token_threshold`), a rolling-window error-rate
 * fraction in `(0, 1]` (`error_rate`), or a spike multiplier `> 1` over the
 * mean cost (`cost_spike`). `notification_channels` are integration ids.
 */
export interface UsageAlertForm {
  alert_type: UsageAlertType;
  threshold: number;
  notification_channels: string[];
}

/** Surface opt-in for contributing usage to team quotas. */
export interface TeamAttributionForm {
  enabled: boolean;
  /**
   * Ordered list of places to look for the caller's identity. The gate uses the
   * first source that yields a non-empty value. Mirrors the backend
   * `caller_identity_sources` (a legacy singular `caller_email_source` is still
   * read and folded into a one-element list).
   */
  caller_identity_sources: CallerIdentitySourceForm[];
  /**
   * When set, a verified but unrecognised caller is auto-provisioned into a
   * member on first sight per the appliance Enrolment rules, instead of the
   * anonymous fallback.
   */
  auto_provision: boolean;
  enforce: boolean;
  allow_individual_overage: boolean;
  /**
   * Surface→team access mapping. When non-empty, only callers belonging to one
   * of these team ids may use the surface (access control, independent of
   * `enforce`). When empty, every resolved caller is allowed.
   */
  allowed_teams: string[];
}

/** A saved surface's provider URL and the provider it belongs to. */
export interface ProviderUrlForm {
  provider: string;
  url: string;
}

/**
 * Response-cache config for a surface. Mirrors the backend `CacheConfig`
 * (`cache: { enabled, ttl_seconds, max_entries, mode, similarity_threshold,
 * embedder }`). `null` on the form when caching is off.
 */
export interface PipeCacheEmbedderForm {
  endpoint_url: string;
  model: string;
  api_key_secret?: string | null;
}

export interface PipeCacheForm {
  enabled: boolean;
  ttl_seconds: number;
  max_entries: number;
  mode: 'exact' | 'semantic';
  similarity_threshold: number;
  embedder: PipeCacheEmbedderForm | null;
}

/**
 * One weighted canary target. `variant` is a variant alias, or '' for the base
 * surface. Backend `CanarySplit { variant?, weight }`.
 */
export interface PipeCanarySplitForm {
  variant: string;
  weight: number;
}

/**
 * Canary / A-B traffic split across variants (`CanaryConfig`). When enabled and
 * a request does not address a variant explicitly, the gateway picks a target by
 * weight. Base-pipe-level (not variant-overridable). `null` when off.
 */
export interface PipeCanaryForm {
  enabled: boolean;
  splits: PipeCanarySplitForm[];
}

/**
 * One attribute-based routing rule (`RoutingRule`). When the `match` condition
 * holds, the request routes to `target.variant` (a variant alias) or, when that
 * is unset, an inline `target.llm` provider target (preserved as-is by the UI).
 */
export interface PipeRoutingRuleForm {
  match:
    | { kind: 'header'; name: string; equals: string }
    | { kind: 'body_field'; field: string; equals: string }
    | { kind: 'modality'; has: string };
  target: { variant?: string | null; llm?: any };
}

/**
 * Export targets for signed governance records (mirrors the backend
 * `GovernanceExport`, `src/governance/config.rs`). Records fan out to the
 * OpenTelemetry exporter and/or any number of configured integrations
 * (webhook, Slack, email, Kafka/Kinesis/Pulsar/Redis stream, Langfuse).
 */
export interface GovernanceExportForm {
  /** Emit each signed VC to the OpenTelemetry log/trace exporter. */
  otel?: boolean;
  /** Integration ids to dispatch each signed record to. */
  integrations?: string[];
}

/**
 * Signed governance recording for a surface (mirrors the backend
 * `GovernanceRecordingConfig`, `src/governance/config.rs`). When `enabled`,
 * every interaction is captured as a signed, chained VC. Base-pipe-level (not
 * variant-overridable). `null` when the surface carries no recording block.
 */
export interface GovernanceRecordingForm {
  enabled: boolean;
  /** Which records keep their text: `true` all, `false` none (digests only), `'blocked'` blocked ones only. */
  capture_bodies?: boolean | 'blocked';
  /** Which interactions are recorded; the backend default is `all`. */
  record_outcomes?: 'all' | 'blocked' | 'blocked_and_failed';
  include_streaming?: boolean;
  retention_days?: number;
  export?: GovernanceExportForm | null;
}

/**
 * Per-surface LLM drift monitoring (mirrors backend `DriftConfig`,
 * `src/drift/config.rs`). When `enabled`, a `sample_rate` fraction of live
 * interactions feeds the surface's drift dimensions. Base-pipe-level (not
 * variant-overridable). `null` when the surface carries no drift block.
 */
export interface DriftForm {
  enabled: boolean;
  sample_rate?: number;
  /** Relative-change fraction flagged `warn` (absent ⇒ backend default 0.25). */
  warn_threshold?: number;
  /** Relative-change fraction flagged `drift` (absent ⇒ backend default 0.50). */
  drift_threshold?: number;
  /** Block a surface save while the surface is drifting past its baseline. */
  gate_on_regression?: boolean;
  /** Replay-based evaluation of the surface's captured "indicative" sessions. */
  eval?: DriftEvalForm;
  /** Per-surface `drift.detected` alert cadence overrides (else gateway defaults). */
  alert_cadence?: { re_alert_interval_mins?: number; max_alerts?: number };
  /** Integration ids the `drift.detected` alert fires to (empty ⇒ event mappings). */
  alert_integrations?: string[];
}

/**
 * Replay-based drift evaluation (mirrors backend `DriftEvalConfig`,
 * `src/drift/config.rs`). Periodically re-runs the surface's captured sessions
 * and compares each new answer to the originally-captured one.
 */
export interface DriftEvalForm {
  enabled?: boolean;
  /** Auto-run schedule; `interval_secs` is floored to 300s by the scheduler. */
  schedule?: { enabled: boolean; interval_secs: number };
  /** Embeddings model (chosen from the catalog) that measures semantic distance. */
  embeddings?: { endpoint_url: string; model: string; api_key_secret?: string };
  /** Cap on how many captured sessions one evaluation replays. */
  max_sessions?: number;
  /** Ceiling on the provider spend (USD) one evaluation run may consume before
   * it stops part-way. Omitted = the appliance default; `0` = no ceiling. */
  max_run_cost_usd?: number;
}

/**
 * Per-surface VP evidence (mirrors backend `VpEvidenceConfig`,
 * `src/pipes/config.rs`). `null` when the surface requires no VP.
 */
export interface VpEvidenceForm {
  enabled: boolean;
  require_present?: boolean;
  source?: 'header' | 'body';
  header_name?: string;
}

/**
 * One extra header sent to the surface's own upstream (mirrors backend
 * `UpstreamHeader`, `src/pipes/upstream_headers.rs`). The value is never stored
 * here — only the secret reference the gateway resolves at request time.
 */
export interface UpstreamHeaderForm {
  name: string;
  secret_id: string;
}

/**
 * Declared price of an upstream in USD per 1M tokens (mirrors backend
 * `TargetPricing`, `src/pipes/types/llm.rs`). Unlike the cost-tracking
 * override, zero is a real price (a model the operator runs themselves).
 */
export interface TargetPricingForm {
  input_per_million: number;
  output_per_million: number;
}

export interface PipeFormData {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  listen_address: string;
  route: string;
  provider: string;
  model: string;
  endpoint_url: string;
  /**
   * The provider URL (`base_url`, or `endpoint` on providers that use it) the
   * saved surface already has, kept for the provider it was saved with. The
   * editor shows no field for it, so a save writes it back unchanged instead
   * of the catalog default; a changed URL moves where the stored key goes.
   */
  provider_url: ProviderUrlForm | null;
  api_key_secret_id: string;
  model_parameters: Record<string, any>;
  rate_limit_enabled: boolean;
  requests_per_minute: number;
  tokens_per_minute: number;
  cost_tracking_enabled: boolean;
  input_price_per_1k: number;
  output_price_per_1k: number;
  override_policy: Record<string, string>;
  opa_policy: PipeOpaPolicy | null;
  prompt_guard: PromptGuardConfig | null;
  judge: JudgeConfig | null;
  jury: JuryConfig | null;
  decider: DeciderConfig | null;
  /**
   * Expert-witness roster (external safety classifiers). Base-pipe-level;
   * edited via the two witness seam circles on the canvas. Flat backend
   * `expert_witnesses` shape.
   */
  expert_witnesses: WitnessConfig[];
  /**
   * Inbound caller authentication. Base-pipe-level (not variant-overridable in
   * v1); edited via the `pipe-caller-auth` edge-bound anchor on the canvas
   * (the same panel component the IDE Surface uses). `null` when no
   * caller-context element is configured.
   */
  source_auth: SourceAuthConfig | null;
  /**
   * Governed server tools (`web_search` / `web_fetch`). Base-pipe-level; the
   * source of truth is the canvas (the `pipe-web-search` / `pipe-web-fetch`
   * Tools-palette nodes), so on save this is derived from the canvas and used
   * only as a fallback. `null` when no tool node is configured.
   */
  server_tools: ServerToolsWire | null;
  /**
   * Per-surface context-window management (middle-out compression). `null`
   * when unconfigured. Round-trips as the backend `context_management` block.
   */
  context_management: ContextManagementForm | null;
  /**
   * Per-surface inbound document ingestion. `null` when unconfigured.
   * Round-trips as the backend `document_ingestion` block.
   */
  document_ingestion: DocumentIngestionForm | null;
  /** Usage limits (monthly spend / token ceilings) edited via canvas nodes. */
  usage_limits: PipeUsageLimitEntry[];
  /** Surface-wide cumulative usage limit, edited on the surface property sidebar. */
  surface_usage_limit: PipeUsageLimitEntry | null;
  /** Team attribution opt-in (surface contributes usage to team quotas). */
  team_attribution: TeamAttributionForm | null;
  /**
   * Signed governance recording (mirrors backend `GovernanceRecordingConfig`,
   * `src/governance/config.rs`). Base-pipe-level (not variant-overridable);
   * edited via the Config (JSON) view and surfaced as a builder header
   * indicator. `null` when the surface carries no recording block.
   */
  governance_recording: GovernanceRecordingForm | null;
  /**
   * Per-surface LLM drift monitoring (mirrors backend `DriftConfig`,
   * `src/drift/config.rs`). Base-pipe-level (not variant-overridable); edited
   * on the surface sidebar / Config (JSON) view. `null` when unconfigured.
   */
  drift: DriftForm | null;
  /**
   * Per-surface VP evidence (mirrors backend `VpEvidenceConfig`). Base-pipe-
   * level; edited on the surface sidebar / Config (JSON) view. `null` when the
   * surface requires no verifiable presentation.
   */
  vp_evidence: VpEvidenceForm | null;
  /**
   * Whether SSE streaming passthrough is allowed when the client requests it.
   * Base-pipe-level (not variant-overridable); edited on the surface sidebar.
   */
  streaming_enabled: boolean;
  forward_caller_token: boolean;
  /**
   * Extra headers sent to this surface's own upstream alongside the provider
   * credential, each value resolved from a secret at request time. Lets any
   * provider reach an upstream that authenticates the gateway separately from
   * the model (mesh ingress, reverse proxy, tunnel ingress key). LLM-surface
   * concern; edited on the LLM config tab.
   */
  upstream_headers: UpstreamHeaderForm[];
  /**
   * Declared price of this surface's own upstream, used ahead of the cost
   * override and the catalog. Not edited in the dashboard; carried through a
   * save so an API-set price (zero for an own model) is not dropped.
   */
  upstream_pricing: TargetPricingForm | null;
  /**
   * Client API formats this surface answers. Inbound format is negotiated per
   * request by path (`openai_chat` = /v1/chat/completions, `anthropic_messages`
   * = /v1/messages, `openai_responses` = /v1/responses) and normalized to the
   * OpenAI-canonical pipeline. Defaults to all three; restrict to lock a surface
   * to specific client dialects. Base-pipe-level; edited on the surface sidebar.
   */
  accepted_ingress_schemas: string[];
  /**
   * Governor ceiling for provider reasoning ("thinking") tokens per request.
   * When set (> 0), a caller's requested reasoning budget is clamped to this
   * value and the effort level lowered to match, bounding both budget-based
   * upstreams (Anthropic, Gemini) and effort-based ones (OpenAI). `null` leaves
   * reasoning uncapped. LLM-surface concern; edited on the LLM config tab.
   */
  max_reasoning_tokens: number | null;
  /**
   * Optional per-surface sandbox sign-in override (public OAuth identifiers
   * only). When set, the Sandbox tab uses it in preference to the provider's
   * catalog `sandbox_auth` (surface-override → provider-default), so a surface
   * can carry its own test identity without editing the shared LLM catalog.
   */
  sandbox_auth: Record<string, unknown> | null;
  /**
   * Optional reference to an OAuth Identifier profile (Credentials store) used
   * as this surface's sandbox "Sign in to test" identity. The preferred sandbox
   * sign-in path — resolved to a PKCE config in the browser, taking precedence
   * over the inline `sandbox_auth` block and the provider catalog default.
   */
  sandbox_oauth_identifier_id: string | null;
  /**
   * Response cache config (exact or semantic matching). `null` when caching is
   * off. Variant-overridable on the backend; edited on the surface sidebar.
   */
  cache: PipeCacheForm | null;
  /**
   * Canary / A-B traffic split across variants. `null` when off. Base-pipe-level
   * (not variant-overridable); edited on the surface sidebar.
   */
  canary: PipeCanaryForm | null;
  /**
   * Attribute-based routing rules (header / body-field match → variant alias or
   * inline target). Evaluated before canary. Base-pipe-level. Empty when unused.
   */
  routing_rules: PipeRoutingRuleForm[];
  /**
   * Whether attribute-based routing is enforced. When off the `routing_rules`
   * are retained (so the surface round-trips and can be re-enabled without
   * rework) but never evaluated. Mirrors the backend `routing_enabled` flag.
   */
  routing_enabled: boolean;
  /**
   * Cross-provider failover config (ordered backups). Base-pipe-level; edited
   * on the LLM upstream fullscreen editor. `null` when off.
   */
  failover: FailoverConfig | null;
  /**
   * Weighted load-balancing pool. Base-pipe-level; edited on the LLM upstream
   * fullscreen editor. `null` when off. Mutually exclusive with `failover`.
   */
  load_balancing: LoadBalancingConfig | null;
  /**
   * Breach / anomaly alerts. Edited on the surface property sidebar; each entry
   * fires through the pipe integration / notification system.
   */
  usage_alerts: UsageAlertForm[];
  /**
   * Whether breach/anomaly alerts are enforced. When off the `usage_alerts` are
   * retained but never evaluated. Mirrors the backend `usage_alerts_enabled`.
   */
  usage_alerts_enabled: boolean;
  /** Variant catalog metadata edited in the variants properties panel. */
  variants: PipeVariant[];
  /** Id of the default (alias-less) variant, when variants are defined. */
  default_variant_id: string | null;
  created_at: string;
}

export const EMPTY_PIPE_FORM: PipeFormData = {
  id: '',
  name: '',
  description: '',
  enabled: true,
  listen_address: '',
  route: '',
  provider: '',
  model: '',
  endpoint_url: '',
  provider_url: null,
  api_key_secret_id: '',
  model_parameters: {},
  rate_limit_enabled: false,
  requests_per_minute: 60,
  tokens_per_minute: 100000,
  cost_tracking_enabled: true,
  input_price_per_1k: 0,
  output_price_per_1k: 0,
  override_policy: {},
  opa_policy: null,
  prompt_guard: null,
  judge: null,
  jury: null,
  decider: null,
  expert_witnesses: [],
  source_auth: null,
  server_tools: null,
  context_management: null,
  document_ingestion: null,
  usage_limits: [],
  surface_usage_limit: null,
  team_attribution: null,
  governance_recording: null,
  drift: null,
  vp_evidence: null,
  streaming_enabled: true,
  forward_caller_token: false,
  upstream_headers: [],
  upstream_pricing: null,
  accepted_ingress_schemas: ['openai_chat', 'anthropic_messages', 'openai_responses'],
  max_reasoning_tokens: null,
  sandbox_auth: null,
  sandbox_oauth_identifier_id: null,
  cache: null,
  canary: null,
  routing_rules: [],
  routing_enabled: false,
  failover: null,
  load_balancing: null,
  usage_alerts: [],
  usage_alerts_enabled: false,
  variants: [],
  default_variant_id: null,
  created_at: '',
};
