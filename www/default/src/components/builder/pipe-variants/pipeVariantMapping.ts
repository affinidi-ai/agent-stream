import type {
  LLMProvider,
  PipeConfig,
  PipeFormData,
  ProviderUrlForm,
} from '../../../pages/EditPipePage/types';
import {
  audioInputFromCanvas,
  buildUpstreamHeaders,
  documentInputFromCanvas,
  imageInputFromCanvas,
  realtimeFromCanvas,
  storedProviderUrl,
} from '../../../pages/EditPipePage/pipeMappingHelpers';
import { applySnapshotToFormData, snapshotFromFormData } from './pipeVariantSnapshot';
import type { PipeSnapshot } from './pipeVariantSnapshot';
import type { PipeVariantMeta, PipeVariantOverridesWire } from './usePipeVariantSnapshots';

/**
 * Load / save mapping for full-snapshot pipe variants. Bridges the wire
 * `PipeVariantOverrides` (`src/pipes/pipe_variants.rs`) and the editor's
 * behavioural {@link PipeSnapshot}. Kept separate from the upstream-only
 * helpers in `pipeMappingHelpers.ts` so the snapshot machinery is self-
 * contained.
 */

/** Builder for the wire `pipe_type` (LLM upstream) from flat upstream fields. */
export type LlmPipeTypeBuilder = (
  upstream: {
    provider: string;
    model: string;
    endpoint_url: string;
    provider_url?: ProviderUrlForm | null;
    api_key_secret_id: string;
    model_parameters?: Record<string, unknown>;
  },
  llmProviders: LLMProvider[]
) => Record<string, unknown>;

/**
 * Project a behavioural snapshot into the wire `PipeVariantOverrides`
 * (frozen `complete: true` snapshot). `buildLlmPipeType` is injected so
 * the variant's `pipe_type` is built identically to the base pipe's.
 */
export function buildPipeVariantOverrides(
  snap: PipeSnapshot,
  llmProviders: LLMProvider[],
  buildLlmPipeType: LlmPipeTypeBuilder
): PipeVariantOverridesWire {
  const overrides: PipeVariantOverridesWire = {
    complete: true,
    pipe_type: buildLlmPipeType(
      {
        provider: snap.provider,
        model: snap.model,
        endpoint_url: snap.endpoint_url,
        provider_url: snap.provider_url,
        api_key_secret_id: snap.api_key_secret_id,
        model_parameters: snap.model_parameters,
      },
      llmProviders
    ),
    rate_limit: {
      enabled: snap.rate_limit_enabled,
      requests_per_minute: snap.requests_per_minute,
      tokens_per_minute: snap.tokens_per_minute,
    },
    cost_tracking: {
      enabled: snap.cost_tracking_enabled,
      input_price_per_1k: snap.input_price_per_1k,
      output_price_per_1k: snap.output_price_per_1k,
    },
  };
  if (snap.override_policy && Object.keys(snap.override_policy).length > 0) {
    overrides.override_policy = snap.override_policy;
  }
  // Upstream headers are the variant's own upstream credential, so each
  // variant carries its own list; under `complete: true` an omitted list
  // sends none, matching the backend.
  const upstreamHeaders = buildUpstreamHeaders(snap.upstream_headers);
  if (upstreamHeaders) overrides.upstream_headers = upstreamHeaders;
  if (snap.opa_policy) overrides.opa_policy = snap.opa_policy;
  if (snap.prompt_guard) overrides.prompt_guard = snap.prompt_guard;
  if (snap.judge) overrides.judge = snap.judge;
  if (snap.jury) overrides.jury = snap.jury;
  // Per-variant inbound modality / realtime blocks come from the variant's own
  // canvas nodes (the runtime reads these structured fields, not the canvas).
  // Under `complete: true` a variant that omits one clears it, so a chat variant
  // with no Audio Stream node has no realtime while a voice variant does — the
  // per-variant separation the Router relies on.
  const realtime = realtimeFromCanvas(snap.canvas);
  if (realtime) overrides.realtime = realtime;
  const audioInput = audioInputFromCanvas(snap.canvas);
  if (audioInput) overrides.audio_input = audioInput;
  const imageInput = imageInputFromCanvas(snap.canvas);
  if (imageInput) overrides.image_input = imageInput;
  const documentIngestion = documentInputFromCanvas(snap.canvas);
  if (documentIngestion) overrides.document_ingestion = documentIngestion;
  if (snap.canvas != null) overrides.canvas = snap.canvas;
  return overrides;
}

/**
 * Resolve one wire variant's overrides into a full behavioural snapshot,
 * starting from the base pipe form. Fields absent from the override
 * (a `complete` snapshot may legitimately clear them) fall back to the
 * base form's value, which also makes the legacy upstream-only wire
 * (only `overrides.pipe_type`) round-trip cleanly.
 */
function snapshotFromWireVariant(
  wire: { overrides?: PipeVariantOverridesWire },
  baseForm: PipeFormData,
  llmProviders: LLMProvider[]
): PipeSnapshot {
  const base = snapshotFromFormData(baseForm);
  const ov = wire.overrides;
  if (!ov) return base;

  const next: PipeSnapshot = { ...base };

  const pt = ov.pipe_type as { provider?: any; endpoint_path?: string } | undefined;
  if (pt?.provider) {
    const prov = pt.provider as Record<string, any>;
    const enumValue = prov._marketplace_source?.purchased_id
      ? `mp_${prov._marketplace_source.purchased_id}`
      : prov.provider_type || prov.provider || base.provider;
    next.provider = enumValue;
    next.model =
      enumValue === 'azure_openai' ? prov.deployment_name || base.model : prov.model || base.model;
    next.api_key_secret_id =
      prov.api_key_secret || prov.api_key_secret_id || base.api_key_secret_id;
    next.endpoint_url = unprefixEndpoint(pt.endpoint_path, enumValue, prov, llmProviders, base);
    next.provider_url = storedProviderUrl(prov, enumValue);
  }

  const rl = ov.rate_limit as
    | { enabled?: boolean; requests_per_minute?: number; tokens_per_minute?: number }
    | undefined;
  if (rl) {
    next.rate_limit_enabled = rl.enabled ?? base.rate_limit_enabled;
    next.requests_per_minute = rl.requests_per_minute ?? base.requests_per_minute;
    next.tokens_per_minute = rl.tokens_per_minute ?? base.tokens_per_minute;
  }

  const ct = ov.cost_tracking as
    | { enabled?: boolean; input_price_per_1k?: number; output_price_per_1k?: number }
    | undefined;
  if (ct) {
    next.cost_tracking_enabled = ct.enabled ?? base.cost_tracking_enabled;
    next.input_price_per_1k = ct.input_price_per_1k ?? base.input_price_per_1k;
    next.output_price_per_1k = ct.output_price_per_1k ?? base.output_price_per_1k;
  }

  // Mirrors `resolve_variant`: an absent list is empty for a complete snapshot
  // or an upstream-swapping variant (the base's headers are the base
  // upstream's credential), and inherited only by a sparse same-upstream one.
  if (Array.isArray(ov.upstream_headers)) {
    next.upstream_headers = ov.upstream_headers;
  } else if (ov.complete || pt?.provider) {
    next.upstream_headers = [];
  }

  next.override_policy = (ov.override_policy as Record<string, string>) ?? base.override_policy;
  next.opa_policy = ov.opa_policy !== undefined ? (ov.opa_policy as any) : base.opa_policy;
  next.prompt_guard = ov.prompt_guard !== undefined ? (ov.prompt_guard as any) : base.prompt_guard;
  next.judge = ov.judge !== undefined ? (ov.judge as any) : base.judge;
  next.jury = ov.jury !== undefined ? (ov.jury as any) : base.jury;
  next.canvas = ov.canvas !== undefined ? ov.canvas : base.canvas;
  return next;
}

/** Strip a provider's version prefix from a wire `endpoint_path`. */
function unprefixEndpoint(
  endpointPath: string | undefined,
  enumValue: string,
  prov: Record<string, any>,
  llmProviders: LLMProvider[],
  base: PipeSnapshot
): string {
  if (enumValue === 'azure_openai') return prov.endpoint || base.endpoint_url;
  if (typeof endpointPath !== 'string') return base.endpoint_url;
  const provider = llmProviders.find(p => p.enum_value === enumValue);
  const prefix = provider?.api_version_prefix || '';
  if (!prefix) return endpointPath;
  // Strip *every* leading prefix repeat. The save side prepends exactly one
  // prefix, so collapsing repeats here keeps the round-trip idempotent and
  // self-heals paths that accumulated duplicate prefixes (e.g.
  // `/v1/v1/v1/chat/completions`) from earlier saves.
  let path = endpointPath;
  while (path.startsWith(prefix)) {
    path = path.slice(prefix.length);
  }
  return path;
}

/**
 * Parse a loaded pipe's wire variant catalog into snapshot-manager
 * inputs: each variant's metadata + its fully-resolved behavioural
 * snapshot, plus the default variant id.
 */
export function parsePipeVariants(
  pipe: PipeConfig,
  baseForm: PipeFormData,
  llmProviders: LLMProvider[]
): {
  variantForms: Array<{ meta: PipeVariantMeta; snapshot: PipeSnapshot }>;
  defaultVariantId: string | null;
} {
  const raw = (pipe as any).variants;
  const list: any[] = Array.isArray(raw) ? raw : [];
  const variantForms = list.map(v => ({
    meta: {
      id: v.id ?? (typeof crypto !== 'undefined' ? crypto.randomUUID() : `${Date.now()}`),
      alias: v.alias ?? '',
      name: v.name ?? '',
      description: typeof v.description === 'string' ? v.description : undefined,
      enabled: v.enabled !== false,
    } as PipeVariantMeta,
    snapshot: snapshotFromWireVariant(v, baseForm, llmProviders),
  }));
  const defaultVariantId =
    typeof (pipe as any).default_variant_id === 'string' && (pipe as any).default_variant_id
      ? (pipe as any).default_variant_id
      : null;
  return { variantForms, defaultVariantId };
}

/** Re-export so the page can build the active form from a base + snapshot. */
export { applySnapshotToFormData, snapshotFromFormData };
export type { PipeSnapshot };
