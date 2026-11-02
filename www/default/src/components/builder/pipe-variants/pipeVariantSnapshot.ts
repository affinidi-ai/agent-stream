import type { PipeFormData } from '../../../pages/EditPipePage/types';

/**
 * Full-snapshot machinery for pipe variants — the JS mirror of the
 * backend `PipeConfig::resolve_variant` (`src/pipes/pipe_variants.rs`).
 *
 * A pipe variant is a `$alias`-addressable **full snapshot** of the
 * pipe's behavioural config. Switching a variant in the builder swaps
 * the behavioural slice of `PipeFormData` wholesale, so the whole
 * canvas (upstream, upstream headers, rate limit, OPA, prompt guard, judge, jury) re-
 * renders for that variant — exactly like the surface `target-variant`
 * snapshot model, adapted to the pipe's flat form state.
 *
 * Identity / routing fields (`id`, `name`, `description`, `enabled`,
 * `listen_address`, `route`, `created_at`) are never part of a variant
 * snapshot: they define where the variant is reachable and must match
 * the base so the variant stays addressable at the same
 * `IN_HOST/route$alias/...` path.
 */

/** The behavioural fields a pipe variant may override. */
export const PIPE_VARIANT_FIELDS = [
  'provider',
  'model',
  'endpoint_url',
  'provider_url',
  'api_key_secret_id',
  'model_parameters',
  'upstream_headers',
  'rate_limit_enabled',
  'requests_per_minute',
  'tokens_per_minute',
  'cost_tracking_enabled',
  'input_price_per_1k',
  'output_price_per_1k',
  'override_policy',
  'opa_policy',
  'prompt_guard',
  'judge',
  'jury',
] as const;

export type PipeVariantField = (typeof PIPE_VARIANT_FIELDS)[number];

/**
 * The behavioural slice of `PipeFormData` a variant snapshots, plus the
 * opaque canvas blob (node positions / viewport) so each variant keeps
 * its own layout across save/reload.
 */
export type PipeSnapshot = Pick<PipeFormData, PipeVariantField> & {
  canvas?: unknown;
};

/** Project the full form into a behavioural snapshot (deep-cloned). */
export function snapshotFromFormData(formData: PipeFormData): PipeSnapshot {
  const snap: Record<string, unknown> = {};
  for (const f of PIPE_VARIANT_FIELDS) {
    snap[f] = clone(formData[f]);
  }
  snap.canvas = clone((formData as { canvas?: unknown }).canvas);
  return snap as PipeSnapshot;
}

/**
 * Overlay a behavioural snapshot onto a form, returning a new form. The
 * identity / routing fields and the variant catalog stay as they are on
 * `formData`; only the behavioural slice (and canvas) is replaced.
 */
export function applySnapshotToFormData(formData: PipeFormData, snap: PipeSnapshot): PipeFormData {
  const next: PipeFormData = { ...formData };
  const writable = next as unknown as Record<string, unknown>;
  for (const f of PIPE_VARIANT_FIELDS) {
    writable[f] = clone(snap[f]);
  }
  (next as { canvas?: unknown }).canvas = clone(snap.canvas);
  return next;
}

/** Plain-JSON deep clone (form state carries no Dates / Maps / Sets). */
function clone<T>(value: T): T {
  if (value === undefined || value === null) return value;
  return JSON.parse(JSON.stringify(value)) as T;
}
