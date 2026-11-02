/** Types for the LLM Drift page. Mirrors the backend drift API
 * (`src/identity/handlers/drift.rs`, `src/drift/`). */

/** Display metadata for one drift dimension (`GET /v1/drift/dimensions`). */
export interface DriftDimensionInfo {
  id: string;
  label: string;
  unit: string;
  is_rate: boolean;
  /** What produces this dimension's observations, shown when its chart is empty
   * so "not applicable to this surface" reads differently from "broken". */
  source_hint?: string;
}

/** One point of a drift series: bucket start (unix seconds), the bucket mean,
 * and how many observations it summarises. */
export interface DriftSeriesPoint {
  t: number;
  mean: number;
  count: number;
}

/** A single drift series' range result (`GET /v1/drift/series`). */
export interface DriftSeriesResponse {
  key: string;
  resolution: string;
  step_secs: number;
  points: DriftSeriesPoint[];
}

/** A variant alias exposed by a surface (for the run-through picker). */
export interface DriftSurfaceVariant {
  alias: string;
  name?: string;
}

/** A surface shown in the drift picker. */
export interface DriftSurface {
  surface_id: string;
  surface_name?: string;
  /** Enabled variant aliases, for the "run through" experiment picker. */
  variants?: DriftSurfaceVariant[];
}

export interface DriftRangePreset {
  label: string;
  secs: number;
}

/** Window presets for the drift charts. */
export const DRIFT_RANGE_PRESETS: DriftRangePreset[] = [
  { label: '1H', secs: 3_600 },
  { label: '6H', secs: 21_600 },
  { label: '24H', secs: 86_400 },
  { label: '7D', secs: 604_800 },
  { label: '30D', secs: 2_592_000 },
];

/** The gauge series key for one surface's dimension. Must match
 * `surface_dimension_key` in `src/drift/dimension.rs`. */
export function driftSeriesKey(surfaceId: string, dimensionId: string): string {
  return `drift:surface:${surfaceId}:${dimensionId}`;
}

/** Format a dimension value for a tick / tooltip, honouring its unit. */
export function formatDriftValue(value: number, info: DriftDimensionInfo): string {
  if (info.is_rate) return `${(value * 100).toFixed(1)}%`;
  if (info.unit === 'ms') return `${Math.round(value)} ms`;
  if (info.unit === 'usd') return `$${value.toFixed(4)}`;
  if (info.unit === 'tokens' || info.unit === 'chars') return `${Math.round(value)}`;
  return value.toFixed(2);
}

/** How far a dimension has moved from its baseline (`GET /v1/drift/verdict`). */
export type DriftStatus = 'stable' | 'warn' | 'drift' | 'unknown';

/** One dimension's verdict against its baseline. */
export interface DimensionVerdict {
  dimension: string;
  label: string;
  status: DriftStatus;
  baseline?: number;
  current?: number;
  delta?: number;
  relative_change?: number;
  sample_count: number;
}

/** A surface's overall drift verdict + per-dimension breakdown. */
export interface SurfaceVerdict {
  surface_id: string;
  status: DriftStatus;
  baseline_captured_at?: string;
  dimensions: DimensionVerdict[];
}

/** Bootstrap tone + label for a drift status badge. */
export function driftStatusTone(status: DriftStatus): { tone: string; label: string } {
  switch (status) {
    case 'drift':
      return { tone: 'danger', label: 'Drift' };
    case 'warn':
      return { tone: 'warning', label: 'Warn' };
    case 'stable':
      return { tone: 'success', label: 'Stable' };
    default:
      return { tone: 'secondary', label: 'No baseline' };
  }
}

/** One sample's result from a run. */
export interface SampleOutcome {
  input: string;
  output?: string;
  passed: boolean;
  error?: string;
  tags: string[];
}

/** What triggered a persisted run (`RunTrigger`, `src/drift/run.rs`). */
export type RunTrigger = 'manual' | 'scheduled';

/** Lifecycle of an async replay-evaluation run (`RunStatus`, `src/drift/run.rs`). */
export type RunStatus =
  | 'pending'
  | 'running'
  | 'completed'
  | 'failed'
  | 'cancelled'
  /** Halted part-way by a cost guard — a usage limit or the run cost ceiling. */
  | 'stopped';

/** Whether a run has reached a terminal state (polling can stop). */
export function isTerminalRun(status: RunStatus): boolean {
  return (
    status === 'completed' || status === 'failed' || status === 'cancelled' || status === 'stopped'
  );
}

/** A persisted evaluation-suite run record (`DriftRun`, `src/drift/run.rs`). */
export interface DriftRun {
  id: string;
  suite_id: string;
  suite_name: string;
  surface_id: string;
  ran_at: string;
  trigger: RunTrigger;
  total: number;
  passed: number;
  errors: number;
  quality: number;
  self_consistency?: number;
  semantic_distance?: number;
  /** The target surface an experiment run went through (differs from `surface_id`). */
  target_surface_id?: string;
  /** The variant an experiment run went through. */
  variant?: string;
  /** Lifecycle status of the (async) run. */
  status: RunStatus;
  /** Sessions replayed so far; equals `total` on a completed run. */
  progress_done: number;
  /** When the run started (RFC3339). */
  started_at?: string;
  /** Why the run failed, stopped or was cancelled, when applicable (operator-facing). */
  failure_reason?: string;
  /** Provider spend this run consumed, in USD, across every stage of every
   * replayed session. `0` on runs recorded before evaluations were metered. */
  cost_usd?: number;
  /** Per-dimension verdict of the run's measured means vs the target surface's
   * baseline (the Evaluation-tab comparison). Empty for a failed / legacy run. */
  dimension_verdicts?: DimensionVerdict[];
  samples: SampleOutcome[];
}

/** One captured surface session — the "indicative surface data" a replay
 * evaluation re-runs (`RecordedSession`, `src/drift/session_store.rs`). */
export interface RecordedSession {
  id: string;
  surface_id: string;
  captured_at: string;
  /** The request `messages` array as sent (opaque here; shown as a summary). */
  messages: unknown;
  output: string;
  latency_ms?: number;
  output_tokens?: number;
}
