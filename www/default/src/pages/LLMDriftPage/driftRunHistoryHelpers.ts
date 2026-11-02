import { driftStatusTone } from './types';
import type { DriftRun, DriftStatus, DriftSurface, RunStatus, RunTrigger } from './types';
import { formatDateTime } from '../../utils/stringUtils';

/** Sortable columns of the cross-surface run-history table. */
export type RunSortColumn =
  | 'surface'
  | 'trigger'
  | 'status'
  | 'verdict'
  | 'quality'
  | 'passed'
  | 'semantic'
  | 'ranAt';

export const RUN_SORT_COLUMNS: readonly RunSortColumn[] = [
  'surface',
  'trigger',
  'status',
  'verdict',
  'quality',
  'passed',
  'semantic',
  'ranAt',
];

export const RUN_SORT_TESTID: Record<RunSortColumn, string> = {
  surface: 'drift-history-sort-surface',
  trigger: 'drift-history-sort-trigger',
  status: 'drift-history-sort-status',
  verdict: 'drift-history-sort-verdict',
  quality: 'drift-history-sort-quality',
  passed: 'drift-history-sort-passed',
  semantic: 'drift-history-sort-semantic',
  ranAt: 'drift-history-sort-ran-at',
};

/** Bootstrap tone for a run's lifecycle status badge. */
export const RUN_STATUS_TONE: Record<RunStatus, string> = {
  completed: 'success',
  failed: 'danger',
  cancelled: 'secondary',
  running: 'info',
  pending: 'info',
};

/** Resolve a surface id to a display name via the surfaces list, falling back
 * to the id when it isn't in the list (e.g. an experiment's target surface). */
export function surfaceNameById(surfaceId: string, surfaces: DriftSurface[]): string {
  return surfaces.find(s => s.surface_id === surfaceId)?.surface_name || surfaceId;
}

/** Resolve a run's (source) surface id to a display name. */
export function runSurfaceName(run: DriftRun, surfaces: DriftSurface[]): string {
  return surfaceNameById(run.surface_id, surfaces);
}

/** Answer-stability tone: green when replays stayed close, red when they drifted. */
export function qualityTone(quality: number): string {
  if (quality >= 0.8) return 'success';
  if (quality >= 0.5) return 'warning';
  return 'danger';
}

/** Display severity of a run's overall drift verdict (drift worst; unknown / no
 * baseline lowest, so a warn or drift is never masked by a baseline-less dim). */
const VERDICT_RANK: Record<DriftStatus, number> = {
  unknown: 0,
  stable: 1,
  warn: 2,
  drift: 3,
};

/** A run's overall drift verdict for the history list: the worst of the
 * dimensions that could be judged against the surface's baseline. Falls back to
 * `unknown` ("No baseline") only when no dimension had a baseline — so a warn or
 * drift on a judged dimension (e.g. response length) is always surfaced, and a
 * baseline-less replay dimension (quality / semantic on a production baseline)
 * never drags an otherwise-stable run down to "No baseline". */
export function runVerdictStatus(run: DriftRun): DriftStatus {
  const judged = (run.dimension_verdicts ?? []).filter(v => v.status !== 'unknown');
  if (judged.length === 0) return 'unknown';
  return judged.reduce<DriftStatus>(
    (worst, v) => (VERDICT_RANK[v.status] > VERDICT_RANK[worst] ? v.status : worst),
    judged[0].status
  );
}

/** Icon + label + tooltip for how a run was triggered, so an operator can tell a
 * hand-run evaluation from one the schedule (or an API client) fired. */
export function triggerMeta(trigger: RunTrigger): { icon: string; label: string; title: string } {
  return trigger === 'scheduled'
    ? {
        icon: 'fa-clock',
        label: 'Scheduled',
        title: "Ran automatically on this surface's drift schedule",
      }
    : {
        icon: 'fa-hand-pointer',
        label: 'Manual',
        title: 'Ran on demand — from the Run evaluation button or an API client',
      };
}

/** Free-text match across every visible field (surface name/id, trigger, status,
 * experiment target/variant, failure reason, quality, pass count, time). */
export function matchesRunFilter(run: DriftRun, term: string, surfaceName: string): boolean {
  const q = term.trim().toLowerCase();
  if (!q) return true;
  const haystack = [
    surfaceName,
    run.surface_id,
    run.trigger,
    run.status,
    run.target_surface_id ?? '',
    run.variant ?? '',
    run.failure_reason ?? '',
    `${Math.round(run.quality * 100)}%`,
    `${run.passed}/${run.total}`,
    run.semantic_distance != null ? run.semantic_distance.toFixed(3) : '',
    driftStatusTone(runVerdictStatus(run)).label,
    formatDateTime(run.ran_at, true),
  ]
    .join(' ')
    .toLowerCase();
  return haystack.includes(q);
}

/** Compare two runs on a column (ascending); the caller applies the direction. */
export function compareRuns(
  a: DriftRun,
  b: DriftRun,
  column: RunSortColumn,
  nameOf: (run: DriftRun) => string
): number {
  switch (column) {
    case 'surface':
      return nameOf(a).localeCompare(nameOf(b));
    case 'trigger':
      return a.trigger.localeCompare(b.trigger);
    case 'status':
      return a.status.localeCompare(b.status);
    case 'verdict':
      return VERDICT_RANK[runVerdictStatus(a)] - VERDICT_RANK[runVerdictStatus(b)];
    case 'quality':
      return a.quality - b.quality;
    case 'passed':
      return a.passed / Math.max(1, a.total) - b.passed / Math.max(1, b.total);
    case 'semantic':
      return (a.semantic_distance ?? -1) - (b.semantic_distance ?? -1);
    case 'ranAt':
      return new Date(a.ran_at).getTime() - new Date(b.ran_at).getTime();
    default:
      return 0;
  }
}

/** Operator-facing explanation + recourse for a failed/stopped/cancelled run,
 * derived from the backend `failure_reason`. `null` for a run that succeeded. */
export interface RunFailureGuidance {
  tone: 'warning' | 'danger';
  reason: string;
  recourse: string;
}

export function runFailureGuidance(run: DriftRun): RunFailureGuidance | null {
  if (run.status !== 'failed' && run.status !== 'cancelled' && run.status !== 'stopped')
    return null;
  const raw = run.failure_reason?.trim();
  const r = (raw ?? '').toLowerCase();

  if (r.includes('no sessions to replay')) {
    return {
      tone: 'warning',
      reason: 'No captured sessions to replay',
      recourse:
        'Drift evaluation replays this surface’s own recent live traffic, and none has been captured yet. Send requests through the surface while drift monitoring is enabled so sessions accumulate, then re-run — or turn off this surface’s evaluation schedule if you don’t want scheduled runs.',
    };
  }
  if (r.includes('replayed sessions failed')) {
    return {
      tone: 'danger',
      reason: raw ?? 'Every replayed session failed',
      recourse:
        'Every replayed request errored — usually the upstream model is unreachable or misconfigured (a bad credential, wrong endpoint, or provider outage). Check the surface’s provider, model, and secret, test it in the Sandbox, then re-run.',
    };
  }
  if (r.includes('auto-suspended')) {
    return {
      tone: 'danger',
      reason: raw ?? 'Scheduled evaluation auto-suspended',
      recourse:
        'Scheduled evaluations were paused after repeated failures. Fix the underlying issue, then run a manual evaluation — a successful run clears the suspension and resumes the schedule.',
    };
  }
  if (r.includes('run cost ceiling')) {
    return {
      tone: 'warning',
      reason: raw ?? 'Run cost ceiling reached',
      recourse:
        'The evaluation stopped part-way because it reached the spend allowed for a single run. Its partial results are kept for inspection but are not folded into the drift charts. Replay fewer sessions, or raise this surface’s evaluation cost ceiling, then re-run.',
    };
  }
  if (r.includes('usage limit')) {
    return {
      tone: 'warning',
      reason: raw ?? 'Target surface usage limit reached',
      recourse:
        'The surface being replayed has exhausted a monthly usage limit, so the evaluation stopped rather than spending past it. Evaluation replays are real upstream calls and count against the same limits as live traffic. Raise the limit or wait for the next month, then re-run.',
    };
  }
  if (run.status === 'cancelled') {
    return {
      tone: 'warning',
      reason: raw ?? 'Cancelled by operator',
      recourse: 'This run was stopped before it finished. Re-run it when ready.',
    };
  }
  return {
    tone: 'danger',
    reason: raw || 'The evaluation did not complete',
    recourse: 'Open the surface to review its configuration, then re-run the evaluation.',
  };
}
