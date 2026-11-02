import React, { useState } from 'react';
import RunSampleList from './RunSampleList';
import type { DriftRun, DriftSurface, RunTrigger } from './types';

function qualityTone(quality: number): string {
  if (quality >= 0.8) return 'success';
  if (quality >= 0.5) return 'warning';
  return 'danger';
}

/** Icon + label + tooltip for how a run was triggered, so an operator can tell a
 * hand-run evaluation from one the schedule (or an API client) fired. */
function triggerMeta(trigger: RunTrigger): { icon: string; label: string; title: string } {
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

interface DriftRunHistoryProps {
  runs: DriftRun[];
  loading: boolean;
  /** For the cross-surface view: resolves each run's surface id to a name. */
  surfaces?: DriftSurface[];
  /** Show which surface each run belongs to (the "all surfaces" view). */
  showSurface?: boolean;
}

/** The list of evaluation runs — one collapsible row per run (optional surface
 * name + quality + pass count + how it was triggered + time), expanding to the
 * run's per-record outcomes. Its header + filtering live in the parent. */
const DriftRunHistory: React.FC<DriftRunHistoryProps> = ({
  runs,
  loading,
  surfaces,
  showSurface,
}) => {
  const [expanded, setExpanded] = useState<string | null>(null);

  if (loading && runs.length === 0) {
    return (
      <p className="small text-muted mb-0" data-testid="drift-runs-loading">
        Loading run history…
      </p>
    );
  }
  if (runs.length === 0) {
    return (
      <p className="small text-muted mb-0" data-testid="drift-runs-empty">
        No evaluations have run yet. Run one from the Evaluation tab, or set a schedule to run them
        automatically.
      </p>
    );
  }

  const nameOf = (id: string) => surfaces?.find(s => s.surface_id === id)?.surface_name || id;

  return (
    <div className="drift-run-history" data-testid="drift-run-history">
      {runs.map(r => {
        const tm = triggerMeta(r.trigger);
        return (
          <div className="drift-run-hist-row" key={r.id}>
            <button
              type="button"
              className="btn btn-sm btn-link text-decoration-none d-flex align-items-center gap-2 w-100 text-start p-1"
              data-testid={`drift-run-${r.id}`}
              onClick={() => setExpanded(e => (e === r.id ? null : r.id))}
            >
              <i
                className={`fas fa-caret-${expanded === r.id ? 'down' : 'right'} text-muted`}
                style={{ width: 10 }}
                aria-hidden="true"
              />
              {showSurface && (
                <span
                  className="badge text-bg-light border text-truncate"
                  style={{ maxWidth: 160 }}
                  title={nameOf(r.surface_id)}
                  data-testid={`drift-run-surface-${r.id}`}
                >
                  {nameOf(r.surface_id)}
                </span>
              )}
              {r.status && r.status !== 'completed' && (
                <span
                  className={`badge text-bg-${
                    r.status === 'failed'
                      ? 'danger'
                      : r.status === 'cancelled'
                        ? 'secondary'
                        : r.status === 'stopped'
                          ? 'warning'
                          : 'info'
                  } text-capitalize`}
                  title={r.failure_reason || undefined}
                  data-testid={`drift-run-status-${r.id}`}
                >
                  {r.status}
                </span>
              )}
              <span
                className={`badge text-bg-${qualityTone(r.quality)}`}
                title="Answer stability — fraction of replays that stayed close to the captured answer"
              >
                {(r.quality * 100).toFixed(0)}%
              </span>
              <span className="small">
                {r.passed}/{r.total}
              </span>
              {r.semantic_distance != null && (
                <span className="badge text-bg-info" title="Semantic distance">
                  SD {r.semantic_distance.toFixed(3)}
                </span>
              )}
              {!!r.cost_usd && (
                <span
                  className="badge text-bg-light border"
                  title="Provider spend this evaluation consumed, across every stage of every replayed session"
                  data-testid={`drift-run-cost-${r.id}`}
                >
                  ${r.cost_usd.toFixed(4)}
                </span>
              )}
              {(r.target_surface_id || r.variant) && (
                <span
                  className="badge text-bg-warning"
                  title="Experiment — ran through a different surface / variant"
                >
                  via {r.target_surface_id ?? 'this surface'}
                  {r.variant ? ` → ${r.variant}` : ''}
                </span>
              )}
              <span className="badge text-bg-secondary" title={tm.title}>
                <i className={`fas ${tm.icon} me-1`} aria-hidden="true" />
                {tm.label}
              </span>
              <span className="small text-muted ms-auto">
                {new Date(r.ran_at).toLocaleString()}
              </span>
            </button>
            {expanded === r.id && (
              <div className="ps-3">
                <RunSampleList samples={r.samples} />
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};

export default DriftRunHistory;
