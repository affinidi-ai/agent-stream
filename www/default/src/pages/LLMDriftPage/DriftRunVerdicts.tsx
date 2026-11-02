import React, { useState } from 'react';
import EvalComparison from './EvalComparison';
import {
  driftStatusTone,
  type DriftDimensionInfo,
  type DriftRun,
  type DriftSurface,
} from './types';

interface DriftRunVerdictsProps {
  run: DriftRun;
  surfaces: DriftSurface[];
  dimensions: DriftDimensionInfo[];
}

/**
 * A run's per-dimension verdict table plus a lazily-rendered twister of
 * baseline-comparison graphs — the target surface's history + baseline charts
 * with this run's value overlaid (`EvalComparison`, charts only). Renders
 * nothing when the run carries no dimension verdicts (a failed / legacy run).
 */
const DriftRunVerdicts: React.FC<DriftRunVerdictsProps> = ({ run, surfaces, dimensions }) => {
  const [graphsOpen, setGraphsOpen] = useState(false);
  const verdicts = run.dimension_verdicts ?? [];
  if (verdicts.length === 0) return null;

  return (
    <>
      <div className="mb-3">
        <h3 className="drift-drawer-section">Dimension verdicts</h3>
        <div className="table-responsive">
          <table className="table table-sm align-middle mb-0">
            <thead>
              <tr className="small text-muted">
                <th>Dimension</th>
                <th className="text-end">Change</th>
                <th className="text-end">Status</th>
              </tr>
            </thead>
            <tbody>
              {verdicts.map(v => {
                const tone = driftStatusTone(v.status);
                return (
                  <tr key={v.dimension}>
                    <td className="small fw-semibold">{v.label}</td>
                    <td className="text-end small text-muted">
                      {v.relative_change != null ? `${(v.relative_change * 100).toFixed(0)}%` : '—'}
                    </td>
                    <td className="text-end">
                      <span className={`badge text-bg-${tone.tone}`}>{tone.label}</span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      <details className="drift-records" onToggle={e => setGraphsOpen(e.currentTarget.open)}>
        <summary className="drift-drawer-section drift-records-summary">
          Baseline comparison graphs
        </summary>
        {graphsOpen && (
          <EvalComparison run={run} surfaces={surfaces} dimensions={dimensions} showTable={false} />
        )}
      </details>
    </>
  );
};

export default DriftRunVerdicts;
