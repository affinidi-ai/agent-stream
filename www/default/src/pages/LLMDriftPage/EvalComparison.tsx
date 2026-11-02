import React, { useEffect, useMemo, useState } from 'react';
import DriftDimensionChart from './DriftDimensionChart';
import { fetchDriftSeries } from './driftApi';
import {
  driftStatusTone,
  formatDriftValue,
  type DriftDimensionInfo,
  type DriftRun,
  type DriftSeriesResponse,
  type DriftSurface,
} from './types';

interface EvalComparisonProps {
  run: DriftRun;
  surfaces: DriftSurface[];
  dimensions: DriftDimensionInfo[];
  /** Hide the per-dimension verdict table (charts + caption only). */
  showTable?: boolean;
}

/** How much of the target surface's history to show behind the eval overlay. */
const WINDOW_SECS = 7 * 24 * 3600;

/**
 * After a completed replay evaluation, compare its measured dimensions to the
 * **target surface's** pinned baseline: a verdict table plus one chart per
 * measured dimension drawing the target's history + baseline with this run's
 * value overlaid, so an operator can see whether the replay would count as drift.
 */
const EvalComparison: React.FC<EvalComparisonProps> = ({
  run,
  surfaces,
  dimensions,
  showTable = true,
}) => {
  const targetSurfaceId = run.target_surface_id ?? run.surface_id;
  const targetName =
    surfaces.find(s => s.surface_id === targetSurfaceId)?.surface_name || targetSurfaceId;
  const verdicts = useMemo(() => run.dimension_verdicts ?? [], [run.dimension_verdicts]);
  const infoById = useMemo<Record<string, DriftDimensionInfo>>(
    () => Object.fromEntries(dimensions.map(d => [d.id, d])),
    [dimensions]
  );
  const [byDim, setByDim] = useState<Record<string, DriftSeriesResponse>>({});

  useEffect(() => {
    let active = true;
    if (!targetSurfaceId || dimensions.length === 0) {
      setByDim({});
      return;
    }
    fetchDriftSeries(targetSurfaceId, WINDOW_SECS, dimensions)
      .then(r => active && setByDim(r.byDim))
      .catch(() => active && setByDim({}));
    return () => {
      active = false;
    };
  }, [targetSurfaceId, dimensions]);

  if (verdicts.length === 0) return null;

  return (
    <div className="drift-eval-comparison border-top mt-3 pt-3" data-testid="drift-eval-comparison">
      <div className="small text-muted mb-2">
        How this run compares to <strong>{targetName}</strong>&apos;s baseline — amber is this run,
        the dashed line is the baseline.
      </div>

      {showTable && (
        <div className="table-responsive mb-3">
          <table
            className="table table-sm align-middle mb-0"
            data-testid="drift-eval-verdict-table"
          >
            <thead>
              <tr className="small text-muted">
                <th>Dimension</th>
                <th className="text-end">Baseline</th>
                <th className="text-end">This run</th>
                <th className="text-end">Change</th>
                <th className="text-end">Status</th>
              </tr>
            </thead>
            <tbody>
              {verdicts.map(v => {
                const info = infoById[v.dimension];
                const tone = driftStatusTone(v.status);
                return (
                  <tr key={v.dimension} data-testid={`drift-eval-verdict-${v.dimension}`}>
                    <td className="small fw-semibold">{v.label}</td>
                    <td className="text-end small">
                      {v.baseline != null && info ? formatDriftValue(v.baseline, info) : '—'}
                    </td>
                    <td className="text-end small">
                      {v.current != null && info ? formatDriftValue(v.current, info) : '—'}
                    </td>
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
      )}

      <div className="drift-grid" data-testid="drift-eval-grid">
        {verdicts.map(v => {
          const info = infoById[v.dimension];
          if (!info) return null;
          return (
            <DriftDimensionChart
              key={v.dimension}
              info={info}
              series={byDim[v.dimension]}
              verdict={v}
              overlay={v.current != null ? { value: v.current, label: 'This run' } : undefined}
            />
          );
        })}
      </div>
    </div>
  );
};

export default EvalComparison;
