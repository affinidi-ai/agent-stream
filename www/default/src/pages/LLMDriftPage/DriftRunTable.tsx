import React from 'react';
import { SortableHeader, type TableSort } from '../../components/shared/tableSort';
import { driftStatusTone, type DriftRun } from './types';
import {
  RUN_SORT_TESTID,
  RUN_STATUS_TONE,
  qualityTone,
  runFailureGuidance,
  runVerdictStatus,
  triggerMeta,
  type RunSortColumn,
} from './driftRunHistoryHelpers';
import { formatDateTime } from '../../utils/stringUtils';

interface DriftRunTableProps {
  runs: DriftRun[];
  sort: TableSort<RunSortColumn>;
  toggleSort: (column: RunSortColumn) => void;
  nameOf: (run: DriftRun) => string;
  selectedId: string | null;
  onSelect: (run: DriftRun) => void;
}

/** The sortable cross-surface run-history table. One row per evaluation run;
 * clicking a row opens the detail slide-over. Column sorting + the surface name
 * resolver are owned by the parent (`HistoryTab`). */
const DriftRunTable: React.FC<DriftRunTableProps> = ({
  runs,
  sort,
  toggleSort,
  nameOf,
  selectedId,
  onSelect,
}) => {
  const hp = (column: RunSortColumn) => ({
    active: sort.column === column,
    direction: sort.direction,
    onSort: () => toggleSort(column),
    testId: RUN_SORT_TESTID[column],
  });

  return (
    <div className="table-responsive">
      <table className="table table-hover table-sm align-middle" data-testid="drift-run-table">
        <thead>
          <tr>
            <SortableHeader label="Surface" width="22%" {...hp('surface')} />
            <SortableHeader label="Trigger" width="10%" {...hp('trigger')} />
            <SortableHeader label="Status" width="14%" {...hp('status')} />
            <SortableHeader label="Verdict" width="11%" {...hp('verdict')} />
            <SortableHeader label="Quality" width="9%" {...hp('quality')} />
            <SortableHeader label="Passed" width="7%" {...hp('passed')} />
            <SortableHeader label="Semantic" width="10%" {...hp('semantic')} />
            <SortableHeader label="Ran at" width="17%" {...hp('ranAt')} />
          </tr>
        </thead>
        <tbody>
          {runs.map(r => {
            const tm = triggerMeta(r.trigger);
            const g = runFailureGuidance(r);
            const hasVerdicts = (r.dimension_verdicts?.length ?? 0) > 0;
            const vt = driftStatusTone(runVerdictStatus(r));
            return (
              <tr
                key={r.id}
                onClick={() => onSelect(r)}
                style={{ cursor: 'pointer' }}
                className={selectedId === r.id ? 'table-active' : undefined}
                data-testid={`drift-run-row-${r.id}`}
              >
                <td>
                  <span className="drift-surface-chip" title={nameOf(r)}>
                    {nameOf(r)}
                  </span>
                  {(r.target_surface_id || r.variant) && (
                    <span
                      className="badge text-bg-warning ms-1"
                      title="Experiment — ran a surface's captured data through a different surface / variant"
                    >
                      Experiment
                    </span>
                  )}
                </td>
                <td>
                  <span className="small text-muted" title={tm.title}>
                    <i className={`fas ${tm.icon} me-1`} aria-hidden="true" />
                    {tm.label}
                  </span>
                </td>
                <td>
                  <span
                    className={`badge text-bg-${RUN_STATUS_TONE[r.status] ?? 'secondary'} text-capitalize`}
                  >
                    {r.status}
                  </span>
                  {g && (
                    <div className="drift-run-reason small text-muted" title={g.reason}>
                      {g.reason}
                    </div>
                  )}
                </td>
                <td>
                  {hasVerdicts ? (
                    <span
                      className={`badge text-bg-${vt.tone}`}
                      title="Worst dimension verdict against this surface's baseline for this run"
                    >
                      {vt.label}
                    </span>
                  ) : (
                    <span className="text-muted">—</span>
                  )}
                </td>
                <td>
                  <span
                    className={`badge text-bg-${qualityTone(r.quality)}`}
                    title="Answer stability — fraction of replays that stayed close to the captured answer"
                  >
                    {(r.quality * 100).toFixed(0)}%
                  </span>
                </td>
                <td className="small">
                  {r.passed}/{r.total}
                </td>
                <td className="small text-muted">
                  {r.semantic_distance != null ? r.semantic_distance.toFixed(3) : '—'}
                </td>
                <td className="small text-muted" title={formatDateTime(r.ran_at, true)}>
                  {formatDateTime(r.ran_at, true)}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};

export default DriftRunTable;
