import React, { useEffect, useMemo, useState } from 'react';
import SearchInput from '../../components/shared/SearchInput';
import { Badge } from '../../components/shared/Badge';
import { AppButton } from '../../components/shared/AppButton';
import { useTableSort, type TableSort } from '../../components/shared/tableSort';
import DriftPagination from './DriftPagination';
import DriftRunDetailPanel from './DriftRunDetailPanel';
import DriftRunTable from './DriftRunTable';
import { useDriftRuns } from './useDriftRuns';
import {
  RUN_SORT_COLUMNS,
  compareRuns,
  matchesRunFilter,
  runSurfaceName,
  type RunSortColumn,
} from './driftRunHistoryHelpers';
import type { DriftDimensionInfo, DriftRun, DriftSurface } from './types';

interface HistoryTabProps {
  surfaces: DriftSurface[];
  dimensions: DriftDimensionInfo[];
  canManage: boolean;
}

const PAGE_SIZE = 10;
const HISTORY_LIMIT = 200;
const DEFAULT_SORT: TableSort<RunSortColumn> = { column: 'ranAt', direction: 'desc' };
const SORT_STORAGE_KEY = 'drift-history-sort';

/**
 * The cross-surface evaluation run history, styled like the LLM Surfaces list:
 * a free-text filter (matching every column), click-to-sort headers, and
 * pagination. Clicking a row slides open the detail panel with the run's full
 * outcome. This is the audit / scheduled-run / failure log for replays.
 */
const HistoryTab: React.FC<HistoryTabProps> = ({ surfaces, dimensions, canManage }) => {
  const { runs, loading, reload } = useDriftRuns(null, 0, HISTORY_LIMIT);
  const [search, setSearch] = useState('');
  const { sort, toggleSort } = useTableSort(RUN_SORT_COLUMNS, DEFAULT_SORT, SORT_STORAGE_KEY);
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<DriftRun | null>(null);

  const nameOf = useMemo(() => (run: DriftRun) => runSurfaceName(run, surfaces), [surfaces]);

  useEffect(() => {
    setPage(1);
  }, [search, sort]);

  const filtered = useMemo(
    () => runs.filter(r => matchesRunFilter(r, search, nameOf(r))),
    [runs, search, nameOf]
  );

  const sorted = useMemo(() => {
    const dir = sort.direction === 'asc' ? 1 : -1;
    return [...filtered].sort((a, b) => {
      const primary = compareRuns(a, b, sort.column, nameOf);
      if (primary !== 0) return primary * dir;
      return new Date(b.ran_at).getTime() - new Date(a.ran_at).getTime();
    });
  }, [filtered, sort, nameOf]);

  const totalPages = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  const paged = sorted.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

  return (
    <div className="card shadow drift-card">
      <div className="card-header py-3 d-flex justify-content-between align-items-center flex-wrap gap-2">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-clock-rotate-left me-1" aria-hidden="true" /> Evaluation history
          {runs.length > 0 && (
            <Badge
              value={filtered.length}
              suffix={search ? ` of ${runs.length}` : undefined}
              className="ms-2"
              ariaLabel={`${filtered.length}${search ? ` of ${runs.length}` : ''} runs`}
            />
          )}
        </h6>
        <div className="d-flex align-items-center gap-2">
          <SearchInput
            value={search}
            onChange={setSearch}
            placeholder="Filter by surface, status, trigger…"
            width="420px"
          />
          <AppButton
            variant="outline-secondary"
            size="sm"
            disabled={loading}
            onClick={reload}
            data-testid="drift-history-refresh"
            iconStart={<i className="fas fa-sync-alt me-1" aria-hidden="true" />}
          >
            Refresh
          </AppButton>
        </div>
      </div>
      <div className="card-body">
        <p className="small text-muted mb-3">
          Every replay evaluation — run manually or on a schedule — is saved here, most recent{' '}
          {HISTORY_LIMIT} across all surfaces. Sort any column, filter across all fields, and click
          a run to see its full outcome.
        </p>
        {loading && runs.length === 0 ? (
          <p className="small text-muted mb-0" data-testid="drift-runs-loading">
            Loading run history…
          </p>
        ) : runs.length === 0 ? (
          <p className="small text-muted mb-0" data-testid="drift-runs-empty">
            No evaluations have run yet. Run one from the Evaluation tab, or set a schedule to run
            them automatically.
          </p>
        ) : filtered.length === 0 ? (
          <div className="text-center text-muted py-4" data-testid="drift-runs-no-match">
            <i className="fas fa-search fa-2x mb-2 d-block" aria-hidden="true" />
            No runs match your filter.
          </div>
        ) : (
          <>
            <DriftRunTable
              runs={paged}
              sort={sort}
              toggleSort={toggleSort}
              nameOf={nameOf}
              selectedId={selected?.id ?? null}
              onSelect={setSelected}
            />
            <DriftPagination
              page={currentPage}
              totalPages={totalPages}
              pageSize={PAGE_SIZE}
              totalItems={sorted.length}
              onPage={setPage}
            />
          </>
        )}
      </div>
      <DriftRunDetailPanel
        run={selected}
        surfaces={surfaces}
        dimensions={dimensions}
        canManage={canManage}
        onClose={() => setSelected(null)}
      />
    </div>
  );
};

export default HistoryTab;
