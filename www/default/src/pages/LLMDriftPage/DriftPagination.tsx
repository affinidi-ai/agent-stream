import React from 'react';

interface DriftPaginationProps {
  page: number;
  totalPages: number;
  pageSize: number;
  totalItems: number;
  onPage: (page: number) => void;
}

/** Numbered pager (first / current±1 / last, ellipsised) for the run-history
 * table, matching the LLM Surfaces list. Renders nothing for a single page. */
const DriftPagination: React.FC<DriftPaginationProps> = ({
  page,
  totalPages,
  pageSize,
  totalItems,
  onPage,
}) => {
  if (totalPages <= 1) return null;

  const pages = Array.from({ length: totalPages }, (_, i) => i + 1)
    .filter(p => p === 1 || p === totalPages || Math.abs(p - page) <= 1)
    .reduce<(number | '...')[]>((acc, p, idx, arr) => {
      if (idx > 0 && p - (arr[idx - 1] as number) > 1) acc.push('...');
      acc.push(p);
      return acc;
    }, []);

  return (
    <div className="d-flex justify-content-between align-items-center mt-2 px-1">
      <small className="text-muted">
        {(page - 1) * pageSize + 1}–{Math.min(page * pageSize, totalItems)} of {totalItems}
      </small>
      <nav aria-label="Evaluation history pages">
        <ul className="pagination pagination-sm mb-0">
          <li className={`page-item ${page <= 1 ? 'disabled' : ''}`}>
            <button
              className="page-link"
              onClick={() => onPage(page - 1)}
              data-testid="drift-history-pagination-prev"
            >
              &lsaquo;
            </button>
          </li>
          {pages.map((p, idx) =>
            p === '...' ? (
              <li key={`ellipsis-${idx}`} className="page-item disabled">
                <span className="page-link">…</span>
              </li>
            ) : (
              <li key={p} className={`page-item ${p === page ? 'active' : ''}`}>
                <button
                  className="page-link"
                  onClick={() => onPage(p as number)}
                  data-testid={`drift-history-pagination-page-${p}`}
                >
                  {p}
                </button>
              </li>
            )
          )}
          <li className={`page-item ${page >= totalPages ? 'disabled' : ''}`}>
            <button
              className="page-link"
              onClick={() => onPage(page + 1)}
              data-testid="drift-history-pagination-next"
            >
              &rsaquo;
            </button>
          </li>
        </ul>
      </nav>
    </div>
  );
};

export default DriftPagination;
