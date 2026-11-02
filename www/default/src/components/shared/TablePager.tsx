import React from 'react';

interface TablePagerProps {
  page: number;
  pageSize: number;
  total: number;
  onPage: (page: number) => void;
}

/** Compact prev/next pager with an "X–Y of Z" count. Renders nothing for ≤1 page. */
const TablePager: React.FC<TablePagerProps> = ({ page, pageSize, total, onPage }) => {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  if (totalPages <= 1) return null;
  return (
    <div className="d-flex justify-content-between align-items-center mt-2 px-1">
      <small className="text-muted">
        {(page - 1) * pageSize + 1}–{Math.min(page * pageSize, total)} of {total}
      </small>
      <nav aria-label="Table pages">
        <ul className="pagination pagination-sm mb-0">
          <li className={`page-item ${page <= 1 ? 'disabled' : ''}`}>
            <button className="page-link" onClick={() => onPage(page - 1)}>
              &lsaquo;
            </button>
          </li>
          <li className={`page-item ${page >= totalPages ? 'disabled' : ''}`}>
            <button className="page-link" onClick={() => onPage(page + 1)}>
              &rsaquo;
            </button>
          </li>
        </ul>
      </nav>
    </div>
  );
};

export default TablePager;
