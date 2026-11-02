import React, { useEffect, useState } from 'react';

export type SortDirection = 'asc' | 'desc';

export interface TableSort<C extends string> {
  column: C;
  direction: SortDirection;
}

export function useTableSort<C extends string>(
  columns: readonly C[],
  defaultSort: TableSort<C>,
  storageKey: string
): { sort: TableSort<C>; toggleSort: (column: C) => void } {
  const load = (): TableSort<C> => {
    try {
      const raw = localStorage.getItem(storageKey);
      if (raw) {
        const parsed = JSON.parse(raw) as Partial<TableSort<C>>;
        if (
          parsed.column &&
          columns.includes(parsed.column) &&
          (parsed.direction === 'asc' || parsed.direction === 'desc')
        ) {
          return { column: parsed.column, direction: parsed.direction };
        }
      }
    } catch {
      // Ignore malformed or unavailable storage and fall back to the default.
    }
    return defaultSort;
  };

  const [sort, setSort] = useState<TableSort<C>>(load);

  useEffect(() => {
    try {
      localStorage.setItem(storageKey, JSON.stringify(sort));
    } catch {
      // Ignore storage write failures (private mode / quota).
    }
  }, [sort, storageKey]);

  const toggleSort = (column: C) =>
    setSort(prev =>
      prev.column === column
        ? { column, direction: prev.direction === 'asc' ? 'desc' : 'asc' }
        : { column, direction: 'asc' }
    );

  return { sort, toggleSort };
}

export const SortCaret: React.FC<{ active: boolean; direction: SortDirection }> = ({
  active,
  direction,
}) => {
  if (!active) {
    return <i className="fas fa-sort ms-1" style={{ opacity: 0.35 }} aria-hidden="true" />;
  }
  return (
    <i className={`fas fa-sort-${direction === 'asc' ? 'up' : 'down'} ms-1`} aria-hidden="true" />
  );
};

interface SortControlProps {
  label: React.ReactNode;
  active: boolean;
  direction: SortDirection;
  onSort: () => void;
  testId: string;
}

export const SortableHeader: React.FC<SortControlProps & { width?: string }> = ({
  label,
  active,
  direction,
  onSort,
  testId,
  width,
}) => (
  <th
    style={{ width, cursor: 'pointer', userSelect: 'none', whiteSpace: 'nowrap' }}
    onClick={onSort}
    data-testid={testId}
    aria-sort={active ? (direction === 'asc' ? 'ascending' : 'descending') : 'none'}
  >
    {label}
    <SortCaret active={active} direction={direction} />
  </th>
);

export const SortSegment: React.FC<SortControlProps> = ({
  label,
  active,
  direction,
  onSort,
  testId,
}) => (
  <span onClick={onSort} data-testid={testId} style={{ cursor: 'pointer', userSelect: 'none' }}>
    {label}
    <SortCaret active={active} direction={direction} />
  </span>
);
