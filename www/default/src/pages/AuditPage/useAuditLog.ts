import { useCallback, useEffect, useMemo, useState } from 'react';
import { apiClient } from '../../api';
import { showToast } from '../../utils/toaster';
import { PAGE_LIMIT } from './auditHelpers';
import type { AuditEntry, AuditResponse, DecisionFilter, FlowFilter, ScopeFilter } from './types';

export interface UseAuditLog {
  entries: AuditEntry[];
  filteredEntries: AuditEntry[];
  total: number;
  categoryCounts: Record<string, number>;
  page: number;
  totalPages: number;
  category: string;
  selectedCats: string[];
  search: string;
  searchInput: string;
  decisionFilter: DecisionFilter;
  flowFilter: FlowFilter;
  scopeFilter: ScopeFilter;
  isLoading: boolean;
  expandedIdx: number | null;
  setPage: (updater: number | ((p: number) => number)) => void;
  setSearchInput: (v: string) => void;
  setDecisionFilter: (v: DecisionFilter) => void;
  setFlowFilter: (v: FlowFilter) => void;
  setScopeFilter: (v: ScopeFilter) => void;
  setExpandedIdx: (idx: number | null) => void;
  reload: () => void;
  clearTextFilter: () => void;
  submitSearch: () => void;
  applyQuickFilter: (term: string, cat?: string) => void;
  toggleCategory: (val: string) => void;
  selectAllCategories: () => void;
}

/**
 * Owns the audit-log server state (paged fetch + text/category filters and the
 * policy-decision refinements flow/scope/decision). Category filtering is an OR
 * set carried as a comma-separated string; flow/scope/decision are single-value
 * query params. Every filter round-trips through `/audit` so `total`,
 * pagination, and `category_counts` reflect the full filtered set, not just the
 * current page.
 */
export function useAuditLog(): UseAuditLog {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [categoryCounts, setCategoryCounts] = useState<Record<string, number>>({});
  const [page, setPage] = useState(1);
  const [category, setCategory] = useState('');
  const [search, setSearch] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [decisionFilter, setDecisionFilter] = useState<DecisionFilter>('');
  const [flowFilter, setFlowFilter] = useState<FlowFilter>('');
  const [scopeFilter, setScopeFilter] = useState<ScopeFilter>('');
  const [isLoading, setIsLoading] = useState(false);
  const [expandedIdx, setExpandedIdx] = useState<number | null>(null);

  const load = useCallback(
    async (
      currentPage: number,
      currentCategory: string,
      currentSearch: string,
      currentDecision: DecisionFilter,
      currentFlow: FlowFilter,
      currentScope: ScopeFilter
    ) => {
      setIsLoading(true);
      try {
        const params = new URLSearchParams({
          limit: String(PAGE_LIMIT),
          page: String(currentPage),
        });
        if (currentCategory) params.set('category', currentCategory);
        if (currentSearch) params.set('filter', currentSearch);
        if (currentDecision) params.set('decision', currentDecision);
        if (currentFlow) params.set('flow', currentFlow);
        if (currentScope) params.set('scope', currentScope);

        const { data } = await apiClient.get<AuditResponse>(`/audit?${params.toString()}`);
        setEntries(data.events ?? []);
        setTotal(data.total ?? 0);
        setCategoryCounts(data.category_counts ?? {});
      } catch (error) {
        const msg = error instanceof Error ? error.message : 'Failed to load audit entries';
        showToast('error', msg);
        setEntries([]);
        setTotal(0);
        setCategoryCounts({});
      } finally {
        setIsLoading(false);
      }
    },
    []
  );

  useEffect(() => {
    load(page, category, search, decisionFilter, flowFilter, scopeFilter);
  }, [page, category, search, decisionFilter, flowFilter, scopeFilter, load]);

  const submitSearch = useCallback(() => {
    setPage(1);
    setSearch(searchInput);
  }, [searchInput]);

  const clearTextFilter = useCallback(() => {
    setPage(1);
    setSearch('');
  }, []);

  const applyQuickFilter = useCallback((term: string, cat?: string) => {
    setSearchInput(term);
    setSearch(term);
    setPage(1);
    setExpandedIdx(null);
    if (cat !== undefined) setCategory(cat);
  }, []);

  const selectedCats = useMemo(() => (category ? category.split(',') : []), [category]);

  const toggleCategory = useCallback(
    (val: string) => {
      setPage(1);
      const set = new Set(selectedCats);
      if (set.has(val)) set.delete(val);
      else set.add(val);
      setCategory(Array.from(set).join(','));
    },
    [selectedCats]
  );

  const selectAllCategories = useCallback(() => {
    setPage(1);
    setCategory('');
  }, []);

  // Reset to the first page whenever a policy-decision refinement changes; the
  // server re-tallies and re-paginates against the new filtered set.
  const changeDecision = useCallback((v: DecisionFilter) => {
    setPage(1);
    setDecisionFilter(v);
  }, []);
  const changeFlow = useCallback((v: FlowFilter) => {
    setPage(1);
    setFlowFilter(v);
  }, []);
  const changeScope = useCallback((v: ScopeFilter) => {
    setPage(1);
    setScopeFilter(v);
  }, []);

  // The server already applies decision/flow/scope, so the returned page is the
  // filtered set; no additional client-side narrowing is needed.
  const filteredEntries = entries;

  const totalPages = Math.max(1, Math.ceil(total / PAGE_LIMIT));

  const reload = useCallback(() => {
    load(page, category, search, decisionFilter, flowFilter, scopeFilter);
  }, [load, page, category, search, decisionFilter, flowFilter, scopeFilter]);

  return {
    entries,
    filteredEntries,
    total,
    categoryCounts,
    page,
    totalPages,
    category,
    selectedCats,
    search,
    searchInput,
    decisionFilter,
    flowFilter,
    scopeFilter,
    isLoading,
    expandedIdx,
    setPage,
    setSearchInput,
    setDecisionFilter: changeDecision,
    setFlowFilter: changeFlow,
    setScopeFilter: changeScope,
    setExpandedIdx,
    reload,
    clearTextFilter,
    submitSearch,
    applyQuickFilter,
    toggleCategory,
    selectAllCategories,
  };
}
