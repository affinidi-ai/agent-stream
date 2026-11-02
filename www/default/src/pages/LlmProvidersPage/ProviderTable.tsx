import React, { useEffect, useMemo } from 'react';
import type { LlmProviderSummary } from '../EditLlmProviderPage/types';
import { EmptyState } from '../../components/shared/EmptyState';

const countOf = (value: unknown): number => (Array.isArray(value) ? value.length : 0);

interface ProviderTableProps {
  providers: LlmProviderSummary[];
  searchTerm: string;
  /** Test-id prefix for rows / empty state (e.g. `llm-providers-builtin`). */
  testIdPrefix: string;
  /**
   * When supplied, rows are clickable and an Actions column with a View button
   * is shown. Omitted for the Custom tab (custom providers are edited via the
   * JSON tab, not the per-provider editor).
   */
  onView?: (enumValue: string) => void;
  /** Title for the "nothing configured yet" empty state. */
  emptyTitle?: string;
  /** Body shown when the source list is genuinely empty (not filtered). */
  emptyLabel?: React.ReactNode;
  /** Optional CTA for the genuinely-empty state (e.g. jump to the JSON tab). */
  emptyCtaLabel?: string;
  emptyCtaIcon?: string;
  emptyCtaClick?: () => void;
  /** Reports the filtered / total counts so the parent can badge the widget. */
  onFilteredCountChange?: (filtered: number, total: number) => void;
}

/**
 * Shared read-only table of LLM providers, rendered identically for the
 * Built-In and Custom tabs of the Models page. Filtering is applied here so
 * both tabs share one search box upstream.
 */
const ProviderTable: React.FC<ProviderTableProps> = ({
  providers,
  searchTerm,
  testIdPrefix,
  onView,
  emptyTitle,
  emptyLabel,
  emptyCtaLabel,
  emptyCtaIcon,
  emptyCtaClick,
  onFilteredCountChange,
}) => {
  const filtered = useMemo(() => {
    const term = searchTerm.trim().toLowerCase();
    if (!term) return providers;
    return providers.filter(
      p =>
        p.name.toLowerCase().includes(term) ||
        p.enum_value.toLowerCase().includes(term) ||
        (p.api_schema ?? '').toLowerCase().includes(term)
    );
  }, [providers, searchTerm]);

  useEffect(() => {
    onFilteredCountChange?.(filtered.length, providers.length);
  }, [filtered.length, providers.length, onFilteredCountChange]);

  if (providers.length === 0) {
    return (
      <div data-testid={`${testIdPrefix}-empty-state`}>
        <EmptyState
          icon="fa-microchip"
          title={emptyTitle ?? 'No providers yet'}
          body={emptyLabel ?? 'No LLM providers configured yet.'}
          ctaLabel={emptyCtaLabel}
          ctaIcon={emptyCtaIcon}
          onCtaClick={emptyCtaClick}
        />
      </div>
    );
  }

  if (filtered.length === 0) {
    return (
      <div className="text-center text-muted py-5" data-testid={`${testIdPrefix}-no-results`}>
        <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
        <p className="mb-0">No providers match your search.</p>
      </div>
    );
  }

  return (
    <div className="table-responsive">
      <table className="table table-hover table-sm">
        <thead>
          <tr>
            <th>Name</th>
            <th>Schema</th>
            <th>Status</th>
            <th>Endpoints</th>
            <th>Models</th>
            {onView && <th>Actions</th>}
          </tr>
        </thead>
        <tbody>
          {filtered.map(provider => (
            <tr
              key={provider.enum_value}
              onClick={onView ? () => onView(provider.enum_value) : undefined}
              style={onView ? { cursor: 'pointer' } : undefined}
              data-testid={`${testIdPrefix}-row-${provider.enum_value}`}
            >
              <td>
                <strong>
                  {provider.icon && <i className={`fas ${provider.icon} me-2`}></i>}
                  {provider.name}
                </strong>
                <div>
                  <small className="text-muted font-monospace">{provider.enum_value}</small>
                </div>
              </td>
              <td>
                {provider.api_schema && (
                  <span className="badge text-bg-secondary">{provider.api_schema}</span>
                )}
              </td>
              <td>
                <span className={`badge text-bg-${provider.enabled ? 'success' : 'secondary'}`}>
                  {provider.enabled ? 'Enabled' : 'Disabled'}
                </span>
              </td>
              <td>{countOf(provider.endpoints)}</td>
              <td>{countOf(provider.models)}</td>
              {onView && (
                <td>
                  <button
                    className="btn btn-sm btn-outline-primary me-1"
                    onClick={e => {
                      e.stopPropagation();
                      onView(provider.enum_value);
                    }}
                    title="View"
                    data-testid={`${testIdPrefix}-view-${provider.enum_value}`}
                  >
                    <i className="fas fa-eye"></i>
                  </button>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default ProviderTable;
