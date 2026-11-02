import React, { useMemo } from 'react';
import {
  formatUsd,
  indexByKey,
  sumWindow,
  type BreakdownItem,
  type SeriesResponse,
  type WindowTotals,
} from './usageSeries';

interface UsageSummaryRow extends BreakdownItem {
  totals: WindowTotals;
}

interface UsageSummaryProps {
  series: SeriesResponse[];
  /** Telemetry key whose window total drives the headline cards. */
  primaryKey: string;
  /** Per-member / per-surface rows; totals are read from the same series. */
  items: BreakdownItem[];
  /** Column header for the breakdown's first column (e.g. "Member"). */
  itemHeading: string;
  /** Section heading above the breakdown table (e.g. "Per member"). */
  itemsTitle: string;
  /** Shown when there are no breakdown rows with activity. */
  emptyItemsText: string;
}

/**
 * Window-scoped usage summary derived from the same telemetry series that feed
 * the charts, so the headline figures and the graphs share one data source and
 * stay in sync as the time-range slider moves. Totals cover the selected window,
 * not the calendar month.
 */
const UsageSummary: React.FC<UsageSummaryProps> = ({
  series,
  primaryKey,
  items,
  itemHeading,
  itemsTitle,
  emptyItemsText,
}) => {
  const byKey = useMemo(() => indexByKey(series), [series]);
  const primary = useMemo(() => sumWindow(byKey.get(primaryKey)), [byKey, primaryKey]);
  const rows = useMemo<UsageSummaryRow[]>(
    () =>
      items
        .map(item => ({ ...item, totals: sumWindow(byKey.get(item.key)) }))
        .sort((a, b) => b.totals.cost - a.totals.cost),
    [items, byKey]
  );

  return (
    <div className="card shadow mb-4">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-receipt"></i> Usage (selected window)
        </h6>
      </div>
      <div className="card-body">
        <div className="row mb-3">
          <div className="col-md-4">
            <div className="card border-0 bg-light">
              <div className="card-body">
                <div className="text-muted">
                  <small>Spend</small>
                </div>
                <h4 className="mb-0">{formatUsd(primary.cost)}</h4>
              </div>
            </div>
          </div>
          <div className="col-md-4">
            <div className="card border-0 bg-light">
              <div className="card-body">
                <div className="text-muted">
                  <small>Tokens</small>
                </div>
                <h4 className="mb-0">{primary.tokens.toLocaleString()}</h4>
              </div>
            </div>
          </div>
          <div className="col-md-4">
            <div className="card border-0 bg-light">
              <div className="card-body">
                <div className="text-muted">
                  <small>Requests</small>
                </div>
                <h4 className="mb-0">{primary.requests.toLocaleString()}</h4>
              </div>
            </div>
          </div>
        </div>
        <h6 className="text-primary">{itemsTitle}</h6>
        {rows.length === 0 ? (
          <p className="text-muted">
            <small>{emptyItemsText}</small>
          </p>
        ) : (
          <div className="table-responsive">
            <table className="table table-sm">
              <thead>
                <tr>
                  <th>{itemHeading}</th>
                  <th>Spend</th>
                  <th>Tokens</th>
                  <th>Requests</th>
                </tr>
              </thead>
              <tbody>
                {rows.map(row => (
                  <tr key={row.id}>
                    <td>
                      {row.label}
                      <div className="text-muted">
                        <small>{row.id}</small>
                      </div>
                    </td>
                    <td>{formatUsd(row.totals.cost)}</td>
                    <td>{row.totals.tokens.toLocaleString()}</td>
                    <td>{row.totals.requests.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default UsageSummary;
