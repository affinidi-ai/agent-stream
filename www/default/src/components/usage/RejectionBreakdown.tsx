import React, { useEffect, useMemo, useRef, useState } from 'react';
import { UI_COLORS, chartBarFill } from '../../utils/uiPalette';
import { fetchRejections, windowForSecs, type RejectionsResponse } from './usageSeries';

interface RejectionBreakdownProps {
  /** Rejection scope-key prefix, e.g. `rejection:all`, `rejection:surface:{id}`,
   * `rejection:team:{id}`, `rejection:member:{id}`. */
  scope: string;
  /** Committed window width (secs) — pass the same window driving the charts. */
  windowSecs: number;
  /** Committed pan offset behind now (0 = live). */
  endOffset: number;
  enabled?: boolean;
  title?: string;
}

/**
 * Window-scoped breakdown of guard rejections by canonical category (hate,
 * toxicity, prompt-injection, …) for a scope (all surfaces / one surface / a
 * team / a member). Reads the `requests` counter of the `rejection:{scope}:*`
 * telemetry series over the selected window, so the figures track the same
 * time-range slider as the spend/token charts. Counts are blocked-request
 * counts: a single rejection contributes to every triggered category plus the
 * `_total`, so categories can overlap and need not sum to the total.
 */
const RejectionBreakdown: React.FC<RejectionBreakdownProps> = ({
  scope,
  windowSecs,
  endOffset,
  enabled = true,
  title = 'Rejections by category (selected window)',
}) => {
  const [data, setData] = useState<RejectionsResponse | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    if (!enabled || !scope) {
      setData(null);
      return;
    }
    abortRef.current?.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    const w = windowForSecs(windowSecs, endOffset);
    fetchRejections(scope, w, undefined, ctrl.signal)
      .then(res => {
        if (abortRef.current === ctrl) setData(res);
      })
      .catch(() => {
        if (abortRef.current === ctrl) setData(null);
      });
    return () => ctrl.abort();
  }, [scope, windowSecs, endOffset, enabled]);

  const rows = useMemo(
    () => (data?.categories ?? []).slice().sort((a, b) => b.count - a.count),
    [data]
  );
  const total = data?.total ?? 0;

  return (
    <div className="card shadow mb-4">
      <div className="card-header py-3 d-flex align-items-center justify-content-between">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-shield-halved"></i> {title}
        </h6>
        <span
          className="badge"
          style={{ backgroundColor: chartBarFill(UI_COLORS.danger), color: '#fff' }}
        >
          {total.toLocaleString()} blocked
        </span>
      </div>
      <div className="card-body">
        {total === 0 || rows.length === 0 ? (
          <p className="text-muted mb-0">
            <small>No content rejections in this window.</small>
          </p>
        ) : (
          <div className="table-responsive">
            <table className="table table-sm align-middle mb-0">
              <thead>
                <tr>
                  <th style={{ width: '30%' }}>Category</th>
                  <th>Share</th>
                  <th style={{ width: '12%' }} className="text-end">
                    Count
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map(row => (
                  <tr key={row.category}>
                    <td>
                      {row.label || row.category}
                      <div className="text-muted">
                        <small>{row.category}</small>
                      </div>
                    </td>
                    <td>
                      <div
                        className="d-flex align-items-center gap-2"
                        title={`${total > 0 ? Math.round((row.count / total) * 100) : 0}% of blocked requests`}
                      >
                        <div
                          style={{
                            background: 'var(--bs-secondary-bg, #e9ecef)',
                            borderRadius: 4,
                            flex: 1,
                            height: 10,
                          }}
                        >
                          <div
                            style={{
                              background: UI_COLORS.danger,
                              borderRadius: 4,
                              height: '100%',
                              width: `${total > 0 ? (row.count / total) * 100 : 0}%`,
                            }}
                            aria-hidden="true"
                          />
                        </div>
                        <small className="text-muted" style={{ minWidth: 36 }}>
                          {total > 0 ? Math.round((row.count / total) * 100) : 0}%
                        </small>
                      </div>
                    </td>
                    <td className="text-end">{row.count.toLocaleString()}</td>
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

export default RejectionBreakdown;
