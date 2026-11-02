import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useApp } from '../context/AppContext';
import { apiClient } from '../api';
import TimeRangeScrubber from './usage/TimeRangeScrubber';
import UsageCharts from './usage/UsageCharts';
import { useUsageSeries } from './usage/useUsageSeries';
import {
  allSurfacesKey,
  formatUsd,
  indexByKey,
  sumWindow,
  surfaceKey,
  type BreakdownItem,
} from './usage/usageSeries';

type TimeRange = '1h' | '24h' | '7d' | '30d';

// Telemetry caps a request at 256 keys; reserve one for the all-surfaces total.
const MAX_SURFACE_KEYS = 250;

interface PipeMetricSummary {
  pipe_id: string;
  pipe_name: string;
  provider: string;
  model: string;
  total_requests: number;
  total_input_tokens: number;
  total_output_tokens: number;
  total_tokens: number;
  total_cost: number;
  avg_latency_ms: number;
  error_count: number;
  success_rate: number;
}

interface PipeMetricsResponse {
  summaries: PipeMetricSummary[];
  total_cost: number;
  total_tokens: number;
  total_requests: number;
}

interface PipeRegistryEntry {
  id: string;
  name: string;
  description?: string;
}

const formatNumber = (num: number): string => {
  if (num >= 1_000_000) return `${(num / 1_000_000).toFixed(2)}M`;
  if (num >= 1_000) return `${(num / 1_000).toFixed(2)}K`;
  return num.toString();
};

const successRateBadge = (rate: number): string =>
  rate >= 99 ? 'text-bg-success' : rate >= 95 ? 'text-bg-warning' : 'text-bg-danger';

// Operational columns come from the metrics store, whose windows are fixed.
// Map the dragged telemetry window width onto the closest supported window.
const metricsRangeForWindow = (windowSecs: number): TimeRange => {
  if (windowSecs <= 3600) return '1h';
  if (windowSecs <= 86_400) return '24h';
  if (windowSecs <= 604_800) return '7d';
  return '30d';
};

const PipeMetricsBreakdown: React.FC = () => {
  const { state } = useApp();
  const navigate = useNavigate();
  const [httpMetrics, setHttpMetrics] = useState<PipeMetricsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pipes, setPipes] = useState<PipeRegistryEntry[]>([]);

  // Telemetry is the single source of truth for spend / tokens / requests.
  const breakdownItems = useMemo<BreakdownItem[]>(
    () =>
      pipes
        .slice(0, MAX_SURFACE_KEYS)
        .map(p => ({ id: p.id, label: p.name || p.id, key: surfaceKey(p.id) })),
    [pipes]
  );
  const keys = useMemo(
    () => [allSurfacesKey(), ...breakdownItems.map(b => b.key)],
    [breakdownItems]
  );
  const usage = useUsageSeries(keys, true);

  const metricsRange = metricsRangeForWindow(usage.windowSecs);

  // 24h (no pipe filter) is pushed over the dashboard websocket; other ranges
  // come from the historical HTTP endpoint with a light polling refresh.
  const wsPipeMetrics = state.globalState.stats?.pipe_metrics as PipeMetricsResponse | undefined;

  const loadMetrics = React.useCallback(async () => {
    try {
      setError(null);
      const params = new URLSearchParams({ time_range: metricsRange });
      const response = await apiClient.fetch(`/api/v1/pipes-metrics?${params}`);
      if (!response.ok) {
        throw new Error(`Failed to fetch metrics: ${response.status} ${response.statusText}`);
      }
      const data: PipeMetricsResponse = await response.json();
      setHttpMetrics(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error occurred');
    }
  }, [metricsRange]);

  useEffect(() => {
    if (metricsRange === '24h') {
      setHttpMetrics(null);
      return;
    }
    loadMetrics();
    const interval = setInterval(loadMetrics, 30000);
    return () => clearInterval(interval);
  }, [metricsRange, loadMetrics]);

  // Surface name / description for the table, joined from the pipes registry.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const response = await apiClient.fetch('/api/v1/pipes');
        if (!response.ok) return;
        const data: Array<{
          id: string;
          name?: string;
          description?: string;
          pipe_type?: { type?: string };
        }> = await response.json();
        if (cancelled) return;
        setPipes(
          data
            .filter(p => p.pipe_type?.type === 'llm')
            .map(p => ({ id: p.id, name: p.name || p.id, description: p.description?.trim() }))
        );
      } catch {
        // Non-fatal: charts still render from the telemetry keys we already hold.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const metrics = metricsRange === '24h' ? (wsPipeMetrics ?? null) : httpMetrics;
  const summaries = useMemo(() => metrics?.summaries ?? [], [metrics]);

  const summaryById = useMemo(() => {
    const map: Record<string, PipeMetricSummary> = {};
    for (const s of summaries) map[s.pipe_id] = s;
    return map;
  }, [summaries]);

  // Per-surface spend / tokens / requests for the window, from telemetry.
  const surfaceTotals = useMemo(() => {
    const byKey = indexByKey(usage.series);
    const out: Record<string, { cost: number; tokens: number; requests: number }> = {};
    for (const item of breakdownItems) {
      out[item.id] = sumWindow(byKey.get(item.key));
    }
    return out;
  }, [usage.series, breakdownItems]);

  const rows = useMemo(
    () =>
      pipes
        .map(p => ({
          pipe: p,
          tele: surfaceTotals[p.id] ?? { cost: 0, tokens: 0, requests: 0 },
          sum: summaryById[p.id],
        }))
        .filter(r => r.tele.requests > 0 || r.tele.cost > 0 || r.tele.tokens > 0 || r.sum)
        .sort((a, b) => b.tele.cost - a.tele.cost),
    [pipes, surfaceTotals, summaryById]
  );

  // Error rate stays an operational figure (telemetry has no error counter).
  const errorTotals = useMemo(
    () =>
      summaries.reduce(
        (acc, m) => ({
          requests: acc.requests + m.total_requests,
          errors: acc.errors + m.error_count,
        }),
        { requests: 0, errors: 0 }
      ),
    [summaries]
  );
  const errorRate =
    errorTotals.requests > 0 ? (errorTotals.errors / errorTotals.requests) * 100 : 0;

  const hasData = rows.length > 0;

  return (
    <>
      <div id="pipe-metrics-section"></div>
      <div className="d-sm-flex align-items-center justify-content-between mb-3">
        <h5 className="m-0 font-weight-bold text-gray-800">
          <i className="fas fa-stream me-2"></i>
          LLM Surface Metrics
        </h5>
      </div>

      <TimeRangeScrubber
        windowSecs={usage.windowSecs}
        endOffsetSecs={usage.endOffset}
        domainSecs={usage.domainSecs}
        overview={usage.overview}
        resolution={usage.resolution}
        loading={usage.loading}
        activePresetLabel={usage.activePresetLabel}
        onPreset={usage.onPreset}
        onWindowChange={usage.onWindowChange}
        onWindowCommit={usage.onWindowCommit}
        onLive={usage.onLive}
      />

      {error && (
        <div className="alert alert-danger" role="alert" data-testid="pipe-metrics-error">
          <i className="fas fa-exclamation-triangle me-2"></i>
          {error}
        </div>
      )}

      <div className="row">
        <div className="col-12 mb-4">
          <div className="card shadow h-100">
            <div className="card-header py-3">
              <h6 className="m-0 font-weight-bold text-primary">Usage over time</h6>
            </div>
            <div className="card-body" data-testid="pipe-metrics-usage-charts">
              <UsageCharts
                series={usage.series}
                stepSecs={usage.stepSecs}
                primaryKey={allSurfacesKey()}
                primaryTitle="Total spend & tokens over time"
                breakdownItems={breakdownItems}
                breakdownTitle="Spend by surface"
                emptyMessage="No usage recorded in this window."
              />
            </div>
          </div>
        </div>
      </div>

      <div className="row">
        <div className="col-xl-4 col-md-6 mb-4">
          <div
            className="card border-left-warning shadow h-100 py-2"
            data-testid="pipe-metrics-error-rate"
          >
            <div className="card-body">
              <div className="row no-gutters align-items-center">
                <div className="col me-2">
                  <div className="text-xs font-weight-bold text-warning text-uppercase mb-1">
                    Error Rate
                  </div>
                  <div className="h5 mb-0 font-weight-bold text-gray-800">
                    {errorRate.toFixed(2)}%
                  </div>
                  <div className="text-xs text-muted mt-1">{errorTotals.errors} errors</div>
                </div>
                <div className="col-auto">
                  <i className="fas fa-exclamation-triangle fa-2x text-gray-300"></i>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="col-xl-8 mb-4">
          <div className="card shadow h-100">
            <div className="card-header py-3">
              <h6 className="m-0 font-weight-bold text-primary">Surface Performance</h6>
            </div>
            <div className="card-body">
              {!hasData ? (
                <div
                  className="alert alert-info mb-0"
                  role="alert"
                  data-testid="pipe-metrics-empty"
                >
                  <i className="fas fa-info-circle me-2"></i>
                  No surface usage recorded for the selected time range.
                </div>
              ) : (
                <div className="table-responsive">
                  <table className="table table-hover" data-testid="pipe-metrics-table">
                    <thead>
                      <tr>
                        <th>Surface</th>
                        <th>Provider</th>
                        <th>Model</th>
                        <th>Requests</th>
                        <th>Total Tokens</th>
                        <th>Avg Latency</th>
                        <th title="Combined spend across every pipeline stage that ran: LLM, Judge, Jury and Decider">
                          Cost{' '}
                          <i
                            className="fas fa-circle-info text-muted"
                            style={{ fontSize: '0.75rem' }}
                          ></i>
                        </th>
                        <th>Success Rate</th>
                      </tr>
                    </thead>
                    <tbody>
                      {rows.map(({ pipe, tele, sum }) => (
                        <tr
                          key={pipe.id}
                          data-testid={`pipe-metrics-row-${pipe.id}`}
                          onClick={() => navigate(`/llm/${pipe.id}`)}
                          style={{ cursor: 'pointer' }}
                          title={`Open ${pipe.name}`}
                        >
                          <td>
                            <strong>{pipe.name}</strong>
                            {pipe.description && (
                              <>
                                <br />
                                <small className="text-muted">{pipe.description}</small>
                              </>
                            )}
                          </td>
                          <td>
                            {sum ? (
                              <span className="badge text-bg-info">{sum.provider}</span>
                            ) : (
                              <span className="text-muted">—</span>
                            )}
                          </td>
                          <td>
                            {sum ? <code>{sum.model}</code> : <span className="text-muted">—</span>}
                          </td>
                          <td>{formatNumber(tele.requests)}</td>
                          <td>
                            <strong>{formatNumber(tele.tokens)}</strong>
                          </td>
                          <td>
                            {sum ? (
                              `${sum.avg_latency_ms}ms`
                            ) : (
                              <span className="text-muted">—</span>
                            )}
                          </td>
                          <td>
                            <strong>{formatUsd(tele.cost)}</strong>
                          </td>
                          <td>
                            {sum ? (
                              <span className={`badge ${successRateBadge(sum.success_rate)}`}>
                                {sum.success_rate.toFixed(2)}%
                              </span>
                            ) : (
                              <span className="text-muted">—</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default PipeMetricsBreakdown;
