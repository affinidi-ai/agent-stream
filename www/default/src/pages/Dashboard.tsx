import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { WS_NONE, WS_DASHBOARD } from '../utils/wsSubscriptions';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  ChartOptions,
  Filler,
} from 'chart.js';
import { useApp } from '../context/AppContext';
import StatCard from '../components/StatCard';
import ChartCard from '../components/ChartCard';
import CacheStatsCards from '../components/shared/CacheStatsCards';
import LoadingOverlay from '../components/usage/LoadingOverlay';
import MetricChart, { ChartTypeSelect } from '../components/usage/MetricChart';
import { useChartAxisColors } from '../utils/chartTheme';
import RejectionBreakdown from '../components/usage/RejectionBreakdown';
import RejectionTimeline from '../components/usage/RejectionTimeline';
import TimeRangeScrubber, { type SparkMetric } from '../components/usage/TimeRangeScrubber';
import { useChartKind } from '../components/usage/chartPrefs';
import { useDragWindow } from '../components/usage/useDragWindow';
import { useOpsSeries } from '../components/usage/useOpsSeries';
import { useUsageSeries } from '../components/usage/useUsageSeries';
import {
  allSurfacesKey,
  formatUsd,
  formatUsdCeil,
  fullStamp,
  indexByKey,
  makeAxisLabels,
  opsAllKey,
  opsSurfaceKey,
  rejectionAllScope,
  sumWindow,
  surfaceKey,
} from '../components/usage/usageSeries';
import { CHART_PALETTE, UI_COLORS } from '../utils/uiPalette';
import { formatBytes } from '../utils/stringUtils';

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

// Static tooltip interaction shared by every chart. Module-level so it keeps a
// stable identity — a fresh object each render would bust the memoised chart
// options below and force a full canvas redraw on every scrubber pointer move.
const BASE_TIME_TOOLTIP = {
  mode: 'index' as const,
  intersect: false,
};

const Dashboard: React.FC = () => {
  const { state, actions, getCurrentStats } = useApp();
  const navigate = useNavigate();

  // Track if we've ever loaded data (to avoid showing spinner on refreshes)
  const hasLoadedOnce = useRef<boolean>(false);

  // Get the currently active stats (global or filtered)
  const stats = getCurrentStats();

  // Mark as loaded once we have stats
  if (stats && !hasLoadedOnce.current) {
    hasLoadedOnce.current = true;
  }

  // One dragged time window shared by every dashboard chart: dragging any rail
  // re-fetches them all in lockstep so they always show the same timespan/scale.
  // Persisted under `dashboard` so a refresh restores the user's last view.
  const win = useDragWindow('dashboard');

  // Per-chart render mode, each persisted so a refresh restores the user's pick.
  const [costKind, setCostKind] = useChartKind('cost', 'points');
  const [tokenKind, setTokenKind] = useChartKind('tokens', 'area');
  const [latencyKind, setLatencyKind] = useChartKind('latency', 'line');
  const [throughputKind, setThroughputKind] = useChartKind('throughput', 'area');
  const [surfaceCostKind, setSurfaceCostKind] = useChartKind('surfaceCost', 'points');
  const [surfaceTrafficKind, setSurfaceTrafficKind] = useChartKind('surfaceTraffic', 'line');

  // Resolve a surface (pipe) id to its display name, from the metrics summaries
  // then the task list. Shared by the top-surface ranking memos below.
  const pipeNameById = useMemo(() => {
    const nameById: Record<string, string> = {};
    stats?.pipe_metrics?.summaries?.forEach((s: any) => {
      if (s.pipe_id && s.pipe_name) nameById[s.pipe_id] = s.pipe_name;
    });
    stats?.pipe_tasks?.tasks?.forEach((t: any) => {
      if (t.id && t.name && !nameById[t.id]) nameById[t.id] = t.name;
    });
    return nameById;
  }, [stats]);

  // Top surfaces by spend — one cost line each on the per-surface chart.
  const surfaceItems = useMemo(() => {
    const ranked = [...(stats?.metrics?.pipe_stats ?? [])]
      .filter((p: any) => p.total_requests > 0 || p.total_cost > 0)
      .sort((a: any, b: any) => b.total_cost - a.total_cost)
      .slice(0, 10);
    return ranked.map((p: any) => ({
      label: pipeNameById[p.pipe_id] || p.pipe_name || 'Unnamed',
      key: surfaceKey(p.pipe_id),
    }));
  }, [stats, pipeNameById]);

  // Top surfaces by traffic (connection count) — one line each on the per-surface
  // traffic chart. Ranked independently of the cost chart: the busiest surface
  // isn't necessarily the most expensive.
  const surfaceTrafficItems = useMemo(() => {
    const ranked = [...(stats?.metrics?.pipe_stats ?? [])]
      .filter((p: any) => p.total_requests > 0)
      .sort((a: any, b: any) => b.total_requests - a.total_requests)
      .slice(0, 10);
    return ranked.map((p: any) => ({
      label: pipeNameById[p.pipe_id] || p.pipe_name || 'Unnamed',
      key: opsSurfaceKey(p.pipe_id),
    }));
  }, [stats, pipeNameById]);

  // Cost + per-surface cost come from the usage (billing) telemetry store; this
  // hook owns the shared rail's overview sparkline.
  const usageKeys = useMemo(
    () => [allSurfacesKey(), ...surfaceItems.map(s => s.key)],
    [surfaceItems]
  );
  const usage = useUsageSeries(usageKeys, true, win, true);
  // Tokens / latency / throughput (appliance-wide) and per-surface traffic come
  // from the operational telemetry store; it shares the same window and skips
  // its own overview fetch. `ops:all` stays first so `ops.points` is the
  // appliance-wide series the token/latency/throughput charts read. Every key
  // (up to 11) is fetched in one batched `/dashboard/ops-series` request.
  const opsKeys = useMemo(
    () => [opsAllKey(), ...surfaceTrafficItems.map(s => s.key)],
    [surfaceTrafficItems]
  );
  const ops = useOpsSeries(opsKeys, true, win, false);

  const usageByKey = useMemo(() => indexByKey(usage.series), [usage.series]);
  const costSeries = usageByKey.get(allSurfacesKey());
  // Window-scoped totals for the top stat cards, so they track the time slider
  // (the lifetime `pipe_stats` aggregate below is only used to rank surfaces).
  const windowTotals = useMemo(() => sumWindow(costSeries), [costSeries]);
  const usageLabels = useMemo(
    () =>
      makeAxisLabels(
        (costSeries?.points ?? []).map(p => p.t),
        usage.stepSecs
      ),
    [costSeries, usage.stepSecs]
  );
  // Raw bucket timestamps for the date-row / day-divider plugin.
  const usageTs = useMemo(() => (costSeries?.points ?? []).map(p => p.t), [costSeries]);
  // Full date+time per bucket for tooltip titles, so the hover keeps fidelity
  // even when an axis tick is abbreviated to just a date or a time.
  const usageStamps = useMemo(
    () => (costSeries?.points ?? []).map(p => fullStamp(p.t)),
    [costSeries]
  );
  const opsLabels = useMemo(
    () =>
      makeAxisLabels(
        ops.points.map(p => p.t),
        ops.stepSecs
      ),
    [ops.points, ops.stepSecs]
  );
  const opsTs = useMemo(() => ops.points.map(p => p.t), [ops.points]);
  const opsStamps = useMemo(() => ops.points.map(p => fullStamp(p.t)), [ops.points]);

  // Clear any dashboard filters when viewing main dashboard (only once on mount)
  useEffect(() => {
    actions.setDashboardFilters(null);
    // Subscribe to everything except logs to reduce WS payload size
    actions.setWsSubscription(WS_DASHBOARD);
    return () => {
      actions.setWsSubscription(WS_NONE);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // Run only once on mount

  const [isRefreshing, setIsRefreshing] = useState(false);

  // Render the shared drag rail bound to the single dashboard window. The same
  // `win` state backs every instance, so all five charts stay synchronised; the
  // usage hook supplies the rail's overview sparkline.
  // One rail per chart (all share the same window). Each passes the metric(s)
  // its own chart plots, so a bar is green only when that chart can actually
  // show the bucket, and muted grey when the bucket has only unrelated activity
  // (e.g. request-only traffic under the cost chart). The latency/throughput
  // charts are request-driven, so `requests` is their signal proxy (the usage
  // overview series carries requests, not ms/bytes).
  const renderScrubber = (relevantMetrics: SparkMetric[]) => (
    <TimeRangeScrubber
      windowSecs={win.windowSecs}
      endOffsetSecs={win.endOffset}
      domainSecs={win.domainSecs}
      overview={usage.overview}
      relevantMetrics={relevantMetrics}
      resolution={usage.resolution}
      loading={usage.loading || ops.loading}
      resolutionPref={win.resolutionPref}
      onResolution={win.onResolution}
      zoom={win.zoom}
      onZoom={win.onZoom}
      onPreset={win.onPreset}
      onWindowChange={win.onWindowChange}
      onWindowCommit={win.onWindowCommit}
      onLive={win.onLive}
    />
  );

  // Debug: Log when dashboard stats change
  useEffect(() => {
    // console.log('Dashboard stats updated:', {
    //   totalConnections: stats?.metrics?.total_connections,
    //   timeSeriesLength: stats?.metrics?.time_series?.length,
    //   latestPoint: stats?.metrics?.time_series?.[stats.metrics.time_series.length - 1]
    // });
  }, [stats?.metrics]);

  // Cost over time — total appliance spend from the usage (billing) telemetry,
  // plus a cache-savings line overlaid from the ops series (mapped by bucket).
  const costChartData = useMemo(() => {
    const savedByT = new Map(ops.points.map(p => [p.t, p.cache_saved_cost]));
    return {
      labels: usageLabels,
      datasets: [
        {
          label: 'Total Cost (USD)',
          data: (costSeries?.points ?? []).map(p => p.cost),
          borderColor: UI_COLORS.success,
          backgroundColor: UI_COLORS.success,
          borderWidth: 2,
          tension: 0.3,
        },
        {
          label: 'Cache Saved (USD)',
          data: (costSeries?.points ?? []).map(p => savedByT.get(p.t) ?? 0),
          borderColor: UI_COLORS.accentTeal,
          backgroundColor: UI_COLORS.accentTeal,
          borderWidth: 2,
          borderDash: [6, 4],
          tension: 0.3,
        },
      ],
    };
  }, [usageLabels, costSeries, ops.points]);

  // Surface cost over time — one line per top surface (by spend), aligned to the
  // total-cost timeline so every surface shares the same buckets.
  const surfaceCostChartData = useMemo(() => {
    const ts = (costSeries?.points ?? []).map(p => p.t);
    return {
      labels: usageLabels,
      datasets: surfaceItems.map((item, i) => {
        const color = CHART_PALETTE[i % CHART_PALETTE.length];
        const byT = new Map((usageByKey.get(item.key)?.points ?? []).map(p => [p.t, p.cost]));
        return {
          label: item.label,
          data: ts.map(t => byT.get(t) ?? null),
          borderColor: color,
          backgroundColor: color,
          borderWidth: 1.5,
          tension: 0.3,
        };
      }),
    };
  }, [usageLabels, surfaceItems, usageByKey, costSeries]);

  // Surface traffic over time — one connection-count line per top surface (by
  // traffic), aligned to the appliance-wide ops timeline so every surface shares
  // the same buckets. Reads the per-surface `ops:surface:{id}` series already
  // fetched alongside `ops:all` in the single ops request.
  const surfaceTrafficChartData = useMemo(() => {
    const ts = ops.points.map(p => p.t);
    return {
      labels: opsLabels,
      datasets: [
        {
          label: 'Cache Hits (all)',
          data: ops.points.map(p => p.cache_hits),
          borderColor: UI_COLORS.accentTeal,
          backgroundColor: UI_COLORS.accentTeal,
          borderWidth: 2,
          borderDash: [6, 4],
          tension: 0.3,
        },
        ...surfaceTrafficItems.map((item, i) => {
          const color = CHART_PALETTE[i % CHART_PALETTE.length];
          const byT = new Map(
            (ops.seriesByKey.get(item.key)?.points ?? []).map(p => [p.t, p.connections])
          );
          return {
            label: item.label,
            data: ts.map(t => byT.get(t) ?? null),
            borderColor: color,
            backgroundColor: color,
            borderWidth: 1.5,
            tension: 0.3,
          };
        }),
      ],
    };
  }, [opsLabels, surfaceTrafficItems, ops.seriesByKey, ops.points]);

  // Prepare data throughput chart data (bytes in/out per interval)
  const dataThroughputChartData = useMemo(
    () => ({
      labels: opsLabels,
      datasets: [
        {
          label: 'Bytes In',
          data: ops.points.map(p => p.request_bytes || 0),
          borderColor: UI_COLORS.primary,
          backgroundColor: UI_COLORS.primary,
          borderWidth: 1,
          tension: 0.4,
        },
        {
          label: 'Bytes Out',
          data: ops.points.map(p => p.response_bytes || 0),
          borderColor: UI_COLORS.accentTeal,
          backgroundColor: UI_COLORS.accentTeal,
          borderWidth: 1,
          tension: 0.4,
        },
      ],
    }),
    [ops.points, opsLabels]
  );

  // Prepare token usage chart data (input/output tokens per interval)
  const tokenUsageChartData = useMemo(
    () => ({
      labels: opsLabels,
      datasets: [
        {
          label: 'Input Tokens',
          data: ops.points.map(p => p.input_tokens || 0),
          borderColor: UI_COLORS.accentPurple,
          backgroundColor: UI_COLORS.accentPurple,
          borderWidth: 1,
          tension: 0.4,
        },
        {
          label: 'Output Tokens',
          data: ops.points.map(p => p.output_tokens || 0),
          borderColor: UI_COLORS.warning,
          backgroundColor: UI_COLORS.warning,
          borderWidth: 1,
          tension: 0.4,
        },
      ],
    }),
    [ops.points, opsLabels]
  );

  // Prepare latency chart data - memoized to avoid recalculating on every render
  const latencyChartData = useMemo(
    () => ({
      labels: opsLabels,
      datasets: [
        {
          label: 'p50 (Median)',
          data: ops.points.map(p => p.p50_latency_ms || 0),
          borderColor: UI_COLORS.success,
          backgroundColor: UI_COLORS.success,
          borderWidth: 2,
          tension: 0.3,
        },
        {
          label: 'p95',
          data: ops.points.map(p => p.p95_latency_ms || 0),
          borderColor: UI_COLORS.warning,
          backgroundColor: UI_COLORS.warning,
          borderWidth: 2,
          tension: 0.3,
        },
        {
          label: 'p99',
          data: ops.points.map(p => p.p99_latency_ms || 0),
          borderColor: UI_COLORS.danger,
          backgroundColor: UI_COLORS.danger,
          borderWidth: 2,
          tension: 0.3,
        },
        {
          label: 'Average',
          data: ops.points.map(p => p.avg_latency_ms || 0),
          borderColor: UI_COLORS.primary,
          backgroundColor: UI_COLORS.primary,
          borderWidth: 1,
          tension: 0.3,
          borderDash: [5, 5],
        },
      ],
    }),
    [ops.points, opsLabels]
  );

  // Chart options for different chart types
  // Tooltip title callbacks resolve the hovered bucket back to its full
  // date+time from the stamp arrays, so the hover always shows complete
  // fidelity even when the x-axis tick is abbreviated to a date or a time.
  // Memoised on the (drag-stable) stamp arrays so the options objects below keep
  // a stable identity while the scrubber is dragged — otherwise every pointer
  // move would hand Chart.js a new options ref and redraw each canvas.
  const usageTooltipTitle = useCallback(
    (items: { dataIndex: number }[]): string =>
      items.length ? (usageStamps[items[0].dataIndex] ?? '') : '',
    [usageStamps]
  );
  const opsTooltipTitle = useCallback(
    (items: { dataIndex: number }[]): string =>
      items.length ? (opsStamps[items[0].dataIndex] ?? '') : '',
    [opsStamps]
  );

  // Explicit axis colours so gridlines paint correctly on first render.
  const axis = useChartAxisColors();

  const costChartOptions = useMemo<ChartOptions<'line'>>(
    () => ({
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: true,
          position: 'top',
          labels: {
            usePointStyle: true,
            pointStyle: 'circle',
            boxWidth: 8,
            boxHeight: 8,
            padding: 15,
          },
        },
        tooltip: {
          ...BASE_TIME_TOOLTIP,
          callbacks: {
            title: usageTooltipTitle,
            label: context => {
              const label = context.dataset.label || '';
              return `${label}: ${formatUsd(context.parsed.y ?? 0)}`;
            },
          },
        },
      },
      scales: {
        x: {
          grid: { color: axis.grid },
          border: { color: axis.border },
          ticks: { color: axis.text },
        },
        y: {
          grid: { color: axis.grid },
          border: { color: axis.border },
          beginAtZero: true,
          ticks: {
            color: axis.text,
            callback: value => formatUsd(typeof value === 'number' ? value : Number(value)),
          },
        },
      },
      interaction: { mode: 'nearest', axis: 'x', intersect: false },
    }),
    [usageTooltipTitle, axis]
  );

  const surfaceCostChartOptions = useMemo<ChartOptions<'line'>>(
    () => ({
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: true,
          position: 'top',
          labels: {
            usePointStyle: true,
            pointStyle: 'circle',
            boxWidth: 8,
            boxHeight: 8,
            padding: 15,
          },
        },
        tooltip: {
          ...BASE_TIME_TOOLTIP,
          callbacks: {
            title: usageTooltipTitle,
            label: context => {
              const label = context.dataset.label || '';
              return `${label}: ${formatUsd(context.parsed.y ?? 0)}`;
            },
          },
        },
      },
      scales: {
        x: {
          grid: { color: axis.grid },
          border: { color: axis.border },
          ticks: { color: axis.text },
        },
        y: {
          grid: { color: axis.grid },
          border: { color: axis.border },
          beginAtZero: true,
          ticks: {
            color: axis.text,
            callback: value => formatUsd(typeof value === 'number' ? value : Number(value)),
          },
        },
      },
      interaction: { mode: 'nearest', axis: 'x', intersect: false },
    }),
    [usageTooltipTitle, axis]
  );

  const surfaceTrafficChartOptions = useMemo<ChartOptions<'line'>>(
    () => ({
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: true,
          position: 'top',
          labels: {
            usePointStyle: true,
            pointStyle: 'circle',
            boxWidth: 8,
            boxHeight: 8,
            padding: 15,
          },
        },
        tooltip: {
          ...BASE_TIME_TOOLTIP,
          callbacks: {
            title: opsTooltipTitle,
            label: context => {
              const label = context.dataset.label || '';
              return `${label}: ${(context.parsed.y ?? 0).toLocaleString()}`;
            },
          },
        },
      },
      scales: {
        x: {
          grid: { color: axis.grid },
          border: { color: axis.border },
          ticks: { color: axis.text },
        },
        y: {
          grid: { color: axis.grid },
          border: { color: axis.border },
          beginAtZero: true,
          ticks: { color: axis.text, precision: 0 },
        },
      },
      interaction: { mode: 'nearest', axis: 'x', intersect: false },
    }),
    [opsTooltipTitle, axis]
  );

  const latencyChartOptions = useMemo<ChartOptions<'line'>>(
    () => ({
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: true,
          position: 'top',
        },
        tooltip: { ...BASE_TIME_TOOLTIP, callbacks: { title: opsTooltipTitle } },
      },
      scales: {
        x: {
          display: true,
          grid: { color: axis.grid },
          border: { color: axis.border },
          ticks: { color: axis.text },
          title: {
            display: true,
            text: 'Time',
          },
        },
        y: {
          display: true,
          grid: { color: axis.grid },
          border: { color: axis.border },
          ticks: { color: axis.text },
          title: {
            display: true,
            text: 'Latency (ms)',
          },
          beginAtZero: true,
        },
      },
      interaction: {
        mode: 'nearest',
        axis: 'x',
        intersect: false,
      },
    }),
    [opsTooltipTitle, axis]
  );

  const dataThroughputChartOptions = useMemo<ChartOptions<'line'>>(
    () => ({
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: true,
          position: 'top',
          labels: {
            usePointStyle: true,
            pointStyle: 'circle',
            boxWidth: 8,
            boxHeight: 8,
            padding: 15,
          },
        },
        tooltip: {
          ...BASE_TIME_TOOLTIP,
          callbacks: {
            title: opsTooltipTitle,
            label: context => {
              const label = context.dataset.label || '';
              return `${label}: ${formatBytes(context.parsed.y ?? 0)}`;
            },
          },
        },
      },
      scales: {
        x: {
          grid: { color: axis.grid },
          border: { color: axis.border },
          ticks: { color: axis.text },
        },
        y: {
          grid: { color: axis.grid },
          border: { color: axis.border },
          beginAtZero: true,
          ticks: {
            color: axis.text,
            callback: value => formatBytes(typeof value === 'number' ? value : Number(value)),
          },
        },
      },
      interaction: { mode: 'nearest', axis: 'x', intersect: false },
    }),
    [opsTooltipTitle, axis]
  );

  const tokenUsageChartOptions = useMemo<ChartOptions<'line'>>(
    () => ({
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: true,
          position: 'top',
          labels: {
            usePointStyle: true,
            pointStyle: 'circle',
            boxWidth: 8,
            boxHeight: 8,
            padding: 15,
          },
        },
        tooltip: {
          ...BASE_TIME_TOOLTIP,
          callbacks: {
            title: opsTooltipTitle,
            label: context => {
              const label = context.dataset.label || '';
              return `${label}: ${(context.parsed.y ?? 0).toLocaleString()}`;
            },
          },
        },
      },
      scales: {
        x: {
          grid: { color: axis.grid },
          border: { color: axis.border },
          ticks: { color: axis.text },
        },
        y: {
          grid: { color: axis.grid },
          border: { color: axis.border },
          beginAtZero: true,
          ticks: {
            color: axis.text,
            precision: 0,
          },
        },
      },
      interaction: { mode: 'nearest', axis: 'x', intersect: false },
    }),
    [opsTooltipTitle, axis]
  );

  const handleManualRefresh = async () => {
    setIsRefreshing(true);
    try {
      await actions.loadDashboardStats();
    } finally {
      setIsRefreshing(false);
    }
  };

  // Only show loading spinner on INITIAL load (when we've never loaded data before)
  // Don't show spinner for subsequent refreshes to avoid disturbing the user
  if (!hasLoadedOnce.current && state.isLoading.dashboard) {
    return (
      <div className="container-fluid">
        <div
          className="d-flex justify-content-center align-items-center"
          style={{ minHeight: 'calc(100vh - 150px)' }}
        >
          <div className="text-center">
            <div className="spinner-border text-primary" role="status"></div>
          </div>
        </div>
      </div>
    );
  }

  // Show error state if there's an error
  if (state.error) {
    return (
      <div className="container-fluid">
        <div className="row justify-content-center">
          <div className="col-lg-6">
            <div className="card border-left-danger shadow">
              <div className="card-body">
                <div className="text-center">
                  <div className="mb-3">
                    <i className="fas fa-exclamation-triangle hero-status-icon danger"></i>
                  </div>
                  <h4 className="text-gray-800">Dashboard Error</h4>
                  <p className="text-gray-600 mb-4">{state.error}</p>
                  <button
                    className="btn btn-primary"
                    onClick={handleManualRefresh}
                    disabled={isRefreshing}
                  >
                    <i className={`fas fa-sync-alt ${isRefreshing ? 'fa-spin' : ''} me-2`}></i>
                    Try Again
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // stats is already declared at the top of the component
  const pipeStats = stats?.metrics?.pipe_stats ?? [];
  // Response-cache effectiveness summed across every surface.
  const cacheTotals = (pipeStats as any[]).reduce(
    (acc, p) => ({
      hits: acc.hits + (p.cache_hits ?? 0),
      savedCost: acc.savedCost + (p.cache_saved_cost ?? 0),
      savedTokens: acc.savedTokens + (p.cache_saved_tokens ?? 0),
      requests: acc.requests + (p.total_requests ?? 0),
    }),
    { hits: 0, savedCost: 0, savedTokens: 0, requests: 0 }
  );

  return (
    <div className="container-fluid" data-testid="page-dashboard">
      {/* Statistics Cards Row */}
      <div id="statistics-section"></div>

      {/* Pipe Metrics Row — always shown */}
      <div className="row">
        <StatCard
          title="Active Surfaces"
          value={pipeStats.length}
          icon="fa-brain"
          color="success"
          onClick={() => navigate('/llm')}
          subtitle={`${pipeStats.filter((p: any) => p.total_requests > 0).length} with traffic`}
          testId="dashboard-stat-pipes"
        />

        {/* LLM Latency Card */}
        <div className="col-xl-3 col-md-6 mb-4">
          <div
            className="card stat-card info shadow h-100 py-2"
            onClick={() => navigate('/tasks')}
            style={{ cursor: 'pointer' }}
            title="Click to view pipe tasks"
          >
            <div className="card-body">
              <div className="row no-gutters align-items-center">
                <div className="col me-2">
                  <div className="text-xs font-weight-bold text-info text-uppercase mb-1">
                    LLM Latency
                    <small
                      className="text-muted d-block"
                      style={{
                        fontSize: '0.65rem',
                        fontWeight: 'normal',
                        textTransform: 'none',
                      }}
                    >
                      Last {stats?.metrics?.latency_window_minutes ?? 60} min
                    </small>
                  </div>
                  <div className="mb-2">
                    <div className="d-flex align-items-center mb-1">
                      <i
                        className="fas fa-microchip text-info me-2"
                        style={{ fontSize: '0.875rem' }}
                      ></i>
                      <span className="text-xs text-muted me-2">Agent Stream:</span>
                      <span className="h6 mb-0 font-weight-bold text-gray-800">
                        {stats?.metrics?.avg_pipe_gateway_processing_ms
                          ? `${stats.metrics.avg_pipe_gateway_processing_ms.toFixed(2)}ms`
                          : 'N/A'}
                      </span>
                    </div>
                    <div className="d-flex align-items-center">
                      <i
                        className="fas fa-brain text-primary me-2"
                        style={{ fontSize: '0.875rem' }}
                      ></i>
                      <span className="text-xs text-muted me-2">LLM Target:</span>
                      <span className="h6 mb-0 font-weight-bold text-gray-800">
                        {stats?.metrics?.avg_pipe_target_processing_ms
                          ? `${stats.metrics.avg_pipe_target_processing_ms.toFixed(2)}ms`
                          : 'N/A'}
                      </span>
                    </div>
                  </div>
                </div>
                <div className="col-auto">
                  <i className="fas fa-tachometer-alt fa-2x text-gray-300"></i>
                </div>
              </div>
            </div>
          </div>
        </div>

        <StatCard
          title="Total Tokens"
          value={(() => {
            const total = windowTotals.tokens;
            if (total >= 1000000) return `${(total / 1000000).toFixed(2)}M`;
            if (total >= 1000) return `${(total / 1000).toFixed(1)}K`;
            return total.toString();
          })()}
          icon="fa-coins"
          color="info"
          onClick={() => navigate('/tasks')}
          subtitle="Combined I/O · selected window"
        />

        <StatCard
          title="Total Cost"
          value={formatUsdCeil(windowTotals.cost)}
          icon="fa-dollar-sign"
          color="danger"
          onClick={() => navigate('/tasks')}
          subtitle={(() => {
            const avgPerInteraction =
              windowTotals.requests > 0 ? windowTotals.cost / windowTotals.requests : 0;
            return `Avg: $${avgPerInteraction.toFixed(4)}/interaction · selected window`;
          })()}
        />
      </div>

      {/* Response-cache effectiveness across all surfaces. */}
      <CacheStatsCards
        variant="stat"
        cacheHits={cacheTotals.hits}
        cacheSavedCost={cacheTotals.savedCost}
        cacheSavedTokens={cacheTotals.savedTokens}
        totalRequests={cacheTotals.requests}
      />

      {/* Charts: every chart shares one dragged window (the rail under each) */}
      <div id="metrics-section"></div>

      <div className="row">
        <ChartCard
          title="Data Throughput Over Time"
          headerActions={
            <ChartTypeSelect
              value={throughputKind}
              onChange={setThroughputKind}
              label="Data throughput over time"
            />
          }
        >
          <div style={{ height: '300px' }} data-testid="dashboard-throughput-chart">
            <MetricChart
              kind={throughputKind}
              data={dataThroughputChartData}
              options={dataThroughputChartOptions}
              ariaLabel="Data throughput over time chart"
              timestamps={opsTs}
              stepSecs={ops.stepSecs}
            />
          </div>
          {renderScrubber(['requests'])}
        </ChartCard>
      </div>

      <div style={{ position: 'relative' }}>
        <LoadingOverlay active={usage.loading || ops.loading} variant="page" />
        <div className="row">
          <ChartCard
            title="Cost Over Time"
            headerActions={
              <ChartTypeSelect value={costKind} onChange={setCostKind} label="Cost over time" />
            }
          >
            <div style={{ height: '300px' }} data-testid="dashboard-cost-chart">
              <MetricChart
                kind={costKind}
                data={costChartData}
                options={costChartOptions}
                ariaLabel="Cost over time chart"
                timestamps={usageTs}
                stepSecs={usage.stepSecs}
              />
            </div>
            {renderScrubber(['cost'])}
          </ChartCard>
        </div>

        <div className="row">
          <ChartCard
            title="Token Usage Over Time"
            headerActions={
              <ChartTypeSelect
                value={tokenKind}
                onChange={setTokenKind}
                label="Token usage over time"
              />
            }
          >
            <div style={{ height: '300px' }} data-testid="dashboard-tokens-chart">
              <MetricChart
                kind={tokenKind}
                data={tokenUsageChartData}
                options={tokenUsageChartOptions}
                ariaLabel="Token usage over time chart"
                timestamps={opsTs}
                stepSecs={ops.stepSecs}
              />
            </div>
            {renderScrubber(['tokens'])}
          </ChartCard>
        </div>

        <div id="latency-section"></div>
        <div className="row">
          <ChartCard
            title="LLM Latency Over Time (p50, p95, p99)"
            headerActions={
              <ChartTypeSelect
                value={latencyKind}
                onChange={setLatencyKind}
                label="LLM latency over time"
              />
            }
          >
            <div style={{ height: '300px' }}>
              <MetricChart
                kind={latencyKind}
                data={latencyChartData}
                options={latencyChartOptions}
                ariaLabel="LLM latency over time chart"
                timestamps={opsTs}
                stepSecs={ops.stepSecs}
              />
            </div>
            {renderScrubber(['requests'])}
          </ChartCard>
        </div>

        <div className="row">
          <ChartCard
            title="Surface Cost Over Time (Top 10)"
            headerActions={
              <ChartTypeSelect
                value={surfaceCostKind}
                onChange={setSurfaceCostKind}
                label="Surface cost over time"
              />
            }
          >
            <div style={{ height: '300px' }} data-testid="dashboard-surface-cost-chart">
              <MetricChart
                kind={surfaceCostKind}
                data={surfaceCostChartData}
                options={surfaceCostChartOptions}
                ariaLabel="Surface cost over time chart"
                timestamps={usageTs}
                stepSecs={usage.stepSecs}
              />
            </div>
            {renderScrubber(['cost'])}
          </ChartCard>
        </div>

        <div className="row">
          <ChartCard
            title="Surface Traffic Over Time (Top 10)"
            headerActions={
              <ChartTypeSelect
                value={surfaceTrafficKind}
                onChange={setSurfaceTrafficKind}
                label="Surface traffic over time"
              />
            }
          >
            <div style={{ height: '300px' }} data-testid="dashboard-surface-traffic-chart">
              <MetricChart
                kind={surfaceTrafficKind}
                data={surfaceTrafficChartData}
                options={surfaceTrafficChartOptions}
                ariaLabel="Surface traffic over time chart"
                timestamps={opsTs}
                stepSecs={ops.stepSecs}
              />
            </div>
            {renderScrubber(['requests'])}
          </ChartCard>
        </div>

        <RejectionTimeline
          scope={rejectionAllScope()}
          windowSecs={win.committed.windowSecs}
          endOffset={win.committed.endOffset}
          resolution={win.resolutionPref}
          chartKindPrefix="dashboard"
        />

        <RejectionBreakdown
          scope={rejectionAllScope()}
          windowSecs={win.committed.windowSecs}
          endOffset={win.committed.endOffset}
        />
      </div>
    </div>
  );
};

export default Dashboard;
