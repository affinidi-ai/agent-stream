import React, { useMemo } from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title as ChartTitle,
  Tooltip,
  Legend,
  ChartOptions,
  Filler,
} from 'chart.js';
import { formatBytes } from '../../../utils/stringUtils';
import PipeLogsViewer from './PipeLogsViewer';
import CacheStatsCards from '../../../components/shared/CacheStatsCards';
import MetricChart, { ChartTypeSelect } from '../../../components/usage/MetricChart';
import RejectionBreakdown from '../../../components/usage/RejectionBreakdown';
import RejectionTimeline from '../../../components/usage/RejectionTimeline';
import TimeRangeScrubber from '../../../components/usage/TimeRangeScrubber';
import { useChartKind } from '../../../components/usage/chartPrefs';
import { useDragWindow } from '../../../components/usage/useDragWindow';
import { useOpsSeries } from '../../../components/usage/useOpsSeries';
import { useUsageSeries } from '../../../components/usage/useUsageSeries';
import {
  fullStamp,
  indexByKey,
  makeAxisLabels,
  opsSurfaceKey,
  rejectionSurfaceScope,
  sumWindow,
  surfaceStageKey,
} from '../../../components/usage/usageSeries';
import { UI_COLORS } from '../../../utils/uiPalette';
import { useChartAxisColors } from '../../../utils/chartTheme';

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  ChartTitle,
  Tooltip,
  Legend,
  Filler
);

interface StageAggregate {
  total_input_tokens: number;
  total_output_tokens: number;
  total_cost: number;
  avg_latency_ms: number;
}

interface PipeStageStats {
  llm: StageAggregate;
  judge: StageAggregate;
  jury: StageAggregate;
  decider: StageAggregate;
}

interface PipeStats {
  pipe_id: string;
  pipe_name: string;
  total_requests: number;
  successful_requests: number;
  failed_requests: number;
  avg_latency_ms: number;
  avg_gateway_processing_ms: number;
  avg_target_processing_ms: number;
  total_input_tokens: number;
  total_output_tokens: number;
  total_cost: number;
  /** Executions served from the response cache (no upstream call). */
  cache_hits?: number;
  /** Cumulative provider spend avoided by cache hits. */
  cache_saved_cost?: number;
  /** Cumulative tokens avoided by cache hits. */
  cache_saved_tokens?: number;
  stage_usage?: PipeStageStats;
  last_request_at?: string;
}

export interface PipeMonitoringTabProps {
  pipeId: string;
  pipeName: string;
  state: any;
  actions: any;
}

const PipeMonitoringTab: React.FC<PipeMonitoringTabProps> = ({ pipeId, pipeName, state }) => {
  const win = useDragWindow('surface-monitoring');
  // Explicit axis colours so gridlines paint correctly on first render.
  const axis = useChartAxisColors();
  const ops = useOpsSeries([opsSurfaceKey(pipeId)], true, win, true);

  // Per-stage cost/tokens for the top cards come from the usage telemetry, so
  // they track the time slider. (Avg latency stays a lifetime figure below —
  // telemetry carries no per-stage latency.) Shares the tab's one window.
  const stageKeys = useMemo(
    () => [
      surfaceStageKey(pipeId, 'llm'),
      surfaceStageKey(pipeId, 'judge'),
      surfaceStageKey(pipeId, 'jury'),
      surfaceStageKey(pipeId, 'decider'),
    ],
    [pipeId]
  );
  const stageUsageSeries = useUsageSeries(stageKeys, !!pipeId, win, false);
  const stageSeriesByKey = useMemo(
    () => indexByKey(stageUsageSeries.series),
    [stageUsageSeries.series]
  );

  const [trafficKind, setTrafficKind] = useChartKind('surfaceMon.traffic', 'area');
  const [errorRateKind, setErrorRateKind] = useChartKind('surfaceMon.errorRate', 'area');
  const [bytesKind, setBytesKind] = useChartKind('surfaceMon.bytes', 'area');
  const [tokensKind, setTokensKind] = useChartKind('surfaceMon.tokens', 'area');
  const [latencyKind, setLatencyKind] = useChartKind('surfaceMon.latency', 'line');

  // Get pipe stats from dashboard
  const pipeStats = useMemo(() => {
    // Get stats from the appropriate view (filtered or global)
    const dashboardStats =
      state.activeView === 'filtered' ? state.filteredState?.stats : state.globalState?.stats;

    const metrics = dashboardStats?.metrics;
    if (!metrics) {
      return null;
    }

    // When filtered by pipe_id, the backend might return a single pipe's stats directly
    // or still return it as an array with one item
    const stats = metrics.pipe_stats;
    if (!stats) {
      return null;
    }

    // If it's an array, find the matching pipe
    if (Array.isArray(stats)) {
      const found = stats.find((p: PipeStats) => p.pipe_id === pipeId);
      return found || null;
    }

    // If it's a single object and matches our pipe, use it
    if ((stats as any).pipe_id === pipeId) {
      return stats as PipeStats;
    }

    return null;
  }, [state.activeView, state.globalState, state.filteredState, pipeId]);

  const labels = useMemo(
    () =>
      makeAxisLabels(
        ops.points.map(p => p.t),
        ops.stepSecs
      ),
    [ops.points, ops.stepSecs]
  );
  // Full date+time per bucket for tooltip titles, so the hover keeps fidelity
  // even when an axis tick is abbreviated to just a date or a time.
  const stamps = useMemo(() => ops.points.map(p => fullStamp(p.t)), [ops.points]); // Raw bucket timestamps for the date-row / day-divider plugin.
  const opsTs = useMemo(() => ops.points.map(p => p.t), [ops.points]);
  const tooltipTitle = (items: { dataIndex: number }[]): string =>
    items.length ? (stamps[items[0].dataIndex] ?? '') : '';

  // Prepare traffic chart data for this pipe from the operational time-series.
  const pipeTrafficChartData = useMemo(
    () => ({
      labels,
      datasets: [
        {
          label: 'Total Requests',
          data: ops.points.map(p => p.connections),
          borderColor: UI_COLORS.primary,
          backgroundColor: UI_COLORS.primary,
          borderWidth: 2,
          tension: 0.3,
        },
        {
          label: 'Successful',
          data: ops.points.map(p => Math.max(0, p.connections - p.failed)),
          borderColor: UI_COLORS.success,
          backgroundColor: UI_COLORS.success,
          borderWidth: 2,
          tension: 0.3,
        },
        {
          label: 'Failed',
          data: ops.points.map(p => p.failed),
          borderColor: UI_COLORS.danger,
          backgroundColor: UI_COLORS.danger,
          borderWidth: 2,
          tension: 0.3,
        },
        {
          label: 'Cache Hits',
          data: ops.points.map(p => p.cache_hits),
          borderColor: UI_COLORS.accentTeal,
          backgroundColor: UI_COLORS.accentTeal,
          borderWidth: 2,
          borderDash: [6, 4],
          tension: 0.3,
        },
      ],
    }),
    [labels, ops.points]
  );

  // Prepare error rate chart data (failed / connections per bucket, as %).
  const pipeErrorRateChartData = useMemo(
    () => ({
      labels,
      datasets: [
        {
          label: 'Error Rate (%)',
          data: ops.points.map(p => (p.connections > 0 ? (p.failed / p.connections) * 100 : 0)),
          borderColor: UI_COLORS.danger,
          backgroundColor: UI_COLORS.danger,
          borderWidth: 2,
          tension: 0.3,
        },
      ],
    }),
    [labels, ops.points]
  );

  // Prepare data transfer chart data (bytes in/out per bucket).
  const pipeBytesChartData = useMemo(
    () => ({
      labels,
      datasets: [
        {
          label: 'Bytes In',
          data: ops.points.map(p => p.request_bytes),
          borderColor: UI_COLORS.primary,
          backgroundColor: UI_COLORS.primary,
          borderWidth: 2,
          tension: 0.3,
        },
        {
          label: 'Bytes Out',
          data: ops.points.map(p => p.response_bytes),
          borderColor: UI_COLORS.accentTeal,
          backgroundColor: UI_COLORS.accentTeal,
          borderWidth: 2,
          tension: 0.3,
        },
      ],
    }),
    [labels, ops.points]
  );

  // Prepare token usage chart data (input/output tokens per bucket).
  const pipeTokensChartData = useMemo(
    () => ({
      labels,
      datasets: [
        {
          label: 'Input Tokens',
          data: ops.points.map(p => p.input_tokens),
          borderColor: UI_COLORS.accentPurple,
          backgroundColor: UI_COLORS.accentPurple,
          borderWidth: 2,
          tension: 0.3,
        },
        {
          label: 'Output Tokens',
          data: ops.points.map(p => p.output_tokens),
          borderColor: UI_COLORS.warning,
          backgroundColor: UI_COLORS.warning,
          borderWidth: 2,
          tension: 0.3,
        },
      ],
    }),
    [labels, ops.points]
  );

  // Prepare latency chart data (p50/p95/p99/avg per bucket).
  const pipeLatencyChartData = useMemo(
    () => ({
      labels,
      datasets: [
        {
          label: 'p50 (Median)',
          data: ops.points.map(p => p.p50_latency_ms),
          borderColor: UI_COLORS.success,
          backgroundColor: UI_COLORS.success,
          borderWidth: 2,
          tension: 0.3,
        },
        {
          label: 'p95',
          data: ops.points.map(p => p.p95_latency_ms),
          borderColor: UI_COLORS.warning,
          backgroundColor: UI_COLORS.warning,
          borderWidth: 2,
          tension: 0.3,
        },
        {
          label: 'p99',
          data: ops.points.map(p => p.p99_latency_ms),
          borderColor: UI_COLORS.danger,
          backgroundColor: UI_COLORS.danger,
          borderWidth: 2,
          tension: 0.3,
        },
        {
          label: 'Average',
          data: ops.points.map(p => p.avg_latency_ms),
          borderColor: UI_COLORS.primary,
          backgroundColor: UI_COLORS.primary,
          borderWidth: 1,
          tension: 0.3,
          borderDash: [5, 5],
        },
      ],
    }),
    [labels, ops.points]
  );

  const renderScrubber = () => (
    <TimeRangeScrubber
      windowSecs={win.windowSecs}
      endOffsetSecs={win.endOffset}
      domainSecs={win.domainSecs}
      overview={ops.overview}
      resolution={ops.resolution}
      loading={ops.loading}
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

  const trafficChartOptions: ChartOptions<'line'> = {
    responsive: true,
    maintainAspectRatio: false,
    interaction: {
      mode: 'index',
      intersect: false,
    },
    plugins: {
      legend: {
        display: true,
        position: 'top',
      },
      title: {
        display: false,
      },
      tooltip: {
        callbacks: {
          title: tooltipTitle,
          label: context => {
            return `${context.dataset.label}: ${context.parsed.y}`;
          },
        },
      },
    },
    scales: {
      y: {
        grid: { color: axis.grid },
        border: { color: axis.border },
        beginAtZero: true,
        title: {
          display: true,
          text: 'Requests',
        },
        ticks: {
          color: axis.text,
          precision: 0,
        },
      },
      x: {
        grid: { color: axis.grid },
        border: { color: axis.border },
        ticks: { color: axis.text },
        title: {
          display: true,
          text: 'Time',
        },
      },
    },
  };

  const errorRateChartOptions: ChartOptions<'line'> = {
    responsive: true,
    maintainAspectRatio: false,
    interaction: {
      mode: 'index',
      intersect: false,
    },
    plugins: {
      legend: {
        display: false,
      },
      title: {
        display: false,
      },
      tooltip: {
        callbacks: {
          title: tooltipTitle,
          label: context => `Error Rate: ${(context.parsed.y ?? 0).toFixed(2)}%`,
        },
      },
    },
    scales: {
      y: {
        grid: { color: axis.grid },
        border: { color: axis.border },
        beginAtZero: true,
        suggestedMax: 100,
        title: {
          display: true,
          text: 'Error Rate (%)',
        },
        ticks: {
          color: axis.text,
          callback: value => `${value}%`,
        },
      },
      x: {
        grid: { color: axis.grid },
        border: { color: axis.border },
        ticks: { color: axis.text },
        title: {
          display: true,
          text: 'Time',
        },
      },
    },
  };

  const bytesChartOptions: ChartOptions<'line'> = {
    responsive: true,
    maintainAspectRatio: false,
    interaction: {
      mode: 'index',
      intersect: false,
    },
    plugins: {
      legend: {
        display: true,
        position: 'top',
      },
      title: {
        display: false,
      },
      tooltip: {
        callbacks: {
          title: tooltipTitle,
          label: context => {
            return `${context.dataset.label}: ${formatBytes(context.parsed.y ?? 0)}`;
          },
        },
      },
    },
    scales: {
      y: {
        grid: { color: axis.grid },
        border: { color: axis.border },
        beginAtZero: true,
        title: {
          display: true,
          text: 'Bytes',
        },
        ticks: {
          color: axis.text,
          callback: value => formatBytes(typeof value === 'number' ? value : Number(value)),
        },
      },
      x: {
        grid: { color: axis.grid },
        border: { color: axis.border },
        ticks: { color: axis.text },
        title: {
          display: true,
          text: 'Time',
        },
      },
    },
  };

  const tokensChartOptions: ChartOptions<'line'> = {
    responsive: true,
    maintainAspectRatio: false,
    interaction: {
      mode: 'index',
      intersect: false,
    },
    plugins: {
      legend: {
        display: true,
        position: 'top',
      },
      title: {
        display: false,
      },
      tooltip: {
        callbacks: {
          title: tooltipTitle,
          label: context => {
            return `${context.dataset.label}: ${context.parsed.y}`;
          },
        },
      },
    },
    scales: {
      y: {
        grid: { color: axis.grid },
        border: { color: axis.border },
        beginAtZero: true,
        title: {
          display: true,
          text: 'Tokens',
        },
        ticks: {
          color: axis.text,
          precision: 0,
        },
      },
      x: {
        grid: { color: axis.grid },
        border: { color: axis.border },
        ticks: { color: axis.text },
        title: {
          display: true,
          text: 'Time',
        },
      },
    },
  };

  const latencyChartOptions: ChartOptions<'line'> = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: true,
        position: 'top',
      },
      tooltip: {
        mode: 'index',
        intersect: false,
        callbacks: {
          title: tooltipTitle,
        },
      },
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
  };

  const currentErrorRate =
    pipeStats && pipeStats.total_requests > 0
      ? (pipeStats.failed_requests / pipeStats.total_requests) * 100
      : 0;

  const emptyStage: StageAggregate = {
    total_input_tokens: 0,
    total_output_tokens: 0,
    total_cost: 0,
    avg_latency_ms: 0,
  };
  const stageUsage = pipeStats?.stage_usage;
  // Avg latency stays a lifetime figure (telemetry carries no per-stage latency).
  const llmStage = stageUsage?.llm ?? emptyStage;
  const judgeStage = stageUsage?.judge ?? emptyStage;
  const juryStage = stageUsage?.jury ?? emptyStage;
  // Windowed per-stage cost + total tokens that track the time slider.
  const stageWindow = (stage: string) =>
    sumWindow(stageSeriesByKey.get(surfaceStageKey(pipeId, stage)));
  const llmWin = stageWindow('llm');
  const judgeWin = stageWindow('judge');
  const juryWin = stageWindow('jury');
  const deciderWin = stageWindow('decider');
  const totalStageCost = llmWin.cost + judgeWin.cost + juryWin.cost + deciderWin.cost;

  const fmtTokens = (n: number) => Math.round(n).toLocaleString();
  const fmtLatency = (ms: number) => `${Math.round(ms).toLocaleString()} ms`;
  const fmtCost = (amount: number) => `$${amount.toFixed(4)}`;

  const renderStageCard = (
    title: string,
    icon: string,
    accent: 'primary' | 'success' | 'info' | 'warning',
    avgLatencyMs: number,
    windowTokens: number
  ) => (
    <div className="col-xl-3 col-md-6 mb-4">
      <div className={`card border-left-${accent} shadow h-100 pipe-stage-card`}>
        <div className="card-body pipe-stage-card__body">
          <div className="d-flex align-items-center justify-content-between">
            <div className="pipe-stage-card__text">
              <div className={`pipe-stage-card__label text-${accent} text-uppercase`}>{title}</div>
              <div className="pipe-stage-card__value text-gray-800">{fmtLatency(avgLatencyMs)}</div>
              <div className="pipe-stage-card__meta text-muted">
                {fmtTokens(windowTokens)} tokens · selected window
              </div>
            </div>
            <i className={`fas ${icon} pipe-stage-card__icon text-gray-300`}></i>
          </div>
        </div>
      </div>
    </div>
  );

  return (
    <div className="pipe-monitoring-tab">
      {/* Per-stage usage summary cards */}
      <div className="row mb-4" data-testid="pipe-stage-usage-cards">
        {renderStageCard('Main LLM', 'fa-robot', 'primary', llmStage.avg_latency_ms, llmWin.tokens)}
        {renderStageCard('Judge', 'fa-gavel', 'info', judgeStage.avg_latency_ms, judgeWin.tokens)}
        {renderStageCard('Jury', 'fa-users', 'success', juryStage.avg_latency_ms, juryWin.tokens)}
        <div className="col-xl-3 col-md-6 mb-4">
          <div className="card border-left-warning shadow h-100 pipe-stage-card">
            <div className="card-body pipe-stage-card__body">
              <div className="d-flex align-items-center justify-content-between">
                <div className="pipe-stage-card__text">
                  <div className="pipe-stage-card__label text-warning text-uppercase">
                    Total Cost
                  </div>
                  <div className="pipe-stage-card__value text-gray-800">
                    {fmtCost(totalStageCost)}
                  </div>
                  <div className="pipe-stage-card__meta text-muted">
                    LLM {fmtCost(llmWin.cost)} · Judge {fmtCost(judgeWin.cost)} · Jury{' '}
                    {fmtCost(juryWin.cost)} · Decider {fmtCost(deciderWin.cost)}
                  </div>
                </div>
                <i className="fas fa-dollar-sign pipe-stage-card__icon text-gray-300"></i>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Cache effectiveness — savings, hits, hit rate, tokens saved. */}
      <CacheStatsCards
        variant="stage"
        cacheHits={pipeStats?.cache_hits ?? 0}
        cacheSavedCost={pipeStats?.cache_saved_cost ?? 0}
        cacheSavedTokens={pipeStats?.cache_saved_tokens ?? 0}
        totalRequests={pipeStats?.total_requests ?? 0}
      />

      {/* Traffic Chart */}
      <div className="row mb-4">
        <div className="col-12">
          <div className="card shadow mb-4">
            <div className="card-header py-3">
              <div className="d-flex justify-content-between align-items-center">
                <h6 className="m-0 font-weight-bold text-primary">
                  <i className="fas fa-chart-line me-2"></i>
                  Surface Traffic Over Time
                </h6>
                <ChartTypeSelect value={trafficKind} onChange={setTrafficKind} label="Traffic" />
              </div>
            </div>
            <div className="card-body">
              <div style={{ height: '300px', position: 'relative' }}>
                <MetricChart
                  kind={trafficKind}
                  data={pipeTrafficChartData}
                  options={trafficChartOptions}
                  ariaLabel="Pipe traffic over time chart"
                  timestamps={opsTs}
                  stepSecs={ops.stepSecs}
                />
              </div>
              {renderScrubber()}
            </div>
          </div>
        </div>
      </div>

      {/* Error Rate Over Time Chart */}
      <div className="row mb-4">
        <div className="col-12">
          <div className="card shadow mb-4">
            <div className="card-header py-3">
              <div className="d-flex justify-content-between align-items-center">
                <h6 className="m-0 font-weight-bold text-primary">
                  <i className="fas fa-exclamation-triangle me-2"></i>
                  Error Rate Over Time
                </h6>
                <span
                  className={`badge ${currentErrorRate > 5 ? 'text-bg-danger' : currentErrorRate > 1 ? 'text-bg-warning' : 'text-bg-success'}`}
                  data-testid="pipe-error-rate-current"
                >
                  {currentErrorRate.toFixed(2)}% current
                </span>
                <ChartTypeSelect
                  value={errorRateKind}
                  onChange={setErrorRateKind}
                  label="Error rate"
                />
              </div>
            </div>
            <div className="card-body">
              <div
                style={{ height: '300px', position: 'relative' }}
                data-testid="pipe-error-rate-chart"
              >
                <MetricChart
                  kind={errorRateKind}
                  data={pipeErrorRateChartData}
                  options={errorRateChartOptions}
                  ariaLabel="Pipe error rate over time chart"
                  timestamps={opsTs}
                  stepSecs={ops.stepSecs}
                />
              </div>
              {renderScrubber()}
            </div>
          </div>
        </div>
      </div>

      {/* Data Transfer Over Time Chart */}
      <div className="row mb-4">
        <div className="col-12">
          <div className="card shadow mb-4">
            <div className="card-header py-3">
              <div className="d-flex justify-content-between align-items-center">
                <h6 className="m-0 font-weight-bold text-primary">
                  <i className="fas fa-exchange-alt me-2"></i>
                  Data Transfer Over Time
                </h6>
                <ChartTypeSelect value={bytesKind} onChange={setBytesKind} label="Data transfer" />
              </div>
            </div>
            <div className="card-body">
              <div style={{ height: '300px', position: 'relative' }} data-testid="pipe-bytes-chart">
                <MetricChart
                  kind={bytesKind}
                  data={pipeBytesChartData}
                  options={bytesChartOptions}
                  ariaLabel="Pipe data transfer over time chart"
                  timestamps={opsTs}
                  stepSecs={ops.stepSecs}
                />
              </div>
              {renderScrubber()}
            </div>
          </div>
        </div>
      </div>

      {/* Token Usage Over Time Chart */}
      <div className="row mb-4">
        <div className="col-12">
          <div className="card shadow mb-4">
            <div className="card-header py-3">
              <div className="d-flex justify-content-between align-items-center">
                <h6 className="m-0 font-weight-bold text-primary">
                  <i className="fas fa-coins me-2"></i>
                  Token Usage Over Time
                </h6>
                <ChartTypeSelect value={tokensKind} onChange={setTokensKind} label="Token usage" />
              </div>
            </div>
            <div className="card-body">
              <div
                style={{ height: '300px', position: 'relative' }}
                data-testid="pipe-tokens-chart"
              >
                <MetricChart
                  kind={tokensKind}
                  data={pipeTokensChartData}
                  options={tokensChartOptions}
                  ariaLabel="Pipe token usage over time chart"
                  timestamps={opsTs}
                  stepSecs={ops.stepSecs}
                />
              </div>
              {renderScrubber()}
            </div>
          </div>
        </div>
      </div>

      {/* Latency Over Time Chart */}
      <div className="row mb-4">
        <div className="col-12">
          <div className="card shadow mb-4">
            <div className="card-header py-3">
              <div className="d-flex justify-content-between align-items-center">
                <h6 className="m-0 font-weight-bold text-primary">
                  <i className="fas fa-tachometer-alt me-2"></i>
                  Connection Latency Over Time (p50, p95, p99)
                </h6>
                <ChartTypeSelect value={latencyKind} onChange={setLatencyKind} label="Latency" />
              </div>
            </div>
            <div className="card-body">
              <div style={{ height: '300px', position: 'relative' }}>
                <MetricChart
                  kind={latencyKind}
                  data={pipeLatencyChartData}
                  options={latencyChartOptions}
                  ariaLabel="Pipe connection latency over time chart"
                  timestamps={opsTs}
                  stepSecs={ops.stepSecs}
                />
              </div>
              {renderScrubber()}
            </div>
          </div>
        </div>
      </div>

      {/* Rejections over time + by category over the selected window */}
      <div className="row mb-4">
        <div className="col-12">
          <RejectionTimeline
            scope={rejectionSurfaceScope(pipeId)}
            windowSecs={win.committed.windowSecs}
            endOffset={win.committed.endOffset}
            resolution={win.resolutionPref}
            enabled={!!pipeId}
            chartKindPrefix="surfaceMon"
          />
        </div>
      </div>
      <div className="row mb-4">
        <div className="col-12">
          <RejectionBreakdown
            scope={rejectionSurfaceScope(pipeId)}
            windowSecs={win.committed.windowSecs}
            endOffset={win.committed.endOffset}
            enabled={!!pipeId}
          />
        </div>
      </div>

      {/* Logs Section */}
      <div className="row">
        <div className="col-12">
          <PipeLogsViewer pipeId={pipeId} pipeName={pipeStats?.pipe_name || pipeName} />
        </div>
      </div>
    </div>
  );
};

export default PipeMonitoringTab;
