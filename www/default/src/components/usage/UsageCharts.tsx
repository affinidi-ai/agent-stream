import React, { useMemo } from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Filler,
  Tooltip,
  Legend,
  type ChartData,
  type ChartOptions,
} from 'chart.js';
import { CHART_PALETTE, UI_COLORS, chartAreaFill } from '../../utils/uiPalette';
import { useChartAxisColors } from '../../utils/chartTheme';
import MetricChart, { ChartTypeSelect } from './MetricChart';
import { useChartKind } from './chartPrefs';
import {
  breakdownRows,
  formatUsd,
  fullStamp,
  indexByKey,
  makeAxisLabels,
  primaryRows,
  type BreakdownItem,
  type SeriesResponse,
} from './usageSeries';

// Registration is global + idempotent; do it here so the member/team usage tabs
// (which don't import the dashboard) still render.
ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Filler, Tooltip, Legend);

const CHART_HEIGHT = 260;

interface UsageChartsProps {
  series: SeriesResponse[];
  stepSecs: number;
  /** Telemetry series key for the headline spend/tokens chart. */
  primaryKey: string;
  primaryTitle: string;
  /** One line per item in the breakdown spend chart. */
  breakdownItems: BreakdownItem[];
  breakdownTitle: string;
  /** Namespace for the per-chart render-mode preferences so each consumer
   * (team / member) persists its own choices. */
  chartKindPrefix: string;
  /** Rendered between the two charts — a synced copy of the time-range slider,
   * mirroring the dashboard's per-chart rail. */
  renderScrubber?: () => React.ReactNode;
}

/**
 * Shared usage-over-time charts: a dual-axis spend/tokens line for a primary
 * series, plus a multi-line spend chart broken down by a set of sub-series.
 * Used by the dashboard (all surfaces / per surface), teams (team / per member),
 * and members (member / per surface) so every view correlates against the same
 * telemetry source with identical visuals. Rendered with Chart.js to match the
 * rest of the dashboard.
 */
const UsageCharts: React.FC<UsageChartsProps> = ({
  series,
  stepSecs,
  primaryKey,
  primaryTitle,
  breakdownItems,
  breakdownTitle,
  chartKindPrefix,
  renderScrubber,
}) => {
  const [primaryKind, setPrimaryKind] = useChartKind(`${chartKindPrefix}.primary`, 'line');
  const [breakdownKind, setBreakdownKind] = useChartKind(`${chartKindPrefix}.breakdown`, 'line');
  const axis = useChartAxisColors();

  const { primaryData, primaryStamps, primaryTs } = useMemo(() => {
    const byKey = indexByKey(series);
    const rows = primaryRows(byKey.get(primaryKey));
    const data: ChartData<'line', (number | null)[]> = {
      labels: makeAxisLabels(
        rows.map(r => r.t),
        stepSecs
      ),
      datasets: [
        {
          label: 'Spend',
          data: rows.map(r => r.cost),
          yAxisID: 'cost',
          borderColor: UI_COLORS.primary,
          backgroundColor: chartAreaFill(UI_COLORS.primary),
          borderWidth: 2,
          pointRadius: 0,
          tension: 0.3,
          fill: false,
        },
        {
          label: 'Tokens',
          data: rows.map(r => r.tokens),
          yAxisID: 'tokens',
          borderColor: UI_COLORS.success,
          backgroundColor: chartAreaFill(UI_COLORS.success),
          borderWidth: 2,
          pointRadius: 0,
          tension: 0.3,
          fill: false,
        },
      ],
    };
    return {
      primaryData: data,
      primaryStamps: rows.map(r => fullStamp(r.t)),
      primaryTs: rows.map(r => r.t),
    };
  }, [series, primaryKey, stepSecs]);

  const { breakdownData, breakdownStamps, breakdownTs } = useMemo(() => {
    const byKey = indexByKey(series);
    const rows = breakdownRows(byKey, breakdownItems);
    const data: ChartData<'line', (number | null)[]> = {
      labels: makeAxisLabels(
        rows.map(r => r.t),
        stepSecs
      ),
      datasets: breakdownItems.map((item, i) => ({
        label: item.label,
        data: rows.map(r => (r[item.id] ?? null) as number | null),
        borderColor: CHART_PALETTE[i % CHART_PALETTE.length],
        backgroundColor: chartAreaFill(CHART_PALETTE[i % CHART_PALETTE.length]),
        borderWidth: 2,
        pointRadius: 0,
        tension: 0.3,
        spanGaps: true,
        fill: false,
      })),
    };
    return {
      breakdownData: data,
      breakdownStamps: rows.map(r => fullStamp(r.t)),
      breakdownTs: rows.map(r => r.t),
    };
  }, [series, breakdownItems, stepSecs]);

  const primaryOptions: ChartOptions<'line'> = useMemo(
    () => ({
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { display: true },
        tooltip: {
          callbacks: {
            title: items => (items.length ? primaryStamps[items[0].dataIndex] : ''),
            label: ctx =>
              ctx.dataset.label === 'Spend'
                ? `Spend: ${formatUsd(Number(ctx.parsed.y))}`
                : `Tokens: ${Number(ctx.parsed.y).toLocaleString()}`,
          },
        },
      },
      scales: {
        x: {
          grid: { display: false },
          border: { color: axis.border },
          ticks: { color: axis.text, maxRotation: 0, autoSkip: true, maxTicksLimit: 8 },
        },
        cost: {
          type: 'linear',
          position: 'left',
          grid: { color: axis.grid },
          border: { color: axis.border },
          ticks: { color: axis.text, callback: v => formatUsd(Number(v)) },
        },
        tokens: {
          type: 'linear',
          position: 'right',
          grid: { drawOnChartArea: false, color: axis.grid },
          border: { color: axis.border },
          ticks: { color: axis.text, callback: v => Number(v).toLocaleString() },
        },
      },
    }),
    [primaryStamps, axis]
  );

  const breakdownOptions: ChartOptions<'line'> = useMemo(
    () => ({
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { display: true },
        tooltip: {
          callbacks: {
            title: items => (items.length ? breakdownStamps[items[0].dataIndex] : ''),
            label: ctx => `${ctx.dataset.label}: ${formatUsd(Number(ctx.parsed.y))}`,
          },
        },
      },
      scales: {
        x: {
          grid: { display: false },
          border: { color: axis.border },
          ticks: { color: axis.text, maxRotation: 0, autoSkip: true, maxTicksLimit: 8 },
        },
        y: {
          grid: { color: axis.grid },
          border: { color: axis.border },
          ticks: { color: axis.text, callback: v => formatUsd(Number(v)) },
        },
      },
    }),
    [breakdownStamps, axis]
  );

  return (
    <>
      <div className="d-flex justify-content-between align-items-center mb-2">
        <h6 className="text-primary mb-0">{primaryTitle}</h6>
        <ChartTypeSelect value={primaryKind} onChange={setPrimaryKind} label={primaryTitle} />
      </div>
      <div style={{ height: CHART_HEIGHT }}>
        <MetricChart
          kind={primaryKind}
          data={primaryData}
          options={primaryOptions}
          ariaLabel={primaryTitle}
          timestamps={primaryTs}
          stepSecs={stepSecs}
        />
      </div>

      {renderScrubber && <div className="my-4">{renderScrubber()}</div>}

      <div className="d-flex justify-content-between align-items-center mt-4 mb-2">
        <h6 className="text-primary mb-0">{breakdownTitle}</h6>
        <ChartTypeSelect value={breakdownKind} onChange={setBreakdownKind} label={breakdownTitle} />
      </div>
      <div style={{ height: CHART_HEIGHT }}>
        <MetricChart
          kind={breakdownKind}
          data={breakdownData}
          options={breakdownOptions}
          ariaLabel={breakdownTitle}
          timestamps={breakdownTs}
          stepSecs={stepSecs}
        />
      </div>
    </>
  );
};

export default UsageCharts;
