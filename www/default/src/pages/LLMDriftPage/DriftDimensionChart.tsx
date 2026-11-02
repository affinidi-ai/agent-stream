import React, { useMemo } from 'react';
import { Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler,
  type ChartData,
  type ChartOptions,
} from 'chart.js';
import { UI_COLORS, chartAreaGradient } from '../../utils/uiPalette';
import { useChartAxisColors } from '../../utils/chartTheme';
import {
  driftStatusTone,
  formatDriftValue,
  type DimensionVerdict,
  type DriftDimensionInfo,
  type DriftSeriesResponse,
} from './types';

// Registration is global + idempotent, so registering here keeps the chart
// self-contained even when the LLM Drift page loads without the dashboard.
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

function formatTick(t: number): string {
  return new Date(t * 1000).toLocaleString([], {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

interface DriftDimensionChartProps {
  info: DriftDimensionInfo;
  series?: DriftSeriesResponse;
  verdict?: DimensionVerdict;
  /** An evaluation's measured value, drawn as a solid amber overlay line so a
   * replay result can be read against the surface's known baseline + history. */
  overlay?: { value: number; label: string };
}

/** One drift dimension plotted over time, with its baseline drawn as a dashed
 * reference line and a drift-status badge. A rate dimension pins the y-axis to
 * `[0, 1]`; a gauge dimension (latency, response length) auto-scales from zero. */
const DriftDimensionChart: React.FC<DriftDimensionChartProps> = ({
  info,
  series,
  verdict,
  overlay,
}) => {
  const axis = useChartAxisColors();
  const points = useMemo(() => series?.points ?? [], [series]);
  const baseline = verdict?.baseline;

  const data = useMemo<ChartData<'line'>>(() => {
    const hasPoints = points.length > 0;
    // A dense series draws a clean line; a sparse one shows point markers so a
    // single point isn't an invisible zero-width line. With no history at all we
    // fall back to a 2-tick axis so the baseline + evaluation overlay still draw.
    const labels = hasPoints ? points.map(p => formatTick(p.t)) : ['', ''];
    const flat = (v: number) => Array.from({ length: labels.length }, () => v);
    const datasets: ChartData<'line'>['datasets'] = [];
    if (hasPoints) {
      datasets.push({
        label: info.label,
        data: points.map(p => p.mean),
        borderColor: UI_COLORS.primary,
        backgroundColor: chartAreaGradient(UI_COLORS.primary),
        fill: true,
        tension: 0.3,
        pointRadius: points.length <= 6 ? 3 : 0,
        pointHoverRadius: 4,
        spanGaps: true,
      });
    }
    if (baseline != null) {
      datasets.push({
        label: 'Baseline',
        data: flat(baseline),
        borderColor: 'rgba(120, 120, 120, 0.9)',
        borderDash: [5, 4],
        borderWidth: 1,
        fill: false,
        pointRadius: 0,
        pointHoverRadius: 0,
      });
    }
    if (overlay) {
      datasets.push({
        label: overlay.label,
        data: flat(overlay.value),
        borderColor: '#f39c12',
        borderWidth: 2,
        fill: false,
        pointRadius: 0,
        pointHoverRadius: 0,
      });
    }
    return { labels, datasets };
  }, [points, info.label, baseline, overlay]);

  const options = useMemo<ChartOptions<'line'>>(
    () => ({
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: {
          display: baseline != null || overlay != null,
          position: 'top',
          labels: { color: axis.text, boxWidth: 12, font: { size: 10 } },
        },
        tooltip: {
          callbacks: {
            label: ctx => `${ctx.dataset.label}: ${formatDriftValue(ctx.parsed.y as number, info)}`,
          },
        },
      },
      scales: {
        x: {
          ticks: { color: axis.text, maxTicksLimit: 6, autoSkip: true, maxRotation: 0 },
          grid: { color: axis.grid },
        },
        y: {
          beginAtZero: true,
          ...(info.is_rate ? { max: 1 } : {}),
          ticks: {
            color: axis.text,
            callback: value => formatDriftValue(Number(value), info),
          },
          grid: { color: axis.grid },
        },
      },
    }),
    [axis, info, baseline, overlay]
  );

  return (
    <div className="drift-chart" data-testid={`drift-chart-${info.id}`}>
      <div className="drift-chart-head">
        <span className="drift-chart-title">
          {info.label}
          {verdict && (
            <span
              className={`badge text-bg-${driftStatusTone(verdict.status).tone} ms-2`}
              data-testid={`drift-status-${info.id}`}
            >
              {driftStatusTone(verdict.status).label}
            </span>
          )}
        </span>
        <span className="drift-chart-unit text-muted">{info.unit}</span>
      </div>
      <div className="drift-chart-canvas">
        {points.length === 0 && overlay == null ? (
          <div className="drift-chart-empty text-muted" data-testid={`drift-empty-${info.id}`}>
            <div>No data in this window</div>
            {info.source_hint && (
              <div className="small mt-1" data-testid={`drift-empty-hint-${info.id}`}>
                {info.source_hint}
              </div>
            )}
          </div>
        ) : (
          <Line data={data} options={options} aria-label={`${info.label} over time`} />
        )}
      </div>
    </div>
  );
};

export default DriftDimensionChart;
