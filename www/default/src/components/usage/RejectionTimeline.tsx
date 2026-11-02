import React, { useEffect, useMemo, useRef, useState } from 'react';
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
import { UI_COLORS, CHART_PALETTE, chartBarFill } from '../../utils/uiPalette';
import { useChartAxisColors } from '../../utils/chartTheme';
import MetricChart, { ChartTypeSelect } from './MetricChart';
import { useChartKind } from './chartPrefs';
import {
  AUTO_RESOLUTION,
  autoFetchParams,
  densifySeries,
  fetchRejections,
  fetchSeries,
  fullStamp,
  indexByKey,
  makeAxisLabels,
  rejectionCategoryKey,
  rejectionTotalKey,
  windowForSecs,
  type RejectionCategoryCount,
  type SeriesResponse,
} from './usageSeries';

// Registration is global + idempotent; do it here so the member/team usage tabs
// (which don't import the dashboard) still render.
ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Filler, Tooltip, Legend);

const CHART_HEIGHT = 300;

interface RejectionTimelineProps {
  /** Rejection scope-key prefix, e.g. `rejection:all`, `rejection:surface:{id}`,
   * `rejection:team:{id}`, `rejection:member:{id}`. */
  scope: string;
  /** Committed window width (secs) — pass the same window driving the charts. */
  windowSecs: number;
  /** Committed pan offset behind now (0 = live). */
  endOffset: number;
  /** Resolution preference (`auto` or a forced tier) — pass the same value as
   * the other charts so the buckets line up. */
  resolution?: string;
  enabled?: boolean;
  title?: string;
  /** Namespace for the render-mode preference so each consumer (dashboard /
   * team / member) persists its own choice. */
  chartKindPrefix: string;
}

/**
 * Window-scoped timeline of guard rejections for a scope (all surfaces / one
 * surface / a team / a member). Charts the **total** blocked count per bucket
 * (`rejection:{scope}:_total`) **plus one line per canonical category** that was
 * triggered in the window (`rejection:{scope}:{category}`), reading the
 * `requests` counter of each telemetry series over the selected window. It
 * tracks the same time-range slider as the spend / token charts and complements
 * the per-category {@link RejectionBreakdown}.
 */
const RejectionTimeline: React.FC<RejectionTimelineProps> = ({
  scope,
  windowSecs,
  endOffset,
  resolution = AUTO_RESOLUTION,
  enabled = true,
  title = 'Rejections over time (selected window)',
  chartKindPrefix,
}) => {
  const [series, setSeries] = useState<SeriesResponse[]>([]);
  const [categories, setCategories] = useState<RejectionCategoryCount[]>([]);
  const abortRef = useRef<AbortController | null>(null);
  const [kind, setKind] = useChartKind(`${chartKindPrefix}.rejectionTimeline`, 'bar');
  const axisColors = useChartAxisColors();

  useEffect(() => {
    if (!enabled || !scope) {
      setSeries([]);
      setCategories([]);
      return;
    }
    abortRef.current?.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    const w = windowForSecs(windowSecs, endOffset);
    // Honour the user's resolution choice, sending `auto` to the backend when
    // they didn't pick a tier so the backend's empty-tier fallback engages and
    // this chart stays consistent with the scrubber overview (which is always
    // fetched at `auto`).
    const { resolution: fetchRes, maxPoints } = autoFetchParams(resolution);
    // First learn which categories were triggered in the window (with labels),
    // then fetch the total + one time-series per active category in one call.
    fetchRejections(scope, w, fetchRes, ctrl.signal)
      .then(rej => {
        if (abortRef.current !== ctrl) return;
        const cats = rej.categories;
        setCategories(cats);
        const keys = [
          rejectionTotalKey(scope),
          ...cats.map(c => rejectionCategoryKey(scope, c.category)),
        ];
        return fetchSeries(keys, w, maxPoints, fetchRes, ctrl.signal);
      })
      .then(res => {
        if (res && abortRef.current === ctrl) setSeries(res.map(s => densifySeries(s, w)));
      })
      .catch(() => {
        if (abortRef.current === ctrl) {
          setSeries([]);
          setCategories([]);
        }
      });
    return () => ctrl.abort();
  }, [scope, windowSecs, endOffset, resolution, enabled]);

  const byKey = useMemo(() => indexByKey(series), [series]);
  const totalSeries = useMemo(() => byKey.get(rejectionTotalKey(scope)) ?? null, [byKey, scope]);
  const stepSecs = totalSeries?.step_secs ?? 30;
  const total = useMemo(
    () => (totalSeries?.points ?? []).reduce((sum, p) => sum + p.requests, 0),
    [totalSeries]
  );

  // Union every series' timestamps onto one sorted axis so a category that fired
  // in a bucket the total didn't report (or vice versa) is never dropped.
  const axis = useMemo(() => {
    const ts = new Set<number>();
    for (const s of series) for (const p of s.points) ts.add(p.t);
    return Array.from(ts).sort((a, b) => a - b);
  }, [series]);
  const stamps = useMemo(() => axis.map(fullStamp), [axis]);

  const requestsByT = (s: SeriesResponse | null | undefined): Map<number, number> => {
    const m = new Map<number, number>();
    for (const p of s?.points ?? []) m.set(p.t, p.requests);
    return m;
  };

  const data: ChartData<'line', (number | null)[]> = useMemo(() => {
    const totalMap = requestsByT(totalSeries);
    const datasets = [
      {
        label: 'Total',
        data: axis.map(t => totalMap.get(t) ?? 0),
        borderColor: UI_COLORS.danger,
        backgroundColor: chartBarFill(UI_COLORS.danger),
        borderWidth: 3,
        pointRadius: 0,
        tension: 0.3,
        fill: false,
        order: 0,
      },
      ...categories.map((c, i) => {
        const color = CHART_PALETTE[i % CHART_PALETTE.length];
        const catMap = requestsByT(byKey.get(rejectionCategoryKey(scope, c.category)));
        return {
          label: c.label,
          data: axis.map(t => catMap.get(t) ?? 0),
          borderColor: color,
          backgroundColor: chartBarFill(color),
          borderWidth: 2,
          pointRadius: 0,
          tension: 0.3,
          fill: false,
          order: i + 1,
        };
      }),
    ];
    return { labels: makeAxisLabels(axis, stepSecs), datasets };
  }, [axis, categories, byKey, totalSeries, scope, stepSecs]);

  const options: ChartOptions<'line'> = useMemo(
    () => ({
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { display: true, position: 'bottom', labels: { boxWidth: 12 } },
        tooltip: {
          callbacks: {
            title: items => (items.length ? stamps[items[0].dataIndex] : ''),
            label: ctx => `${ctx.dataset.label}: ${Number(ctx.parsed.y).toLocaleString()} blocked`,
          },
        },
      },
      scales: {
        x: {
          grid: { display: false },
          border: { color: axisColors.border },
          ticks: { color: axisColors.text, maxRotation: 0, autoSkip: true, maxTicksLimit: 8 },
        },
        y: {
          grid: { color: axisColors.grid },
          border: { color: axisColors.border },
          beginAtZero: true,
          ticks: {
            color: axisColors.text,
            precision: 0,
            callback: v => Number(v).toLocaleString(),
          },
        },
      },
    }),
    [stamps, axisColors]
  );

  return (
    <div className="card shadow mb-4">
      <div className="card-header py-3 d-flex align-items-center justify-content-between">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-chart-column"></i> {title}
        </h6>
        <div className="d-flex align-items-center gap-2">
          <span
            className="badge"
            style={{ backgroundColor: chartBarFill(UI_COLORS.danger), color: '#fff' }}
          >
            {total.toLocaleString()} blocked
          </span>
          <ChartTypeSelect value={kind} onChange={setKind} label={title} />
        </div>
      </div>
      <div className="card-body">
        {total === 0 ? (
          <p className="text-muted mb-0">
            <small>No content rejections in this window.</small>
          </p>
        ) : (
          <div style={{ height: CHART_HEIGHT }}>
            <MetricChart
              kind={kind}
              data={data}
              options={options}
              ariaLabel={title}
              timestamps={axis}
              stepSecs={stepSecs}
            />
          </div>
        )}
      </div>
    </div>
  );
};

export default RejectionTimeline;
