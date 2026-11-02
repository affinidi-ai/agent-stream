import React, { useCallback, useMemo, useRef, useState } from 'react';
import { Bar, Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  BarController,
  BarElement,
  type ChartData,
  type ChartDataset,
  type ChartOptions,
} from 'chart.js';
import { UI_COLORS, chartAreaGradient, chartBarFill } from '../../utils/uiPalette';
import { CHART_KIND_OPTIONS, type ChartKind } from './chartPrefs';
import { DATE_ROW_HEIGHT, dateBoundaryPlugin } from './dateBoundaryPlugin';
import { ceilingLinePlugin } from './chartCeilingPlugin';

// Bar rendering is opt-in per chart; register its controller/element here so the
// component is self-contained (registration is global + idempotent). The
// date-boundary plugin draws the horizontal date row + day-change dividers; the
// ceiling plugin draws the red truncation line when the peak slider is engaged.
ChartJS.register(BarController, BarElement, dateBoundaryPlugin, ceilingLinePlugin);

/** Sub-day resolution threshold (secs): below a day, the axis shows rotated time
 * labels and the date row is drawn beneath them. */
const DAY_SECS = 86_400;

/** Lowest the peak-truncation slider can pull the ceiling (5% of the data peak),
 * so the axis never collapses to zero height. */
const MIN_CEILING = 0.05;

type LineData = ChartData<'line', (number | null)[]>;
type LineDataset = ChartDataset<'line', (number | null)[]>;

function styleDataset(ds: LineDataset, kind: ChartKind): LineDataset {
  const color = typeof ds.borderColor === 'string' ? ds.borderColor : UI_COLORS.primary;
  switch (kind) {
    case 'line':
      return { ...ds, showLine: true, fill: false, pointRadius: 0, pointHoverRadius: 4 };
    case 'area':
      return {
        ...ds,
        showLine: true,
        fill: true,
        backgroundColor: chartAreaGradient(color) as unknown as LineDataset['backgroundColor'],
        pointRadius: 0,
        pointHoverRadius: 4,
      };
    case 'points':
      return { ...ds, showLine: false, fill: false, pointRadius: 3, pointHoverRadius: 5 };
    case 'bar':
      return { ...ds, backgroundColor: chartBarFill(color), borderColor: color, borderWidth: 0 };
  }
}

/** Apply a render-mode's styling to every dataset, preserving each dataset's
 * own colour. Used by {@link MetricChart} so one data memo serves all modes. */
export function applyChartKind(data: LineData, kind: ChartKind): LineData {
  return { ...data, datasets: data.datasets.map(ds => styleDataset(ds, kind)) };
}

interface MetricChartProps {
  kind: ChartKind;
  data: LineData;
  options: ChartOptions<'line'>;
  ariaLabel: string;
  /** Unix-second timestamp per category index (aligned with `data.labels`). When
   * provided with a sub-day `stepSecs`, a horizontal date row + day-change
   * dividers are drawn beneath the rotated time labels. */
  timestamps?: number[];
  /** Served bucket width (secs); the date row is only drawn for sub-day steps. */
  stepSecs?: number;
}

/** Merge padding of either shape into an object form so we can extend `bottom`. */
function normalizePadding(padding: NonNullable<ChartOptions<'line'>['layout']>['padding']): {
  top?: number;
  right?: number;
  bottom?: number;
  left?: number;
} {
  if (typeof padding === 'number') {
    return { top: padding, right: padding, bottom: padding, left: padding };
  }
  return { ...(padding ?? {}) };
}

type ScaleMap = Record<
  string,
  { axis?: string; min?: number; max?: number } & Record<string, unknown>
>;

/** The largest finite value plotted on each y-axis (keyed by `yAxisID`, default
 * `'y'`), so the truncation slider can cap each axis relative to its own peak. */
function dataMaxByAxis(data: LineData): Record<string, number> {
  const maxes: Record<string, number> = {};
  for (const ds of data.datasets) {
    const axis = ds.yAxisID ?? 'y';
    for (const v of ds.data) {
      if (typeof v === 'number' && Number.isFinite(v) && v > (maxes[axis] ?? 0)) {
        maxes[axis] = v;
      }
    }
  }
  return maxes;
}

/** Return a new scales object with every y-axis `max` capped at `pct` of that
 * axis's data peak, leaving the x-axis and all other scale config untouched. */
function capYScales(
  scales: ChartOptions<'line'>['scales'],
  pct: number,
  maxByAxis: Record<string, number>,
  overallMax: number
): ChartOptions<'line'>['scales'] {
  const src = (scales ?? {}) as ScaleMap;
  const out: ScaleMap = { ...src };
  let yIds = Object.keys(src).filter(id => id !== 'x' && src[id]?.axis !== 'x');
  if (yIds.length === 0) yIds = ['y'];
  for (const id of yIds) {
    const axisMax = maxByAxis[id] ?? overallMax;
    if (axisMax <= 0) continue;
    out[id] = { ...(src[id] ?? {}), max: axisMax * pct };
  }
  return out as ChartOptions<'line'>['scales'];
}

/** Renders a time-series as a line/area/points chart, or columns in `bar` mode,
 * from a single line-shaped data memo. The selected mode only re-styles the
 * datasets, so switching modes never refetches or reshapes the series. A subtle
 * vertical slider on the right lets the user truncate tall peaks (cap the y-axis)
 * to magnify smaller data; a red dashed line marks the truncation level. */
const MetricChart: React.FC<MetricChartProps> = ({
  kind,
  data,
  options,
  ariaLabel,
  timestamps,
  stepSecs,
}) => {
  const styled = useMemo(() => applyChartKind(data, kind), [data, kind]);
  // Peak-truncation ceiling as a fraction (1 = no truncation). Local per-chart
  // state, so it persists across live data refreshes but resets on remount.
  const [ceiling, setCeiling] = useState(1);
  const maxByAxis = useMemo(() => dataMaxByAxis(data), [data]);
  const overallMax = useMemo(() => Math.max(0, ...Object.values(maxByAxis)), [maxByAxis]);
  const ceilingActive = ceiling < 0.999 && overallMax > 0;

  // When a sub-day resolution is served, hand the raw timestamps to the
  // date-boundary plugin and reserve room below the axis for its date row. When
  // the truncation slider is engaged, cap every y-axis and arm the ceiling line.
  const opts = useMemo<ChartOptions<'line'>>(() => {
    const showDates = !!timestamps && timestamps.length > 0 && !!stepSecs && stepSecs < DAY_SECS;
    let base = options;
    if (showDates) {
      const pad = normalizePadding(options.layout?.padding);
      base = {
        ...options,
        layout: {
          ...options.layout,
          padding: { ...pad, bottom: (pad.bottom ?? 0) + DATE_ROW_HEIGHT },
        },
        plugins: {
          ...options.plugins,
          dateBoundary: { stamps: timestamps, showDates: true },
        },
      };
    }
    if (!ceilingActive) return base;
    return {
      ...base,
      scales: capYScales(base.scales, ceiling, maxByAxis, overallMax),
      plugins: { ...base.plugins, ceilingLine: { active: true } },
    };
  }, [options, timestamps, stepSecs, ceilingActive, ceiling, maxByAxis, overallMax]);

  const chartEl =
    kind === 'bar' ? (
      <Bar
        aria-label={ariaLabel}
        role="img"
        data={styled as unknown as ChartData<'bar', (number | null)[]>}
        options={opts as unknown as ChartOptions<'bar'>}
        redraw={false}
      />
    ) : (
      <Line aria-label={ariaLabel} role="img" data={styled} options={opts} redraw={false} />
    );

  return (
    <div className="metric-chart-shell">
      <div className="metric-chart-shell__canvas">{chartEl}</div>
      <ChartCeilingSlider
        value={ceiling}
        onChange={setCeiling}
        label={ariaLabel}
        disabled={overallMax <= 0}
      />
    </div>
  );
};

// Memoised so a parent re-render (e.g. every scrubber pointer-move while
// dragging the time window) skips the chart entirely when its data/options refs
// are unchanged, avoiding a Chart.js canvas redraw over thousands of points.
const MemoisedMetricChart = React.memo(MetricChart);

interface ChartCeilingSliderProps {
  /** Ceiling as a fraction of the data peak (1 = no truncation). */
  value: number;
  onChange: (value: number) => void;
  /** Chart label, for the accessible slider name. */
  label: string;
  /** Greyed out + non-interactive (still occupies its column) when the chart has
   * no positive data to truncate, so the plot never shifts sideways. */
  disabled?: boolean;
}

/** A subtle custom vertical slider docked to the right of a chart. Pulling the
 * handle down from the top caps the chart's y-axis, truncating tall peaks so the
 * smaller data occupies more of the plot. Double-click (or `Home`) resets. It
 * always reserves its column (greyed out when `disabled`) so the chart canvas
 * keeps a constant width and never jumps when data arrives or empties. */
const ChartCeilingSlider: React.FC<ChartCeilingSliderProps> = ({
  value,
  onChange,
  label,
  disabled,
}) => {
  const trackRef = useRef<HTMLDivElement>(null);
  const draggingRef = useRef(false);

  const setFromY = useCallback(
    (clientY: number) => {
      const el = trackRef.current;
      if (!el) return;
      const rect = el.getBoundingClientRect();
      if (rect.height <= 0) return;
      const fraction = 1 - (clientY - rect.top) / rect.height;
      onChange(Math.min(1, Math.max(MIN_CEILING, fraction)));
    },
    [onChange]
  );

  const handlePointerDown = (e: React.PointerEvent<HTMLDivElement>) => {
    if (disabled) return;
    draggingRef.current = true;
    e.currentTarget.setPointerCapture(e.pointerId);
    setFromY(e.clientY);
  };
  const handlePointerMove = (e: React.PointerEvent<HTMLDivElement>) => {
    if (draggingRef.current) setFromY(e.clientY);
  };
  const handlePointerUp = (e: React.PointerEvent<HTMLDivElement>) => {
    draggingRef.current = false;
    try {
      e.currentTarget.releasePointerCapture(e.pointerId);
    } catch {
      /* pointer already released */
    }
  };
  const handleKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (disabled) return;
    if (e.key === 'ArrowUp') {
      onChange(Math.min(1, value + 0.05));
      e.preventDefault();
    } else if (e.key === 'ArrowDown') {
      onChange(Math.max(MIN_CEILING, value - 0.05));
      e.preventDefault();
    } else if (e.key === 'Home') {
      onChange(1);
      e.preventDefault();
    }
  };

  const active = !disabled && value < 0.999;
  const offsetTop = (1 - value) * 100; // handle/cut distance from the top, in %
  const pct = Math.round(value * 100);

  return (
    <div
      className={`chart-ceiling${active ? ' chart-ceiling--active' : ''}${disabled ? ' chart-ceiling--disabled' : ''}`}
    >
      <div
        ref={trackRef}
        className="chart-ceiling__track"
        role="slider"
        tabIndex={disabled ? -1 : 0}
        aria-label={`Truncate peaks above for ${label}`}
        aria-valuemin={Math.round(MIN_CEILING * 100)}
        aria-valuemax={100}
        aria-valuenow={pct}
        aria-valuetext={`${pct}% of peak`}
        aria-disabled={disabled}
        title={
          disabled ? 'No data to truncate' : 'Drag down to truncate peaks · double-click to reset'
        }
        onPointerDown={handlePointerDown}
        onPointerMove={handlePointerMove}
        onPointerUp={handlePointerUp}
        onDoubleClick={() => !disabled && onChange(1)}
        onKeyDown={handleKeyDown}
      >
        <div className="chart-ceiling__cut" style={{ height: `${offsetTop}%` }} />
        <div className="chart-ceiling__handle" style={{ top: `${offsetTop}%` }}>
          {active && <span className="chart-ceiling__badge">{pct}%</span>}
        </div>
      </div>
    </div>
  );
};

interface ChartTypeSelectProps {
  value: ChartKind;
  onChange: (kind: ChartKind) => void;
  label: string;
}

/** Compact dropdown that picks a chart's render mode. */
export const ChartTypeSelect: React.FC<ChartTypeSelectProps> = ({ value, onChange, label }) => (
  <select
    className="form-select form-select-sm chart-type-select"
    aria-label={`${label} chart type`}
    value={value}
    onChange={e => onChange(e.target.value as ChartKind)}
  >
    {CHART_KIND_OPTIONS.map(opt => (
      <option key={opt.value} value={opt.value}>
        {opt.label}
      </option>
    ))}
  </select>
);

export default MemoisedMetricChart;
