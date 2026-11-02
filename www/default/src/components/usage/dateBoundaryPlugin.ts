import { type Chart, type ChartType, type Plugin } from 'chart.js';
import { UI_COLORS, withAlpha } from '../../utils/uiPalette';
import { dateBoundaries } from './usageSeries';

/** Extra vertical space (px) the chart reserves below its rotated time labels so
 * the horizontal date row this plugin draws is never clipped. {@link MetricChart}
 * adds this to `layout.padding.bottom` whenever the date row is active. */
export const DATE_ROW_HEIGHT = 24;

/** Gap (px) between the centred date label and the bracket rules on each side. */
const LABEL_GAP = 8;

/** Half-height (px) of the vertical end-cap ticks that bound each date range. */
const CAP_HALF = 5;

/** Per-chart config the plugin reads from `options.plugins.dateBoundary`. */
export interface DateBoundaryOptions {
  /** Unix-second timestamp per category index, aligned with `data.labels`. */
  stamps: number[];
  /** Whether to draw the date row + dividers (only for sub-day resolutions). */
  showDates: boolean;
}

// Register `dateBoundary` as a typed plugin option so consumers can set
// `options.plugins.dateBoundary` without casting.
declare module 'chart.js' {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  interface PluginOptionsByType<TType extends ChartType> {
    dateBoundary?: DateBoundaryOptions;
  }
}

/** Theme-aware colours for the divider line and date text. Canvas can't read CSS
 * variables, so we branch on the `body.dark-theme` class the app already sets. */
function themeColors(): { line: string; text: string } {
  const dark = typeof document !== 'undefined' && document.body.classList.contains('dark-theme');
  return {
    line: withAlpha(UI_COLORS.neutral, dark ? 0.35 : 0.3),
    text: dark ? UI_COLORS.neutral : UI_COLORS.neutralMuted,
  };
}

/**
 * Draws a second x-axis tier beneath a sub-day time axis: for each calendar
 * date, a **centred date label bracketed by a horizontal rule** that spans the
 * date's full range of buckets, capped by a short vertical tick at each end —
 * i.e. `|——— JUN 27 ———|`. This keeps the diagonal time labels uncluttered while
 * making it obvious which run of times belongs to which day and exactly where
 * each day starts and ends. Inactive unless `options.plugins.dateBoundary.showDates`
 * is set (sub-day resolutions only).
 */
export const dateBoundaryPlugin: Plugin<'line' | 'bar'> = {
  id: 'dateBoundary',
  afterDatasetsDraw(chart: Chart) {
    const opts = chart.options.plugins?.dateBoundary;
    if (!opts?.showDates || !opts.stamps?.length) return;
    const xScale = chart.scales.x;
    if (!xScale) return;
    const area = chart.chartArea;
    const ctx = chart.ctx;
    const stamps = opts.stamps;
    const boundaries = dateBoundaries(stamps);
    if (boundaries.length === 0) return;
    const n = stamps.length;
    const { line, text } = themeColors();

    // Half a category slot, so each range extends from bucket centres out to the
    // bucket edges (adjacent ranges then meet exactly at the day boundary).
    const c0 = xScale.getPixelForValue(0);
    const c1 = n > 1 ? xScale.getPixelForValue(1) : c0;
    const half = n > 1 ? Math.abs(c1 - c0) / 2 : (area.right - area.left) / 2;
    const clampX = (x: number) => Math.min(Math.max(x, area.left), area.right);
    const crisp = (x: number) => Math.round(x) + 0.5;
    // Centre the bracket row vertically within the reserved strip below the axis.
    const yMid = crisp(chart.height - DATE_ROW_HEIGHT / 2);

    ctx.save();
    ctx.strokeStyle = line;
    ctx.fillStyle = text;
    ctx.lineWidth = 1;
    ctx.lineCap = 'butt';
    ctx.setLineDash([]);
    ctx.font = '600 11px Inter, Nunito, system-ui, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';

    for (let k = 0; k < boundaries.length; k++) {
      const startIdx = boundaries[k].index;
      const endIdx = k + 1 < boundaries.length ? boundaries[k + 1].index - 1 : n - 1;
      const x0 = clampX(xScale.getPixelForValue(startIdx) - half);
      const x1 = clampX(xScale.getPixelForValue(endIdx) + half);
      const width = x1 - x0;
      if (width <= 0) continue;

      const label = boundaries[k].label.toUpperCase();
      const halfText = ctx.measureText(label).width / 2;
      // Too cramped to seat the label without spilling into the next range.
      if (width < halfText * 2 + 6) continue;

      const cx = (x0 + x1) / 2;
      const leftEnd = cx - halfText - LABEL_GAP;
      const rightStart = cx + halfText + LABEL_GAP;
      const lx0 = crisp(x0);
      const lx1 = crisp(x1);

      ctx.beginPath();
      // Vertical end caps bounding the range.
      ctx.moveTo(lx0, yMid - CAP_HALF);
      ctx.lineTo(lx0, yMid + CAP_HALF);
      ctx.moveTo(lx1, yMid - CAP_HALF);
      ctx.lineTo(lx1, yMid + CAP_HALF);
      // Horizontal rule, broken around the centred label.
      if (leftEnd > x0) {
        ctx.moveTo(lx0, yMid);
        ctx.lineTo(crisp(leftEnd), yMid);
      }
      if (rightStart < x1) {
        ctx.moveTo(crisp(rightStart), yMid);
        ctx.lineTo(lx1, yMid);
      }
      ctx.stroke();

      ctx.fillText(label, Math.round(cx), yMid);
    }

    ctx.restore();
  },
};
