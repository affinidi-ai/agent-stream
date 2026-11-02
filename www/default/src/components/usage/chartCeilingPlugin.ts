import { type Chart, type ChartType, type Plugin } from 'chart.js';

/** Per-chart config the plugin reads from `options.plugins.ceilingLine`. */
export interface CeilingLineOptions {
  /** Draw the truncation marker only when the y-axis has been capped below the
   * data's natural peak (the slider moved off 100%). */
  active: boolean;
}

// Register `ceilingLine` as a typed plugin option so `MetricChart` can set
// `options.plugins.ceilingLine` without casting.
declare module 'chart.js' {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  interface PluginOptionsByType<TType extends ChartType> {
    ceilingLine?: CeilingLineOptions;
  }
}

/** Danger red, matching the app's `--danger` token, at full strength. */
const RED = 'rgba(239, 68, 68, 0.9)';

/**
 * Draws a horizontal **red dashed line across the top of the plot area** when a
 * chart's y-axis has been truncated by the peak-truncation slider. Because the
 * slider caps `scales.y.max` at the chosen fraction of the data peak, the top
 * edge of the plot *is* the truncation level — any peaks above it are clipped by
 * the chart area — so a dashed rule there makes it obvious the view is capped and
 * exactly where. Inactive (nothing drawn) unless `options.plugins.ceilingLine.active`.
 */
export const ceilingLinePlugin: Plugin<'line' | 'bar'> = {
  id: 'ceilingLine',
  afterDatasetsDraw(chart: Chart) {
    if (!chart.options.plugins?.ceilingLine?.active) return;
    const area = chart.chartArea;
    if (!area) return;
    const ctx = chart.ctx;
    const y = Math.round(area.top) + 1;
    ctx.save();
    ctx.beginPath();
    ctx.setLineDash([5, 4]);
    ctx.lineWidth = 1.5;
    ctx.strokeStyle = RED;
    ctx.moveTo(area.left, y);
    ctx.lineTo(area.right, y);
    ctx.stroke();
    ctx.restore();
  },
};
