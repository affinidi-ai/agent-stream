export const UI_COLORS = {
  /** Primary brand blue — used for titles, buttons, and badges */
  primary: '#4a90e2',
  primaryStrong: '#2e5a8f',

  /** Semantic status colors */
  success: '#10b981',
  warning: '#f59e0b',
  danger: '#ef4444',

  /** Accent colors for charts, flows, and highlights */
  accentTeal: '#00bcd4',
  accentPurple: '#7b68ee',
  orange: '#fd7e14',

  /** Neutral grays */
  neutral: '#94a3b8',
  neutralStrong: '#4b5563',
  neutralMuted: '#6b7280',

  /** Surfaces */
  panelBackground: '#f9fafb',
} as const;

export const FLOW_COLORS = {
  source: UI_COLORS.accentPurple,
  identity: UI_COLORS.warning,
  channel: UI_COLORS.primary,
  pipe: UI_COLORS.orange,
  fabricGateway: UI_COLORS.accentTeal,
  target: UI_COLORS.success,
  neutral: UI_COLORS.neutralStrong,
} as const;

export const CHART_PALETTE = [
  UI_COLORS.primary,
  UI_COLORS.success,
  UI_COLORS.accentTeal,
  UI_COLORS.warning,
  UI_COLORS.danger,
  UI_COLORS.accentPurple,
  UI_COLORS.orange,
  UI_COLORS.neutralStrong,
  UI_COLORS.primaryStrong,
  UI_COLORS.neutral,
];

export const withAlpha = (hex: string, alpha: number) => {
  const normalizedHex = hex.replace('#', '');
  const value =
    normalizedHex.length === 3
      ? normalizedHex
          .split('')
          .map(char => char + char)
          .join('')
      : normalizedHex;

  const red = parseInt(value.slice(0, 2), 16);
  const green = parseInt(value.slice(2, 4), 16);
  const blue = parseInt(value.slice(4, 6), 16);

  return `rgba(${red}, ${green}, ${blue}, ${alpha})`;
};

export const chartAreaFill = (hex: string, alpha = 0.12) => withAlpha(hex, alpha);

export const chartBarFill = (hex: string, alpha = 0.82) => withAlpha(hex, alpha);

/**
 * Chart.js scriptable `backgroundColor` that paints an area fill as a vertical
 * linear gradient — `topAlpha` at the top of the chart plot area, fading to
 * `bottomAlpha` at the bottom. Returns `undefined` on the first paint (before
 * Chart.js has measured `chartArea`) — Chart.js falls back to `borderColor`
 * for that frame, then recomputes.
 */
export const chartAreaGradient =
  (hex: string, topAlpha = 1, bottomAlpha = 0.1) =>
  (ctx: {
    chart: {
      ctx: CanvasRenderingContext2D;
      chartArea?: { top: number; bottom: number };
    };
  }): CanvasGradient | string | undefined => {
    const { chartArea, ctx: c } = ctx.chart;
    if (!chartArea) return undefined;
    const g = c.createLinearGradient(0, chartArea.top, 0, chartArea.bottom);
    g.addColorStop(0, withAlpha(hex, topAlpha));
    g.addColorStop(1, withAlpha(hex, bottomAlpha));
    return g;
  };
