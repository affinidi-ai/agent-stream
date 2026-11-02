import { Chart as ChartJS } from 'chart.js';
import { useSyncExternalStore } from 'react';

// Tuned for the dashboard's dark-theme background (~#1e1e1e). Light enough to
// be legible without overpowering the data series.
const DARK = {
  text: 'rgba(241, 245, 249, 0.78)',
  grid: 'rgba(255, 255, 255, 0.14)',
  border: 'rgba(255, 255, 255, 0.22)',
};

const LIGHT = {
  text: '#666',
  grid: 'rgba(0, 0, 0, 0.1)',
  border: 'rgba(0, 0, 0, 0.1)',
};

/** The axis colours for the given theme. Returns one of two stable references
 * (DARK / LIGHT) so it is safe to use directly in `useMemo` dependency lists. */
export function getChartAxisColors(isDark: boolean): {
  text: string;
  grid: string;
  border: string;
} {
  return isDark ? DARK : LIGHT;
}

function subscribeTheme(onChange: () => void): () => void {
  if (typeof document === 'undefined') return () => {};
  const observer = new MutationObserver(onChange);
  observer.observe(document.body, { attributes: true, attributeFilter: ['class'] });
  return () => observer.disconnect();
}

function isDarkSnapshot(): boolean {
  return typeof document !== 'undefined' && document.body.classList.contains('dark-theme');
}

/** Current chart axis colours, recomputed whenever the dashboard theme toggles.
 * Set these directly on each chart's scale options (grid / ticks / border) so
 * gridlines paint with the correct colour on first render instead of relying on
 * globally-mutated Chart.js defaults. */
export function useChartAxisColors(): { text: string; grid: string; border: string } {
  const isDark = useSyncExternalStore(subscribeTheme, isDarkSnapshot, () => false);
  return getChartAxisColors(isDark);
}

export function applyChartTheme(isDark: boolean): void {
  const t = isDark ? DARK : LIGHT;
  ChartJS.defaults.color = t.text;
  ChartJS.defaults.borderColor = t.border;
  if (ChartJS.defaults.scale) {
    ChartJS.defaults.scale.grid = {
      ...(ChartJS.defaults.scale.grid || {}),
      color: t.grid,
    };
    ChartJS.defaults.scale.ticks = {
      ...(ChartJS.defaults.scale.ticks || {}),
      color: t.text,
    };
    const scaleDefaults = ChartJS.defaults.scale as {
      border?: Record<string, unknown>;
    };
    scaleDefaults.border = {
      ...(scaleDefaults.border || {}),
      color: t.border,
    };
  }
  ChartJS.instances &&
    Object.values(ChartJS.instances).forEach(c => {
      try {
        c.update('none');
      } catch {
        /* noop */
      }
    });
}
