import { useCallback, useState } from 'react';

const NS = 'agentstream.dashboard';

/** Render mode for a time-series chart. `line` connects every bucket (trend),
 * `area` fills under the line, `bar` shows each bucket as a column (spikes), and
 * `points` plots discrete dots without joining sparse gaps. */
export type ChartKind = 'line' | 'area' | 'bar' | 'points';

export const CHART_KIND_OPTIONS: { label: string; value: ChartKind }[] = [
  { label: 'Line', value: 'line' },
  { label: 'Area', value: 'area' },
  { label: 'Bars', value: 'bar' },
  { label: 'Points', value: 'points' },
];

const CHART_KINDS: ChartKind[] = ['line', 'area', 'bar', 'points'];
const isChartKind = (v: unknown): v is ChartKind =>
  typeof v === 'string' && (CHART_KINDS as string[]).includes(v);

function readString(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeString(key: string, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* storage unavailable (private mode / quota) — preference is best-effort */
  }
}

/** Per-chart render-mode preference, persisted under a namespaced localStorage
 * key so a page refresh restores the user's last choice for each chart. */
export function useChartKind(id: string, fallback: ChartKind): [ChartKind, (k: ChartKind) => void] {
  const storageKey = `${NS}.chartKind.${id}`;
  const [kind, setKind] = useState<ChartKind>(() => {
    const stored = readString(storageKey);
    return isChartKind(stored) ? stored : fallback;
  });
  const update = useCallback(
    (k: ChartKind) => {
      setKind(k);
      writeString(storageKey, k);
    },
    [storageKey]
  );
  return [kind, update];
}

/** Persisted drag-window preferences: the timeframe width, its rail extent, the
 * resolution choice, and the rail's horizontal zoom factor. The pan offset is
 * intentionally not persisted so a refresh re-anchors the window to "now"
 * (live). `zoom` is optional so a prefs blob saved before the feature shipped
 * still loads (falls back to 1×). */
export interface WindowPrefs {
  windowSecs: number;
  domainSecs: number;
  resolutionPref: string;
  zoom?: number;
}

export function loadWindowPrefs(storageKey: string | undefined): WindowPrefs | null {
  if (!storageKey) return null;
  const raw = readString(`${NS}.window.${storageKey}`);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (
      typeof parsed?.windowSecs === 'number' &&
      typeof parsed?.domainSecs === 'number' &&
      typeof parsed?.resolutionPref === 'string'
    ) {
      const prefs: WindowPrefs = {
        windowSecs: parsed.windowSecs,
        domainSecs: parsed.domainSecs,
        resolutionPref: parsed.resolutionPref,
      };
      if (typeof parsed.zoom === 'number' && Number.isFinite(parsed.zoom)) {
        prefs.zoom = parsed.zoom;
      }
      return prefs;
    }
  } catch {
    /* malformed JSON — fall back to defaults */
  }
  return null;
}

export function saveWindowPrefs(storageKey: string, prefs: WindowPrefs): void {
  writeString(`${NS}.window.${storageKey}`, JSON.stringify(prefs));
}
