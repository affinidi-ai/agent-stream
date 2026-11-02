import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  AUTO_RESOLUTION,
  MIN_WINDOW_SECS,
  RANGE_PRESETS,
  ZOOM_DEFAULT,
  clampZoom,
  defaultResolutionFor,
  deriveDomain,
  forcedResolutionFits,
  type RangePreset,
} from './usageSeries';
import { loadWindowPrefs, saveWindowPrefs } from './chartPrefs';

const DEFAULT_PRESET = RANGE_PRESETS.find(p => p.label === '24H') ?? RANGE_PRESETS[0];

const clamp = (v: number, lo: number, hi: number): number => Math.min(Math.max(v, lo), hi);

export interface DragWindow {
  windowSecs: number;
  endOffset: number;
}

export interface DragWindowState {
  /** Live (draft) window width while dragging — drives the rail visuals. */
  windowSecs: number;
  /** Live (draft) pan offset behind now (0 = live). */
  endOffset: number;
  /** Committed window that drives the fetch (set on pointer up / preset / live). */
  committed: DragWindow;
  /** Rail context extent. Stable across pan/resize; only a preset changes it. */
  domainSecs: number;
  /** User's resolution choice: `auto` (smart default) or a forced tier label. */
  resolutionPref: string;
  /** Concrete tier sent to the store: the smart default when `auto`, else the
   * forced choice. Drives the main chart fetch. */
  effectiveResolution: string;
  /** Horizontal zoom factor for the scrubber rail (1× = fit container). Does
   * not change the time the window represents, only how densely the rail draws
   * it; higher values stretch the inner rail wider and scroll horizontally. */
  zoom: number;
  onWindowChange: (windowSecs: number, endOffsetSecs: number) => void;
  onWindowCommit: () => void;
  onPreset: (preset: RangePreset) => void;
  onResolution: (pref: string) => void;
  onZoom: (zoom: number) => void;
  onLive: () => void;
}

/**
 * Owns the dragged time window shared by the usage and operational dashboards:
 * a live "draft" (width + pan offset, updated continuously while dragging to
 * drive only the rail's visuals) and a "committed" window (set on pointer up,
 * preset, or live) that actually drives data fetches. Splitting the two keeps a
 * drag from firing one request per pointer move. Pure window state only — the
 * consuming hook owns the fetch effects so the same gadget can drive telemetry
 * (spend/tokens) or operational (connections/latency) series alike.
 *
 * Pass a `storageKey` to persist the timeframe width, rail extent, and
 * resolution choice to localStorage so a page refresh restores the user's last
 * view. The pan offset is not persisted — a refresh re-anchors to now (live).
 */
export function useDragWindow(storageKey?: string): DragWindowState {
  const persisted = useMemo(() => loadWindowPrefs(storageKey), [storageKey]);
  const initialWindow = persisted?.windowSecs ?? DEFAULT_PRESET.secs;
  const initialDomain = persisted?.domainSecs ?? deriveDomain(initialWindow);

  const [windowSecs, setWindowSecs] = useState(initialWindow);
  const [endOffset, setEndOffset] = useState(0);
  const [committed, setCommitted] = useState<DragWindow>({
    windowSecs: initialWindow,
    endOffset: 0,
  });
  const draftRef = useRef<DragWindow>({ windowSecs: initialWindow, endOffset: 0 });

  // The rail extent is held stable for the lifetime of a zoom level so that
  // panning or resizing the window never rescales the rail underneath the
  // cursor. Only a preset jump re-derives it. Keeping it fixed also guarantees
  // the committed offset/width stay valid against the same domain, so releasing
  // a resize can never knock the fetched window into an empty region.
  const [domainSecs, setDomainSecs] = useState(initialDomain);

  // The user's resolution choice. `auto` resolves to a smart default keyed off
  // the committed window width; an explicit tier forces that exact resolution.
  const [resolutionPref, setResolutionPref] = useState(
    persisted?.resolutionPref ?? AUTO_RESOLUTION
  );
  const onResolution = useCallback((pref: string) => setResolutionPref(pref), []);

  // Horizontal zoom factor for the scrubber rail — a pure visual density knob
  // (does not change the committed window or the fetched buckets), so it
  // doesn't participate in the drag/commit flow.
  const [zoom, setZoom] = useState<number>(clampZoom(persisted?.zoom ?? ZOOM_DEFAULT));
  const onZoom = useCallback((z: number) => setZoom(clampZoom(z)), []);

  // A forced tier that no longer suits the window (e.g. 1m buckets dragged down
  // to a 30s window) reverts to `auto` so the dropdown reflects the fallback.
  useEffect(() => {
    if (!forcedResolutionFits(resolutionPref, committed.windowSecs)) {
      setResolutionPref(AUTO_RESOLUTION);
    }
  }, [resolutionPref, committed.windowSecs]);

  const effectiveResolution =
    resolutionPref === AUTO_RESOLUTION
      ? defaultResolutionFor(committed.windowSecs)
      : resolutionPref;

  // Persist the user's timeframe + resolution + zoom so a refresh restores them.
  useEffect(() => {
    if (!storageKey) return;
    saveWindowPrefs(storageKey, {
      windowSecs: committed.windowSecs,
      domainSecs,
      resolutionPref,
      zoom,
    });
  }, [storageKey, committed.windowSecs, domainSecs, resolutionPref, zoom]);

  const onWindowChange = useCallback(
    (w: number, off: number) => {
      const width = clamp(w, MIN_WINDOW_SECS, domainSecs);
      const offset = clamp(off, 0, domainSecs - width);
      draftRef.current = { windowSecs: width, endOffset: offset };
      setWindowSecs(width);
      setEndOffset(offset);
    },
    [domainSecs]
  );
  const onWindowCommit = useCallback(() => {
    setCommitted({ ...draftRef.current });
  }, []);
  const onPreset = useCallback((p: RangePreset) => {
    const off = Math.max(0, p.endOffset ?? 0);
    const dom = deriveDomain(p.secs, off);
    const width = clamp(p.secs, MIN_WINDOW_SECS, dom);
    const offset = clamp(off, 0, dom - width);
    draftRef.current = { windowSecs: width, endOffset: offset };
    setDomainSecs(dom);
    setWindowSecs(width);
    setEndOffset(offset);
    setCommitted({ windowSecs: width, endOffset: offset });
  }, []);
  const onLive = useCallback(() => {
    const width = draftRef.current.windowSecs;
    draftRef.current = { windowSecs: width, endOffset: 0 };
    setEndOffset(0);
    setCommitted({ windowSecs: width, endOffset: 0 });
  }, []);

  return {
    windowSecs,
    endOffset,
    committed,
    domainSecs,
    resolutionPref,
    effectiveResolution,
    zoom,
    onWindowChange,
    onWindowCommit,
    onPreset,
    onResolution,
    onZoom,
    onLive,
  };
}
