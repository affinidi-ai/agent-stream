import { useCallback, useEffect, useRef, useState } from 'react';
import {
  autoFetchParams,
  densifySeries,
  fetchSeries,
  overviewResolutionFor,
  windowForSecs,
  type RangePreset,
  type SeriesPoint,
  type SeriesResponse,
} from './usageSeries';
import { useDragWindow, type DragWindow, type DragWindowState } from './useDragWindow';

/** Upper bound on buckets we ask the backend to return for the rail overview
 * — the tier is chosen by {@link overviewResolutionFor} to follow the chart's
 * tier, so this only bounds the payload for extreme domain:tier ratios. */
const OVERVIEW_MAX_POINTS = 5000;

/** Min gap between websocket-triggered live refreshes so a burst of server
 * pushes can't flood the telemetry endpoint. */
const LIVE_REFRESH_THROTTLE_MS = 2000;

/** Websocket message types that signal new telemetry worth a live refresh. */
const LIVE_REFRESH_TYPES = new Set(['dashboard_delta', 'refresh_dashboard']);

export interface UsageSeriesState {
  series: SeriesResponse[];
  stepSecs: number;
  resolution: string;
  loading: boolean;
  /** Width of the selected window in seconds (the dragged timescale). */
  windowSecs: number;
  /** How far the window's right edge sits behind now (0 = live). */
  endOffset: number;
  /** Committed window (width + pan) that drives the fetch — use this to fetch
   * companion data (e.g. the rejection breakdown) for the same window. */
  committed: DragWindow;
  /** Extent the overview rail spans, derived from the committed window. */
  domainSecs: number;
  /** Sparkline points for the primary key across the whole `domainSecs`. */
  overview: SeriesPoint[];
  /** User's resolution choice (`auto` or a forced tier). */
  resolutionPref: string;
  onResolution: (pref: string) => void;
  /** Horizontal zoom factor for the scrubber rail (visual density only). */
  zoom: number;
  onZoom: (zoom: number) => void;
  onPreset: (preset: RangePreset) => void;
  /**
   * Update the dragged window's visual state (width + pan offset) without
   * fetching — called continuously while dragging the rail.
   */
  onWindowChange: (windowSecs: number, endOffsetSecs: number) => void;
  /** Commit the current dragged window, triggering the fetch (on pointer up). */
  onWindowCommit: () => void;
  onLive: () => void;
  reload: () => void;
}

/**
 * Owns the dragged time window (via {@link useDragWindow}) and fetches the given
 * telemetry series for it, plus a coarse overview series across the rail's whole
 * context extent for the drag gadget's sparkline. Resolution always follows the
 * dragged window width (auto): a narrower window yields finer buckets. Shared by
 * the dashboard, team, and member usage views so they all draw from the one
 * telemetry source with identical controls.
 *
 * In-flight requests are aborted when a newer committed window supersedes them.
 *
 * `keys` may be rebuilt every render; the effect depends on its joined form so a
 * new array with the same contents doesn't trigger a refetch.
 *
 * Pass `sharedWindow` to drive this hook from an externally-owned dragged window
 * (so several charts pan in lockstep off one rail); when omitted the hook owns
 * its own window. Set `fetchOverview = false` when another hook already supplies
 * the rail's sparkline, to skip the redundant overview round trip.
 */
export function useUsageSeries(
  keys: string[],
  enabled = true,
  sharedWindow?: DragWindowState,
  fetchOverview = true
): UsageSeriesState {
  const internalWin = useDragWindow();
  const win = sharedWindow ?? internalWin;
  const [series, setSeries] = useState<SeriesResponse[]>([]);
  const [stepSecs, setStepSecs] = useState(30);
  const [resolution, setResolution] = useState('—');
  const [loading, setLoading] = useState(false);
  const [overview, setOverview] = useState<SeriesPoint[]>([]);

  const loadAbortRef = useRef<AbortController | null>(null);
  const overviewAbortRef = useRef<AbortController | null>(null);

  const keysKey = keys.join(',');
  const { committed, domainSecs, effectiveResolution } = win;

  // `silent` skips the loading flag (no spinner) and keeps the last good data on
  // error, so a websocket-driven live tick refreshes the chart in place.
  const load = useCallback(
    async (silent = false) => {
      if (!enabled || keys.length === 0) {
        setSeries([]);
        return;
      }
      loadAbortRef.current?.abort();
      const ctrl = new AbortController();
      loadAbortRef.current = ctrl;
      const w = windowForSecs(committed.windowSecs, committed.endOffset);
      // Force the width-derived tier (the same one the dropdown and overview
      // use) for *every* key, rather than passing `auto` and letting the
      // backend pick the finest fitting tier per key. Per-key auto returns
      // dense keys (e.g. `surfaces:all`) at a coarser tier than sparse ones, so
      // a multi-line chart lands on mismatched time grids that can't align.
      const { resolution: fetchRes, maxPoints } = autoFetchParams(effectiveResolution);
      try {
        if (!silent) setLoading(true);
        const data = await fetchSeries(keys, w, maxPoints, fetchRes, ctrl.signal);
        if (loadAbortRef.current !== ctrl) return; // superseded by a newer commit
        const densified = data.map(s => densifySeries(s, w));
        setSeries(densified);
        setStepSecs(data[0]?.step_secs ?? 30);
        setResolution(data[0]?.resolution ?? '—');
        setLoading(false);
      } catch {
        if (loadAbortRef.current === ctrl) {
          if (!silent) setSeries([]);
          setLoading(false);
        }
      }
    },
    // keysKey stands in for the keys array identity.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [enabled, keysKey, committed.windowSecs, committed.endOffset, effectiveResolution]
  );

  useEffect(() => {
    load(false);
  }, [load]);

  // Live mode (window anchored to now): silently refresh in place when the
  // server pushes new telemetry over the websocket, so the chart "magically"
  // updates without the loading spinner. The fetch re-anchors `to` to now.
  const isLive = committed.endOffset === 0;
  const lastLiveRef = useRef(0);
  useEffect(() => {
    if (!enabled || !isLive) return;
    const onWs = (e: Event) => {
      const msg = (e as CustomEvent).detail as { type?: string } | undefined;
      if (!msg?.type || !LIVE_REFRESH_TYPES.has(msg.type)) return;
      const now = Date.now();
      if (now - lastLiveRef.current < LIVE_REFRESH_THROTTLE_MS) return;
      lastLiveRef.current = now;
      load(true);
    };
    window.addEventListener('ws-message', onWs);
    return () => window.removeEventListener('ws-message', onWs);
  }, [enabled, isLive, load]);

  // Overview sparkline: the primary key across the rail's whole context extent.
  // The overview follows the chart's tier so a rail bar covers no more time
  // than one chart bucket; otherwise a coarse rail bar aggregates activity from
  // a period much wider than a narrow selection, and the user can pick a slot
  // that shows a bar in the rail but is legitimately empty in the chart.
  // Overview sparkline for the scrubber rail. The rail renders a **fixed**
  // domain `[now - domainSecs, now]` and the selection window pans *within* it,
  // so the overview must be fetched for that same fixed domain (endOffset 0) —
  // NOT the committed window's endOffset. Sliding it by endOffset would move the
  // fetched data out from under the fixed render domain, making rail bars near
  // `now` vanish when the selection is panned into the past. Refetches only when
  // the key set, domain, or chart tier changes (all commit-boundary events), so
  // panning/resizing within a tier stays a single round trip.
  useEffect(() => {
    if (!enabled || !fetchOverview || keys.length === 0) {
      setOverview([]);
      return;
    }
    overviewAbortRef.current?.abort();
    const ctrl = new AbortController();
    overviewAbortRef.current = ctrl;
    const overviewWin = windowForSecs(domainSecs, 0);
    const overviewRes = overviewResolutionFor(effectiveResolution, domainSecs);
    fetchSeries([keys[0]], overviewWin, OVERVIEW_MAX_POINTS, overviewRes, ctrl.signal)
      .then(data => {
        if (overviewAbortRef.current !== ctrl) return;
        const pts = data[0]?.points ?? [];
        setOverview(pts);
      })
      .catch(() => {
        if (overviewAbortRef.current === ctrl) setOverview([]);
      });
    // keysKey stands in for the keys array identity.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, fetchOverview, keysKey, domainSecs, effectiveResolution]);

  useEffect(
    () => () => {
      loadAbortRef.current?.abort();
      overviewAbortRef.current?.abort();
    },
    []
  );

  return {
    series,
    stepSecs,
    resolution,
    loading,
    windowSecs: win.windowSecs,
    endOffset: win.endOffset,
    committed: win.committed,
    domainSecs: win.domainSecs,
    overview,
    resolutionPref: win.resolutionPref,
    onResolution: win.onResolution,
    zoom: win.zoom,
    onZoom: win.onZoom,
    onPreset: win.onPreset,
    onWindowChange: win.onWindowChange,
    onWindowCommit: win.onWindowCommit,
    onLive: win.onLive,
    reload: () => load(false),
  };
}
