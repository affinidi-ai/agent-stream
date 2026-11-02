import { useCallback, useEffect, useRef, useState } from 'react';
import {
  autoFetchParams,
  densifyOpsSeries,
  fetchOpsSeries,
  overviewResolutionFor,
  windowForSecs,
  type OpsSeriesPoint,
  type OpsSeriesResponse,
  type RangePreset,
  type SeriesPoint,
} from './usageSeries';
import { useDragWindow, type DragWindowState } from './useDragWindow';

/** Upper bound on buckets we ask the backend to return for the rail overview
 * — the tier is chosen by {@link overviewResolutionFor} to follow the chart's
 * tier, so this only bounds the payload for extreme domain:tier ratios. */
const OVERVIEW_MAX_POINTS = 5000;

/** Min gap between websocket-triggered live refreshes so a burst of server
 * pushes can't flood the ops-series endpoint. */
const LIVE_REFRESH_THROTTLE_MS = 2000;

/** Websocket message types that signal new telemetry worth a live refresh. */
const LIVE_REFRESH_TYPES = new Set(['dashboard_delta', 'refresh_dashboard']);

export interface OpsSeriesState {
  /** Points for the primary key (`keys[0]`, e.g. `ops:all`). */
  points: OpsSeriesPoint[];
  /** Every requested operational series keyed by its series key. */
  seriesByKey: Map<string, OpsSeriesResponse>;
  stepSecs: number;
  resolution: string;
  loading: boolean;
  windowSecs: number;
  endOffset: number;
  domainSecs: number;
  /** Sparkline points for the drag rail (primary key activity over the domain). */
  overview: SeriesPoint[];
  /** User's resolution choice (`auto` or a forced tier). */
  resolutionPref: string;
  onResolution: (pref: string) => void;
  /** Horizontal zoom factor for the scrubber rail (visual density only). */
  zoom: number;
  onZoom: (zoom: number) => void;
  onPreset: (preset: RangePreset) => void;
  onWindowChange: (windowSecs: number, endOffsetSecs: number) => void;
  onWindowCommit: () => void;
  onLive: () => void;
  reload: () => void;
}

/** Map an operational overview series into the rail's `SeriesPoint` shape, using
 * connection volume as the sparkline magnitude (the rail draws `cost`). */
function toRailPoints(series: OpsSeriesResponse | undefined): SeriesPoint[] {
  if (!series) return [];
  return series.points.map(p => ({
    t: p.t,
    cost: p.connections,
    tokens: p.input_tokens + p.output_tokens,
    requests: p.connections,
  }));
}

/**
 * Operational-metrics analogue of {@link import('./useUsageSeries').useUsageSeries}.
 * Owns the dragged window (via {@link useDragWindow}) and fetches the given
 * `ops:*` series for it from the windowed `/dashboard/ops-series` endpoint, plus
 * a coarse overview for the drag rail's sparkline. Backs the dashboard's shared
 * rail so every operational chart (connections, throughput, tokens, latency)
 * pans through history in lockstep. In-flight requests are aborted when a newer
 * committed window supersedes them.
 *
 * Pass `sharedWindow` to drive this hook from an externally-owned dragged window
 * (so it pans in lockstep with other charts off one rail); when omitted the hook
 * owns its own window. Set `fetchOverview = false` when another hook already
 * supplies the rail's sparkline, to skip the redundant overview round trip.
 */
export function useOpsSeries(
  keys: string[],
  enabled = true,
  sharedWindow?: DragWindowState,
  fetchOverview = true
): OpsSeriesState {
  const internalWin = useDragWindow();
  const win = sharedWindow ?? internalWin;
  const [seriesByKey, setSeriesByKey] = useState<Map<string, OpsSeriesResponse>>(new Map());
  const [points, setPoints] = useState<OpsSeriesPoint[]>([]);
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
        setSeriesByKey(new Map());
        setPoints([]);
        return;
      }
      loadAbortRef.current?.abort();
      const ctrl = new AbortController();
      loadAbortRef.current = ctrl;
      const w = windowForSecs(committed.windowSecs, committed.endOffset);
      // Force the width-derived tier for every key (see useUsageSeries) so all
      // series in the chart share one time grid instead of the backend picking
      // a different tier per key by data density.
      const { resolution: fetchRes, maxPoints } = autoFetchParams(effectiveResolution);
      try {
        if (!silent) setLoading(true);
        const data = await fetchOpsSeries(keys, w, maxPoints, fetchRes, ctrl.signal);
        if (loadAbortRef.current !== ctrl) return; // superseded by a newer commit
        const byKey = new Map(data.map(s => [s.key, densifyOpsSeries(s, w)]));
        setSeriesByKey(byKey);
        setPoints(byKey.get(keys[0])?.points ?? []);
        setStepSecs(data[0]?.step_secs ?? 30);
        setResolution(data[0]?.resolution ?? '—');
        setLoading(false);
      } catch {
        if (loadAbortRef.current === ctrl) {
          if (!silent) {
            setSeriesByKey(new Map());
            setPoints([]);
          }
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

  // Overview sparkline: follows the chart's tier so a rail bar covers no more
  // time than one chart bucket. See {@link overviewResolutionFor} for why.
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
    fetchOpsSeries([keys[0]], overviewWin, OVERVIEW_MAX_POINTS, overviewRes, ctrl.signal)
      .then(data => {
        if (overviewAbortRef.current !== ctrl) return;
        const rail = toRailPoints(data[0]);
        setOverview(rail);
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
    points,
    seriesByKey,
    stepSecs,
    resolution,
    loading,
    windowSecs: win.windowSecs,
    endOffset: win.endOffset,
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
