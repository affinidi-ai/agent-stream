import { apiClient } from '../../api';

/** One bucket returned by the telemetry API. `t` is unix seconds. */
export interface SeriesPoint {
  t: number;
  cost: number;
  tokens: number;
  requests: number;
}

/** A single series' range result: which resolution tier served it + points. */
export interface SeriesResponse {
  key: string;
  resolution: string;
  step_secs: number;
  points: SeriesPoint[];
}

export interface RangePreset {
  label: string;
  secs: number;
  /** Seconds the window's right edge sits behind now (0 = anchored to now).
   * Fixed presets are always live (0); calendar presets pin a past window. */
  endOffset?: number;
}

/** Quick window presets, coarsest last. The store auto-picks the resolution. */
export const RANGE_PRESETS: RangePreset[] = [
  { label: '30s', secs: 30 },
  { label: '1m', secs: 60 },
  { label: '5m', secs: 300 },
  { label: '30m', secs: 1_800 },
  { label: '1H', secs: 3600 },
  { label: '6H', secs: 21_600 },
  { label: '24H', secs: 86_400 },
  { label: '7D', secs: 604_800 },
  { label: '30D', secs: 2_592_000 },
  { label: '1Y', secs: 31_536_000 },
];

/** `auto` lets the store pick the resolution for the window. The drag rail
 * always fetches at `auto`, so resolution follows the dragged window width. */
export const AUTO_RESOLUTION = 'auto';

/** Resolution tiers (label = backend tier key, secs = bucket width), finest
 * first — keep in lockstep with the backend `TIERS` (`src/telemetry/types.rs`). */
export const TIER_STEPS: { label: string; secs: number }[] = [
  { label: '30s', secs: 30 },
  { label: '1m', secs: 60 },
  { label: '5m', secs: 300 },
  { label: '30m', secs: 1_800 },
  { label: '1h', secs: 3_600 },
  { label: '12h', secs: 43_200 },
  { label: '24h', secs: 86_400 },
  { label: '7d', secs: 604_800 },
  { label: '30d', secs: 2_592_000 },
  { label: '1y', secs: 31_536_000 },
];

/** Target ceiling on buckets a smart-default resolution aims to show. The
 * default is the **finest** tier whose bucket count stays at or below this, so a
 * window shows useful per-day/per-hour detail (24H → hourly, 7D → 12-hourly, 30D
 * → daily, 1Y → monthly) rather than an over-aggregated handful of points that
 * hides individual days. Chosen just under the next-finer tier's count for the
 * common presets so those land on clean resolutions. */
const MAX_AUTO_BUCKETS = 45;

/** Smart default resolution for an `auto` window: the **finest** tier whose
 * bucket count for the window is `<= `{@link MAX_AUTO_BUCKETS}, giving readable
 * per-day detail (24H → hourly, 7D → 12-hourly, 30D → daily, 1Y → monthly). Falls
 * back to the coarsest tier for windows wider than a year. The user can override
 * this with an explicit tier. */
export function defaultResolutionFor(windowSecs: number): string {
  for (const tier of TIER_STEPS) {
    if (windowSecs / tier.secs <= MAX_AUTO_BUCKETS) {
      return tier.label;
    }
  }
  return TIER_STEPS[TIER_STEPS.length - 1].label;
}

/** Fetch defaults for a chart series that honour the user's resolution choice.
 * When pref is `auto` we send `auto` to the backend with `max_points =
 * MAX_AUTO_BUCKETS` (matching {@link defaultResolutionFor}); when pref is a
 * forced tier we send it verbatim. */
export function autoFetchParams(resolutionPref: string): {
  resolution: string;
  maxPoints: number;
} {
  if (resolutionPref === AUTO_RESOLUTION) {
    return { resolution: AUTO_RESOLUTION, maxPoints: MAX_AUTO_BUCKETS };
  }
  return { resolution: resolutionPref, maxPoints: 300 };
}

/** Bucket width (secs) for a tier label, or `undefined` for an unknown label. */
export function tierSecsForLabel(label: string): number | undefined {
  return TIER_STEPS.find(t => t.label === label)?.secs;
}

/** Ceiling on buckets the scrubber overview will fetch. Comfortably fills a
 * dense rail (typical rail is under 1000 px, even zoomed) without shipping a
 * pathological payload for extreme domain:tier ratios. */
const OVERVIEW_MAX_BUCKETS = 5000;

/** Tier for the scrubber-rail overview so a rail bar covers **no more time
 * than one chart bucket** at the current chart tier. Otherwise a coarse rail
 * bar (e.g. 7-day buckets over a 1Y rail, which is what auto picks for a 30D
 * preset) aggregates activity from a period much wider than a narrow selection
 * window — the user sees a bar in the rail, moves the selection there, and the
 * chart (at a much finer tier) legitimately shows nothing because the activity
 * was elsewhere inside that coarse bucket. The overview follows the chart's
 * tier so a rail bar always corresponds to what the chart can show; when the
 * chart tier over the whole domain would exceed {@link OVERVIEW_MAX_BUCKETS}
 * we walk to the finest coarser tier that fits — at worst the rail bar is one
 * tier wider than the chart, which the user reads intuitively. */
export function overviewResolutionFor(chartResolution: string, domainSecs: number): string {
  const chartStep = tierSecsForLabel(chartResolution);
  if (chartStep === undefined) return AUTO_RESOLUTION;
  if (domainSecs / chartStep <= OVERVIEW_MAX_BUCKETS) return chartResolution;
  for (const tier of TIER_STEPS) {
    if (tier.secs >= chartStep && domainSecs / tier.secs <= OVERVIEW_MAX_BUCKETS) {
      return tier.label;
    }
  }
  return chartResolution;
}

/** Fewest buckets a forced resolution must yield to remain sensible. Below this
 * the window is too short for the chosen bucket (e.g. a 30s window with 1m
 * buckets renders under one bar), so the rail reverts to `auto`. */
const MIN_FORCED_BUCKETS = 2;

/** Most buckets a forced resolution may yield before it's unusable — e.g.
 * 1-minute buckets over a 30-day window is ~43k slots, which can't be rendered
 * or gap-filled sensibly. Past this the rail reverts to `auto` (which picks a
 * sensible coarser tier). Kept in step with the densifier's own ceiling so a
 * *kept* forced tier is always fillable. */
const MAX_FORCED_BUCKETS = 5000;

/** Widest window (secs) the 30s tier may be forced on. A full day at 30s is
 * ~2880 buckets per chart, which ships too much data to scrub smoothly, so from
 * 24h up the dropdown disables 30s and a forced 30s reverts to `auto`. */
const MAX_30S_WINDOW_SECS = 86_400;

/** Whether a forced resolution tier still makes sense for a window width. A
 * forced tier coarser than ~half the window yields too few buckets to read, and
 * one far finer than the window yields tens of thousands of unfillable slots; in
 * either case the caller should fall back to `auto`. An unknown/`auto` label
 * always fits. */
export function forcedResolutionFits(resolution: string, windowSecs: number): boolean {
  if (resolution === AUTO_RESOLUTION) return true;
  const secs = tierSecsForLabel(resolution);
  if (secs === undefined) return true;
  if (resolution === '30s' && windowSecs >= MAX_30S_WINDOW_SECS) return false;
  const buckets = windowSecs / secs;
  return buckets >= MIN_FORCED_BUCKETS && buckets <= MAX_FORCED_BUCKETS;
}

/** Resolution choices for the manual override dropdown. `auto` defers to
 * {@link defaultResolutionFor}; the rest force an exact tier for the window. */
export const RESOLUTION_OPTIONS: { label: string; value: string }[] = [
  { label: 'Auto', value: AUTO_RESOLUTION },
  { label: '30 sec', value: '30s' },
  { label: '1 min', value: '1m' },
  { label: '5 min', value: '5m' },
  { label: '30 min', value: '30m' },
  { label: '1 hour', value: '1h' },
  { label: '12 hours', value: '12h' },
  { label: '1 day', value: '24h' },
  { label: '7 days', value: '7d' },
  { label: '30 days', value: '30d' },
  { label: '1 year', value: '1y' },
];

/** Overview-rail context extents (secs), coarsest last. The rail snaps its
 * domain to the smallest of these that comfortably contains the selected
 * window, so the selection stays a grabbable fraction of the rail. */
export const DOMAIN_STEPS = [300, 1800, 3600, 21_600, 86_400, 604_800, 2_592_000, 31_536_000];

/** Largest rail extent / widest selectable window (1Y). */
export const MAX_DOMAIN_SECS = DOMAIN_STEPS[DOMAIN_STEPS.length - 1];

/** Floor for a dragged window (30s) so the finest telemetry tier is reachable. */
export const MIN_WINDOW_SECS = 30;

/** Horizontal zoom range for the scrubber rail. 1× fits the rail to its
 * container (current behaviour); higher values stretch the inner content wider
 * so bars/overview thicken and the rail scrolls horizontally. Bounded so the
 * inner width stays under ~10k px on realistic containers. */
export const ZOOM_MIN = 1;
export const ZOOM_MAX = 10;
export const ZOOM_STEP = 0.5;
export const ZOOM_DEFAULT = 1;

export const clampZoom = (v: number): number => {
  if (!Number.isFinite(v)) return ZOOM_DEFAULT;
  return Math.min(Math.max(v, ZOOM_MIN), ZOOM_MAX);
};

/** Pick the overview-rail extent for a selected window width so the selection
 * occupies at most ~1/3 of the rail and stays easy to grab and resize. When the
 * window is pinned `endOffsetSecs` behind now (a calendar preset), the rail must
 * also reach back far enough to contain the whole offset window. */
export function deriveDomain(windowSecs: number, endOffsetSecs = 0): number {
  const target = Math.max(windowSecs * 3, Math.max(0, endOffsetSecs) + windowSecs);
  return DOMAIN_STEPS.find(s => s >= target) ?? MAX_DOMAIN_SECS;
}

const MONTH_LABELS = [
  'Jan',
  'Feb',
  'Mar',
  'Apr',
  'May',
  'Jun',
  'Jul',
  'Aug',
  'Sep',
  'Oct',
  'Nov',
  'Dec',
];

/** Calendar-anchored quick presets: month-to-date followed by one preset per
 * full calendar month from last month back to January of the current year. Each
 * carries a concrete width plus an `endOffset` behind now, so the dragged window
 * lands exactly on that month's `[start, end)` (the current month, MTD, is
 * capped at now). Computed from `now` because the bounds shift each day. */
export function buildCalendarPresets(now: Date = new Date()): RangePreset[] {
  const nowSecs = Math.floor(now.getTime() / 1000);
  const year = now.getFullYear();
  const month = now.getMonth();
  const monthStartSecs = (m: number): number => Math.floor(new Date(year, m, 1).getTime() / 1000);

  const startOfThisMonth = monthStartSecs(month);
  const presets: RangePreset[] = [
    { label: 'MTD', secs: Math.max(MIN_WINDOW_SECS, nowSecs - startOfThisMonth), endOffset: 0 },
  ];

  for (let m = month - 1; m >= 0; m--) {
    const start = monthStartSecs(m);
    const end = monthStartSecs(m + 1);
    presets.push({
      label: MONTH_LABELS[m],
      secs: Math.max(MIN_WINDOW_SECS, end - start),
      endOffset: Math.max(0, nowSecs - end),
    });
  }
  return presets;
}

export interface TimeWindow {
  from: number;
  to: number;
}

/** Resolve a concrete `[from, to]` window for a width, panned `endOffsetSecs`
 * seconds back from now (0 = live/anchored to now). Bounds are floored to whole
 * unix seconds — drag math yields fractional seconds, but the telemetry API
 * deserializes `from`/`to` as integers and 400s on a decimal point. */
export function windowForSecs(windowSecs: number, endOffsetSecs: number): TimeWindow {
  const now = Math.floor(Date.now() / 1000);
  const to = now - Math.floor(Math.max(0, endOffsetSecs));
  return { from: Math.floor(to - windowSecs), to };
}

/** The current calendar month so far (UTC), aligned with the backend's monthly
 * usage-cap reset. Used to chart "percentage of monthly cap consumed". */
export function monthToDateWindow(): TimeWindow {
  const now = new Date();
  const from = Math.floor(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1) / 1000);
  return { from, to: Math.floor(Date.now() / 1000) };
}

/** Fetch one or more series in a single round trip. When `resolution` names a
 * tier (not `auto`) the store serves that exact resolution for the window. */
export async function fetchSeries(
  keys: string[],
  window: TimeWindow,
  maxPoints = 300,
  resolution: string = AUTO_RESOLUTION,
  signal?: AbortSignal
): Promise<SeriesResponse[]> {
  if (keys.length === 0) return [];
  const params = new URLSearchParams({
    keys: keys.join(','),
    from: String(Math.floor(window.from)),
    to: String(Math.floor(window.to)),
    max_points: String(maxPoints),
  });
  if (resolution && resolution !== AUTO_RESOLUTION) {
    params.set('resolution', resolution);
  }
  const res = await apiClient.get<SeriesResponse[]>(`/telemetry/series?${params.toString()}`, {
    signal,
  });
  return res.data;
}

export function indexByKey(series: SeriesResponse[]): Map<string, SeriesResponse> {
  return new Map(series.map(s => [s.key, s]));
}

/** One bucket of operational metrics returned by `/dashboard/ops-series`.
 * Mirrors the backend `OpsSeriesPoint`; `t` is unix seconds. */
export interface OpsSeriesPoint {
  t: number;
  connections: number;
  failed: number;
  gateway_faults: number;
  rule_accepts: number;
  rule_denies: number;
  request_bytes: number;
  response_bytes: number;
  input_tokens: number;
  output_tokens: number;
  avg_latency_ms: number;
  p50_latency_ms: number;
  p95_latency_ms: number;
  p99_latency_ms: number;
  min_latency_ms: number;
  max_latency_ms: number;
  latency_samples: number;
  /** Requests served from the response cache (a subset of `connections`). */
  cache_hits: number;
  /** Provider spend avoided by cache hits in this bucket (USD). */
  cache_saved_cost: number;
}

/** A single operational series' range result. Mirrors `OpsSeriesResponse`. */
export interface OpsSeriesResponse {
  key: string;
  resolution: string;
  step_secs: number;
  points: OpsSeriesPoint[];
}

/** Operational series-key builders — keep in lockstep with
 * `src/metrics/ops_telemetry.rs`. */
export const opsAllKey = (): string => 'ops:all';
export const opsSurfaceKey = (surfaceId: string): string => `ops:surface:${surfaceId}`;

/** Fetch one or more operational series in a single round trip. Resolution
 * follows the dragged window width unless an explicit tier is named. */
export async function fetchOpsSeries(
  keys: string[],
  window: TimeWindow,
  maxPoints = 300,
  resolution: string = AUTO_RESOLUTION,
  signal?: AbortSignal
): Promise<OpsSeriesResponse[]> {
  if (keys.length === 0) return [];
  const params = new URLSearchParams({
    keys: keys.join(','),
    from: String(Math.floor(window.from)),
    to: String(Math.floor(window.to)),
    max_points: String(maxPoints),
  });
  if (resolution && resolution !== AUTO_RESOLUTION) {
    params.set('resolution', resolution);
  }
  const res = await apiClient.get<OpsSeriesResponse[]>(
    `/dashboard/ops-series?${params.toString()}`,
    { signal }
  );
  return res.data;
}

/** Ceiling on reconstructed buckets. A forced-fine tier over a very wide sparse
 * span could otherwise expand to millions of buckets; past this we keep the raw
 * sparse series rather than freeze the browser densifying it. */
const MAX_DENSE_BUCKETS = 5000;

/** Seconds in a day. */
const DAY_SECS = 86_400;

/** Unix seconds of the local-calendar midnight that starts the day containing
 * `epochSecs`. Local (not UTC) so it lines up with the local-date bracket labels
 * the date-boundary plugin draws. */
function startOfLocalDaySecs(epochSecs: number): number {
  const d = new Date(epochSecs * 1000);
  d.setHours(0, 0, 0, 0);
  return Math.floor(d.getTime() / 1000);
}

/** Reconstruct the full step-aligned bucket grid, inserting `zero(t)` buckets for
 * every empty slot. The telemetry store persists only buckets that recorded
 * activity (sparse), so a category-axis chart collapses empty spans — e.g. 27 Jun
 * rendering immediately beside 13 Jul with nothing between, and a half-empty day
 * rendering narrower than a full one.
 *
 * When a `range` (the requested `[from, to]` window) is given, the grid spans the
 * **whole window** so every bucket exists — leading, trailing, and wholly-empty
 * spans included — surfacing real "no data" gaps. At **sub-day resolutions whose
 * window spans more than one day** the span is snapped out to whole *local* days
 * (matching the local-date bracket labels), so every rendered day holds the same
 * number of buckets and therefore the same width — otherwise a multi-day window
 * that starts/ends mid-day would render its edge days narrower than the full ones
 * between. A rolling window of one day or less is filled to its exact bounds (not
 * snapped), so a 24h selection draws a 24h span that matches the scrubber rather
 * than the ~48h span of the two calendar days it straddles. The grid always stays
 * on the tier's UTC step alignment, so real samples still land on it. Without a
 * range it spans only the first→last returned point. Returns the input unchanged
 * when there is nothing to fill or the grid would exceed {@link MAX_DENSE_BUCKETS}. */
function densifyPoints<P extends { t: number }>(
  points: P[],
  stepSecs: number,
  zero: (t: number) => P,
  range?: TimeWindow
): P[] {
  if (stepSecs <= 0) return points;
  const byT = new Map(points.map(p => [p.t, p]));
  let start: number;
  let end: number;
  if (range) {
    const dayFrom = startOfLocalDaySecs(range.from);
    const dayTo = startOfLocalDaySecs(range.to);
    const spansMultipleDays = range.to - range.from > DAY_SECS;
    if (stepSecs < DAY_SECS && spansMultipleDays && dayFrom !== dayTo) {
      // Sub-day resolution over a genuinely multi-day window: snap out to whole
      // local days so each rendered day is complete (equal width). Align to the
      // tier's UTC step grid so real samples still fall on grid slots. A rolling
      // window of one day or less is NOT snapped — snapping it to the two
      // calendar days it straddles would draw a ~48h span for a 24h selection,
      // contradicting the scrubber's 24h highlight.
      start = Math.ceil(dayFrom / stepSecs) * stepSecs;
      end = Math.floor((dayTo + DAY_SECS - 1) / stepSecs) * stepSecs;
    } else {
      // Single day (or less), or day-or-coarser resolution: fill exactly the
      // window so the chart span matches the selected window.
      start = Math.floor(range.from / stepSecs) * stepSecs;
      end = Math.floor(range.to / stepSecs) * stepSecs;
    }
    // Defensive: widen to any point the backend returned outside these bounds.
    for (const p of points) {
      if (p.t < start) start = p.t;
      if (p.t > end) end = p.t;
    }
  } else {
    if (points.length < 2) return points;
    let min = points[0].t;
    let max = points[0].t;
    for (const p of points) {
      if (p.t < min) min = p.t;
      if (p.t > max) max = p.t;
    }
    start = min;
    end = max;
  }
  if (end < start) return points;
  if ((end - start) / stepSecs + 1 > MAX_DENSE_BUCKETS) return points;
  const dense: P[] = [];
  for (let t = start; t <= end; t += stepSecs) {
    dense.push(byT.get(t) ?? zero(t));
  }
  return dense;
}

/** Fill the empty buckets of a usage series with zero-valued samples so its
 * timeline is evenly spaced (see {@link densifyPoints}). Pass the requested
 * window to fill the whole span (equal-width days, visible no-data gaps). */
export function densifySeries(series: SeriesResponse, range?: TimeWindow): SeriesResponse {
  return {
    ...series,
    points: densifyPoints(
      series.points,
      series.step_secs,
      t => ({
        t,
        cost: 0,
        tokens: 0,
        requests: 0,
      }),
      range
    ),
  };
}

function zeroOpsPoint(t: number): OpsSeriesPoint {
  return {
    t,
    connections: 0,
    failed: 0,
    gateway_faults: 0,
    rule_accepts: 0,
    rule_denies: 0,
    request_bytes: 0,
    response_bytes: 0,
    input_tokens: 0,
    output_tokens: 0,
    avg_latency_ms: 0,
    p50_latency_ms: 0,
    p95_latency_ms: 0,
    p99_latency_ms: 0,
    min_latency_ms: 0,
    max_latency_ms: 0,
    latency_samples: 0,
    cache_hits: 0,
    cache_saved_cost: 0,
  };
}

/** Fill the empty buckets of an operational series with zero-valued samples so
 * its timeline is evenly spaced (see {@link densifyPoints}). Pass the requested
 * window to fill the whole span (equal-width days, visible no-data gaps). */
export function densifyOpsSeries(series: OpsSeriesResponse, range?: TimeWindow): OpsSeriesResponse {
  return {
    ...series,
    points: densifyPoints(series.points, series.step_secs, zeroOpsPoint, range),
  };
}

/** Telemetry series-key builders — keep in lockstep with `src/telemetry/mod.rs`. */
export const allSurfacesKey = (): string => 'surfaces:all';
export const surfaceKey = (pipeId: string): string => `surface:${pipeId}`;
export const surfaceStageKey = (pipeId: string, stage: string): string =>
  `surface:${pipeId}:stage:${stage}`;
export const memberKey = (memberId: string): string => `member:${memberId}`;
export const teamKey = (teamId: string): string => `team:${teamId}`;
export const memberSurfaceKey = (memberId: string, pipeId: string): string =>
  `member:${memberId}:surface:${pipeId}`;

/** Rows for a primary spend/tokens dual-axis chart. */
export interface PrimaryRow {
  t: number;
  cost: number;
  tokens: number;
}

export function primaryRows(series: SeriesResponse | undefined): PrimaryRow[] {
  if (!series) return [];
  return series.points.map(p => ({ t: p.t, cost: p.cost, tokens: p.tokens }));
}

/** One breakdown line: a stable id (recharts dataKey), a display label, and the
 * telemetry series key that feeds it. */
export interface BreakdownItem {
  id: string;
  label: string;
  key: string;
}

/** Rows for a multi-line breakdown spend chart: one numeric column per item id. */
export interface BreakdownRow {
  t: number;
  [id: string]: number;
}

export function breakdownRows(
  seriesByKey: Map<string, SeriesResponse>,
  items: BreakdownItem[]
): BreakdownRow[] {
  const byT = new Map<number, BreakdownRow>();
  for (const item of items) {
    const series = seriesByKey.get(item.key);
    if (!series) continue;
    for (const p of series.points) {
      const row = byT.get(p.t) ?? { t: p.t };
      row[item.id] = (row[item.id] ?? 0) + p.cost;
      byT.set(p.t, row);
    }
  }
  return Array.from(byT.values()).sort((a, b) => a.t - b.t);
}

/** Sum a series' points over the whole loaded window. */
export interface WindowTotals {
  cost: number;
  tokens: number;
  requests: number;
}

export function sumWindow(series: SeriesResponse | undefined): WindowTotals {
  const totals: WindowTotals = { cost: 0, tokens: 0, requests: 0 };
  if (!series) return totals;
  for (const p of series.points) {
    totals.cost += p.cost;
    totals.tokens += p.tokens;
    totals.requests += p.requests;
  }
  return totals;
}

/** Format a USD amount, keeping sub-cent LLM spend visible instead of rounding
 * it to `$0.00`. */
export function formatUsd(amount: number): string {
  if (amount <= 0) return '$0.00';
  if (amount < 0.01) {
    const trimmed = amount.toFixed(6).replace(/0+$/, '').replace(/\.$/, '');
    return trimmed === '0' ? '<$0.000001' : `$${trimmed}`;
  }
  return `$${amount.toFixed(2)}`;
}

/** Format a USD amount rounded UP (ceiling) to the nearest 2 decimal places,
 * e.g. 0.031 -> `$0.04`. Used for headline totals where any fractional spend
 * should always round up to the next cent. */
export function formatUsdCeil(amount: number): string {
  if (!Number.isFinite(amount) || amount <= 0) return '$0.00';
  return `$${(Math.ceil(amount * 100) / 100).toFixed(2)}`;
}

/** Build category-axis labels for a run of bucket timestamps. Sub-day
 * resolutions return **time-only** labels (which Chart.js rotates diagonally);
 * the calendar date is drawn as a separate horizontal row beneath them by the
 * {@link import('./dateBoundaryPlugin')} plugin, keyed off {@link dateBoundaries}.
 * Day-or-coarser resolutions give every bucket its own date, so they show dates
 * on the axis directly (month/day, or month/year at ≥30-day buckets). Full
 * date+time stays available via {@link fullStamp} in the chart tooltip. */
export function makeAxisLabels(timestamps: number[], stepSecs: number): string[] {
  const at = (t: number) => new Date(t * 1000);
  if (stepSecs >= 2_592_000) {
    return timestamps.map(t => at(t).toLocaleDateString([], { month: 'short', year: '2-digit' }));
  }
  if (stepSecs >= 86_400) {
    return timestamps.map(t => at(t).toLocaleDateString([], { month: 'short', day: 'numeric' }));
  }
  const timeOpts: Intl.DateTimeFormatOptions =
    stepSecs >= 3600 ? { hour: '2-digit' } : { hour: '2-digit', minute: '2-digit' };
  return timestamps.map(t => at(t).toLocaleTimeString([], timeOpts));
}

/** A calendar-date change within a run of bucket timestamps: the category index
 * where a new date starts and the date's short label. */
export interface DateBoundary {
  index: number;
  label: string;
}

/** The category indices where the calendar date changes across a run of bucket
 * timestamps, each with its short date label. Drives the horizontal date row and
 * the date-change divider lines the {@link import('./dateBoundaryPlugin')} plugin
 * draws beneath a sub-day time axis. The first bucket is always a boundary. */
export function dateBoundaries(timestamps: number[]): DateBoundary[] {
  const out: DateBoundary[] = [];
  let prevKey = '';
  for (let i = 0; i < timestamps.length; i++) {
    const d = new Date(timestamps[i] * 1000);
    const key = `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
    if (key !== prevKey) {
      prevKey = key;
      out.push({ index: i, label: d.toLocaleDateString([], { month: 'short', day: 'numeric' }) });
    }
  }
  return out;
}

/** Full date+time label for a bucket timestamp — used for tooltip titles so the
 * hover always carries complete fidelity even when the axis tick is abbreviated
 * to just a date or a time. */
export function fullStamp(t: number | undefined): string {
  return t === undefined ? '' : new Date(t * 1000).toLocaleString();
}

/** Units for the human-readable span label, largest first. Months are the usual
 * 30-day approximation (this labels the selected window *width*, not a
 * calendar-accurate diff). */
const DURATION_UNITS: { label: string; secs: number }[] = [
  { label: 'month', secs: 2_592_000 },
  { label: 'day', secs: 86_400 },
  { label: 'hour', secs: 3_600 },
  { label: 'minute', secs: 60 },
  { label: 'second', secs: 1 },
];

/** The maximum number of significant units shown, so a span reads e.g.
 * "3 months, 5 days, 2 hours" rather than trailing all the way down to seconds. */
const MAX_DURATION_PARTS = 3;

/** Render a duration in seconds as a normalised span, e.g. `95 * 86400 + 2 * 3600`
 * → "3 months, 5 days, 2 hours". Shows the {@link MAX_DURATION_PARTS} most
 * significant non-zero units, pluralised. */
export function formatDuration(totalSecs: number): string {
  let rem = Math.max(0, Math.round(totalSecs));
  const parts: string[] = [];
  for (const { label, secs } of DURATION_UNITS) {
    const value = Math.floor(rem / secs);
    rem -= value * secs;
    if (value > 0) {
      parts.push(`${value} ${label}${value === 1 ? '' : 's'}`);
      if (parts.length === MAX_DURATION_PARTS) break;
    }
  }
  return parts.length > 0 ? parts.join(', ') : '0 seconds';
}

/** One canonical rejection category and its count over the queried window. */
export interface RejectionCategoryCount {
  category: string;
  label: string;
  count: number;
}

/** `/telemetry/rejections` result: total blocked count + per-category breakdown
 * for a scope over a window. Mirrors the backend `RejectionsResponse`. */
export interface RejectionsResponse {
  scope: string;
  from: number;
  to: number;
  total: number;
  categories: RejectionCategoryCount[];
}

/** Rejection scope-key builders (the key prefix before `:{category}`) — keep in
 * lockstep with `src/telemetry/mod.rs`. */
export const rejectionAllScope = (): string => 'rejection:all';
export const rejectionSurfaceScope = (pipeId: string): string => `rejection:surface:${pipeId}`;
export const rejectionSurfaceStageScope = (pipeId: string, stage: string): string =>
  `rejection:surface:${pipeId}:stage:${stage}`;
export const rejectionTeamScope = (teamId: string): string => `rejection:team:${teamId}`;
export const rejectionMemberScope = (memberId: string): string => `rejection:member:${memberId}`;

/** Reserved category recorded once per rejection — its per-bucket `requests`
 * counter is the total blocked count. Keep in lockstep with
 * `REJECTION_TOTAL_CATEGORY` in `src/telemetry/mod.rs`. */
export const REJECTION_TOTAL_CATEGORY = '_total';

/** Telemetry series key for a rejection scope's total blocked count over time:
 * the `requests` field of this series is the per-bucket rejection count, so it
 * can be charted via {@link fetchSeries} like any other time-series. */
export const rejectionTotalKey = (scope: string): string => `${scope}:${REJECTION_TOTAL_CATEGORY}`;

/** Telemetry series key for a single canonical rejection category over time:
 * the `requests` field is the per-bucket count of rejections that triggered this
 * category. Keep in lockstep with the key shape in `src/telemetry/mod.rs`. */
export const rejectionCategoryKey = (scope: string, category: string): string =>
  `${scope}:${category}`;

/** Fetch the per-category rejection breakdown for a scope over a window. */
export async function fetchRejections(
  scope: string,
  window: TimeWindow,
  resolution: string = AUTO_RESOLUTION,
  signal?: AbortSignal
): Promise<RejectionsResponse> {
  const params = new URLSearchParams({
    scope,
    from: String(Math.floor(window.from)),
    to: String(Math.floor(window.to)),
  });
  if (resolution && resolution !== AUTO_RESOLUTION) {
    params.set('resolution', resolution);
  }
  const res = await apiClient.get<RejectionsResponse>(
    `/telemetry/rejections?${params.toString()}`,
    { signal }
  );
  return res.data;
}
