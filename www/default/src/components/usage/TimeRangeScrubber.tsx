import React, { useEffect, useMemo, useRef, useState } from 'react';
import { UI_COLORS } from '../../utils/uiPalette';
import {
  MIN_WINDOW_SECS,
  RANGE_PRESETS,
  RESOLUTION_OPTIONS,
  ZOOM_DEFAULT,
  ZOOM_MAX,
  ZOOM_MIN,
  ZOOM_STEP,
  buildCalendarPresets,
  clampZoom,
  forcedResolutionFits,
  formatDuration,
  type RangePreset,
  type SeriesPoint,
} from './usageSeries';

interface TimeRangeScrubberProps {
  /** Width of the selected window in seconds (the dragged timescale). */
  windowSecs: number;
  /** How far the window's right edge sits behind now (0 = live). */
  endOffsetSecs: number;
  /** Extent the rail spans, in seconds (derived from the window width). */
  domainSecs: number;
  /** Sparkline points for the primary key across the whole domain. */
  overview: SeriesPoint[];
  /** Which usage metric(s) the chart(s) beneath this rail actually plot. A rail
   * bar is drawn in the primary colour when its bucket has a value for one of
   * these, and muted grey when the bucket has only *other* activity (e.g. a
   * request count under a cost chart) — so the rail never implies a chart should
   * show data it legitimately can't. Defaults to `['cost']`. */
  relevantMetrics?: SparkMetric[];
  /** Resolution tier the store actually served for the current window. */
  resolution: string;
  loading: boolean;
  /** User's resolution choice: `auto` (smart default) or a forced tier. */
  resolutionPref: string;
  onResolution: (pref: string) => void;
  /** Horizontal zoom factor for the rail (1× = fit container). Pure visual
   * density — does not change the time the window represents. */
  zoom?: number;
  onZoom?: (zoom: number) => void;
  onPreset: (preset: RangePreset) => void;
  onWindowChange: (windowSecs: number, endOffsetSecs: number) => void;
  /** Commit the dragged window (fetch happens here, on pointer up). */
  onWindowCommit: () => void;
  onLive: () => void;
}

const RAIL_HEIGHT = 56;
/** Within this fraction of the right edge, snap the window back to live. */
const LIVE_SNAP_FRACTION = 0.01;
/** Minimum bar height (viewBox units) for any bucket with cost > 0, so a small
 * cost next to a large spike still reads as a visible tick instead of a
 * sub-pixel stub lost at the baseline. */
const MIN_BAR_UNITS = 10;

type DragMode = 'move' | 'left' | 'right' | 'pan';

interface DragState {
  mode: DragMode;
  startX: number;
  railWidth: number;
  startWindow: number;
  startOffset: number;
  startScrollLeft?: number;
}

const clamp = (v: number, lo: number, hi: number): number => Math.min(Math.max(v, lo), hi);

const formatStamp = (unix: number): string =>
  new Date(unix * 1000).toLocaleString([], {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });

/** Unix seconds → a `datetime-local` input value (`YYYY-MM-DDTHH:mm`) in local
 * time, so the picker opens on the bound the caption shows. */
const toDatetimeLocal = (unix: number): string => {
  const d = new Date(unix * 1000);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
};

/** Usage metric a rail bar can represent — matched to what the attached
 * chart(s) plot, so bars with only *unrelated* activity can be greyed out. */
export type SparkMetric = 'cost' | 'tokens' | 'requests';

interface SparkBars {
  /** Bars whose bucket has a value for one of the rail's relevant metrics. */
  relevant: string;
  /** Bars with activity but no value for any relevant metric — drawn muted so
   * the rail never implies the attached chart should show data it can't. */
  muted: string;
}

/** Build discrete vertical bars (one per bucket) in a 0..100 viewBox, split into
 * `relevant` bars (the bucket has a value for a metric the attached chart plots)
 * and `muted` bars (the bucket has only *other* activity — e.g. request counts
 * under a cost chart). A bar overview — not a connected line — so sparse spend
 * shows as spikes at the real event times instead of a misleading diagonal ramp
 * drawn between two far-apart points across otherwise-empty time. */
function buildSparkBars(
  points: SeriesPoint[],
  domainStart: number,
  domainSecs: number,
  relevantMetrics: SparkMetric[]
): SparkBars {
  if (points.length === 0) return { relevant: '', muted: '' };
  // Per-metric peak, so a relevant bar's height is its fraction of the tallest
  // bucket in whichever relevant metric it scores highest.
  const maxByMetric: Record<SparkMetric, number> = {
    cost: Math.max(...points.map(p => p.cost), 0),
    tokens: Math.max(...points.map(p => p.tokens), 0),
    requests: Math.max(...points.map(p => p.requests), 0),
  };
  const relevantSegs: string[] = [];
  const mutedSegs: string[] = [];
  for (const p of points) {
    if (!(p.cost > 0 || p.tokens > 0 || p.requests > 0)) continue; // no activity
    const x = clamp(((p.t - domainStart) / domainSecs) * 100, 0, 100);
    const isRelevant = relevantMetrics.some(m => p[m] > 0);
    if (isRelevant) {
      // Peak fraction across the relevant metrics: a bar reads tall if it is
      // high in ANY metric the attached chart plots. Floored at MIN_BAR_UNITS so
      // a tiny value still shows as a visible tick.
      const frac = Math.max(
        0,
        ...relevantMetrics.map(m => (maxByMetric[m] > 0 ? p[m] / maxByMetric[m] : 0))
      );
      const height = MIN_BAR_UNITS + frac * (96 - MIN_BAR_UNITS);
      relevantSegs.push(`M${x.toFixed(2)},100 L${x.toFixed(2)},${(100 - height).toFixed(2)}`);
    } else {
      // Activity present but irrelevant to the attached chart — a short grey tick.
      mutedSegs.push(`M${x.toFixed(2)},100 L${x.toFixed(2)},${(100 - MIN_BAR_UNITS).toFixed(2)}`);
    }
  }
  return { relevant: relevantSegs.join(' '), muted: mutedSegs.join(' ') };
}

/**
 * Drag gadget for the usage charts: an overview rail showing the primary series
 * across a wide context, with a draggable/resizable selection window over it.
 * Grab the middle to pan the window, grab an edge to resize it (which is the
 * zoom — a narrower window auto-fetches finer buckets), or click empty rail to
 * jump there. Preset chips quick-jump the width; the caption reads the live
 * bounds and the resolution the store served. Shared by the dashboard, team, and
 * member usage views.
 */
const TimeRangeScrubber: React.FC<TimeRangeScrubberProps> = ({
  windowSecs,
  endOffsetSecs,
  domainSecs,
  overview,
  relevantMetrics = ['cost'],
  resolution,
  loading,
  resolutionPref,
  onResolution,
  zoom,
  onZoom,
  onPreset,
  onWindowChange,
  onWindowCommit,
  onLive,
}) => {
  const viewportRef = useRef<HTMLDivElement>(null);
  const railRef = useRef<HTMLDivElement>(null);
  const dragRef = useRef<DragState | null>(null);
  const effectiveZoom = clampZoom(zoom ?? ZOOM_DEFAULT);
  const zoomEnabled = typeof onZoom === 'function';
  // Track the visible slice of the zoomed rail so we can pin the start/end
  // handles to the viewport edges when the true selection edge scrolls off
  // screen — the handles must always be reachable no matter how far the user
  // zooms in.
  const [scrollLeft, setScrollLeft] = useState(0);
  const [viewportWidth, setViewportWidth] = useState(0);
  // One ordered flow of preset chips: the fixed widths up to 30D, then the
  // calendar presets (MTD, then each month back to January), then 1Y last. The
  // calendar bounds shift only by date, so computing once per mount suffices.
  const presets = useMemo<RangePreset[]>(() => {
    const oneYear = RANGE_PRESETS.filter(p => p.label === '1Y');
    const upTo30D = RANGE_PRESETS.filter(p => p.label !== '1Y');
    return [...upTo30D, ...buildCalendarPresets(), ...oneYear];
  }, []);
  // While a drag is in progress the reference "now" is frozen so the data bars
  // and the un-dragged edge stay put under the cursor; without this, the live
  // clock advancing across the drag's many re-renders makes the whole rail
  // (bars included) creep, which reads as data "moving by itself".
  const [dragNow, setDragNow] = useState<number | null>(null);
  // Which bound (if any) is being edited via the date/time popover.
  const [editing, setEditing] = useState<null | 'start' | 'end'>(null);
  const [editValue, setEditValue] = useState('');

  const now = dragNow ?? Math.floor(Date.now() / 1000);
  const domainStart = now - domainSecs;
  const winTo = now - endOffsetSecs;
  const winFrom = winTo - windowSecs;

  const leftPct = clamp(((winFrom - domainStart) / domainSecs) * 100, 0, 100);
  const rightPct = clamp(((winTo - domainStart) / domainSecs) * 100, 0, 100);
  const widthPct = Math.max(rightPct - leftPct, 1.2);
  const isLive = endOffsetSecs <= 0;
  // A drag re-renders on every pointer move, but `domainStart`/`domainSecs` are
  // frozen for the drag (see `dragNow`) and `overview` only changes on commit,
  // so the bars are identical every frame. Memoise them — recomputing across
  // thousands of buckets (e.g. 1 day of 30s buckets) each move is what makes the
  // scrubber feel jumpy. `metricsKey` gives a stable dep for the metrics array.
  const metricsKey = relevantMetrics.join(',');
  const bars = useMemo(
    () => buildSparkBars(overview, domainStart, domainSecs, relevantMetrics),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [overview, domainStart, domainSecs, metricsKey]
  );

  // When the zoom factor changes, recenter the viewport on the selection window
  // so the user isn't left staring at empty rail after zooming in. Runs only on
  // zoom transitions (not on drag), so panning the window doesn't fight the
  // scrollbar.
  useEffect(() => {
    const viewport = viewportRef.current;
    const rail = railRef.current;
    if (!viewport || !rail) return;
    const railWidth = rail.getBoundingClientRect().width;
    const viewportWidth = viewport.getBoundingClientRect().width;
    if (railWidth <= viewportWidth) {
      viewport.scrollLeft = 0;
      return;
    }
    const centrePx = ((leftPct + widthPct / 2) / 100) * railWidth;
    viewport.scrollLeft = clamp(centrePx - viewportWidth / 2, 0, railWidth - viewportWidth);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [effectiveZoom]);

  // Track the viewport's current scroll offset and rendered width so we can
  // decide, on every render, whether the selection's start/end edge is
  // currently visible or has scrolled off screen (and needs a pinned handle).
  useEffect(() => {
    const viewport = viewportRef.current;
    if (!viewport) return;
    const readSize = () => setViewportWidth(viewport.getBoundingClientRect().width);
    const readScroll = () => setScrollLeft(viewport.scrollLeft);
    readSize();
    readScroll();
    viewport.addEventListener('scroll', readScroll, { passive: true });
    const ro = new ResizeObserver(readSize);
    ro.observe(viewport);
    return () => {
      viewport.removeEventListener('scroll', readScroll);
      ro.disconnect();
    };
  }, []);

  // Compute where each selection edge sits inside the (potentially zoomed and
  // scrolled) rail, and whether it is currently outside the viewport. The
  // pinned red handles below are rendered only when the true edge is off-screen.
  const railWidthPx = viewportWidth * effectiveZoom;
  const leftEdgePx = (leftPct / 100) * railWidthPx;
  const rightEdgePx = (rightPct / 100) * railWidthPx;
  const viewportRight = scrollLeft + viewportWidth;
  // A 0.5px epsilon avoids flickering the pinned handle on rounding at 1×.
  const startOffLeft = viewportWidth > 0 && leftEdgePx < scrollLeft - 0.5;
  const startOffRight = viewportWidth > 0 && leftEdgePx > viewportRight + 0.5;
  const endOffLeft = viewportWidth > 0 && rightEdgePx < scrollLeft - 0.5;
  const endOffRight = viewportWidth > 0 && rightEdgePx > viewportRight + 0.5;
  const startConstrained = startOffLeft || startOffRight;
  const endConstrained = endOffLeft || endOffRight;

  // Open the date/time popover for a bound, pre-filled with its current value.
  const beginEdit = (which: 'start' | 'end') => {
    setEditValue(toDatetimeLocal(which === 'start' ? winFrom : winTo));
    setEditing(which);
  };

  // Apply the picked date/time. Editing the **start** keeps the end fixed and
  // resizes the window; editing the **end** keeps the start fixed and re-pans it.
  // Both go through `onPreset` so the rail domain is re-derived and committed in
  // one step (same path as a preset chip), reusing its clamping.
  const applyEdit = () => {
    const parsed = Date.parse(editValue);
    if (!Number.isFinite(parsed)) {
      setEditing(null);
      return;
    }
    const picked = Math.floor(parsed / 1000);
    const nowSecs = Math.floor(Date.now() / 1000);
    if (editing === 'start') {
      const secs = Math.max(MIN_WINDOW_SECS, winTo - picked);
      onPreset({ label: 'custom', secs, endOffset: endOffsetSecs });
    } else if (editing === 'end') {
      const endOffset = Math.max(0, nowSecs - picked);
      const secs = Math.max(MIN_WINDOW_SECS, picked - winFrom);
      onPreset({ label: 'custom', secs, endOffset });
    }
    setEditing(null);
  };

  const beginDrag = (mode: DragMode) => (e: React.PointerEvent) => {
    const rail = railRef.current;
    if (!rail) return;
    e.preventDefault();
    rail.setPointerCapture(e.pointerId);
    setDragNow(Math.floor(Date.now() / 1000));
    dragRef.current = {
      mode,
      startX: e.clientX,
      railWidth: rail.getBoundingClientRect().width,
      startWindow: windowSecs,
      startOffset: endOffsetSecs,
    };
  };

  // Same as `beginDrag` but captures on the sibling handle itself, so it works
  // for the pinned red edge handles that live outside the scrolling rail. The
  // rail's bounding-rect width still represents `domainSecs`, so the delta math
  // in `onPointerMove` stays correct. On pointerdown the edge snaps to the
  // mouse position (in rail time) so a drag starting at the pinned handle moves
  // the edge under the cursor immediately — otherwise a small drag from the
  // viewport edge would still be relative to the off-screen true edge and the
  // window would appear unresponsive.
  const beginConstrainedDrag =
    (mode: 'left' | 'right') => (e: React.PointerEvent<HTMLDivElement>) => {
      const rail = railRef.current;
      if (!rail) return;
      e.preventDefault();
      e.stopPropagation();
      e.currentTarget.setPointerCapture(e.pointerId);
      setDragNow(Math.floor(Date.now() / 1000));
      const rect = rail.getBoundingClientRect();
      const frac = clamp((e.clientX - rect.left) / rect.width, 0, 1);
      const mouseTime = domainStart + frac * domainSecs;
      let newWindow = windowSecs;
      let newOffset = endOffsetSecs;
      if (mode === 'left') {
        newWindow = clamp(winTo - mouseTime, MIN_WINDOW_SECS, domainSecs - endOffsetSecs);
      } else {
        newOffset = clamp(now - mouseTime, 0, domainSecs - MIN_WINDOW_SECS);
        newWindow = clamp(mouseTime - winFrom, MIN_WINDOW_SECS, domainSecs - newOffset);
      }
      onWindowChange(newWindow, newOffset);
      dragRef.current = {
        mode,
        startX: e.clientX,
        railWidth: rect.width,
        startWindow: newWindow,
        startOffset: newOffset,
      };
    };

  const onRailPointerDown = (e: React.PointerEvent) => {
    // When zoomed in, dragging outside the selection window pans the scrubber
    // track horizontally (scrolls the viewport). When zoomed out or clicking
    // on the selection, jumps the window or starts a move/resize.
    const rail = railRef.current;
    const viewport = viewportRef.current;
    if (!rail || !viewport) return;
    const rect = rail.getBoundingClientRect();
    const frac = clamp((e.clientX - rect.left) / rect.width, 0, 1);
    const clickTime = domainStart + frac * domainSecs;
    const isInsideWindow = clickTime >= winFrom && clickTime <= winTo;

    // If zoomed in and clicking outside the window, start a pan (scroll).
    if (effectiveZoom > 1 && !isInsideWindow) {
      rail.setPointerCapture(e.pointerId);
      setDragNow(now);
      dragRef.current = {
        mode: 'pan',
        startX: e.clientX,
        railWidth: rect.width,
        startWindow: windowSecs,
        startOffset: endOffsetSecs,
        startScrollLeft: viewport.scrollLeft,
      };
      return;
    }

    // Otherwise, normal behavior: jump the window to center on the click,
    // then continue as a move-drag.
    const desiredTo = clickTime + windowSecs / 2;
    const off = clamp(now - desiredTo, 0, domainSecs - windowSecs);
    onWindowChange(windowSecs, off);
    rail.setPointerCapture(e.pointerId);
    setDragNow(now);
    dragRef.current = {
      mode: 'move',
      startX: e.clientX,
      railWidth: rect.width,
      startWindow: windowSecs,
      startOffset: off,
    };
  };

  const onPointerMove = (e: React.PointerEvent) => {
    const d = dragRef.current;
    if (!d) return;
    const viewport = viewportRef.current;
    if (!viewport) return;

    if (d.mode === 'pan') {
      // Dragging on empty rail when zoomed: scroll the viewport horizontally.
      // The rail width is `viewportWidth * effectiveZoom`, and moving the mouse
      // by a pixel should scroll the viewport proportionally.
      const dxPx = e.clientX - d.startX;
      const newScrollLeft = clamp((d.startScrollLeft ?? 0) - dxPx, 0, d.railWidth - viewportWidth);
      viewport.scrollLeft = newScrollLeft;
      return;
    }

    const dxSecs = ((e.clientX - d.startX) / d.railWidth) * domainSecs;
    if (d.mode === 'move') {
      const off = clamp(d.startOffset - dxSecs, 0, domainSecs - d.startWindow);
      onWindowChange(d.startWindow, off);
    } else if (d.mode === 'left') {
      const win = clamp(d.startWindow - dxSecs, MIN_WINDOW_SECS, domainSecs - d.startOffset);
      onWindowChange(win, d.startOffset);
    } else {
      const off = clamp(d.startOffset - dxSecs, 0, domainSecs - MIN_WINDOW_SECS);
      const win = clamp(d.startWindow + (d.startOffset - off), MIN_WINDOW_SECS, domainSecs - off);
      onWindowChange(win, off);
    }
  };

  const endDrag = () => {
    if (!dragRef.current) return;
    dragRef.current = null;
    setDragNow(null);
    if (endOffsetSecs > 0 && endOffsetSecs < domainSecs * LIVE_SNAP_FRACTION) {
      onWindowChange(windowSecs, 0);
    }
    onWindowCommit();
  };

  return (
    <div className="mb-3">
      <div className="d-flex flex-wrap align-items-center justify-content-between gap-2 mb-2">
        <div
          className="btn-group btn-group-sm time-range-presets"
          role="group"
          aria-label="Quick ranges"
        >
          {presets.map(p => (
            <button
              key={p.label}
              type="button"
              className="btn btn-outline-primary range-preset-btn"
              onClick={e => {
                e.currentTarget.blur();
                onPreset(p);
              }}
            >
              {p.label}
            </button>
          ))}
          <button
            type="button"
            className={`btn ${isLive ? 'btn-success' : 'btn-outline-success'} ms-2`}
            onClick={onLive}
            disabled={isLive}
            title="Snap the window to now"
          >
            <i className="fas fa-circle me-1" style={{ fontSize: '0.5rem' }}></i>Live
          </button>
        </div>
        <span className="text-muted small d-flex align-items-center gap-2">
          {loading && (
            <span
              className="spinner-border spinner-border-sm"
              role="status"
              aria-hidden="true"
            ></span>
          )}
          <span className="d-flex align-items-center gap-1">
            <i className="fas fa-layer-group"></i>
            {resolution !== '—' ? `${resolution} buckets` : '—'}
          </span>
          <select
            className="form-select form-select-sm"
            style={{ width: 'auto' }}
            value={resolutionPref}
            onChange={e => onResolution(e.target.value)}
            title="Bucket resolution. Auto picks a sensible default for the window; pick a tier to override."
            aria-label="Resolution"
          >
            {RESOLUTION_OPTIONS.map(o => {
              // Disable a tier that is absurd for the current window (too few or
              // too many buckets) so the user can't pick one that would just snap
              // back to Auto. `auto` always fits.
              const fits = forcedResolutionFits(o.value, windowSecs);
              return (
                <option key={o.value} value={o.value} disabled={!fits}>
                  {o.label}
                </option>
              );
            })}
          </select>
          {zoomEnabled && (
            <span
              className="d-flex align-items-center gap-1"
              title="Horizontal zoom for the scrubber rail. Stretches the rail wider so bars thicken and the rail scrolls horizontally — does not change the time window it represents."
            >
              <i className="fas fa-search-plus" aria-hidden="true"></i>
              <input
                type="range"
                className="form-range"
                style={{ width: 90 }}
                min={ZOOM_MIN}
                max={ZOOM_MAX}
                step={ZOOM_STEP}
                value={effectiveZoom}
                onChange={e => onZoom?.(Number(e.target.value))}
                onDoubleClick={() => onZoom?.(ZOOM_DEFAULT)}
                aria-label="Scrubber zoom"
                data-testid="scrubber-zoom"
              />
              <span
                className="text-muted"
                style={{
                  minWidth: '2.5em',
                  textAlign: 'right',
                  fontVariantNumeric: 'tabular-nums',
                }}
              >
                {effectiveZoom.toFixed(1)}×
              </span>
            </span>
          )}
        </span>
      </div>

      <div className="position-relative">
        <div
          ref={viewportRef}
          className="rounded time-range-scrubber-viewport"
          style={{
            height: RAIL_HEIGHT,
            background: 'rgba(255,255,255,0.03)',
            border: '1px solid rgba(255,255,255,0.08)',
            overflowX: effectiveZoom > 1 ? 'scroll' : 'hidden',
            overflowY: 'hidden',
            touchAction: effectiveZoom > 1 ? 'pan-x' : 'none',
            scrollbarWidth: 'none',
            msOverflowStyle: 'none',
          }}
        >
          <div
            ref={railRef}
            className="position-relative"
            role="group"
            aria-label="Drag to select a time window"
            style={{
              height: '100%',
              width: `${effectiveZoom * 100}%`,
              minWidth: '100%',
              cursor: 'crosshair',
              touchAction: 'none',
              userSelect: 'none',
            }}
            onPointerDown={onRailPointerDown}
            onPointerMove={onPointerMove}
            onPointerUp={endDrag}
            onPointerCancel={endDrag}
          >
            <svg
              width="100%"
              height="100%"
              viewBox="0 0 100 100"
              preserveAspectRatio="none"
              style={{ position: 'absolute', inset: 0, pointerEvents: 'none' }}
            >
              {bars.muted && (
                <path
                  d={bars.muted}
                  fill="none"
                  stroke={UI_COLORS.neutralMuted}
                  strokeWidth={1.5}
                  strokeLinecap="round"
                  vectorEffect="non-scaling-stroke"
                  opacity={0.5}
                />
              )}
              {bars.relevant && (
                <path
                  d={bars.relevant}
                  fill="none"
                  stroke={UI_COLORS.success}
                  strokeWidth={1.5}
                  strokeLinecap="round"
                  vectorEffect="non-scaling-stroke"
                  opacity={0.85}
                />
              )}
            </svg>

            <div
              className="position-absolute top-0 h-100"
              onPointerDown={e => {
                e.stopPropagation();
                beginDrag('move')(e);
              }}
              style={{
                left: `${leftPct}%`,
                width: `${widthPct}%`,
                background: 'rgba(74,144,226,0.22)',
                borderLeft: `2px solid ${UI_COLORS.primary}`,
                borderRight: `2px solid ${UI_COLORS.primary}`,
                cursor: 'grab',
              }}
            >
              <span
                onPointerDown={e => {
                  e.stopPropagation();
                  beginDrag('left')(e);
                }}
                style={{
                  position: 'absolute',
                  left: -5,
                  top: 0,
                  width: 10,
                  height: '100%',
                  cursor: 'ew-resize',
                }}
              />
              <span
                onPointerDown={e => {
                  e.stopPropagation();
                  beginDrag('right')(e);
                }}
                style={{
                  position: 'absolute',
                  right: -5,
                  top: 0,
                  width: 10,
                  height: '100%',
                  cursor: 'ew-resize',
                }}
              />
            </div>

            {isLive && (
              <span
                className="badge bg-success position-absolute"
                style={{ right: 4, top: 4, pointerEvents: 'none', fontSize: '0.6rem' }}
              >
                LIVE
              </span>
            )}
          </div>
        </div>

        {startConstrained && (
          <div
            onPointerDown={beginConstrainedDrag('left')}
            onPointerMove={onPointerMove}
            onPointerUp={endDrag}
            onPointerCancel={endDrag}
            title={`Start of window is off-screen (${startOffLeft ? 'left' : 'right'}). Drag to resize the window.`}
            aria-label="Selection start (constrained)"
            data-testid="scrubber-start-constrained"
            style={{
              position: 'absolute',
              top: 0,
              [startOffLeft ? 'left' : 'right']: 0,
              width: 3,
              height: RAIL_HEIGHT,
              background: UI_COLORS.danger,
              cursor: 'ew-resize',
              zIndex: 3,
              touchAction: 'none',
              boxShadow: '0 0 6px rgba(239,68,68,0.6)',
            }}
          />
        )}
        {endConstrained && (
          <div
            onPointerDown={beginConstrainedDrag('right')}
            onPointerMove={onPointerMove}
            onPointerUp={endDrag}
            onPointerCancel={endDrag}
            title={`End of window is off-screen (${endOffLeft ? 'left' : 'right'}). Drag to resize the window.`}
            aria-label="Selection end (constrained)"
            data-testid="scrubber-end-constrained"
            style={{
              position: 'absolute',
              top: 0,
              [endOffLeft ? 'left' : 'right']: 0,
              width: 3,
              height: RAIL_HEIGHT,
              background: UI_COLORS.danger,
              cursor: 'ew-resize',
              zIndex: 3,
              touchAction: 'none',
              boxShadow: '0 0 6px rgba(239,68,68,0.6)',
            }}
          />
        )}
      </div>

      <div className="d-flex justify-content-between align-items-center text-muted small mt-1 position-relative">
        <button
          type="button"
          className="btn btn-link btn-sm p-0 text-muted text-decoration-none scrubber-bound"
          title="Click to set the start date & time"
          onClick={() => beginEdit('start')}
          data-testid="scrubber-edit-start"
        >
          {formatStamp(winFrom)}
        </button>
        <span className="fw-semibold" title="Selected time span">
          {formatDuration(windowSecs)}
        </span>
        <button
          type="button"
          className="btn btn-link btn-sm p-0 text-muted text-decoration-none scrubber-bound"
          title="Click to set the end date & time"
          onClick={() => beginEdit('end')}
          data-testid="scrubber-edit-end"
        >
          {formatStamp(winTo)}
        </button>

        {editing && (
          <>
            <div
              className="position-fixed top-0 start-0 w-100 h-100"
              style={{ zIndex: 1040 }}
              onClick={() => setEditing(null)}
            />
            <div
              className="position-absolute card shadow-sm"
              style={{
                zIndex: 1050,
                top: 'calc(100% + 4px)',
                [editing === 'start' ? 'left' : 'right']: 0,
                minWidth: 240,
              }}
              data-testid="scrubber-datetime-popover"
            >
              <div className="card-body p-2">
                <label className="form-label small mb-1">
                  {editing === 'start' ? 'Start' : 'End'} date &amp; time
                </label>
                <input
                  type="datetime-local"
                  className="form-control form-control-sm mb-2"
                  value={editValue}
                  autoFocus
                  onChange={e => setEditValue(e.target.value)}
                  onKeyDown={e => {
                    if (e.key === 'Enter') applyEdit();
                    if (e.key === 'Escape') setEditing(null);
                  }}
                  data-testid="scrubber-datetime-input"
                />
                <div className="d-flex gap-2 justify-content-end">
                  <button
                    type="button"
                    className="btn btn-sm btn-outline-secondary"
                    onClick={() => setEditing(null)}
                    data-testid="scrubber-datetime-cancel"
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    className="btn btn-sm btn-primary"
                    onClick={applyEdit}
                    data-testid="scrubber-datetime-apply"
                  >
                    Apply
                  </button>
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
};

export default TimeRangeScrubber;
