import { useCallback, useEffect, useMemo, useState } from 'react';
import { usePermissions } from '../../context/PermissionsContext';
import { showToast } from '../../utils/toaster';
import { fetchDriftSeries, fetchDriftSurfaces, pinDriftBaseline } from './driftApi';
import {
  DRIFT_RANGE_PRESETS,
  type DimensionVerdict,
  type DriftDimensionInfo,
  type DriftSeriesResponse,
  type DriftStatus,
  type DriftSurface,
  type SurfaceVerdict,
} from './types';

export interface UseDriftSeries {
  surfaces: DriftSurface[];
  dimensions: DriftDimensionInfo[];
  /** Latest fetched series, keyed by dimension id. */
  series: Record<string, DriftSeriesResponse>;
  selectedSurfaceId: string | null;
  rangeSecs: number;
  loadingSurfaces: boolean;
  loadingSeries: boolean;
  /** Per-dimension drift verdict for the current window, keyed by dimension id. */
  verdictByDim: Record<string, DimensionVerdict>;
  /** The surface's overall drift status for the current window. */
  overallStatus: DriftStatus;
  /** When the current baseline was pinned, if any. */
  baselineCapturedAt: string | null;
  /** Whether the caller may pin a baseline (`drift.manage`). */
  canManage: boolean;
  /** Whether a baseline capture is in flight. */
  capturing: boolean;
  /** Pin the current window as the surface's baseline. */
  captureBaseline: () => Promise<void>;
  selectSurface: (id: string) => void;
  setRangeSecs: (secs: number) => void;
  reload: () => void;
}

/** Default window: 24H. */
const DEFAULT_RANGE_SECS = DRIFT_RANGE_PRESETS[2].secs;

/**
 * Loads the drift dimensions and the drift-enabled surfaces, then the per-
 * dimension time-series + verdict for the selected surface over the selected
 * window. The `/drift/*` fetches live in `driftApi.ts`; this hook owns state,
 * effects, and the baseline action. Reads only the administrator-gated API.
 */
export function useDriftSeries(): UseDriftSeries {
  const [surfaces, setSurfaces] = useState<DriftSurface[]>([]);
  const [dimensions, setDimensions] = useState<DriftDimensionInfo[]>([]);
  const [series, setSeries] = useState<Record<string, DriftSeriesResponse>>({});
  const [selectedSurfaceId, setSelectedSurfaceId] = useState<string | null>(null);
  const [rangeSecs, setRangeSecs] = useState(DEFAULT_RANGE_SECS);
  const [loadingSurfaces, setLoadingSurfaces] = useState(false);
  const [loadingSeries, setLoadingSeries] = useState(false);
  const [verdict, setVerdict] = useState<SurfaceVerdict | null>(null);
  const [capturing, setCapturing] = useState(false);
  const { hasPermission } = usePermissions();
  const canManage = hasPermission('drift.manage');

  const loadSurfaces = useCallback(async () => {
    setLoadingSurfaces(true);
    try {
      const { dimensions: dims, surfaces: list } = await fetchDriftSurfaces();
      setDimensions(dims);
      setSurfaces(list);
      setSelectedSurfaceId(prev => prev ?? list[0]?.surface_id ?? null);
    } catch (error) {
      showToast('error', error instanceof Error ? error.message : 'Failed to load drift surfaces');
      setSurfaces([]);
    } finally {
      setLoadingSurfaces(false);
    }
  }, []);

  const loadSeries = useCallback(
    async (surfaceId: string, secs: number, dims: DriftDimensionInfo[]) => {
      if (dims.length === 0) return;
      setLoadingSeries(true);
      try {
        const { byDim, verdict: v } = await fetchDriftSeries(surfaceId, secs, dims);
        setSeries(byDim);
        setVerdict(v);
      } catch (error) {
        showToast('error', error instanceof Error ? error.message : 'Failed to load drift series');
        setSeries({});
        setVerdict(null);
      } finally {
        setLoadingSeries(false);
      }
    },
    []
  );

  useEffect(() => {
    loadSurfaces();
  }, [loadSurfaces]);

  useEffect(() => {
    if (selectedSurfaceId) {
      loadSeries(selectedSurfaceId, rangeSecs, dimensions);
    } else {
      setSeries({});
    }
  }, [selectedSurfaceId, rangeSecs, dimensions, loadSeries]);

  const reload = useCallback(() => {
    if (selectedSurfaceId) {
      loadSeries(selectedSurfaceId, rangeSecs, dimensions);
    }
  }, [selectedSurfaceId, rangeSecs, dimensions, loadSeries]);

  const captureBaseline = useCallback(async () => {
    if (!selectedSurfaceId) return;
    setCapturing(true);
    try {
      await pinDriftBaseline(selectedSurfaceId, rangeSecs);
      showToast('success', 'Baseline pinned to the current window');
      await loadSeries(selectedSurfaceId, rangeSecs, dimensions);
    } catch (error) {
      showToast('error', error instanceof Error ? error.message : 'Failed to pin baseline');
    } finally {
      setCapturing(false);
    }
  }, [selectedSurfaceId, rangeSecs, dimensions, loadSeries]);

  const verdictByDim = useMemo(() => {
    const out: Record<string, DimensionVerdict> = {};
    (verdict?.dimensions ?? []).forEach(v => {
      out[v.dimension] = v;
    });
    return out;
  }, [verdict]);

  return {
    surfaces,
    dimensions,
    series,
    selectedSurfaceId,
    rangeSecs,
    loadingSurfaces,
    loadingSeries,
    verdictByDim,
    overallStatus: verdict?.status ?? 'unknown',
    baselineCapturedAt: verdict?.baseline_captured_at ?? null,
    canManage,
    capturing,
    captureBaseline,
    selectSurface: setSelectedSurfaceId,
    setRangeSecs,
    reload,
  };
}
