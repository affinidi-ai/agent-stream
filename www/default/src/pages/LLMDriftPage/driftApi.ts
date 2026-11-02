import { apiClient } from '../../api';
import {
  driftSeriesKey,
  type DriftDimensionInfo,
  type DriftRun,
  type DriftSeriesResponse,
  type DriftSurface,
  type SurfaceVerdict,
} from './types';

/** Minimal `/pipes` row: the surfaces list is filtered to those with drift
 * monitoring enabled (drift is an LLM-surface-only concern). */
interface PipeListItem {
  id: string;
  name?: string;
  drift?: { enabled?: boolean } | null;
  variants?: { alias: string; name?: string; enabled?: boolean }[];
}

/** Fetch the drift dimensions and the drift-enabled surfaces in one round. */
export async function fetchDriftSurfaces(): Promise<{
  dimensions: DriftDimensionInfo[];
  surfaces: DriftSurface[];
}> {
  const [dimsRes, pipesRes] = await Promise.all([
    apiClient.get<DriftDimensionInfo[]>('/drift/dimensions'),
    apiClient.get<PipeListItem[]>('/pipes'),
  ]);
  const surfaces: DriftSurface[] = (pipesRes.data ?? [])
    .filter(p => p.drift?.enabled)
    .map(p => ({
      surface_id: p.id,
      surface_name: p.name,
      variants: (p.variants ?? [])
        .filter(v => v.enabled !== false)
        .map(v => ({ alias: v.alias, name: v.name })),
    }));
  return { dimensions: dimsRes.data ?? [], surfaces };
}

/** Fetch the per-dimension series (keyed by dimension id) + the surface verdict
 * for `surfaceId` over the trailing `secs` window. */
export async function fetchDriftSeries(
  surfaceId: string,
  secs: number,
  dims: DriftDimensionInfo[]
): Promise<{ byDim: Record<string, DriftSeriesResponse>; verdict: SurfaceVerdict | null }> {
  const to = Math.floor(Date.now() / 1000);
  const from = to - secs;
  const keys = dims.map(d => driftSeriesKey(surfaceId, d.id)).join(',');
  const params = new URLSearchParams({
    keys,
    from: String(from),
    to: String(to),
    max_points: '300',
    resolution: 'auto',
  });
  const verdictParams = new URLSearchParams({
    surface_id: surfaceId,
    from: String(from),
    to: String(to),
  });
  const [seriesRes, verdictRes] = await Promise.all([
    apiClient.get<DriftSeriesResponse[]>(`/drift/series?${params.toString()}`),
    apiClient.get<SurfaceVerdict>(`/drift/verdict?${verdictParams.toString()}`),
  ]);
  const byDim: Record<string, DriftSeriesResponse> = {};
  (seriesRes.data ?? []).forEach(s => {
    const dim = s.key.split(':').pop();
    if (dim) byDim[dim] = s;
  });
  return { byDim, verdict: verdictRes.data ?? null };
}

/** Pin the current window as the surface's drift baseline. */
export async function pinDriftBaseline(surfaceId: string, rangeSecs: number): Promise<void> {
  const params = new URLSearchParams({ surface_id: surfaceId, window_secs: String(rangeSecs) });
  await apiClient.post(`/drift/baseline?${params.toString()}`);
}

/** Start an async replay evaluation; returns the **running** run record to poll.
 * Optionally runs the source's sessions through a different target / variant. */
export async function startDriftEval(
  surfaceId: string,
  targetSurfaceId?: string,
  variant?: string
): Promise<DriftRun> {
  const params = new URLSearchParams({ surface_id: surfaceId });
  if (targetSurfaceId && targetSurfaceId !== surfaceId) {
    params.set('target_surface_id', targetSurfaceId);
  }
  if (variant) params.set('variant', variant);
  const { data } = await apiClient.post<DriftRun>(`/drift/eval/run?${params.toString()}`);
  return data;
}

/** Fetch one run: in-flight runs report live progress, finished ones the result. */
export async function fetchDriftRun(runId: string): Promise<DriftRun> {
  const { data } = await apiClient.get<DriftRun>(`/drift/runs/${encodeURIComponent(runId)}`);
  return data;
}

/** Request cancellation of an in-flight run (stops cleanly between sessions). */
export async function cancelDriftRun(runId: string): Promise<void> {
  await apiClient.post(`/drift/eval/cancel?run_id=${encodeURIComponent(runId)}`);
}
