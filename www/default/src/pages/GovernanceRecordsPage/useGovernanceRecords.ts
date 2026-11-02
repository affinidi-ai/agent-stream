import { useCallback, useEffect, useMemo, useState } from 'react';
import { apiClient } from '../../api';
import { showToast } from '../../utils/toaster';
import { RECORDS_LIMIT } from './governanceHelpers';
import type { ChainVerdict, StoredRecord, SurfaceSummary } from './types';

export interface UseGovernanceRecords {
  surfaces: SurfaceSummary[];
  records: StoredRecord[];
  verdict: ChainVerdict | null;
  selectedSurfaceId: string | null;
  selectedSurface: SurfaceSummary | null;
  loadingSurfaces: boolean;
  loadingRecords: boolean;
  verifying: boolean;
  selectSurface: (id: string) => void;
  reload: () => void;
  verify: () => Promise<void>;
}

/** Best-effort map of live surface id → {name, description} from `/pipes`, used
 * to enrich the governance surface picker with a human-readable description.
 * Tolerant of failure (returns an empty map) so the viewer still works. */
async function loadPipeMeta(): Promise<Map<string, { name?: string; description?: string }>> {
  try {
    const { data } =
      await apiClient.get<Array<{ id: string; name?: string; description?: string }>>('/pipes');
    const map = new Map<string, { name?: string; description?: string }>();
    (data ?? []).forEach(p => map.set(p.id, { name: p.name, description: p.description }));
    return map;
  } catch {
    return new Map();
  }
}

/** Loads the governance surfaces, then the signed records for the selected
 * surface, and runs an on-demand chain verification — mirroring the audit-log
 * fetch pattern (single `apiClient.get`, toast on failure). */
export function useGovernanceRecords(): UseGovernanceRecords {
  const [surfaces, setSurfaces] = useState<SurfaceSummary[]>([]);
  const [records, setRecords] = useState<StoredRecord[]>([]);
  const [verdict, setVerdict] = useState<ChainVerdict | null>(null);
  const [selectedSurfaceId, setSelectedSurfaceId] = useState<string | null>(null);
  const [loadingSurfaces, setLoadingSurfaces] = useState(false);
  const [loadingRecords, setLoadingRecords] = useState(false);
  const [verifying, setVerifying] = useState(false);

  const loadSurfaces = useCallback(async () => {
    setLoadingSurfaces(true);
    try {
      const [{ data }, pipeMeta] = await Promise.all([
        apiClient.get<SurfaceSummary[]>('/governance/surfaces'),
        loadPipeMeta(),
      ]);
      // Join the live surface config for a description (and a current name).
      const list: SurfaceSummary[] = (data ?? []).map(s => {
        const meta = pipeMeta.get(s.surface_id);
        return {
          surface_id: s.surface_id,
          surface_name: s.surface_name ?? meta?.name,
          surface_description: meta?.description,
        };
      });
      setSurfaces(list);
      setSelectedSurfaceId(prev => prev ?? list[0]?.surface_id ?? null);
    } catch (error) {
      showToast(
        'error',
        error instanceof Error ? error.message : 'Failed to load governance surfaces'
      );
      setSurfaces([]);
    } finally {
      setLoadingSurfaces(false);
    }
  }, []);

  const loadRecords = useCallback(async (surfaceId: string) => {
    setLoadingRecords(true);
    setVerdict(null);
    try {
      const params = new URLSearchParams({ surface_id: surfaceId, limit: String(RECORDS_LIMIT) });
      const { data } = await apiClient.get<StoredRecord[]>(
        `/governance/records?${params.toString()}`
      );
      // Newest first for display.
      setRecords((data ?? []).slice().reverse());
    } catch (error) {
      showToast(
        'error',
        error instanceof Error ? error.message : 'Failed to load governance records'
      );
      setRecords([]);
    } finally {
      setLoadingRecords(false);
    }
  }, []);

  const verify = useCallback(async () => {
    if (!selectedSurfaceId) return;
    setVerifying(true);
    try {
      const params = new URLSearchParams({ surface_id: selectedSurfaceId });
      const { data } = await apiClient.get<ChainVerdict>(`/governance/verify?${params.toString()}`);
      setVerdict(data);
      if (data.valid) {
        showToast(
          'success',
          `Chain valid — ${data.count} record${data.count === 1 ? '' : 's'} verified`
        );
      } else {
        showToast('error', `Chain verification failed: ${data.error ?? 'unknown error'}`);
      }
    } catch (error) {
      showToast('error', error instanceof Error ? error.message : 'Chain verification failed');
    } finally {
      setVerifying(false);
    }
  }, [selectedSurfaceId]);

  useEffect(() => {
    loadSurfaces();
  }, [loadSurfaces]);

  useEffect(() => {
    if (selectedSurfaceId) {
      loadRecords(selectedSurfaceId);
    } else {
      setRecords([]);
    }
  }, [selectedSurfaceId, loadRecords]);

  const selectSurface = useCallback((id: string) => setSelectedSurfaceId(id), []);
  const reload = useCallback(() => {
    if (selectedSurfaceId) loadRecords(selectedSurfaceId);
  }, [selectedSurfaceId, loadRecords]);

  const selectedSurface = useMemo(
    () => surfaces.find(s => s.surface_id === selectedSurfaceId) ?? null,
    [surfaces, selectedSurfaceId]
  );

  return {
    surfaces,
    records,
    verdict,
    selectedSurfaceId,
    selectedSurface,
    loadingSurfaces,
    loadingRecords,
    verifying,
    selectSurface,
    reload,
    verify,
  };
}
