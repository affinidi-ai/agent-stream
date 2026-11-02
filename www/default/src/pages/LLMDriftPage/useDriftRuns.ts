import { useCallback, useEffect, useState } from 'react';
import { apiClient } from '../../api';
import { showToast } from '../../utils/toaster';
import type { DriftRun } from './types';

export interface UseDriftRuns {
  runs: DriftRun[];
  loading: boolean;
  reload: () => void;
}

/**
 * Loads a surface's persisted evaluation-suite run history (`GET /drift/runs`),
 * newest first. `refreshKey` lets the parent force a reload after a run
 * completes so a fresh run appears without a manual refresh. `limit` caps the
 * cross-surface fetch (ignored by the backend when a `surfaceId` is given).
 */
export function useDriftRuns(
  surfaceId: string | null,
  refreshKey: number,
  limit?: number
): UseDriftRuns {
  const [runs, setRuns] = useState<DriftRun[]>([]);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      // No surface id ⇒ the most recent runs across all surfaces.
      const params = new URLSearchParams();
      if (surfaceId) params.set('surface_id', surfaceId);
      if (limit != null) params.set('limit', String(limit));
      const query = params.toString() ? `?${params.toString()}` : '';
      const { data } = await apiClient.get<DriftRun[]>(`/drift/runs${query}`);
      setRuns(data ?? []);
    } catch (error) {
      showToast('error', error instanceof Error ? error.message : 'Failed to load run history');
      setRuns([]);
    } finally {
      setLoading(false);
    }
  }, [surfaceId, limit]);

  useEffect(() => {
    load();
  }, [load, refreshKey]);

  return { runs, loading, reload: load };
}
