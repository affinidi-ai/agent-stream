import { useCallback, useEffect, useRef, useState } from 'react';
import { apiClient } from '../../api';
import { showToast } from '../../utils/toaster';
import { cancelDriftRun, fetchDriftRun, startDriftEval } from './driftApi';
import { isTerminalRun, type DriftRun, type RecordedSession } from './types';

export interface RunEvalOpts {
  /** Run the source's sessions through this surface instead (experiment). */
  targetSurfaceId?: string;
  /** Run through this variant of the target (experiment). */
  variant?: string;
}

export interface UseDriftSessions {
  sessions: RecordedSession[];
  loading: boolean;
  running: boolean;
  /** The in-flight run (live progress) while an evaluation is replaying. */
  runningRun: DriftRun | null;
  /** The last terminal run (completed / failed / cancelled). */
  lastResult: DriftRun | null;
  runEval: (opts?: RunEvalOpts) => Promise<void>;
  cancelRun: () => Promise<void>;
  reload: () => void;
}

/** How often to poll an in-flight run for progress. */
const POLL_MS = 1500;

/** Toast + chart-refresh for a run that just reached a terminal state. */
function reportTerminal(run: DriftRun, onRan: () => void): void {
  if (run.status === 'completed') {
    showToast('success', `Replayed ${run.total} session${run.total === 1 ? '' : 's'}`);
    onRan();
  } else if (run.status === 'cancelled') {
    showToast('info', 'Evaluation cancelled');
  } else if (run.status === 'stopped') {
    showToast('warning', run.failure_reason || 'Evaluation stopped on cost');
  } else {
    showToast('error', run.failure_reason || 'Evaluation failed');
  }
}

/**
 * Loads a surface's captured "indicative" sessions (`GET /drift/sessions`) and
 * runs an on-demand replay evaluation **asynchronously**: `runEval` starts the
 * run (`POST /drift/eval/run`) and this hook polls `GET /drift/runs/{id}` for
 * live progress until it is terminal, exposing `cancelRun`. Optionally runs
 * through a different target surface / variant (an experiment). `onRan` refreshes
 * the page charts after a completed self-run folds fresh dimension points.
 */
export function useDriftSessions(surfaceId: string | null, onRan: () => void): UseDriftSessions {
  const [sessions, setSessions] = useState<RecordedSession[]>([]);
  const [loading, setLoading] = useState(false);
  const [runningRun, setRunningRun] = useState<DriftRun | null>(null);
  const [lastResult, setLastResult] = useState<DriftRun | null>(null);
  const runId = runningRun?.id ?? null;
  const onRanRef = useRef(onRan);
  onRanRef.current = onRan;

  const load = useCallback(async () => {
    if (!surfaceId) {
      setSessions([]);
      return;
    }
    setLoading(true);
    try {
      const { data } = await apiClient.get<RecordedSession[]>(
        `/drift/sessions?surface_id=${encodeURIComponent(surfaceId)}`
      );
      setSessions(data ?? []);
    } catch (error) {
      showToast(
        'error',
        error instanceof Error ? error.message : 'Failed to load captured sessions'
      );
      setSessions([]);
    } finally {
      setLoading(false);
    }
  }, [surfaceId]);

  useEffect(() => {
    setLastResult(null);
    setRunningRun(null);
    load();
  }, [load]);

  // Poll the in-flight run until it reaches a terminal state.
  useEffect(() => {
    if (!runId) return;
    let active = true;
    const tick = async () => {
      try {
        const run = await fetchDriftRun(runId);
        if (!active) return;
        if (isTerminalRun(run.status)) {
          setRunningRun(null);
          setLastResult(run);
          reportTerminal(run, onRanRef.current);
        } else {
          setRunningRun(run);
        }
      } catch {
        // Transient poll error — keep trying; the next tick recovers.
      }
    };
    const timer = window.setInterval(tick, POLL_MS);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [runId]);

  const runEval = useCallback(
    async (opts?: RunEvalOpts) => {
      if (!surfaceId || runId) return;
      setLastResult(null);
      try {
        const run = await startDriftEval(surfaceId, opts?.targetSurfaceId, opts?.variant);
        setRunningRun(run);
      } catch (error) {
        showToast('error', error instanceof Error ? error.message : 'Failed to start evaluation');
      }
    },
    [surfaceId, runId]
  );

  const cancelRun = useCallback(async () => {
    if (!runId) return;
    try {
      await cancelDriftRun(runId);
      showToast('info', 'Cancelling evaluation…');
    } catch (error) {
      showToast('error', error instanceof Error ? error.message : 'Failed to cancel');
    }
  }, [runId]);

  return {
    sessions,
    loading,
    running: runningRun !== null,
    runningRun,
    lastResult,
    runEval,
    cancelRun,
    reload: load,
  };
}
