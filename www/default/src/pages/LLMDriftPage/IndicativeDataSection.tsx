import React, { useEffect, useState } from 'react';
import EvalComparison from './EvalComparison';
import EvalRunStatus from './EvalRunStatus';
import ReplayControls from './ReplayControls';
import { useDriftSessions } from './useDriftSessions';
import { type DriftDimensionInfo, type DriftSurface } from './types';

interface IndicativeDataSectionProps {
  surfaceId: string;
  surfaces: DriftSurface[];
  canManage: boolean;
  onRan: () => void;
  dimensions: DriftDimensionInfo[];
}

/**
 * The replay-evaluation panel for the selected surface: shows how many records
 * it has captured (the "indicative surface data"), lets an operator replay them
 * — optionally pulling in a **different surface's** records and/or running them
 * through a **different surface / variant** to A/B a change without disturbing
 * the baseline. Backed by `/drift/sessions` + `/drift/eval/run`; the run history
 * lives on its own History tab.
 */
const IndicativeDataSection: React.FC<IndicativeDataSectionProps> = ({
  surfaceId,
  surfaces,
  canManage,
  onRan,
  dimensions,
}) => {
  const [sourceId, setSourceId] = useState(surfaceId);
  const [targetSurfaceId, setTargetSurfaceId] = useState(surfaceId);
  const [targetVariant, setTargetVariant] = useState('');
  const data = useDriftSessions(sourceId, onRan);

  // Reset selections when the page surface changes.
  useEffect(() => {
    setSourceId(surfaceId);
    setTargetSurfaceId(surfaceId);
    setTargetVariant('');
  }, [surfaceId]);

  const recordCount = data.sessions.length;
  const isExperiment = targetSurfaceId !== sourceId || targetVariant !== '';

  const handleRun = () => {
    if (!isExperiment) return data.runEval();
    return data.runEval({ targetSurfaceId, variant: targetVariant || undefined });
  };

  return (
    <div className="card shadow drift-card" data-testid="drift-indicative">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-database me-1" aria-hidden="true" /> Indicative surface data
          <span className="badge text-bg-secondary ms-2" data-testid="drift-session-count">
            {recordCount}
          </span>
        </h6>
      </div>
      <div className="card-body">
        <div
          className="alert alert-info d-flex gap-2 py-2 small mb-3"
          data-testid="drift-eval-help"
        >
          <i className="fas fa-circle-info mt-1 flex-shrink-0" aria-hidden="true" />
          <div>
            <strong>Replay evaluation</strong> measures how this surface's answers move over time.
            It has captured <strong data-testid="drift-record-count">{recordCount}</strong> recent
            prompt/response record{recordCount === 1 ? '' : 's'} automatically while drift
            monitoring is on (the records themselves aren't shown). Pick the{' '}
            <strong>source data</strong> to replay and the <strong>target surface</strong> /{' '}
            <strong>variant</strong> to run it through, then <strong>Run evaluation</strong>. Live
            progress appears below while it runs; the outcome — answer <strong>stability</strong>{' '}
            and <strong>semantic distance</strong> — shows underneath and is saved to the{' '}
            <strong>History</strong> tab. A plain self-run also updates the charts on the{' '}
            <strong>Drift over time</strong> tab.
          </div>
        </div>

        {canManage && (
          <ReplayControls
            surfaces={surfaces}
            sourceId={sourceId}
            onSourceChange={setSourceId}
            targetSurfaceId={targetSurfaceId}
            onTargetSurfaceChange={id => {
              setTargetSurfaceId(id);
              setTargetVariant('');
            }}
            targetVariant={targetVariant}
            onTargetVariantChange={setTargetVariant}
            recordCount={recordCount}
            running={data.running}
            onRun={handleRun}
          />
        )}

        {data.loading ? (
          <p className="small text-muted mb-0" data-testid="drift-session-loading">
            Loading captured records…
          </p>
        ) : recordCount === 0 ? (
          <p className="small text-muted mb-0" data-testid="drift-session-empty">
            No records captured yet. Send some traffic to this surface (with drift monitoring
            enabled) and it will be available to replay here.
          </p>
        ) : null}

        <EvalRunStatus
          runningRun={data.runningRun}
          lastResult={data.lastResult}
          onCancel={data.cancelRun}
        />

        {data.lastResult?.status === 'completed' && (
          <EvalComparison run={data.lastResult} surfaces={surfaces} dimensions={dimensions} />
        )}
      </div>
    </div>
  );
};

export default IndicativeDataSection;
