import React from 'react';
import { AppButton } from '../../components/shared/AppButton';
import EvalResultView from './EvalResultView';
import type { DriftRun } from './types';

interface EvalRunStatusProps {
  /** The in-flight run (live progress), when one is replaying. */
  runningRun: DriftRun | null;
  /** The last terminal run (completed / failed / stopped / cancelled). */
  lastResult: DriftRun | null;
  onCancel: () => void;
}

/** Badge tone + label for a terminal run that produced no full result. */
const terminalMeta = (status: DriftRun['status']): { tone: string; label: string } => {
  switch (status) {
    case 'cancelled':
      return { tone: 'secondary', label: 'Cancelled' };
    case 'stopped':
      return { tone: 'warning', label: 'Stopped on cost' };
    default:
      return { tone: 'danger', label: 'Failed' };
  }
};

/**
 * Live progress + a Cancel control for an in-flight replay evaluation, or the
 * terminal outcome — a completed run's metrics ({@link EvalResultView}) or a
 * failed / stopped / cancelled run's reason note.
 */
const EvalRunStatus: React.FC<EvalRunStatusProps> = ({ runningRun, lastResult, onCancel }) => {
  if (runningRun) {
    const { total, progress_done: done } = runningRun;
    const known = total > 0;
    const pct = known ? Math.round((done / total) * 100) : 0;
    return (
      <div className="border-top mt-3 pt-3" data-testid="eval-run-progress">
        <div className="d-flex align-items-center justify-content-between mb-2">
          <span className="small fw-semibold">
            <i className="fas fa-spinner fa-spin me-1" aria-hidden="true" />{' '}
            {known ? `Replaying ${done}/${total}` : 'Starting evaluation…'}
          </span>
          <AppButton
            variant="outline-danger"
            size="sm"
            onClick={onCancel}
            data-testid="eval-run-cancel"
            iconStart={<i className="fas fa-stop me-1" aria-hidden="true" />}
          >
            Cancel
          </AppButton>
        </div>
        <div className="progress" style={{ height: 6 }}>
          <div
            className="progress-bar"
            role="progressbar"
            style={{ width: `${pct}%`, transition: 'width 0.3s ease' }}
            aria-valuenow={pct}
            aria-valuemin={0}
            aria-valuemax={100}
          />
        </div>
      </div>
    );
  }
  if (!lastResult) return null;
  if (lastResult.status === 'completed') return <EvalResultView result={lastResult} />;
  const { tone, label } = terminalMeta(lastResult.status);
  return (
    <div className={`alert alert-${tone} py-2 small mt-3`} data-testid="eval-run-terminal">
      <strong>{label}.</strong> {lastResult.failure_reason || ''}
      {lastResult.progress_done > 0 &&
        ` (${lastResult.progress_done}/${lastResult.total} replayed)`}
      {!!lastResult.cost_usd && (
        <span data-testid="eval-run-cost"> · ${lastResult.cost_usd.toFixed(4)} spent</span>
      )}
    </div>
  );
};

export default EvalRunStatus;
