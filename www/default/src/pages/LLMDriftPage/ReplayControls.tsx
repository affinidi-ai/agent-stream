import React, { useMemo } from 'react';
import { AppButton } from '../../components/shared/AppButton';
import { targetVariantOptions } from './evalTargets';
import type { DriftSurface } from './types';

interface ReplayControlsProps {
  surfaces: DriftSurface[];
  sourceId: string;
  onSourceChange: (id: string) => void;
  targetSurfaceId: string;
  onTargetSurfaceChange: (id: string) => void;
  targetVariant: string;
  onTargetVariantChange: (alias: string) => void;
  recordCount: number;
  running: boolean;
  onRun: () => void;
}

/**
 * The replay-evaluation selectors: three cascading dropdowns — **source data**,
 * **target surface** (with a sync button between them that matches the target to
 * the source for a self-check), and **target variant** — the Run button, and a
 * live summary of exactly what a run will do. The variant dropdown is read-only
 * ("Base variant") when the target surface has no additional variants, and
 * updates as the target surface changes.
 */
const ReplayControls: React.FC<ReplayControlsProps> = ({
  surfaces,
  sourceId,
  onSourceChange,
  targetSurfaceId,
  onTargetSurfaceChange,
  targetVariant,
  onTargetVariantChange,
  recordCount,
  running,
  onRun,
}) => {
  const variantOptions = useMemo(
    () => targetVariantOptions(surfaces, targetSurfaceId),
    [surfaces, targetSurfaceId]
  );
  const hasVariants = variantOptions.length > 1;
  const isExperiment = targetSurfaceId !== sourceId || targetVariant !== '';
  const sourceName = surfaces.find(s => s.surface_id === sourceId)?.surface_name || sourceId;
  const targetName =
    surfaces.find(s => s.surface_id === targetSurfaceId)?.surface_name || targetSurfaceId;
  const variantLabel = variantOptions.find(o => o.value === targetVariant)?.label ?? 'Base variant';

  return (
    <div className="row g-2 align-items-end mb-3">
      <div className="col-12 col-md">
        <label htmlFor="drift-eval-source" className="form-label small mb-1">
          Surface Source Data to Replay
        </label>
        <select
          id="drift-eval-source"
          className="form-select form-select-sm"
          data-testid="drift-eval-source"
          value={sourceId}
          onChange={e => onSourceChange(e.target.value)}
        >
          {surfaces.map(s => (
            <option key={s.surface_id} value={s.surface_id}>
              {s.surface_name || s.surface_id}
            </option>
          ))}
        </select>
      </div>
      <div className="col-12 col-md-auto text-center">
        <button
          type="button"
          className="btn btn-outline-secondary btn-sm"
          data-testid="drift-eval-sync-target"
          title="Set the Evaluation Target Surface to match the source (a self-check)"
          aria-label="Set target surface to match source"
          disabled={targetSurfaceId === sourceId && targetVariant === ''}
          onClick={() => {
            onTargetSurfaceChange(sourceId);
            onTargetVariantChange('');
          }}
        >
          <i className="fas fa-angles-right" aria-hidden="true" />
        </button>
      </div>
      <div className="col-12 col-md">
        <label htmlFor="drift-eval-through" className="form-label small mb-1">
          Evaluation Target Surface
        </label>
        <select
          id="drift-eval-through"
          className="form-select form-select-sm"
          data-testid="drift-eval-through"
          value={targetSurfaceId}
          onChange={e => onTargetSurfaceChange(e.target.value)}
        >
          {surfaces.map(s => (
            <option key={s.surface_id} value={s.surface_id}>
              {s.surface_name || s.surface_id}
            </option>
          ))}
        </select>
      </div>
      <div className="col-12 col-md">
        <label htmlFor="drift-eval-variant" className="form-label small mb-1">
          Target Variant
        </label>
        <select
          id="drift-eval-variant"
          className="form-select form-select-sm"
          data-testid="drift-eval-variant"
          value={targetVariant}
          disabled={!hasVariants}
          title={hasVariants ? undefined : 'This surface has no variants beyond its base'}
          onChange={e => onTargetVariantChange(e.target.value)}
        >
          {variantOptions.map(o => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      </div>
      <div className="col-12 col-md-auto">
        <AppButton
          variant="primary"
          size="sm"
          className="w-100"
          loading={running}
          loadingLabel=" Replaying..."
          disabled={recordCount === 0}
          onClick={onRun}
          data-testid="drift-run-eval"
          iconStart={<i className="fas fa-play me-1" aria-hidden="true" />}
        >
          {isExperiment ? 'Run experiment' : 'Run evaluation'}
        </AppButton>
      </div>
      <div className="col-12">
        <p className="small mb-0" data-testid="drift-eval-summary">
          <i className="fas fa-arrow-right me-1 text-primary" aria-hidden="true" />
          {isExperiment ? (
            <>
              Replays <strong>{sourceName}</strong>&apos;s {recordCount} record
              {recordCount === 1 ? '' : 's'} through{' '}
              <strong>
                {targetName}
                {targetVariant ? ` (${variantLabel})` : ''}
              </strong>{' '}
              — an experiment, so {sourceName}&apos;s baseline stays unchanged.
            </>
          ) : (
            <>
              Re-checks <strong>{sourceName}</strong> against its own {recordCount} record
              {recordCount === 1 ? '' : 's'}. Change <strong>Evaluation Target Surface</strong> or{' '}
              <strong>Target Variant</strong> to replay these records through a different surface or
              variant.
            </>
          )}
        </p>
      </div>
    </div>
  );
};

export default ReplayControls;
