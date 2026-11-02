import React from 'react';
import { createPortal } from 'react-dom';
import { Link } from 'react-router-dom';
import DriftRunVerdicts from './DriftRunVerdicts';
import RunSampleList from './RunSampleList';
import type { DriftDimensionInfo, DriftRun, DriftSurface } from './types';
import {
  RUN_STATUS_TONE,
  qualityTone,
  runFailureGuidance,
  surfaceNameById,
  triggerMeta,
} from './driftRunHistoryHelpers';
import { formatDateTime } from '../../utils/stringUtils';

interface DriftRunDetailPanelProps {
  run: DriftRun | null;
  surfaces: DriftSurface[];
  dimensions: DriftDimensionInfo[];
  canManage: boolean;
  onClose: () => void;
}

/** One labelled cell of the summary grid. */
const Cell: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
  <div className="drift-detail-cell">
    <dt>{label}</dt>
    <dd>{children}</dd>
  </div>
);

/**
 * Right-side slide-over that shows a single evaluation run's full detail: a
 * summary grid (status, trigger, quality, pass count, semantic distance, plus
 * the source-data surface for an experiment), any failure reason with actionable
 * recourse, the per-dimension verdict against the surface's baseline, and every
 * replayed record. Opens when a history row is clicked; the backdrop or the
 * close button dismisses it.
 */
const DriftRunDetailPanel: React.FC<DriftRunDetailPanelProps> = ({
  run,
  surfaces,
  dimensions,
  canManage,
  onClose,
}) => {
  if (!run) return null;
  const guidance = runFailureGuidance(run);
  // An experiment replays a surface's captured data through a different surface
  // or variant; the panel is headed by the surface being evaluated (the target),
  // with the source of the replayed data shown separately.
  const isExperiment = !!(run.target_surface_id || run.variant);
  const evaluatedId = run.target_surface_id ?? run.surface_id;
  const evaluatedName = surfaceNameById(evaluatedId, surfaces);
  const sourceName = surfaceNameById(run.surface_id, surfaces);

  // Portal to <body>: the drawer is fixed-positioned, but the glassmorphism
  // card ancestors use backdrop-filter/transform, which would otherwise make
  // `position: fixed` resolve against the card (breaking the 100vh height and
  // the body scroll). Rendering at the document root escapes that.
  return createPortal(
    <>
      <div className="drift-drawer-backdrop" onClick={onClose} aria-hidden="true" />
      <aside
        className="drift-drawer"
        role="region"
        aria-label="Evaluation run details"
        data-testid="drift-run-detail-panel"
      >
        <div className="drift-drawer-header">
          <div className="drift-drawer-heading">
            <div className="drift-drawer-eyebrow">
              <i className="fas fa-clock-rotate-left text-primary" aria-hidden="true" />
              <span>Evaluation run</span>
              {isExperiment && (
                <span
                  className="badge text-bg-warning"
                  title="Experiment — ran a surface's captured data through a different surface / variant"
                >
                  Experiment
                </span>
              )}
            </div>
            <h2 className="drift-drawer-title">
              {evaluatedName}
              {run.variant ? ` → ${run.variant}` : ''}
            </h2>
            <div className="drift-drawer-sub">
              <code className="drift-drawer-id" title={evaluatedId}>
                {evaluatedId}
              </code>
            </div>
            <div className="drift-drawer-sub text-muted">{formatDateTime(run.ran_at, true)}</div>
          </div>
          <button
            type="button"
            className="btn-close drift-drawer-close"
            aria-label="Close"
            onClick={onClose}
            data-testid="drift-run-detail-close"
          />
        </div>

        <div className="drift-drawer-body">
          <dl className="drift-detail-grid">
            <Cell label="Status">
              <span
                className={`badge text-bg-${RUN_STATUS_TONE[run.status] ?? 'secondary'} text-capitalize`}
              >
                {run.status}
              </span>
            </Cell>
            <Cell label="Trigger">
              <i className={`fas ${triggerMeta(run.trigger).icon} me-1`} aria-hidden="true" />
              {triggerMeta(run.trigger).label}
            </Cell>
            <Cell label="Quality">
              <span className={`badge text-bg-${qualityTone(run.quality)}`}>
                {(run.quality * 100).toFixed(0)}%
              </span>
            </Cell>
            <Cell label="Passed">
              {run.passed}/{run.total}
            </Cell>
            {run.semantic_distance != null && (
              <Cell label="Semantic distance">{run.semantic_distance.toFixed(3)}</Cell>
            )}
            {isExperiment && <Cell label="Source data from Surface">{sourceName}</Cell>}
          </dl>

          {guidance && (
            <div
              className={`alert alert-${guidance.tone} py-2 px-3 small mb-3`}
              role="alert"
              data-testid="drift-run-failure"
            >
              <div className="fw-semibold mb-1">
                <i className="fas fa-triangle-exclamation me-1" aria-hidden="true" />
                {guidance.reason}
              </div>
              <div>{guidance.recourse}</div>
            </div>
          )}

          <DriftRunVerdicts run={run} surfaces={surfaces} dimensions={dimensions} />

          <details className="drift-records">
            <summary className="drift-drawer-section drift-records-summary">
              Replayed records ({run.samples.length})
            </summary>
            {run.samples.length > 0 ? (
              <div className="drift-records-scroll">
                <RunSampleList samples={run.samples} />
              </div>
            ) : (
              <p className="small text-muted mb-0 mt-2">
                No per-record outcomes were captured for this run.
              </p>
            )}
          </details>
        </div>

        {canManage && (
          <div className="drift-drawer-footer">
            <Link
              to={`/llm/${run.surface_id}`}
              className="btn btn-sm btn-outline-primary"
              data-testid="drift-run-detail-schedule"
              title="Open this surface to enable or change its automatic drift evaluation schedule"
            >
              <i className="fas fa-calendar-alt me-1" aria-hidden="true" />
              Open surface &amp; schedule
            </Link>
          </div>
        )}
      </aside>
    </>,
    document.body
  );
};

export default DriftRunDetailPanel;
