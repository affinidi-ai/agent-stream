import React from 'react';
import type { PipeTemplate } from '../../api';

export interface PipeStarterPickerProps {
  templates: PipeTemplate[];
  loading: boolean;
  error: string | null;
  applyingStarterId: string | null;
  expandedId: string | null;
  onToggleExpand: (id: string) => void;
  onApply: (tpl: PipeTemplate) => void;
  onCancel: () => void;
  onStartBlank: () => void;
}

/**
 * Brand-new-pipe starter picker (mirrors the New Surface flow). Picking a
 * template seeds the form and reveals the builder; "Start blank" skips to an
 * empty canvas. Presentational only — all state lives in the page.
 */
const PipeStarterPicker: React.FC<PipeStarterPickerProps> = ({
  templates,
  loading,
  error,
  applyingStarterId,
  expandedId,
  onToggleExpand,
  onApply,
  onCancel,
  onStartBlank,
}) => {
  return (
    <div className="container-fluid surface-page-fill surface-page-fill--picker">
      <div className="surface-canvas-protocol-picker">
        <div
          className="card shadow channel-editor-card surface-picker-card"
          role="dialog"
          aria-modal="true"
          aria-label="Pick a starter template for this LLM Surface"
        >
          <div className="card-header py-3 d-flex align-items-center">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-layer-group me-2"></i> Create new LLM Surface
            </h6>
          </div>
          <div className="card-body-channel-editor surface-picker-card__body">
            <p className="text-muted small mb-3">
              Select a Starter Template to begin designing your LLM interaction.
            </p>
            {loading ? (
              <div className="text-muted small">
                <span className="spinner-border spinner-border-sm me-2" />
                Loading starter templates…
              </div>
            ) : error ? (
              <div className="alert alert-danger py-2 px-3 small mb-0">
                <i className="fas fa-times-circle me-1" />
                {error}
              </div>
            ) : templates.length === 0 ? (
              <div className="text-muted small">
                No starter templates are installed. Ship one with <code>tags: ["starter"]</code>, or
                start blank below.
              </div>
            ) : (
              <ul className="list-unstyled mb-0">
                {templates.map(tpl => {
                  const applying = applyingStarterId === tpl.id;
                  const icon = tpl.icon ? `fa-${tpl.icon}` : 'fa-diagram-project';
                  const hasDetails = !!tpl.details && tpl.details.trim().length > 0;
                  const expanded = expandedId === tpl.id;
                  const toggle = () => {
                    if (!hasDetails) return;
                    onToggleExpand(tpl.id);
                  };
                  return (
                    <li key={tpl.id} className="surface-template-row surface-template-row--static">
                      <div
                        className="surface-template-row__header surface-template-row__header--static"
                        role={hasDetails ? 'button' : undefined}
                        tabIndex={hasDetails ? 0 : undefined}
                        aria-expanded={hasDetails ? expanded : undefined}
                        style={{ cursor: hasDetails ? 'pointer' : 'default' }}
                        onClick={toggle}
                        onKeyDown={e => {
                          if (!hasDetails) return;
                          if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault();
                            toggle();
                          }
                        }}
                      >
                        <i className={`fas ${icon} surface-template-row__icon`} />
                        <div className="flex-grow-1" style={{ minWidth: 0 }}>
                          <div className="surface-template-row__title">{tpl.name}</div>
                          {tpl.description && (
                            <div className="surface-template-row__description">
                              {tpl.description}
                            </div>
                          )}
                        </div>
                        <button
                          type="button"
                          className="btn btn-sm btn-primary surface-template-row__action"
                          disabled={applying}
                          aria-label={`Use template ${tpl.name}`}
                          title={`Use template ${tpl.name}`}
                          onClick={e => {
                            e.stopPropagation();
                            onApply(tpl);
                          }}
                        >
                          {applying ? (
                            <span className="spinner-border spinner-border-sm" />
                          ) : (
                            <i className="fas fa-arrow-right" />
                          )}
                        </button>
                        {hasDetails && (
                          <i
                            className={`fas fa-chevron-${expanded ? 'up' : 'down'} text-muted`}
                            style={{ fontSize: 11 }}
                          />
                        )}
                      </div>
                      {hasDetails && expanded && (
                        <div className="surface-template-row__body">
                          <div className="surface-template-row__details">{tpl.details}</div>
                        </div>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
          <div className="card-footer d-flex justify-content-between">
            <button type="button" className="btn btn-secondary btn-sm" onClick={onCancel}>
              Cancel
            </button>
            <button type="button" className="btn btn-outline-primary btn-sm" onClick={onStartBlank}>
              <i className="fas fa-file me-1" />
              Start blank
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PipeStarterPicker;
