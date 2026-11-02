import React from 'react';
import {
  DeciderConfig,
  MirrorConfig,
  SurfaceExecutionMode,
  DECIDER_MODE_OPTIONS,
  surfaceModeFromDecider,
  surfaceModeOption,
  modeToDeciderPatch,
  DEFAULT_DECIDER_PROMPT,
  DEFAULT_MERGE_PROMPT,
  makeDefaultMirrorConfig,
  makeDefaultDeciderLlm,
} from '../../../components/shared/deciderModel';

interface DeciderEditorProps {
  decider: DeciderConfig;
  onChange: (updates: Partial<DeciderConfig>) => void;
  onClose?: () => void;
}

// Lazily resolved so the element registry (and its unit tests) never pull the
// provider selector's heavy ESM dependency graph into module load.
const DeciderLlmEditor = React.lazy(() => import('./DeciderLlmEditor'));

/**
 * Full-area editor for the decider. The Mode dropdown (mirroring the sidebar)
 * picks route / compare / consolidate; the editor then owns the router LLM +
 * routing prompt (route) or the merger LLM + merge prompt (consolidate). The
 * candidate roster lives on the node sidebar.
 */
const DeciderEditor: React.FC<DeciderEditorProps> = ({ decider, onChange, onClose }) => {
  const surfaceMode = surfaceModeFromDecider(decider);
  const mirror: MirrorConfig = decider.mirror ?? makeDefaultMirrorConfig();

  // The fullscreen editor switches among decider modes only; 'direct' (removing
  // the decider) is a sidebar action, so it never appears in this dropdown.
  const setMode = (mode: SurfaceExecutionMode) => {
    if (mode === 'direct') return;
    onChange(modeToDeciderPatch(decider, mode));
  };
  const setMirror = (updates: Partial<MirrorConfig>) =>
    onChange({ mirror: { ...mirror, ...updates } });

  return (
    <div>
      <div className="card shadow-sm mb-4">
        <div className="card-header bg-light d-flex justify-content-between align-items-center">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-code-branch me-2"></i>
            Decider Configuration
          </h6>
          {onClose && (
            <button type="button" className="btn btn-sm btn-outline-secondary" onClick={onClose}>
              <i className="fas fa-times me-1"></i>
              Close tab
            </button>
          )}
        </div>
        <div className="card-body">
          <div className="mb-3">
            <label className="d-block mb-1" style={{ fontSize: '13px' }} htmlFor="decider-mode">
              Mode
            </label>
            <select
              id="decider-mode"
              className="form-select form-select-sm"
              value={surfaceMode}
              onChange={e => setMode(e.target.value as SurfaceExecutionMode)}
            >
              {DECIDER_MODE_OPTIONS.map(o => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
            <small className="form-text text-muted">
              {surfaceModeOption(surfaceMode).description}
            </small>
          </div>

          <hr className="my-3" />

          {surfaceMode === 'route' ? (
            <>
              <div className="alert alert-info py-2 mb-3" style={{ fontSize: '12px' }}>
                <i className="fas fa-info-circle me-1" /> The Decider LLM reads each request and the
                candidate menu, then names one candidate id. Keep it small and fast — it runs on
                every request before the chosen candidate serves the response.
              </div>

              <h6 className="text-dark mb-3" style={{ fontSize: '13px' }}>
                <i className="fas fa-robot me-2"></i>
                Router LLM
              </h6>
              <React.Suspense fallback={<div className="text-muted">Loading LLM editor…</div>}>
                <DeciderLlmEditor
                  llm={decider.llm ?? makeDefaultDeciderLlm()}
                  onChange={llm => onChange({ llm })}
                  idPrefix="decider"
                />
              </React.Suspense>

              <div className="d-flex align-items-center mb-3">
                <div className="custom-control custom-switch">
                  <input
                    type="checkbox"
                    className="custom-control-input"
                    id="decider-disable-thinking"
                    checked={decider.disable_thinking === true}
                    onChange={e => onChange({ disable_thinking: e.target.checked || undefined })}
                  />
                  <label
                    className="custom-control-label"
                    htmlFor="decider-disable-thinking"
                    style={{ fontSize: '13px' }}
                  >
                    <i className="fas fa-brain me-1"></i>
                    Disable thinking
                  </label>
                </div>
              </div>

              <hr className="my-3" />

              <div className="mb-0">
                <div className="d-flex justify-content-between align-items-center mb-1">
                  <label style={{ fontSize: '13px' }} className="m-0">
                    Routing instructions
                  </label>
                  <button
                    type="button"
                    className="btn btn-link btn-sm p-0"
                    onClick={() => onChange({ system_prompt: DEFAULT_DECIDER_PROMPT })}
                  >
                    Reset to default
                  </button>
                </div>
                <textarea
                  className="form-control form-control-sm"
                  rows={6}
                  value={decider.system_prompt || ''}
                  onChange={e => onChange({ system_prompt: e.target.value })}
                  placeholder={DEFAULT_DECIDER_PROMPT}
                />
                <small className="form-text text-muted">
                  The candidate menu (id, name, description) is appended automatically. Tell the
                  router to reply with JSON naming one candidate id.
                </small>
              </div>
            </>
          ) : (
            <>
              <div className="alert alert-info py-2 mb-3" style={{ fontSize: '12px' }}>
                <i className="fas fa-info-circle me-1" /> Mirror sends every request to{' '}
                <strong>all</strong> candidates concurrently. Streaming is disabled and the request
                waits for every candidate (billed per candidate).
              </div>

              {surfaceMode === 'merge' ? (
                <>
                  <hr className="my-3" />
                  <h6 className="text-dark mb-3" style={{ fontSize: '13px' }}>
                    <i className="fas fa-compress-arrows-alt me-2"></i>
                    Merger LLM
                  </h6>
                  <React.Suspense fallback={<div className="text-muted">Loading LLM editor…</div>}>
                    <DeciderLlmEditor
                      llm={mirror.merger ?? makeDefaultDeciderLlm()}
                      onChange={merger => setMirror({ merger })}
                      idPrefix="merger"
                    />
                  </React.Suspense>

                  <div className="d-flex align-items-center mb-3">
                    <div className="custom-control custom-switch">
                      <input
                        type="checkbox"
                        className="custom-control-input"
                        id="merger-disable-thinking"
                        checked={mirror.disable_thinking === true}
                        onChange={e =>
                          setMirror({ disable_thinking: e.target.checked || undefined })
                        }
                      />
                      <label
                        className="custom-control-label"
                        htmlFor="merger-disable-thinking"
                        style={{ fontSize: '13px' }}
                      >
                        <i className="fas fa-brain me-1"></i>
                        Disable thinking
                      </label>
                    </div>
                  </div>

                  <hr className="my-3" />

                  <div className="mb-0">
                    <div className="d-flex justify-content-between align-items-center mb-1">
                      <label style={{ fontSize: '13px' }} className="m-0">
                        Merge instructions
                      </label>
                      <button
                        type="button"
                        className="btn btn-link btn-sm p-0"
                        onClick={() => setMirror({ merge_system_prompt: DEFAULT_MERGE_PROMPT })}
                      >
                        Reset to default
                      </button>
                    </div>
                    <textarea
                      className="form-control form-control-sm"
                      rows={5}
                      value={mirror.merge_system_prompt || ''}
                      onChange={e => setMirror({ merge_system_prompt: e.target.value })}
                      placeholder={DEFAULT_MERGE_PROMPT}
                    />
                    <small className="form-text text-muted">
                      The candidate answers are appended automatically. Tell the merger how to
                      combine them into a single best answer.
                    </small>
                  </div>
                </>
              ) : (
                <div className="alert alert-secondary py-2 mb-0" style={{ fontSize: '12px' }}>
                  <i className="fas fa-users me-1" /> Collect returns a response listing every
                  candidate answer (with per-candidate model, tokens and cost) for a human to
                  review. No merger LLM is needed.
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default DeciderEditor;
