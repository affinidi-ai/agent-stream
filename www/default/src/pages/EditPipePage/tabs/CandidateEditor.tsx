import React from 'react';
import { DeciderCandidate } from '../../../components/shared/deciderModel';

interface CandidateEditorProps {
  candidate: DeciderCandidate;
  onChange: (updates: Partial<DeciderCandidate>) => void;
  onClose?: () => void;
}

// Lazily resolved so the element registry (and its unit tests) never pull the
// provider selector's heavy ESM dependency graph into module load. The chunk
// is fetched only when the editor actually renders.
const DeciderLlmEditor = React.lazy(() => import('./DeciderLlmEditor'));

/**
 * Full-area editor for a single decider candidate — its routing identity
 * (id, name, description the router uses to pick it) and the upstream LLM it
 * resolves to. The candidate's id must be stable: the decider's enum output
 * names it, so changing it re-points the route. Identity (name) is also shown
 * in the node sidebar; this editor owns the id/description and full LLM config.
 */
const CandidateEditor: React.FC<CandidateEditorProps> = ({ candidate, onChange, onClose }) => {
  return (
    <div>
      <div className="card shadow-sm mb-4">
        <div className="card-header bg-light d-flex justify-content-between align-items-center">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-brain me-2"></i>
            Candidate Configuration
          </h6>
          {onClose && (
            <button type="button" className="btn btn-sm btn-outline-secondary" onClick={onClose}>
              <i className="fas fa-times me-1"></i>
              Close tab
            </button>
          )}
        </div>
        <div className="card-body">
          <div className="row">
            <div className="col-md-4 mb-3">
              <label style={{ fontSize: '13px' }}>Candidate id</label>
              <input
                type="text"
                className="form-control form-control-sm"
                value={candidate.id || ''}
                onChange={e => onChange({ id: e.target.value })}
                placeholder="e.g. fast"
              />
              <small className="form-text text-muted">
                Stable id the router selects. Letters, numbers and dashes.
              </small>
            </div>
            <div className="col-md-8 mb-3">
              <label style={{ fontSize: '13px' }}>Name</label>
              <input
                type="text"
                className="form-control form-control-sm"
                value={candidate.name || ''}
                onChange={e => onChange({ name: e.target.value })}
                placeholder="Candidate name…"
              />
            </div>
          </div>

          <div className="mb-3">
            <label style={{ fontSize: '13px' }}>Description</label>
            <textarea
              className="form-control form-control-sm"
              rows={2}
              value={candidate.description || ''}
              onChange={e => onChange({ description: e.target.value })}
              placeholder="When should the router pick this candidate? Shown to the router LLM."
            />
            <small className="form-text text-muted">
              The router reads this to decide when to route here.
            </small>
          </div>

          <hr className="my-3" />

          <h6 className="text-dark mb-3" style={{ fontSize: '13px' }}>
            <i className="fas fa-robot me-2"></i>
            LLM Configuration
          </h6>
          <React.Suspense fallback={<div className="text-muted">Loading LLM editor…</div>}>
            <DeciderLlmEditor
              llm={candidate.llm}
              onChange={llm => onChange({ llm })}
              idPrefix="candidate"
            />
          </React.Suspense>
        </div>
      </div>
    </div>
  );
};

export default CandidateEditor;
