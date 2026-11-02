import React, { useState } from 'react';
import CapabilityMapEditor from './CapabilityMapEditor';
import ModelParameterEditor from './ModelParameterEditor';
import RateLimitingEditor from './RateLimitingEditor';
import { Field } from './readonly';
import type { LlmModel } from './types';

interface ModelEditorProps {
  model: LlmModel;
  testId: string;
}

const ModelEditor: React.FC<ModelEditorProps> = ({ model, testId }) => {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="card mb-2 border">
      <div className="card-header bg-light d-flex justify-content-between align-items-center py-2">
        <button
          type="button"
          className="btn btn-link text-decoration-none text-start flex-grow-1 p-0"
          onClick={() => setExpanded(prev => !prev)}
          data-testid={`${testId}-toggle`}
        >
          <i className={`fas fa-chevron-${expanded ? 'down' : 'right'} me-2 text-muted`}></i>
          <strong>{model.name || 'Unnamed model'}</strong>
          {model.value && <code className="ms-2 small">{model.value}</code>}
          {model.enabled === false && (
            <span className="badge text-bg-secondary ms-2">Disabled</span>
          )}
        </button>
      </div>
      {expanded && (
        <div className="card-body">
          <div className="row">
            <div className="col-md-6">
              <Field label="Display name" value={model.name} small testId={`${testId}-name`} />
            </div>
            <div className="col-md-6">
              <Field
                label="Model value (API id)"
                value={model.value}
                mono
                small
                testId={`${testId}-value`}
              />
            </div>
            <div className="col-md-6">
              <Field
                label="Cost / 1k input"
                value={String(model.cost_per_1k_input)}
                small
                testId={`${testId}-cost-input`}
              />
            </div>
            <div className="col-md-6">
              <Field
                label="Cost / 1k output"
                value={String(model.cost_per_1k_output)}
                small
                testId={`${testId}-cost-output`}
              />
            </div>
          </div>

          <div className="mb-3">
            <label className="form-label small mb-1">Parameters</label>
            {model.model_parameters.length === 0 ? (
              <div className="text-muted small fst-italic">None</div>
            ) : (
              model.model_parameters.map((param, paramIndex) => (
                <ModelParameterEditor
                  key={paramIndex}
                  param={param}
                  testId={`${testId}-param-${paramIndex}`}
                />
              ))
            )}
          </div>

          <CapabilityMapEditor flags={model.capabilities} testId={`${testId}-capabilities`} />

          <div className="mb-1">
            <label className="form-label small mb-1">Rate limiting</label>
            {model.rate_limiting ? (
              <RateLimitingEditor rateLimiting={model.rate_limiting} testId={`${testId}-rate`} />
            ) : (
              <div className="text-muted small fst-italic" data-testid={`${testId}-rate-none`}>
                Not configured
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default ModelEditor;
