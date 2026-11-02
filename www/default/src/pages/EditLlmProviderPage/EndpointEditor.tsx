import React, { useState } from 'react';
import EndpointParameterEditor from './EndpointParameterEditor';
import { BadgeField, BadgeList, Field } from './readonly';
import type { LlmEndpoint } from './types';

interface EndpointEditorProps {
  endpoint: LlmEndpoint;
  testId: string;
}

const EndpointEditor: React.FC<EndpointEditorProps> = ({ endpoint, testId }) => {
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
          <strong>{endpoint.name || 'Unnamed endpoint'}</strong>
          {endpoint.path && <code className="ms-2 small">{endpoint.path}</code>}
          {endpoint.is_default && <span className="badge bg-info ms-2">default</span>}
        </button>
      </div>
      {expanded && (
        <div className="card-body">
          <div className="row">
            <div className="col-md-6">
              <Field label="Name" value={endpoint.name} small testId={`${testId}-name`} />
            </div>
            <div className="col-md-6">
              <Field label="Path" value={endpoint.path} mono small testId={`${testId}-path`} />
            </div>
          </div>
          <Field
            label="Description"
            value={endpoint.description}
            small
            testId={`${testId}-description`}
          />
          <BadgeField label="Default endpoint" small>
            <span
              className={`badge bg-${endpoint.is_default ? 'info' : 'secondary'}`}
              data-testid={`${testId}-default`}
            >
              {endpoint.is_default ? 'Yes' : 'No'}
            </span>
          </BadgeField>

          <BadgeField label="Capabilities" small>
            <BadgeList values={endpoint.capabilities} testId={`${testId}-capabilities`} />
          </BadgeField>

          <div className="mb-3">
            <label className="form-label small mb-1">Parameters</label>
            {endpoint.endpoint_parameters.length === 0 ? (
              <div className="text-muted small fst-italic">None</div>
            ) : (
              endpoint.endpoint_parameters.map((param, paramIndex) => (
                <EndpointParameterEditor
                  key={paramIndex}
                  param={param}
                  testId={`${testId}-param-${paramIndex}`}
                />
              ))
            )}
          </div>

          <div className="row">
            <div className="col-md-6">
              <BadgeField label="Moderation models" small>
                <BadgeList
                  values={endpoint.moderation_models}
                  testId={`${testId}-moderation-models`}
                />
              </BadgeField>
            </div>
            <div className="col-md-6">
              <BadgeField label="Moderation categories" small>
                <BadgeList
                  values={endpoint.moderation_categories}
                  testId={`${testId}-moderation-categories`}
                />
              </BadgeField>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default EndpointEditor;
