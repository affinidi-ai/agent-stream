import React from 'react';
import { BadgeField, BadgeList, Field } from './readonly';
import type { EndpointParameter } from './types';

interface EndpointParameterEditorProps {
  param: EndpointParameter;
  testId: string;
}

const EndpointParameterEditor: React.FC<EndpointParameterEditorProps> = ({ param, testId }) => {
  return (
    <div className="pb-2 mb-3 border-bottom">
      <div className="d-flex justify-content-between align-items-center mb-3">
        <span className="small fw-bold">{param.name || param.label || 'Parameter'}</span>
        <span className="badge bg-secondary">{param.type}</span>
      </div>
      <div className="row">
        <div className="col-md-4">
          <Field label="Name" value={param.name} mono small testId={`${testId}-name`} />
        </div>
        <div className="col-md-8">
          <Field label="Label" value={param.label} small testId={`${testId}-label`} />
        </div>
        <div className="col-md-6">
          <Field label="Default" value={param.default} small testId={`${testId}-default`} />
        </div>
        <div className="col-md-6">
          <Field
            label="Description"
            value={param.description}
            small
            testId={`${testId}-description`}
          />
        </div>
      </div>
      {param.type === 'select' && (
        <BadgeField label="Options" small>
          <BadgeList values={param.options} testId={`${testId}-options`} />
        </BadgeField>
      )}
      {param.applies_to_models.length > 0 && (
        <BadgeField label="Applies to models" small>
          <BadgeList values={param.applies_to_models} testId={`${testId}-applies`} />
        </BadgeField>
      )}
    </div>
  );
};

export default EndpointParameterEditor;
