import React from 'react';
import { BadgeField, BadgeList, Field } from './readonly';
import type { ModelParameter } from './types';

interface ModelParameterEditorProps {
  param: ModelParameter;
  testId: string;
}

const ModelParameterEditor: React.FC<ModelParameterEditorProps> = ({ param, testId }) => {
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
        <div className="col-md-5">
          <Field label="Label" value={param.label} small testId={`${testId}-label`} />
        </div>
        <div className="col-md-3">
          <Field label="Default" value={param.default} small testId={`${testId}-default`} />
        </div>
        {param.type === 'number' && (
          <>
            <div className="col-md-4">
              <Field
                label="Min"
                value={param.min === undefined ? '' : String(param.min)}
                small
                testId={`${testId}-min`}
              />
            </div>
            <div className="col-md-4">
              <Field
                label="Max"
                value={param.max === undefined ? '' : String(param.max)}
                small
                testId={`${testId}-max`}
              />
            </div>
            <div className="col-md-4">
              <Field
                label="Step"
                value={param.step === undefined ? '' : String(param.step)}
                small
                testId={`${testId}-step`}
              />
            </div>
          </>
        )}
        <div className="col-12">
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
    </div>
  );
};

export default ModelParameterEditor;
