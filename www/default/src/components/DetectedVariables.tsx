import React from 'react';
import { TemplateVariable } from '../utils/templateVariables';

interface DetectedVariablesProps {
  variables: TemplateVariable[];
  contextDescription?: string;
}

/**
 * Shared component for displaying detected template variables
 * Ensures consistent formatting across all integration types
 */
const DetectedVariables: React.FC<DetectedVariablesProps> = ({
  variables,
  contextDescription = 'template',
}) => {
  return (
    <div className="card shadow mb-4">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-code me-2"></i>
          Detected Variables
        </h6>
      </div>
      <div className="card-body">
        {variables.length === 0 ? (
          <p className="text-muted small mb-0">No variables detected in {contextDescription}</p>
        ) : (
          <div>
            <p className="text-muted small mb-2">Variables found in your {contextDescription}:</p>
            {variables.map(variable => (
              <div key={variable.name} className="mb-2 p-2 bg-light border rounded">
                {variable.label ? (
                  <div>
                    <div className="font-weight-bold small">{variable.label}</div>
                    <code className="text-muted small">${'{' + variable.name + '}'}</code>
                  </div>
                ) : (
                  <code className="d-block small">${'{' + variable.name + '}'}</code>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default DetectedVariables;
