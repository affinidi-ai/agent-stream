import React from 'react';
import ModelEditor from './ModelEditor';
import type { LlmModel } from './types';

interface ModelsSectionProps {
  models: LlmModel[];
  testId: string;
}

const ModelsSection: React.FC<ModelsSectionProps> = ({ models, testId }) => {
  return (
    <div data-testid={`${testId}-section`}>
      {models.length === 0 ? (
        <div className="text-center text-muted py-4">
          <i className="fas fa-cube fa-2x mb-2 d-block opacity-50"></i>
          No models configured.
        </div>
      ) : (
        models.map((model, index) => (
          <ModelEditor key={index} model={model} testId={`${testId}-${index}`} />
        ))
      )}
    </div>
  );
};

export default ModelsSection;
