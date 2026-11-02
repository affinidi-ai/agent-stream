import React from 'react';
import type { LlmProviderForm } from './types';

interface RawSectionProps {
  form: LlmProviderForm;
  testId: string;
}

const RawSection: React.FC<RawSectionProps> = ({ form, testId }) => {
  const json = JSON.stringify(form, null, 2);

  return (
    <div data-testid={`${testId}-section`}>
      <div className="d-flex justify-content-between align-items-center mb-1">
        <span className="fw-semibold small">Provider JSON</span>
        <button
          className="btn btn-sm btn-outline-secondary"
          onClick={() => navigator.clipboard?.writeText(json)}
          data-testid={`${testId}-copy`}
        >
          <i className="fas fa-copy me-1" /> Copy
        </button>
      </div>
      <pre className="bg-light border rounded p-3 mb-0 small" data-testid={`${testId}-json`}>
        {json}
      </pre>
    </div>
  );
};

export default RawSection;
