import React from 'react';
import EndpointEditor from './EndpointEditor';
import type { LlmEndpoint } from './types';

interface EndpointsSectionProps {
  endpoints: LlmEndpoint[];
  testId: string;
}

const EndpointsSection: React.FC<EndpointsSectionProps> = ({ endpoints, testId }) => {
  return (
    <div data-testid={`${testId}-section`}>
      {endpoints.length === 0 ? (
        <div className="text-center text-muted py-4">
          <i className="fas fa-plug fa-2x mb-2 d-block opacity-50"></i>
          No endpoints configured.
        </div>
      ) : (
        endpoints.map((endpoint, index) => (
          <EndpointEditor key={index} endpoint={endpoint} testId={`${testId}-${index}`} />
        ))
      )}
    </div>
  );
};

export default EndpointsSection;
