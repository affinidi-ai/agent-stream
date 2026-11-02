import React from 'react';
import { BadgeField } from './readonly';
import type { CapabilityFlag } from './types';

interface CapabilityMapEditorProps {
  flags: CapabilityFlag[];
  testId: string;
}

const CapabilityMapEditor: React.FC<CapabilityMapEditorProps> = ({ flags, testId }) => {
  return (
    <BadgeField label="Capabilities" small>
      {flags.length === 0 ? (
        <span className="text-muted small fst-italic" data-testid={`${testId}-empty`}>
          None
        </span>
      ) : (
        <div className="d-flex flex-wrap gap-1" data-testid={testId}>
          {flags.map((flag, index) => (
            <span
              className={`badge fw-normal font-monospace bg-${flag.value ? 'success' : 'secondary'}`}
              key={`${flag.key}-${index}`}
              data-testid={`${testId}-value-${index}`}
            >
              <i className={`fas fa-${flag.value ? 'check' : 'times'} me-1`}></i>
              {flag.key || 'capability'}
            </span>
          ))}
        </div>
      )}
    </BadgeField>
  );
};

export default CapabilityMapEditor;
