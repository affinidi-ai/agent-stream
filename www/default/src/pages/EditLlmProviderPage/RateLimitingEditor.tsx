import React from 'react';
import { Field } from './readonly';
import type { RateLimiting, RateLimitRange } from './types';

interface RateLimitingEditorProps {
  rateLimiting: RateLimiting;
  testId: string;
}

interface RangeRowProps {
  label: string;
  range: RateLimitRange;
  testId: string;
}

const RangeRow: React.FC<RangeRowProps> = ({ label, range, testId }) => (
  <div className="mb-2">
    <label className="form-label small fw-bold text-muted mb-1">{label}</label>
    <div className="row">
      {(['min', 'max', 'default'] as const).map(key => (
        <div className="col-4" key={key}>
          <Field
            label={<span className="text-capitalize">{key}</span>}
            value={String(range[key])}
            small
            testId={`${testId}-${key}`}
          />
        </div>
      ))}
    </div>
  </div>
);

const RateLimitingEditor: React.FC<RateLimitingEditorProps> = ({ rateLimiting, testId }) => {
  return (
    <div className="pt-1">
      <div className="d-flex gap-3 mb-3">
        <span className="small" data-testid={`${testId}-can-disable`}>
          Can disable:{' '}
          <span className={`badge bg-${rateLimiting.can_disable ? 'success' : 'secondary'}`}>
            {rateLimiting.can_disable ? 'Yes' : 'No'}
          </span>
        </span>
        <span className="small" data-testid={`${testId}-can-change`}>
          Can change:{' '}
          <span className={`badge bg-${rateLimiting.can_change ? 'success' : 'secondary'}`}>
            {rateLimiting.can_change ? 'Yes' : 'No'}
          </span>
        </span>
      </div>
      <RangeRow
        label="Requests per minute"
        range={rateLimiting.requests_per_minute}
        testId={`${testId}-rpm`}
      />
      <RangeRow
        label="Tokens per minute"
        range={rateLimiting.tokens_per_minute}
        testId={`${testId}-tpm`}
      />
    </div>
  );
};

export default RateLimitingEditor;
