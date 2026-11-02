import React, { useState } from 'react';
import { DEFAULT_REJECTION, RejectionConfig } from './llmPii';

export type HandlingChoice = 'reject' | 'redact' | 'pseudonymize';

const OPTIONS: { value: HandlingChoice; label: string; desc: string }[] = [
  {
    value: 'reject',
    label: 'Reject the call completely',
    desc: 'Block the entire request when this detector matches.',
  },
  {
    value: 'redact',
    label: 'Redact the text that matches the pattern',
    desc: 'Replace every match with a fixed token (e.g. <EMAIL>).',
  },
  {
    value: 'pseudonymize',
    label: 'Use a NER ID to preserve context',
    desc: 'Replace each distinct value with a stable NER ID (e.g. [EMAIL_NER_001]) so relationships survive while the raw value is hidden.',
  },
];

interface WhenDetectedProps {
  /** Unique prefix for DOM ids / test ids so multiple editors don't collide. */
  idPrefix: string;
  value: HandlingChoice;
  onChange: (choice: HandlingChoice) => void;
  rejection?: RejectionConfig | null;
  onRejectionChange: (field: keyof RejectionConfig, value: unknown) => void;
  /** Extra controls shown only under the Pseudonymize choice (restore, pronoun/coref links). */
  pseudonymizeOptions?: React.ReactNode;
}

/**
 * Shared "When detected" handling control used by both the regex Request Filter
 * and the model PII Detector, so both read the same: pick Reject / Redact /
 * Pseudonymize, with the rejection editor under Reject and the pseudonymize
 * sub-options under Pseudonymize.
 */
const WhenDetected: React.FC<WhenDetectedProps> = ({
  idPrefix,
  value,
  onChange,
  rejection,
  onRejectionChange,
  pseudonymizeOptions,
}) => {
  const [showBody, setShowBody] = useState(false);
  const selected = OPTIONS.find(o => o.value === value);

  return (
    <div className="mb-2">
      <label className="font-weight-bold" style={{ fontSize: '13px' }}>
        When detected
      </label>
      <select
        className="form-control form-control-sm dropdown-styling"
        data-testid={`${idPrefix}-action`}
        style={{ maxWidth: '420px' }}
        value={value}
        onChange={e => onChange(e.target.value as HandlingChoice)}
      >
        {OPTIONS.map(o => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      {selected && <small className="form-text text-muted">{selected.desc}</small>}

      {value === 'reject' && (
        <div
          className="p-3 rounded mt-2"
          style={{ background: 'rgba(0,0,0,0.02)', border: '1px solid rgba(0,0,0,0.06)' }}
        >
          <div className="d-flex align-items-center mb-1">
            <i className="fas fa-ban text-danger me-2"></i>
            <span className="font-weight-bold" style={{ fontSize: '13px' }}>
              Rejection response
            </span>
          </div>
          <small className="form-text text-muted mb-2">
            Returned to the caller when a rule matches. Default: 403 with a JSON policy error.
          </small>
          <div className="row">
            <div className="col-md-3">
              <label style={{ fontSize: '12px' }}>Status code</label>
              <input
                type="number"
                className="form-control form-control-sm"
                data-testid={`${idPrefix}-reject-status`}
                value={rejection?.status_code ?? DEFAULT_REJECTION.status_code}
                onChange={e =>
                  onRejectionChange('status_code', parseInt(e.target.value, 10) || 403)
                }
                min={400}
                max={599}
              />
            </div>
            <div className="col-md-4">
              <label style={{ fontSize: '12px' }}>Content-Type</label>
              <select
                className="form-control form-control-sm dropdown-styling"
                value={rejection?.content_type ?? DEFAULT_REJECTION.content_type}
                onChange={e => onRejectionChange('content_type', e.target.value)}
              >
                <option value="application/json">application/json</option>
                <option value="text/plain">text/plain</option>
              </select>
            </div>
          </div>
          <div className="mt-2 mb-0">
            <label style={{ fontSize: '12px' }}>
              Response body
              <button
                type="button"
                className="btn btn-xs btn-link ms-1 p-0"
                onClick={() => setShowBody(!showBody)}
                style={{ fontSize: '11px' }}
              >
                {showBody ? 'hide' : 'show'}
              </button>
            </label>
            {showBody && (
              <textarea
                className="form-control form-control-sm font-monospace"
                style={{ fontFamily: 'monospace', fontSize: '12px', minHeight: '80px' }}
                value={rejection?.body ?? DEFAULT_REJECTION.body}
                onChange={e => onRejectionChange('body', e.target.value)}
                rows={3}
              />
            )}
          </div>
        </div>
      )}

      {value === 'pseudonymize' && pseudonymizeOptions}
    </div>
  );
};

export default WhenDetected;
