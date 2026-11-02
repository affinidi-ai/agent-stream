import React from 'react';

export interface DecisionConfig {
  mode: 'json' | 'regex';
  // JSON mode
  json_field?: string;
  json_approve_value?: string;
  // Regex mode
  approve_pattern?: string;
  reject_pattern?: string;
}

interface DecisionEvaluatorProps {
  value: DecisionConfig;
  onChange: (config: DecisionConfig) => void;
  compact?: boolean;
  /** Unique id prefix for radio buttons */
  idPrefix?: string;
}

const DecisionEvaluator: React.FC<DecisionEvaluatorProps> = ({
  value,
  onChange,
  compact = false,
  idPrefix = 'decision',
}) => {
  const handleModeChange = (mode: 'json' | 'regex') => {
    onChange({ ...value, mode });
  };

  const labelStyle = compact ? { fontSize: '12px' } : {};
  const inputStyle = compact ? { fontSize: '12px', padding: '4px 8px' } : {};

  return (
    <div>
      <div className="d-flex align-items-center mb-2">
        <label className="me-3 mb-0" style={labelStyle}>
          <strong>Decision Mode:</strong>
        </label>
        <div className="custom-control custom-radio custom-control-inline">
          <input
            type="radio"
            id={`${idPrefix}_mode_json`}
            name={`${idPrefix}_mode`}
            className="custom-control-input"
            checked={value.mode === 'json'}
            onChange={() => handleModeChange('json')}
          />
          <label
            className="custom-control-label"
            htmlFor={`${idPrefix}_mode_json`}
            style={labelStyle}
          >
            JSON
          </label>
        </div>
        <div className="custom-control custom-radio custom-control-inline">
          <input
            type="radio"
            id={`${idPrefix}_mode_regex`}
            name={`${idPrefix}_mode`}
            className="custom-control-input"
            checked={value.mode === 'regex'}
            onChange={() => handleModeChange('regex')}
          />
          <label
            className="custom-control-label"
            htmlFor={`${idPrefix}_mode_regex`}
            style={labelStyle}
          >
            Regex
          </label>
        </div>
      </div>

      {value.mode === 'json' && (
        <div className="row">
          <div className="col-md-6">
            <div className="mb-3">
              <label style={labelStyle}>JSON Field Name</label>
              <input
                type="text"
                className="form-control"
                style={inputStyle}
                value={value.json_field || 'decision'}
                onChange={e => onChange({ ...value, json_field: e.target.value })}
                placeholder="decision"
              />
              <small className="form-text text-muted">
                The JSON field in the LLM response to check (default: "decision")
              </small>
            </div>
          </div>
          <div className="col-md-6">
            <div className="mb-3">
              <label style={labelStyle}>Approve Value</label>
              <input
                type="text"
                className="form-control"
                style={inputStyle}
                value={value.json_approve_value || 'approve'}
                onChange={e => onChange({ ...value, json_approve_value: e.target.value })}
                placeholder="approve"
              />
              <small className="form-text text-muted">
                The value that means "approved" (default: "approve")
              </small>
            </div>
          </div>
        </div>
      )}

      {value.mode === 'regex' && (
        <div className="row">
          <div className="col-md-6">
            <div className="mb-3">
              <label style={labelStyle}>Approve Pattern *</label>
              <input
                type="text"
                className="form-control font-monospace"
                style={inputStyle}
                value={value.approve_pattern || ''}
                onChange={e => onChange({ ...value, approve_pattern: e.target.value })}
                placeholder="(?i)\bAPPROVED\b"
              />
              <small className="form-text text-muted">
                Regex pattern — if matched in the response, the decision is "approved"
              </small>
            </div>
          </div>
          <div className="col-md-6">
            <div className="mb-3">
              <label style={labelStyle}>Reject Pattern</label>
              <input
                type="text"
                className="form-control font-monospace"
                style={inputStyle}
                value={value.reject_pattern || ''}
                onChange={e => onChange({ ...value, reject_pattern: e.target.value })}
                placeholder="(?i)\bREJECTED\b"
              />
              <small className="form-text text-muted">
                Optional — checked first. If matched, immediately rejects.
              </small>
            </div>
          </div>
        </div>
      )}

      {!compact && (
        <div className="alert alert-info mt-2" style={{ fontSize: '13px' }}>
          <i className="fas fa-lightbulb me-2"></i>
          {value.mode === 'json' ? (
            <>
              <strong>JSON mode:</strong> Instruct the LLM to return a JSON response like{' '}
              <code>{`{"${value.json_field || 'decision'}": "${value.json_approve_value || 'approve'}", "details": "..."}`}</code>
              . The evaluator parses the response as JSON and checks the field value.
            </>
          ) : (
            <>
              <strong>Regex mode:</strong> The evaluator applies regex patterns to the raw LLM
              response text. The reject pattern is checked first — if it matches, the request is
              rejected immediately. Then the approve pattern is checked — if it matches, the request
              is approved. If neither matches, the request is rejected (fail-safe).
            </>
          )}
        </div>
      )}
    </div>
  );
};

export default DecisionEvaluator;
