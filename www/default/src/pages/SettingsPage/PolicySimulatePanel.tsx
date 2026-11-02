import React, { useState } from 'react';
import { apiClient } from '../../api';

interface SimulateResult {
  allow: boolean;
  reason?: string;
  policy_type: string;
  version?: number;
  content_hash: string;
  query: string;
}

interface PolicySimulatePanelProps {
  policyId: string;
  /** The policy type currently selected in the editor (may be unsaved). */
  policyType: 'appliance' | 'llm' | 'ide';
  /** The current editor Rego — evaluated as a draft so unsaved edits are tested. */
  draftPolicy: string;
  /** Saved sample input, owned by the editor form so it persists on save. */
  sampleInput: string;
  onSampleInputChange: (value: string) => void;
}

export const POLICY_SIMULATE_DEFAULT_INPUT = `{
  "schema_version": 1,
  "action": "dispatch",
  "http": { "method": "POST", "path": "/", "headers": {} },
  "source_auth": {
    "method": "jwt_bearer",
    "subject": "user@example.com",
    "claims": { "role": "admin" }
  }
}`;

/**
 * Dry-run the policy currently in the editor against a sample input, without
 * touching any runtime engine or live traffic. Evaluates the unsaved draft body
 * via `POST /policy-definitions/{id}/simulate`.
 */
const PolicySimulatePanel: React.FC<PolicySimulatePanelProps> = ({
  policyId,
  policyType,
  draftPolicy,
  sampleInput,
  onSampleInputChange,
}) => {
  const [result, setResult] = useState<SimulateResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);

  const run = async () => {
    setError(null);
    setResult(null);
    let input: unknown;
    try {
      input = JSON.parse(sampleInput);
    } catch {
      setError('Sample input must be valid JSON.');
      return;
    }
    try {
      setRunning(true);
      const resp = await apiClient.fetch(
        `/api/v1/policy-definitions/${encodeURIComponent(policyId)}/simulate`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ input, policy: draftPolicy, policy_type: policyType }),
        }
      );
      if (!resp.ok) {
        const detail = await resp.text().catch(() => '');
        throw new Error(detail || `Dry-run failed: ${resp.statusText}`);
      }
      setResult((await resp.json()) as SimulateResult);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Dry-run failed');
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="card shadow-sm mb-4 border-left-primary" data-testid="policy-simulate-panel">
      <div className="card-body py-3 px-3">
        <div className="d-flex justify-content-between align-items-center mb-2">
          <h6 className="font-weight-bold text-primary mb-0">
            <i className="fas fa-flask me-2"></i>
            Test (dry-run)
          </h6>
          <button
            type="button"
            className="btn btn-sm btn-outline-primary"
            onClick={run}
            disabled={running}
            data-testid="policy-simulate-run"
          >
            <i className={`fas ${running ? 'fa-spinner fa-spin' : 'fa-play'} me-1`}></i>
            {running ? 'Running…' : 'Run against the draft above'}
          </button>
        </div>
        <p className="text-muted small mb-2">
          Evaluates the Rego currently in the editor (unsaved) against the sample <code>input</code>{' '}
          below. Nothing is enforced — no engine or live traffic is touched.
        </p>
        <textarea
          className="form-control font-monospace small mb-2"
          rows={8}
          style={{ fontSize: '0.8rem' }}
          value={sampleInput}
          onChange={e => onSampleInputChange(e.target.value)}
          data-testid="policy-simulate-input"
        />
        {error && (
          <div className="alert alert-danger py-2 px-3 mb-0">
            <i className="fas fa-exclamation-triangle me-2"></i>
            {error}
          </div>
        )}
        {result && (
          <div
            className="policy-surface-box rounded py-2 px-3 mb-0"
            data-testid="policy-simulate-result"
          >
            <div className="d-flex align-items-center mb-1">
              <span className={`badge ${result.allow ? 'text-bg-success' : 'text-bg-danger'} me-2`}>
                {result.allow ? 'ALLOW' : 'DENY'}
              </span>
              {result.reason && <span className="small">{result.reason}</span>}
            </div>
            <div className="small text-muted">
              <code>{result.query}</code>
              {typeof result.version === 'number' ? ` · v${result.version}` : ' · draft'} ·{' '}
              {result.content_hash}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default PolicySimulatePanel;
