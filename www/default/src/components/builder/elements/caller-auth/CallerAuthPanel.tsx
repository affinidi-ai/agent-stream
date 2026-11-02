import React from 'react';
import { Form } from 'react-bootstrap';
import type { ConfigPanelProps } from '../types';
import { jwtAudienceSet } from './sourceAuthMapping';

/**
 * Compact sidebar panel for the Caller Auth element. Picks the method
 * and defers all method-specific configuration (JWT strategy dropdown,
 * audience chips, mTLS certificate dropdown, etc.) to the fullscreen
 * editor — same pattern the Access Point used before caller-auth was
 * promoted to its own canvas element.
 */
const CallerAuthPanel: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  openFullscreenEditor,
}) => {
  const method = config.method_type || 'jwt_bearer';
  const audienceUnset = method === 'jwt_bearer' && !jwtAudienceSet(config);

  return (
    <>
      <div className="config-section surface-info-panel surface-info-panel--success">
        <div className="surface-info-panel-title">
          <i className="fas fa-circle-info me-1" />
          Caller Authentication Context
        </div>
        <div className="surface-info-panel-summary">
          Extracts the authenticated caller's context from the inbound request and exposes it to the
          rest of the pipeline — used by OPA policies (<code>input.caller_auth</code>) and by
          workload binding to populate <code>userIdentity</code> in the outbound / response VP.
          Without this, downstream stages only see the agent identity, not the human (or service) on
          whose behalf the call is being made.
        </div>
      </div>

      {audienceUnset && (
        <div className="config-section">
          <div className="alert alert-danger py-2 px-2 mb-0 small d-flex align-items-start gap-2">
            <i className="fas fa-exclamation-triangle mt-1" />
            <span>
              No accepted audience — the Surface cannot be saved until you set one in{' '}
              <strong>Configure…</strong>
            </span>
          </div>
        </div>
      )}

      <div className="config-section">
        <label>Authentication Method</label>
        <Form.Select
          size="sm"
          value={method}
          onChange={e => updateField('method_type', e.target.value)}
        >
          <option value="jwt_bearer">JWT Bearer</option>
          <option value="api_key">API Key (secret store)</option>
          <option value="api_key_provider">API Key (provider)</option>
          <option value="mtls">mTLS (Mutual TLS)</option>
        </Form.Select>
        <button
          className="btn btn-outline-primary btn-sm w-100 mt-2"
          onClick={() => openFullscreenEditor?.()}
          disabled={!openFullscreenEditor}
        >
          <i className="fas fa-pen-to-square me-1" /> Configure…
        </button>
      </div>
    </>
  );
};

export default CallerAuthPanel;
