import React, { useState } from 'react';
import { Form } from 'react-bootstrap';
import type { RequiredHeader } from '../../types';
import {
  ACCESS_TOKEN_RESOURCE_KINDS,
  AccessTokenResourceKind,
  anchored,
  evaluateScopePreview,
  validateScopeConfig,
} from './accessTokenScopeHelpers';

interface AccessTokenScopePreviewProps {
  pattern: string;
  headers: RequiredHeader[];
}

const AccessTokenScopePreview: React.FC<AccessTokenScopePreviewProps> = ({ pattern, headers }) => {
  const [sampleHeaders, setSampleHeaders] = useState<Record<string, string>>({});
  const [resourceKind, setResourceKind] = useState<AccessTokenResourceKind>('pipes');
  const [resourceId, setResourceId] = useState('');
  const preview = evaluateScopePreview(pattern, headers, sampleHeaders, resourceKind, resourceId);
  const configErrors = validateScopeConfig(pattern, headers);

  const headerOutcome = (header: RequiredHeader): 'ok' | 'mismatch' | 'invalid-regex' => {
    const regex = header.pattern ? anchored(header.pattern) : null;
    if (!regex) return 'invalid-regex';
    return regex.test(sampleHeaders[header.name.trim().toLowerCase()] ?? '') ? 'ok' : 'mismatch';
  };

  if (!pattern.trim() && headers.length === 0) return null;

  return (
    <div className="card bg-light border-0 mt-3" data-testid="access-token-scope-preview">
      <div className="card-body p-2">
        <div className="small fw-semibold text-muted mb-2">
          <i className="fas fa-flask me-1" aria-hidden="true" /> Test this scope
        </div>
        <div className="small text-muted mb-2">Patterns must match the entire sample value.</div>
        {headers
          .filter(header => header.name.trim())
          .map((header, index) => {
            const name = header.name.trim().toLowerCase();
            const outcome = headerOutcome(header);
            return (
              <div className="d-flex align-items-center gap-2 mb-1" key={`${name}-${index}`}>
                <label
                  className="small font-monospace"
                  style={{ minWidth: 160 }}
                  htmlFor={`pat-test-header-${index}`}
                >
                  {header.name.trim()}
                </label>
                <Form.Control
                  id={`pat-test-header-${index}`}
                  size="sm"
                  value={sampleHeaders[name] ?? ''}
                  placeholder="sample value"
                  onChange={event =>
                    setSampleHeaders(current => ({ ...current, [name]: event.target.value }))
                  }
                  data-testid={`access-token-test-header-${index}`}
                />
                {outcome === 'ok' && (
                  <i
                    className="fas fa-check text-success"
                    aria-hidden="true"
                    data-testid={`access-token-test-header-result-${index}`}
                  />
                )}
                {outcome === 'mismatch' && (
                  <span
                    className="small text-danger text-nowrap"
                    title="No full-value match"
                    data-testid={`access-token-test-header-result-${index}`}
                  >
                    <i className="fas fa-times me-1" aria-hidden="true" /> no match
                  </span>
                )}
                {outcome === 'invalid-regex' && (
                  <span
                    className="badge text-bg-warning"
                    data-testid={`access-token-test-header-result-${index}`}
                  >
                    bad regex
                  </span>
                )}
              </div>
            );
          })}
        <div className="d-flex align-items-center gap-2 mt-2">
          <label className="small text-muted" style={{ minWidth: 160 }} htmlFor="pat-test-kind">
            Resource kind
          </label>
          <Form.Select
            id="pat-test-kind"
            size="sm"
            value={resourceKind}
            onChange={event => setResourceKind(event.target.value as AccessTokenResourceKind)}
            data-testid="access-token-test-resource-kind"
          >
            {ACCESS_TOKEN_RESOURCE_KINDS.map(([kind, label]) => (
              <option value={kind} key={kind}>
                {label}
              </option>
            ))}
          </Form.Select>
        </div>
        <div className="d-flex align-items-center gap-2 mt-2">
          <label
            className="small text-muted"
            style={{ minWidth: 160 }}
            htmlFor="pat-test-resource-id"
          >
            Sample entity ID
          </label>
          <Form.Control
            id="pat-test-resource-id"
            size="sm"
            className="font-monospace"
            value={resourceId}
            onChange={event => setResourceId(event.target.value)}
            data-testid="access-token-test-id"
          />
          {resourceId && pattern.trim() && (
            <span
              className={`badge ${preview.allowed ? 'text-bg-success' : 'text-bg-danger'}`}
              data-testid="access-token-test-result"
            >
              {preview.allowed ? 'allowed' : 'denied'}
            </span>
          )}
        </div>
        {resourceId && (
          <div className="small mt-2">
            <span className="text-muted me-2">Canonical target</span>
            <code data-testid="access-token-canonical-target">{preview.target}</code>
          </div>
        )}
        {configErrors.length > 0 && (
          <ul className="small text-danger mt-2 mb-0" data-testid="access-token-preview-errors">
            {configErrors.map(error => (
              <li key={error}>{error}</li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
};

export default AccessTokenScopePreview;
