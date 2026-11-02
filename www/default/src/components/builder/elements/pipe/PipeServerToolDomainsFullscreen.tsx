import React from 'react';
import type { ConfigPanelProps } from '../types';
import DomainListEditor from '../../../shared/DomainListEditor';

/**
 * Full-area domain-policy editor shared by the Web Search and Web Fetch tools
 * (registered as their `FullscreenPanel`). A baseline — allow all URLs except a
 * block-list, or block all URLs except an allow-list — plus a single exception
 * list edited as discrete entries (add / remove), not a comma-separated string.
 * Writes `domain_policy` and `domain_exceptions` on the tool node config; the
 * canvas maps those into `server_tools.web_*` on save.
 */
const PipeServerToolDomainsFullscreen: React.FC<ConfigPanelProps> = ({
  node,
  config,
  updateField,
  closeFullscreenEditor,
}) => {
  const policy: 'allow_all' | 'block_all' =
    config?.domain_policy === 'block_all' ? 'block_all' : 'allow_all';
  const exceptions: string[] = Array.isArray(config?.domain_exceptions)
    ? config.domain_exceptions
    : [];
  const isFetch = node?.type === 'pipe-web-fetch';
  const toolLabel = isFetch ? 'Web Fetch' : 'Web Search';
  const verb = isFetch ? 'fetch' : 'return results from';

  const summary =
    policy === 'allow_all'
      ? exceptions.length === 0
        ? 'All domains are currently allowed.'
        : `All domains are allowed except the ${exceptions.length} listed below.`
      : exceptions.length === 0
        ? 'All domains are currently blocked — add at least one to permit it.'
        : `Only the ${exceptions.length} listed domain(s) are allowed.`;

  return (
    <div className="container-fluid py-4">
      <div className="d-flex justify-content-between align-items-center mb-4">
        <div>
          <h4 className="mb-1">
            <i className="fas fa-globe me-2 text-primary" />
            {toolLabel} - domain policy
          </h4>
          <div className="text-muted small">
            Control which domains this tool may {verb}. Matching is by domain suffix, so
            <code className="mx-1">example.com</code> also covers <code>docs.example.com</code>.
          </div>
        </div>
        <button
          type="button"
          className="btn btn-outline-secondary btn-sm"
          onClick={() => closeFullscreenEditor?.()}
          disabled={!closeFullscreenEditor}
        >
          <i className="fas fa-times me-1" />
          Close
        </button>
      </div>

      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-shield-halved me-2" />
            Baseline
          </h6>
        </div>
        <div className="card-body">
          <div className="form-check mb-2">
            <input
              className="form-check-input"
              type="radio"
              name="tool-domain-policy"
              id="tool-domain-allow-all"
              checked={policy === 'allow_all'}
              onChange={() => updateField('domain_policy', 'allow_all')}
              data-testid="tool-domain-allow-all"
            />
            <label className="form-check-label" htmlFor="tool-domain-allow-all">
              <strong>Allow all URLs</strong> by default, except the domains below
              <span className="text-muted"> (block-list)</span>
            </label>
          </div>
          <div className="form-check mb-0">
            <input
              className="form-check-input"
              type="radio"
              name="tool-domain-policy"
              id="tool-domain-block-all"
              checked={policy === 'block_all'}
              onChange={() => updateField('domain_policy', 'block_all')}
              data-testid="tool-domain-block-all"
            />
            <label className="form-check-label" htmlFor="tool-domain-block-all">
              <strong>Block all URLs</strong> by default, except the domains below
              <span className="text-muted"> (allow-list)</span>
            </label>
          </div>
        </div>
      </div>

      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-list me-2" />
            {policy === 'allow_all' ? 'Blocked domains' : 'Allowed domains'}
          </h6>
        </div>
        <div className="card-body">
          <DomainListEditor
            domains={exceptions}
            onChange={next => updateField('domain_exceptions', next)}
            placeholder="example.com"
            testId="tool-domain"
          />
          <p className="text-muted small mt-3 mb-0">{summary}</p>
        </div>
      </div>
    </div>
  );
};

export default PipeServerToolDomainsFullscreen;
