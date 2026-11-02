import React from 'react';
import { Form } from 'react-bootstrap';
import type { CallerIdentitySourceForm } from '../../../../pages/EditPipePage/types';

interface CallerIdentitySourcesEditorProps {
  sources: CallerIdentitySourceForm[];
  disabled?: boolean;
  onChange: (sources: CallerIdentitySourceForm[]) => void;
}

const defaultSource = (): CallerIdentitySourceForm => ({ type: 'header', name: 'x-user-email' });

const sourceForType = (
  type: CallerIdentitySourceForm['type'],
  prev: CallerIdentitySourceForm
): CallerIdentitySourceForm => {
  switch (type) {
    case 'header':
      return { type: 'header', name: prev.type === 'header' ? prev.name : 'x-user-email' };
    case 'jwt_claim':
      return { type: 'jwt_claim', claim: prev.type === 'jwt_claim' ? prev.claim : 'email' };
    case 'body_json_path':
      return {
        type: 'body_json_path',
        path: prev.type === 'body_json_path' ? prev.path : 'user.email',
      };
    case 'mtls':
      return { type: 'mtls', binding: prev.type === 'mtls' ? prev.binding : 'email_san' };
    default:
      return { type: 'api_key' };
  }
};

/**
 * Ordered editor for the surface's caller-identity sources. The gate uses the
 * first source that yields a non-empty value, so operators can list several
 * (e.g. a JWT claim, then an API key) and let the appliance pick whichever the
 * caller presents.
 */
const CallerIdentitySourcesEditor: React.FC<CallerIdentitySourcesEditorProps> = ({
  sources,
  disabled,
  onChange,
}) => {
  const update = (index: number, next: CallerIdentitySourceForm) => {
    onChange(sources.map((s, i) => (i === index ? next : s)));
  };

  const remove = (index: number) => onChange(sources.filter((_, i) => i !== index));

  return (
    <div className="mb-3">
      <label className="form-label small text-muted mb-1">
        Caller identity is read from (first match wins)
      </label>

      {sources.length === 0 && (
        <div className="small text-muted mb-2">
          No sources yet — add at least one for attribution to resolve a caller.
        </div>
      )}

      {sources.map((source, index) => (
        <div className="d-flex gap-2 align-items-start mb-2" key={index}>
          <Form.Select
            size="sm"
            data-testid={`team-attribution-source-type-${index}`}
            value={source.type}
            disabled={disabled}
            onChange={e =>
              update(
                index,
                sourceForType(e.target.value as CallerIdentitySourceForm['type'], source)
              )
            }
          >
            <option value="header">Request header</option>
            <option value="jwt_claim">JWT claim</option>
            <option value="body_json_path">Request body (JSON path)</option>
            <option value="mtls">mTLS client certificate</option>
            <option value="api_key">API key owner</option>
          </Form.Select>

          {source.type === 'header' && (
            <input
              type="text"
              className="form-control form-control-sm"
              data-testid={`team-attribution-source-value-${index}`}
              value={source.name}
              disabled={disabled}
              placeholder="x-user-email"
              onChange={e => update(index, { type: 'header', name: e.target.value })}
            />
          )}
          {source.type === 'jwt_claim' && (
            <input
              type="text"
              className="form-control form-control-sm"
              data-testid={`team-attribution-source-value-${index}`}
              value={source.claim}
              disabled={disabled}
              placeholder="email"
              onChange={e => update(index, { type: 'jwt_claim', claim: e.target.value })}
            />
          )}
          {source.type === 'body_json_path' && (
            <input
              type="text"
              className="form-control form-control-sm"
              data-testid={`team-attribution-source-value-${index}`}
              value={source.path}
              disabled={disabled}
              placeholder="user.email"
              onChange={e => update(index, { type: 'body_json_path', path: e.target.value })}
            />
          )}
          {source.type === 'mtls' && (
            <Form.Select
              size="sm"
              data-testid={`team-attribution-mtls-binding-${index}`}
              value={source.binding}
              disabled={disabled}
              onChange={e =>
                update(index, {
                  type: 'mtls',
                  binding: e.target.value as 'email_san' | 'subject_cn',
                })
              }
            >
              <option value="email_san">Email SAN</option>
              <option value="subject_cn">Subject CN</option>
            </Form.Select>
          )}
          {source.type === 'api_key' && (
            <input
              type="text"
              className="form-control form-control-sm"
              value="—"
              disabled
              readOnly
            />
          )}

          <button
            type="button"
            className="btn btn-sm btn-outline-danger"
            disabled={disabled}
            title="Remove source"
            data-testid={`team-attribution-source-remove-${index}`}
            onClick={() => remove(index)}
          >
            <i className="fas fa-times"></i>
          </button>
        </div>
      ))}

      <button
        type="button"
        className="btn btn-sm btn-outline-secondary"
        disabled={disabled}
        data-testid="team-attribution-source-add"
        onClick={() => onChange([...sources, defaultSource()])}
      >
        <i className="fas fa-plus me-1"></i> Add source
      </button>
    </div>
  );
};

export default CallerIdentitySourcesEditor;
