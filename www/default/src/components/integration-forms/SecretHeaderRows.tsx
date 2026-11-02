import React from 'react';
import CredentialSecretField from './CredentialSecretField';
import type { SecretOptions } from '../../hooks/useSecretOptions';
import type { HeaderSecretRefs } from '../../utils/integrationCredentials';

export interface SecretHeaderRow {
  name: string;
  secretId: string;
}

export const rowsFromRefs = (refs: HeaderSecretRefs | undefined): SecretHeaderRow[] =>
  Object.entries(refs ?? {}).map(([name, secretId]) => ({ name, secretId }));

export const refsFromRows = (rows: SecretHeaderRow[]): HeaderSecretRefs | undefined => {
  const entries = rows
    .filter(row => row.name.trim() !== '' && row.secretId !== '')
    .map((row): [string, string] => [row.name.trim(), row.secretId]);
  return entries.length > 0 ? Object.fromEntries(entries) : undefined;
};

interface SecretHeaderRowsProps {
  rows: SecretHeaderRow[];
  onChange: (rows: SecretHeaderRow[]) => void;
  secretOptions: SecretOptions;
  disabled?: boolean;
}

const SecretHeaderRows: React.FC<SecretHeaderRowsProps> = ({
  rows,
  onChange,
  secretOptions,
  disabled = false,
}) => {
  const update = (index: number, patch: Partial<SecretHeaderRow>) =>
    onChange(rows.map((row, i) => (i === index ? { ...row, ...patch } : row)));

  return (
    <div className="mb-3" data-testid="webhook-secret-headers">
      <label className="form-label">
        Secret Headers <span className="text-muted">(Optional)</span>
      </label>
      {rows.map((row, index) => (
        <div className="row align-items-start" key={index}>
          <div className="col-md-5 mb-2">
            <label htmlFor={`webhook-secret-header-name-${index}`} className="form-label small">
              Header name
            </label>
            <input
              type="text"
              id={`webhook-secret-header-name-${index}`}
              className="form-control font-monospace"
              value={row.name}
              onChange={e => update(index, { name: e.target.value })}
              placeholder="Authorization"
              disabled={disabled}
              data-testid={`webhook-secret-header-name-${index}`}
            />
          </div>
          <div className="col-md-6">
            <CredentialSecretField
              label="Secret"
              secretOptions={secretOptions}
              selectedSecretId={row.secretId}
              onChange={secretId => update(index, { secretId })}
              disabled={disabled}
              testId={`webhook-secret-header-secret-${index}`}
            />
          </div>
          <div className="col-md-1 pt-md-4">
            <button
              type="button"
              className="btn btn-sm btn-outline-danger mt-md-2"
              onClick={() => onChange(rows.filter((_, i) => i !== index))}
              disabled={disabled}
              aria-label={`Remove secret header ${row.name || index + 1}`}
              data-testid={`webhook-secret-header-remove-${index}`}
            >
              <i className="fas fa-trash" aria-hidden="true" />
            </button>
          </div>
        </div>
      ))}
      <button
        type="button"
        className="btn btn-sm btn-outline-primary"
        onClick={() => onChange([...rows, { name: '', secretId: '' }])}
        disabled={disabled}
        data-testid="webhook-secret-header-add-button"
      >
        <i className="fas fa-plus me-1" aria-hidden="true" />
        Add secret header
      </button>
      <small className="form-text text-muted d-block">
        Headers whose value is read from a stored secret at delivery, such as an Authorization
        token.
      </small>
    </div>
  );
};

export default SecretHeaderRows;
