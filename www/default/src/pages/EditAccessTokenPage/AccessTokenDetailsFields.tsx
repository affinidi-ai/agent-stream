import React, { useState } from 'react';
import { formatDateTime } from '../../utils/stringUtils';
import type { AccessTokenMeta } from '../../types';

interface AccessTokenDetailsFieldsProps {
  isEditMode: boolean;
  meta: AccessTokenMeta | null;
  revoked: boolean;
  name: string;
  description: string;
  onNameChange: (value: string) => void;
  onDescriptionChange: (value: string) => void;
}

const AccessTokenDetailsFields: React.FC<AccessTokenDetailsFieldsProps> = ({
  isEditMode,
  meta,
  revoked,
  name,
  description,
  onNameChange,
  onDescriptionChange,
}) => {
  const [idCopied, setIdCopied] = useState(false);

  const copyId = async () => {
    if (!meta) return;
    await navigator.clipboard.writeText(meta.id);
    setIdCopied(true);
    setTimeout(() => setIdCopied(false), 2000);
  };

  return (
    <>
      {revoked && (
        <div className="alert alert-warning small">
          <i className="fas fa-ban me-1" aria-hidden="true" /> This token was revoked
          {meta?.revoked_at ? ` on ${formatDateTime(meta.revoked_at)}` : ''} and can no longer be
          used or edited.
        </div>
      )}
      <div className="mb-3">
        <label htmlFor="pat-name">
          Name <span className="text-danger">*</span>
        </label>
        <input
          id="pat-name"
          type="text"
          className="form-control"
          value={name}
          disabled={revoked}
          maxLength={120}
          placeholder="e.g. external"
          onChange={event => onNameChange(event.target.value)}
          required
        />
      </div>

      {isEditMode && meta && (
        <div className="mb-3">
          <label htmlFor="pat-id">Token ID</label>
          <div className="input-group">
            <input
              id="pat-id"
              type="text"
              className="form-control font-monospace bg-light"
              value={meta.id}
              readOnly
              disabled
              style={{ cursor: 'not-allowed' }}
            />
            <button
              className="btn btn-outline-secondary"
              type="button"
              onClick={copyId}
              title="Copy token ID"
              data-testid="access-token-copy-id-button"
            >
              <i className={`fas ${idCopied ? 'fa-check' : 'fa-copy'}`} aria-hidden="true" />
            </button>
          </div>
          <small className="form-text text-muted">
            <i className="fas fa-lock me-1" aria-hidden="true" />
            The token identifier cannot be changed.
          </small>
        </div>
      )}

      <div className="mb-3">
        <label htmlFor="pat-description">Description</label>
        <input
          id="pat-description"
          type="text"
          className="form-control"
          value={description}
          disabled={revoked}
          maxLength={280}
          placeholder="What is this token used for?"
          onChange={event => onDescriptionChange(event.target.value)}
        />
      </div>
    </>
  );
};

export default AccessTokenDetailsFields;
