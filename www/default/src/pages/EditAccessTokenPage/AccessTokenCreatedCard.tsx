import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import type { AccessTokenCreated } from '../../types';
import AccessTokenEditHeader from './AccessTokenEditHeader';

interface AccessTokenCreatedCardProps {
  created: AccessTokenCreated;
  listRoute: string;
}

/** One-time copy of a freshly minted token secret; the value stays masked on screen. */
const AccessTokenCreatedCard: React.FC<AccessTokenCreatedCardProps> = ({ created, listRoute }) => {
  const navigate = useNavigate();
  const [copied, setCopied] = useState(false);

  const copyToken = async () => {
    await navigator.clipboard.writeText(created.token);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="container-fluid" data-testid="page-access-token-created">
      <AccessTokenEditHeader
        title="Access Token Created"
        subtitle="Copy the token secret now — it can never be retrieved again."
        onBack={() => navigate(listRoute)}
      />
      <div className="row">
        <div className="col-lg-8">
          <div className="card shadow mb-4">
            <div className="card-header py-3">
              <h6 className="m-0 font-weight-bold text-primary">Token Secret</h6>
            </div>
            <div className="card-body">
              <div className="alert alert-success">
                <i className="fas fa-check-circle me-1" aria-hidden="true" /> Token{' '}
                <strong>{created.name}</strong> created.
              </div>
              <label className="form-label small fw-semibold">Token secret</label>
              <div className="input-group mb-2">
                <input
                  type="password"
                  className="form-control font-monospace"
                  readOnly
                  autoComplete="off"
                  value={created.token}
                  aria-label="Token secret (hidden)"
                  data-testid="access-token-secret"
                />
                <button
                  className="btn btn-outline-primary"
                  type="button"
                  onClick={copyToken}
                  data-testid="access-token-copy-secret-button"
                >
                  <i className={`fas ${copied ? 'fa-check' : 'fa-copy'} me-1`} aria-hidden="true" />
                  {copied ? 'Copied' : 'Copy'}
                </button>
              </div>
              <div className="alert alert-warning small mb-3">
                <i className="fas fa-triangle-exclamation me-1" aria-hidden="true" /> Copy this now
                — it is hidden on screen and can never be retrieved again. Use it as a{' '}
                <code>Authorization: Bearer</code> header on the management API.
              </div>
              <button
                className="btn btn-primary"
                type="button"
                onClick={() => navigate(listRoute)}
                data-testid="access-token-done-button"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AccessTokenCreatedCard;
