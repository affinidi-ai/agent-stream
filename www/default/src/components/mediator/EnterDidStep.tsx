import React, { useState } from 'react';

interface EnterDidStepProps {
  onNext: (did: string) => void;
  onCancel: () => void;
}

const EnterDidStep: React.FC<EnterDidStepProps> = ({ onNext, onCancel }) => {
  const [did, setDid] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    const trimmedDid = did.trim();

    // Validate DID format
    if (!trimmedDid) {
      setError('Please enter a DID');
      return;
    }

    if (!trimmedDid.startsWith('did:')) {
      setError('DID must start with "did:"');
      return;
    }

    // Comprehensive DID validation using regex
    // DID format: did:method:method-specific-id
    // - method: lowercase alphanumeric and hyphens
    // - method-specific-id: alphanumeric, dots, underscores, colons, percent-encoded, hyphens
    const didRegex = /^did:[a-z0-9]+:[a-zA-Z0-9._:%-]+$/;
    if (!didRegex.test(trimmedDid)) {
      setError(
        'Invalid DID format. Must be "did:method:method-specific-id" with valid characters (no quotes, backslashes, or spaces)'
      );
      return;
    }

    // Check for illegal characters that could cause server issues
    if (
      trimmedDid.includes('"') ||
      trimmedDid.includes('\\') ||
      trimmedDid.includes('\n') ||
      trimmedDid.includes('\r')
    ) {
      setError('DID contains illegal characters (quotes, backslashes, or line breaks)');
      return;
    }

    // Validate basic structure: must have at least 3 parts (did:method:id)
    const parts = trimmedDid.split(':');
    if (parts.length < 3 || parts[0] !== 'did' || !parts[1] || !parts[2]) {
      setError('DID must have format "did:method:method-specific-id"');
      return;
    }

    onNext(trimmedDid);
  };

  return (
    <div className="card shadow">
      <div className="card-body">
        <div className="welcome-screen">
          <h2>Add New DIDCommm v2.1 Mediator</h2>
          <p>
            Enter the DID (Decentralized Identifier) of the mediator you want to connect to. The
            system will attempt to resolve the DID and retrieve the mediator's DID document.
          </p>

          <form onSubmit={handleSubmit}>
            <div className="mb-4">
              <label htmlFor="did" className="form-label">
                <strong>Mediator DID *</strong>
              </label>
              <input
                type="text"
                className={`form-control ${error ? 'is-invalid' : ''}`}
                id="did"
                value={did}
                onChange={e => setDid(e.target.value)}
                placeholder="did:web:example.com:mediator"
                autoFocus
              />
              {error && (
                <div className="invalid-feedback" style={{ marginTop: '10px' }}>
                  {error}
                </div>
              )}
              <small className="form-text text-muted">
                The DID must start with "did:" followed by the method and identifier (e.g.,
                did:web:example.com:mediator)
              </small>
            </div>

            <div className="d-flex justify-content-between">
              <button type="button" className="btn btn-secondary" onClick={onCancel}>
                <i className="fas fa-times me-1"></i> Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={!did.trim()}>
                <i className="fas fa-arrow-right me-1"></i> Next
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default EnterDidStep;
