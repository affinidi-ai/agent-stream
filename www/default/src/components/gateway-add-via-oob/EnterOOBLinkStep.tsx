import React, { useState } from 'react';
import { validateUrl } from '../../utils/urlValidation';

interface EnterOOBLinkStepProps {
  onNext: (link: string, secret: string) => void;
  onBack?: () => void;
  onCancel: () => void;
  initialLink?: string;
  initialSecret?: string;
}

const EnterOOBLinkStep: React.FC<EnterOOBLinkStepProps> = ({
  onNext,
  onBack,
  onCancel,
  initialLink = '',
  initialSecret = '',
}) => {
  const [link, setLink] = useState(initialLink);
  const [secret, setSecret] = useState(initialSecret);
  const [error, setError] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!link.trim()) {
      setError('Please enter a connection point link');
      return;
    }

    // Validate that it's a URL
    const decodedLink = (() => {
      try {
        return decodeURIComponent(link);
      } catch {
        return link;
      }
    })();
    const linkCheck = validateUrl(decodedLink);
    if (!linkCheck.valid) {
      setError(linkCheck.error);
      return;
    }

    // Check if it looks like an OOB invitation URL (contains _oobid parameter)
    if (!link.includes('_oobid=') && !link.includes('oob')) {
      setError("This doesn't appear to be a valid Connection Point Link?");
      return;
    }

    if (!secret.trim()) {
      setError('Connection secret is required');
      return;
    }

    onNext(decodeURIComponent(link), secret);
  };

  return (
    <div className="card shadow">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-link me-2"></i> Enter Connection Point Link
        </h6>
      </div>
      <div className="card-body">
        <p className="text-muted">
          Enter the Connection Point Link provided by the administrator of the appliance you wish to
          connect to. This link allows you to establish a secure DIDComm connection to that
          appliance.
        </p>

        <form onSubmit={handleSubmit}>
          {error && (
            <div className="alert alert-danger" role="alert">
              <i className="fas fa-exclamation-circle me-2"></i>
              {error}
            </div>
          )}

          <div className="mb-4">
            <label htmlFor="oobLink" className="form-label fw-bold">
              Connection Point Link <span className="text-danger">*</span>
            </label>
            <input
              type="text"
              className="form-control form-control-lg"
              id="oobLink"
              value={link}
              onChange={e => setLink(e.target.value)}
              placeholder="https://example.mediator.com/oob?_oobid=..."
              required
              autoFocus
            />
            <small className="form-text text-muted">
              Example: https://apse1.mediator.affinidi.io/oob?_oobid=abc123...
            </small>
          </div>

          <div className="mb-4">
            <label htmlFor="oobSecret" className="form-label fw-bold">
              Connection Secret <span className="text-danger">*</span>
            </label>
            <input
              type="text"
              className="form-control form-control-lg font-monospace"
              id="oobSecret"
              value={secret}
              onChange={e => setSecret(e.target.value)}
              placeholder="Enter the connection secret..."
              required
            />
            <small className="form-text text-muted">
              <i className="fas fa-lock me-1"></i>
              Enter the secret provided by the Connection Point administrator. This secret is
              required to accept the invitation.
            </small>
          </div>

          <div className="alert alert-info" role="alert">
            <i className="fas fa-info-circle me-3"></i>
            <strong style={{ whiteSpace: 'nowrap', marginRight: '20px' }}>
              What is a Connection Point Link?
            </strong>
            <p className="mb-0 mt-2">
              A Connection Point Link is a URL created by an appliance administrator that allows
              another appliance to connect to theirs via a Connection Point. The administrator
              creates this link and shares it with you securely. Once you enter the link, the system
              will use it to establish a secure DIDComm connection to that appliance.
            </p>
          </div>

          <div className="d-flex justify-content-between mt-4">
            <div>
              {onBack && (
                <button type="button" className="btn btn-secondary me-2" onClick={onBack}>
                  <i className="fas fa-arrow-left me-2"></i> Back
                </button>
              )}
              <button type="button" className="btn btn-secondary" onClick={onCancel}>
                <i className="fas fa-times me-2"></i> Cancel
              </button>
            </div>
            <button type="submit" className="btn btn-primary">
              Next <i className="fas fa-arrow-right ms-2"></i>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default EnterOOBLinkStep;
