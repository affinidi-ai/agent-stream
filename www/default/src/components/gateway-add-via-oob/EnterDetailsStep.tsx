import React, { useState } from 'react';

interface EnterDetailsStepProps {
  onNext: (name: string, description: string, didMethod: string) => void;
  onCancel: () => void;
  initialName?: string;
  initialDescription?: string;
  initialDidMethod?: string;
}

const EnterDetailsStep: React.FC<EnterDetailsStepProps> = ({
  onNext,
  onCancel,
  initialName = '',
  initialDescription = '',
  initialDidMethod = 'web',
}) => {
  const [name, setName] = useState(initialName);
  const [description, setDescription] = useState(initialDescription);
  const [didMethod, setDidMethod] = useState(initialDidMethod);
  const [error, setError] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    if (!name.trim()) {
      setError('Agent Stream name is required');
      return;
    }

    onNext(name.trim(), description.trim(), didMethod);
  };

  return (
    <div className="card shadow">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-info-circle me-2"></i> Enter Agent Stream Details
        </h6>
      </div>
      <div className="card-body">
        <p className="text-muted">
          Provide a name and description for the Agent Stream you're connecting to. This will help
          you identify it in your Agent Stream list.
        </p>

        {error && (
          <div className="alert alert-danger alert-dismissible fade show" role="alert">
            {error}
            <button
              type="button"
              className="btn-close"
              onClick={() => setError('')}
              aria-label="Close"
            />
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="mb-3">
            <label htmlFor="gatewayName">
              Agent Stream Name <span className="text-danger">*</span>
            </label>
            <input
              type="text"
              className="form-control"
              id="gatewayName"
              value={name}
              onChange={e => setName(e.target.value)}
              required
            />
            <small className="form-text text-muted">
              Choose a descriptive name to easily identify this Agent Stream Connection Point
            </small>
          </div>

          <div className="mb-3">
            <label htmlFor="gatewayDescription">Description (Optional)</label>
            <input
              className="form-control"
              id="gatewayDescription"
              value={description}
              onChange={e => setDescription(e.target.value)}
            />
            <small className="form-text text-muted">
              Add any additional details about this Agent Stream Connection Point
            </small>
          </div>

          <div className="mb-3">
            <label htmlFor="didMethod">DID Method</label>
            <select
              className="form-select"
              id="didMethod"
              value={didMethod}
              onChange={e => setDidMethod(e.target.value)}
            >
              <option value="web">Web (did:web)</option>
              <option value="webvh">WebVH (did:webvh)</option>
              <option value="peer">Peer (did:peer)</option>
            </select>
            <small className="form-text text-muted">
              The DID method used to generate the identity for this connection.
            </small>
          </div>

          <div className="d-flex justify-content-between">
            <button type="button" className="btn btn-secondary" onClick={onCancel}>
              <i className="fas fa-times me-1"></i> Cancel
            </button>
            <button type="submit" className="btn btn-primary">
              Next <i className="fas fa-arrow-right ms-1"></i>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default EnterDetailsStep;
