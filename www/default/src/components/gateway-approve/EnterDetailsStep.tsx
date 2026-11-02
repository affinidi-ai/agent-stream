import React, { useState } from 'react';
import { topAndTail } from '../../utils/stringUtils';

interface EnterDetailsStepProps {
  onNext: (name: string, description: string) => void;
  onCancel: () => void;
  initialName?: string;
  initialDescription?: string;
  gatewayDid: string;
}

const EnterDetailsStep: React.FC<EnterDetailsStepProps> = ({
  onNext,
  onCancel,
  initialName = '',
  initialDescription = '',
  gatewayDid,
}) => {
  const [name, setName] = useState(initialName);
  const [description, setDescription] = useState(initialDescription);
  const [error, setError] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    if (!name.trim()) {
      setError('Gateway name is required');
      return;
    }

    onNext(name.trim(), description.trim());
  };

  return (
    <div className="card shadow">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-info-circle me-2"></i> Enter Gateway Details
        </h6>
      </div>
      <div className="card-body">
        <div className="alert alert-info">
          <i className="fas fa-info-circle me-2"></i>
          <strong>Connection Request Received</strong>A remote gateway has requested to establish a
          connection. Please provide a name and description to identify this connection.
        </div>

        <div className="mb-3">
          <label className="text-muted">
            <small>Gateway DID:</small>
          </label>
          <div>
            <code style={{ fontSize: '0.85rem' }}>{gatewayDid}</code>
          </div>
        </div>

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
              Gateway Name <span className="text-danger">*</span>
            </label>
            <input
              type="text"
              className="form-control"
              id="gatewayName"
              placeholder="e.g., Partner Gateway, Production Server, etc."
              value={name}
              onChange={e => setName(e.target.value)}
              required
            />
            <small className="form-text text-muted">
              Choose a descriptive name to easily identify the remote Gateway in your list of
              Gateways
            </small>
          </div>

          <div className="mb-3">
            <label htmlFor="gatewayDescription">Description (Optional)</label>
            <input
              className="form-control"
              id="gatewayDescription"
              placeholder="e.g., Connection to partner organization's appliance"
              value={description}
              onChange={e => setDescription(e.target.value)}
            />
            <small className="form-text text-muted">
              Add any additional details about this Gateway connection in your list of Gateways
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
