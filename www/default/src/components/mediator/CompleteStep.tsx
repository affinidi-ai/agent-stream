import React from 'react';

interface CompleteStepProps {
  mediator: any;
  onFinish: () => void;
  onViewMediator: () => void;
}

const CompleteStep: React.FC<CompleteStepProps> = ({ mediator, onFinish, onViewMediator }) => {
  return (
    <div className="card shadow">
      <div className="card-body">
        <div className="text-center py-5">
          <div className="mb-4">
            <i className="fas fa-check-circle hero-status-icon success"></i>
          </div>

          <h3 className="mb-3">Mediator Added Successfully!</h3>

          <p className="text-muted mb-4">
            The mediator has been successfully added to your system.
          </p>

          <div className="card bg-light mb-4 mx-auto" style={{ maxWidth: '600px' }}>
            <div className="card-body text-start">
              <h5 className="font-weight-bold mb-3 text-center">{mediator.name}</h5>

              <div className="mb-3">
                <strong>Mediator DID:</strong>
                <div className="mt-1">
                  <code style={{ fontSize: '0.85rem', wordBreak: 'break-all' }}>
                    {mediator.did}
                  </code>
                </div>
              </div>

              {mediator.our_did && (
                <div className="mb-3">
                  <strong>Our DID:</strong>
                  <div className="mt-1">
                    <code style={{ fontSize: '0.85rem', wordBreak: 'break-all' }}>
                      {mediator.our_did}
                    </code>
                  </div>
                  <small className="text-muted d-block mt-1">
                    <i className="fas fa-info-circle me-1"></i>
                    This is a persistent did:peer used for administrative communications with this
                    mediator
                  </small>
                </div>
              )}

              {mediator.description && (
                <div className="mb-3">
                  <strong>Description:</strong>
                  <div className="mt-1">{mediator.description}</div>
                </div>
              )}

              <div className="mb-3">
                <strong>Status:</strong>
                <div className="mt-1">
                  <span className="badge text-bg-success">ACTIVE</span>
                </div>
              </div>

              <div className="mb-0">
                <strong>Created:</strong>
                <div className="mt-1">{new Date(mediator.created_at).toLocaleString()}</div>
              </div>
            </div>
          </div>

          <div className="d-flex justify-content-center" style={{ gap: '1rem' }}>
            <button type="button" className="btn btn-secondary" onClick={onFinish}>
              <i className="fas fa-list me-2"></i> View All Mediators
            </button>
            <button type="button" className="btn btn-primary" onClick={onViewMediator}>
              <i className="fas fa-edit me-2"></i> Edit Mediator
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CompleteStep;
