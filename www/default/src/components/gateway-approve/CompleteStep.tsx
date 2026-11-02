import React from 'react';

interface CompleteStepProps {
  gateway: any;
  onFinish: () => void;
  onViewGateway: () => void;
}

const CompleteStep: React.FC<CompleteStepProps> = ({ gateway, onFinish, onViewGateway }) => {
  return (
    <div className="card shadow">
      <div className="card-header py-3 bg-success text-white">
        <h6 className="m-0 font-weight-bold">
          <i className="fas fa-check-circle me-2"></i> Gateway Connection Approved!
        </h6>
      </div>
      <div className="card-body">
        <div className="text-center py-4">
          <div className="mb-3">
            <i className="fas fa-check-circle hero-status-icon success"></i>
          </div>
          <h4 className="mt-3">Connection Successfully Established</h4>
          <p className="text-muted">The gateway connection has been approved and is now active.</p>
        </div>

        {gateway && (
          <div className="card bg-light">
            <div className="card-body">
              <h6 className="text-primary mb-3">Gateway Information</h6>
              <dl className="row mb-0" style={{ fontSize: '0.875rem' }}>
                <dt className="col-sm-3">Name:</dt>
                <dd className="col-sm-9">{gateway.name}</dd>

                <dt className="col-sm-3">Description:</dt>
                <dd className="col-sm-9">
                  {gateway.description || (
                    <span className="text-muted">No description provided</span>
                  )}
                </dd>

                <dt className="col-sm-3">Status:</dt>
                <dd className="col-sm-9">
                  <span className="badge text-bg-success">ACTIVE</span>
                </dd>

                {gateway.did && (
                  <>
                    <dt className="col-sm-3">Gateway DID:</dt>
                    <dd className="col-sm-9">
                      <code style={{ fontSize: '0.75rem' }}>{gateway.did}</code>
                    </dd>
                  </>
                )}
              </dl>
            </div>
          </div>
        )}

        <div className="alert alert-info mt-3">
          <i className="fas fa-info-circle me-2"></i>
          The remote gateway can now communicate with this appliance. You can manage this connection
          from the Gateways page.
        </div>

        <div className="d-flex justify-content-between mt-4">
          <button type="button" className="btn btn-primary" onClick={onFinish}>
            <i className="fas fa-list me-1"></i> Back to Gateways
          </button>
          <button type="button" className="btn btn-info" onClick={onViewGateway}>
            <i className="fas fa-eye me-1"></i> View Gateway Details
          </button>
        </div>
      </div>
    </div>
  );
};

export default CompleteStep;
