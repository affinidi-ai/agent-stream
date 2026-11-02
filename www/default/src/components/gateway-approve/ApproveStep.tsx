import React, { useState } from 'react';
import { apiClient } from '../../api';
import { topAndTail } from '../../utils/stringUtils';

interface ApproveStepProps {
  gatewayId: string;
  name: string;
  description: string;
  gatewayDid: string;
  onApproved: (gateway: any) => void;
  onBack: () => void;
  onCancel: () => void;
}

const ApproveStep: React.FC<ApproveStepProps> = ({
  gatewayId,
  name,
  description,
  gatewayDid,
  onApproved,
  onBack,
  onCancel,
}) => {
  const [isApproving, setIsApproving] = useState(false);
  const [error, setError] = useState('');

  const handleApprove = async () => {
    setIsApproving(true);
    setError('');

    try {
      const response = await apiClient.post(`/gateways/${gatewayId}/approve`, {
        name,
        description,
      });
      onApproved(response.data);
    } catch (err: any) {
      console.error('Approval failed:', err);
      setError(err.response?.data || 'Failed to approve gateway connection');
      setIsApproving(false);
    }
  };

  return (
    <div className="card shadow">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-check-circle me-2"></i> Confirm Approval
        </h6>
      </div>
      <div className="card-body">
        <div className="alert alert-warning">
          <i className="fas fa-exclamation-triangle me-2"></i>
          <strong>Review Gateway Details</strong>
          <div className="mt-1">
            Please confirm the details below before approving this connection. The remote gateway
            will be able to communicate with this appliance once approved.
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

        <div className="card bg-light mb-3">
          <div className="card-body">
            <h6 className="text-primary mb-3">Gateway Information</h6>
            <dl className="row mb-0" style={{ fontSize: '0.875rem' }}>
              <dt className="col-sm-3">Name:</dt>
              <dd className="col-sm-9">{name}</dd>

              <dt className="col-sm-3">Description:</dt>
              <dd className="col-sm-9">
                {description || <span className="text-muted">No description provided</span>}
              </dd>

              <dt className="col-sm-3">Gateway DID:</dt>
              <dd className="col-sm-9">
                <code style={{ fontSize: '0.75rem' }}>{gatewayDid}</code>
              </dd>
            </dl>
          </div>
        </div>

        {isApproving && (
          <div className="alert alert-info">
            <div className="spinner-border spinner-border-sm me-2" role="status">
              <span className="sr-only">Approving...</span>
            </div>
            Establishing connection and sending approval to remote gateway...
          </div>
        )}

        <div className="d-flex justify-content-between">
          <div>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={onBack}
              disabled={isApproving}
            >
              <i className="fas fa-arrow-left me-1"></i> Back
            </button>
          </div>
          <div>
            <button
              type="button"
              className="btn btn-outline-secondary me-2"
              onClick={onCancel}
              disabled={isApproving}
            >
              <i className="fas fa-times me-1"></i> Cancel
            </button>
            <button
              type="button"
              className="btn btn-success"
              onClick={handleApprove}
              disabled={isApproving}
            >
              {isApproving ? (
                <>
                  <span
                    className="spinner-border spinner-border-sm me-1"
                    role="status"
                    aria-hidden="true"
                  ></span>
                  Approving...
                </>
              ) : (
                <>
                  <i className="fas fa-check me-1"></i> Approve Connection
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ApproveStep;
