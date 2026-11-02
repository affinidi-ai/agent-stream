import React from 'react';
import { formatDateTime, timeAgo } from '../../utils/stringUtils';

interface ConnectionPoint {
  id: string;
  gateway_id: string;
  name: string;
  description: string;
  oob_url: string;
  use_count: number;
  created_at: string;
  last_used_at?: string;
  expires_at?: string;
  enabled?: boolean;
  did_method?: string;
}

interface ConnectionPointFormData {
  name: string;
  description: string;
  enabled: boolean;
}

interface ConnectionPointOverviewTabProps {
  connectionPoint: ConnectionPoint | null;
  formData: ConnectionPointFormData;
  onInputChange: (field: keyof ConnectionPointFormData, value: string | boolean) => void;
  onCopyUrl: () => void;
}

const ConnectionPointOverviewTab: React.FC<ConnectionPointOverviewTabProps> = ({
  connectionPoint,
  formData,
  onInputChange,
  onCopyUrl,
}) => {
  // Force re-render every 30 seconds to update relative time displays ("5 minutes ago")
  const [, setTick] = React.useState(0);
  React.useEffect(() => {
    const interval = setInterval(() => {
      setTick(prev => prev + 1);
    }, 30000); // Update every 30 seconds

    return () => clearInterval(interval);
  }, []);

  if (!connectionPoint) {
    return <div>Loading...</div>;
  }

  const isExpired = connectionPoint.expires_at
    ? new Date(connectionPoint.expires_at) < new Date()
    : false;

  return (
    <>
      <div className="card shadow-sm mb-4">
        <div className="card-header bg-light">
          <div className="d-flex justify-content-between align-items-center">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-info-circle"></i> Connection Information
            </h6>
          </div>
        </div>
        <div className="card-body">
          {/* Connection Point Link */}
          <div className="mb-3">
            <label htmlFor="cp-edit-link">Connection Point Link</label>
            <div className="input-group">
              <input
                type="text"
                className="form-control"
                id="cp-edit-link"
                value={connectionPoint.oob_url}
                readOnly
                style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}
              />
              <button
                className="btn btn-outline-secondary"
                type="button"
                onClick={onCopyUrl}
                title="Copy to clipboard"
              >
                <i className="fas fa-copy"></i>
              </button>
            </div>
          </div>

          {/* Name */}
          <div className="mb-3">
            <label htmlFor="cp-edit-name">Connection Point Name</label>
            <input
              type="text"
              className="form-control"
              id="cp-edit-name"
              value={formData.name}
              onChange={e => onInputChange('name', e.target.value)}
            />
          </div>

          {/* Description */}
          <div className="mb-3">
            <label htmlFor="cp-edit-description">Description</label>
            <input
              type="text"
              className="form-control"
              id="cp-edit-description"
              value={formData.description}
              onChange={e => onInputChange('description', e.target.value)}
              placeholder="Enter connection point description"
            />
          </div>

          {/* DID Method */}
          {connectionPoint.did_method && (
            <div className="mb-3">
              <label htmlFor="cp-edit-did-method">DID Method</label>
              <input
                type="text"
                className="form-control"
                id="cp-edit-did-method"
                value={
                  connectionPoint.did_method === 'peer'
                    ? 'Peer (did:peer)'
                    : connectionPoint.did_method === 'webvh'
                      ? 'WebVH (did:webvh)'
                      : 'Web (did:web)'
                }
                readOnly
                disabled
              />
            </div>
          )}

          <div className="mb-3">
            <i className="fas fa-clock text-muted me-2"></i>
            <strong> Last Used: </strong>
            {connectionPoint.last_used_at ? (
              <span>
                {timeAgo(connectionPoint.last_used_at)}
                <span className="text-muted">
                  {' '}
                  - {formatDateTime(connectionPoint.last_used_at, true)}
                </span>
              </span>
            ) : (
              <span className="text-muted">Never used</span>
            )}
          </div>
          <div className="mb-4">
            <div className="form-check">
              <input
                type="checkbox"
                className="form-check-input"
                id="cp-edit-enabled"
                checked={formData.enabled}
                onChange={e => onInputChange('enabled', e.target.checked)}
              />
              <label className="form-check-label" htmlFor="cp-edit-enabled">
                <strong>Connection Point Enabled</strong> - When unchecked, this connection point
                will be disabled
                {!formData.enabled && (
                  <span className="badge text-bg-warning ms-2">
                    <i className="fas fa-power-off"></i> DISABLED
                  </span>
                )}
              </label>
            </div>
          </div>
          <div className="mb-3">
            <span className={`badge badge-${isExpired ? 'danger' : 'success'} me-2`}>
              {isExpired ? 'EXPIRED' : 'VALID'}
            </span>
            <span className="badge text-bg-info me-2">
              <i className="fas fa-chart-line"></i> {connectionPoint.use_count} Uses
            </span>
          </div>
        </div>
      </div>
    </>
  );
};

export default ConnectionPointOverviewTab;
