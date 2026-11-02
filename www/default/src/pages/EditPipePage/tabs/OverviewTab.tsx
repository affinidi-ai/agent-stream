import React from 'react';
import { formatDateTime } from '../../../utils/stringUtils';
import PipeFlowVisualization, { PipeFlowVisualizationProps } from './PipeFlowVisualization';

interface RoutingConfig {
  available_listen_addresses: string[];
  pipe_path_prefix: Array<{ id: string; name: string; prefix: string }>;
}

interface FormData {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  listen_address: string;
  route: string;
  created_at: string;
}

interface OverviewTabProps {
  formData: FormData;
  handleInputChange: (field: string, value: any) => void;
  routingConfig: RoutingConfig | null;
  selectedPrefix: string;
  setSelectedPrefix: (value: string) => void;
  customPath: string;
  setCustomPath: (value: string) => void;
  setIsModified: (value: boolean) => void;
  flowProps?: PipeFlowVisualizationProps;
}

const OverviewTab: React.FC<OverviewTabProps> = ({
  formData,
  handleInputChange,
  routingConfig,
  selectedPrefix,
  setSelectedPrefix,
  customPath,
  setCustomPath,
  setIsModified,
  flowProps,
}) => {
  return (
    <>
      {/* Pipe Flow Visualization */}
      {flowProps && <PipeFlowVisualization {...flowProps} />}

      {/* Listener Info Box */}
      {formData.listen_address && formData.route && (
        <div className="alert alert-success mb-3" style={{ fontSize: '14px' }}>
          <i className="fas fa-info-circle me-2"></i>
          <strong>Pipe Listener:</strong> {formData.listen_address}
          {formData.route}
          <button
            type="button"
            className="btn btn-xs ms-2"
            style={{ padding: '2px 6px', fontSize: '11px', outline: 'none' }}
            onClick={e => {
              navigator.clipboard.writeText(`${formData.listen_address}${formData.route}`);
              const btn = e.currentTarget as HTMLButtonElement;
              const originalHtml = btn.innerHTML;
              btn.innerHTML = '<i class="fas fa-check"></i>';
              setTimeout(() => {
                btn.innerHTML = originalHtml;
              }, 2000);
            }}
            title="Copy to clipboard"
          >
            <i className="fas fa-copy"></i>
          </button>
        </div>
      )}

      <div className="card shadow-sm mb-4">
        <div className="card-header bg-light">
          <div className="d-flex justify-content-between align-items-center">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-info-circle"></i> Pipe Information
            </h6>
          </div>
        </div>
        <div className="card-body">
          <div className="row">
            <div className="col-md-6">
              <div className="mb-3">
                <label>Name *</label>
                <input
                  type="text"
                  className="form-control"
                  value={formData.name}
                  onChange={e => handleInputChange('name', e.target.value)}
                  required
                />
                <small className="form-text text-muted">Unique identifier for this pipe</small>
              </div>
            </div>
            <div className="col-md-6">
              <div className="mb-3">
                <label>Status</label>
                <div className="custom-control custom-switch mt-2">
                  <input
                    type="checkbox"
                    className="custom-control-input"
                    id="enabled"
                    checked={formData.enabled}
                    onChange={e => handleInputChange('enabled', e.target.checked)}
                  />
                  <label className="custom-control-label" htmlFor="enabled">
                    {formData.enabled ? 'Enabled' : 'Disabled'}
                  </label>
                </div>
                <small className="form-text text-muted">
                  When disabled, this pipe will not process any requests
                </small>
              </div>
            </div>
          </div>

          <div className="mb-3">
            <label>Description</label>
            <input
              className="form-control"
              value={formData.description}
              onChange={e => handleInputChange('description', e.target.value)}
              placeholder="Add a description for this pipe..."
            />
          </div>

          <div className="row">
            <div className="col-md-6">
              <div className="mb-3">
                <label>Pipe Identifier</label>
                <input
                  type="text"
                  className="form-control form-control-readonly"
                  value={formData.id}
                  readOnly
                  style={{ cursor: 'not-allowed' }}
                />
                <small className="form-text text-muted">Unique identifier for this pipe</small>
              </div>
            </div>
            <div className="col-md-6">
              <div className="mb-3">
                <label>Created At</label>
                <input
                  type="text"
                  className="form-control form-control-readonly"
                  value={formData.created_at ? formatDateTime(formData.created_at, true) : '-'}
                  readOnly
                  style={{ cursor: 'not-allowed' }}
                />
                <small className="form-text text-muted">Timestamp when this pipe was created</small>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Listener Configuration Card */}
      <div className="card shadow-sm mb-4">
        <div className="card-header bg-light">
          <div className="d-flex justify-content-between align-items-center">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-network-wired"></i> Listener Configuration
            </h6>
          </div>
        </div>
        <div className="card-body">
          <div className="row">
            <div className="col-md-12 mb-3">
              <label className="form-label font-weight-bold">
                Listen Address <span className="text-danger">*</span>
              </label>
              <select
                className="form-control dropdown-styling"
                value={formData.listen_address || ''}
                onChange={e => {
                  handleInputChange('listen_address', e.target.value);
                }}
                disabled={!routingConfig}
              >
                {!routingConfig ? (
                  <option value="">Loading...</option>
                ) : routingConfig.available_listen_addresses.length === 0 ? (
                  <option value="">No addresses available</option>
                ) : (
                  <>
                    <option value="">-- Select listen address --</option>
                    {routingConfig.available_listen_addresses.map(addr => (
                      <option key={addr} value={addr}>
                        {addr}
                      </option>
                    ))}
                  </>
                )}
              </select>
              <small className="form-text text-muted">The host:port this pipe listens on</small>
            </div>
          </div>

          <div className="row">
            <div className="col-md-6 mb-3">
              <label className="form-label font-weight-bold">
                Pipe Prefix <span className="text-danger">*</span>
              </label>
              <select
                className="form-control dropdown-styling"
                value={selectedPrefix}
                onChange={e => {
                  setSelectedPrefix(e.target.value);
                  setIsModified(true);
                  // Update formData.route with new prefix
                  const normalizedPath = customPath.startsWith('/')
                    ? customPath.substring(1)
                    : customPath;
                  const newRoute =
                    e.target.value && normalizedPath ? `${e.target.value}/${normalizedPath}` : '';
                  handleInputChange('route', newRoute);
                }}
                disabled={!routingConfig || routingConfig.pipe_path_prefix.length === 0}
              >
                {!routingConfig ? (
                  <option value="">Loading...</option>
                ) : routingConfig.pipe_path_prefix.length === 0 ? (
                  <option value="">No prefixes available</option>
                ) : (
                  <>
                    <option value="">-- Select prefix --</option>
                    {routingConfig.pipe_path_prefix.map(item => (
                      <option key={item.id} value={item.prefix}>
                        {item.name}
                      </option>
                    ))}
                  </>
                )}
              </select>
              <small className="form-text text-muted">Select the path prefix for your pipe</small>
            </div>
            <div className="col-md-6 mb-3">
              <label className="form-label font-weight-bold">
                Custom Path <span className="text-danger">*</span>
              </label>
              <input
                type="text"
                className="form-control"
                value={customPath.startsWith('/') ? customPath.substring(1) : customPath}
                onChange={e => {
                  const newCustomPath = e.target.value;
                  setCustomPath(newCustomPath);
                  setIsModified(true);
                  // Update formData.route with new custom path
                  const normalizedPath = newCustomPath.startsWith('/')
                    ? newCustomPath.substring(1)
                    : newCustomPath;
                  const newRoute =
                    selectedPrefix && normalizedPath ? `${selectedPrefix}/${normalizedPath}` : '';
                  handleInputChange('route', newRoute);
                }}
                placeholder="e.g., my-gpt-4"
              />
              <small className="form-text text-muted">
                Enter a custom path segment (without leading slash)
              </small>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default OverviewTab;
