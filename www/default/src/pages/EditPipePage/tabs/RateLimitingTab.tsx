import React from 'react';

// Types
interface RateLimitConfig {
  can_disable: boolean;
  can_change: boolean;
  requests_per_minute: {
    min: number;
    max: number;
    default: number;
  };
  tokens_per_minute: {
    min: number;
    max: number;
    default: number;
  };
}

interface Model {
  rate_limiting?: RateLimitConfig;
}

interface FormData {
  listen_address: string;
  route: string;
  rate_limit_enabled: boolean;
  requests_per_minute: number;
  tokens_per_minute: number;
}

interface RateLimitingTabProps {
  formData: FormData;
  handleInputChange: (field: string, value: any) => void;
  selectedModel: Model | null;
}

const RateLimitingTab: React.FC<RateLimitingTabProps> = ({
  formData,
  handleInputChange,
  selectedModel,
}) => {
  return (
    <>
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
              <i className="fas fa-tachometer-alt"></i> Rate Limiting
            </h6>
            <div className="custom-control custom-switch">
              <input
                type="checkbox"
                className="custom-control-input"
                id="rate_limit_enabled"
                checked={formData.rate_limit_enabled}
                onChange={e => handleInputChange('rate_limit_enabled', e.target.checked)}
                disabled={
                  selectedModel?.rate_limiting ? !selectedModel.rate_limiting.can_disable : false
                }
              />
              <label className="custom-control-label" htmlFor="rate_limit_enabled">
                Enabled
                {selectedModel?.rate_limiting && !selectedModel.rate_limiting.can_disable && (
                  <span className="badge text-bg-secondary ms-2">Required</span>
                )}
              </label>
            </div>
          </div>
        </div>
        {formData.rate_limit_enabled && (
          <div className="card-body">
            <>
              <div className="alert alert-info">
                <i className="fas fa-info-circle me-2"></i>
                <strong>Rate Limiting Benefits:</strong>
                <ul className="mb-0 mt-2">
                  <li>Prevent exceeding provider API quotas</li>
                  <li>Control costs by limiting token usage</li>
                  <li>Improve system stability with predictable load</li>
                  <li>Avoid rate limit errors from LLM providers</li>
                </ul>
              </div>

              <div className="row">
                <div className="col-md-6">
                  <div className="mb-3">
                    <label>
                      Requests per Minute
                      <span className="text-danger ms-1">*</span>
                      {selectedModel?.rate_limiting && !selectedModel.rate_limiting.can_change && (
                        <span className="badge text-bg-secondary ms-2">Fixed</span>
                      )}
                    </label>
                    <input
                      type="number"
                      className="form-control"
                      value={formData.requests_per_minute}
                      onChange={e => {
                        const val = e.target.value === '' ? 0 : parseInt(e.target.value, 10);
                        handleInputChange('requests_per_minute', val);
                      }}
                      min={selectedModel?.rate_limiting?.requests_per_minute.min || 1}
                      max={selectedModel?.rate_limiting?.requests_per_minute.max || 10000}
                      disabled={
                        selectedModel?.rate_limiting
                          ? !selectedModel.rate_limiting.can_change
                          : false
                      }
                      required
                    />
                    <small className="form-text text-muted">
                      {selectedModel?.rate_limiting?.can_change
                        ? `Allowed range: ${selectedModel.rate_limiting.requests_per_minute.min} - ${selectedModel.rate_limiting.requests_per_minute.max} (default: ${selectedModel.rate_limiting.requests_per_minute.default}) • ~${(formData.requests_per_minute / 60).toFixed(1)} requests per second`
                        : selectedModel?.rate_limiting && !selectedModel.rate_limiting.can_change
                          ? `Fixed at ${selectedModel.rate_limiting.requests_per_minute.default} requests per minute for this model • ~${(formData.requests_per_minute / 60).toFixed(1)} requests per second`
                          : `Maximum number of requests allowed per minute • ~${(formData.requests_per_minute / 60).toFixed(1)} requests per second`}
                    </small>
                  </div>
                </div>

                <div className="col-md-6">
                  <div className="mb-3">
                    <label>
                      Tokens per Minute
                      <span className="text-danger ms-1">*</span>
                      {selectedModel?.rate_limiting && !selectedModel.rate_limiting.can_change && (
                        <span className="badge text-bg-secondary ms-2">Fixed</span>
                      )}
                    </label>
                    <input
                      type="number"
                      className="form-control"
                      value={formData.tokens_per_minute}
                      onChange={e => {
                        const val = e.target.value === '' ? 0 : parseInt(e.target.value, 10);
                        handleInputChange('tokens_per_minute', val);
                      }}
                      min={selectedModel?.rate_limiting?.tokens_per_minute.min || 1000}
                      max={selectedModel?.rate_limiting?.tokens_per_minute.max || 1000000}
                      step="1000"
                      disabled={
                        selectedModel?.rate_limiting
                          ? !selectedModel.rate_limiting.can_change
                          : false
                      }
                      required
                    />
                    <small className="form-text text-muted">
                      {selectedModel?.rate_limiting?.can_change
                        ? `Allowed range: ${selectedModel.rate_limiting.tokens_per_minute.min.toLocaleString()} - ${selectedModel.rate_limiting.tokens_per_minute.max.toLocaleString()} (default: ${selectedModel.rate_limiting.tokens_per_minute.default.toLocaleString()}) • ~${Math.round(formData.tokens_per_minute / 60).toLocaleString()} tokens per second`
                        : selectedModel?.rate_limiting && !selectedModel.rate_limiting.can_change
                          ? `Fixed at ${selectedModel.rate_limiting.tokens_per_minute.default.toLocaleString()} tokens per minute for this model • ~${Math.round(formData.tokens_per_minute / 60).toLocaleString()} tokens per second`
                          : `Maximum tokens processed per minute • ~${Math.round(formData.tokens_per_minute / 60).toLocaleString()} tokens per second`}
                    </small>
                  </div>
                </div>
              </div>

              <div className="alert alert-warning mt-3">
                <i className="fas fa-exclamation-triangle me-2"></i>
                <strong>Provider Limits:</strong> Make sure these values are within your LLM
                provider's tier limits. Exceeding provider quotas may result in throttling or
                additional charges.
              </div>
            </>
          </div>
        )}
      </div>
    </>
  );
};

export default RateLimitingTab;
