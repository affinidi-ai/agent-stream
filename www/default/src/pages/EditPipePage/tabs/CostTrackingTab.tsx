import React from 'react';

// Types
interface FormData {
  listen_address: string;
  route: string;
  cost_tracking_enabled: boolean;
  input_price_per_1k: number;
  output_price_per_1k: number;
}

interface CostTrackingTabProps {
  formData: FormData;
  handleInputChange: (field: string, value: any) => void;
}

const CostTrackingTab: React.FC<CostTrackingTabProps> = ({ formData, handleInputChange }) => {
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
              <i className="fas fa-dollar-sign"></i> Cost Tracking
            </h6>
          </div>
        </div>
        <div className="card-body">
          <div className="mb-3">
            <div className="custom-control custom-switch">
              <input
                type="checkbox"
                className="custom-control-input"
                id="cost_tracking_enabled"
                checked={formData.cost_tracking_enabled}
                onChange={e => handleInputChange('cost_tracking_enabled', e.target.checked)}
              />
              <label className="custom-control-label" htmlFor="cost_tracking_enabled">
                Enable Cost Tracking
              </label>
            </div>
            <small className="form-text text-muted">
              Track and monitor costs for this LLM pipe
            </small>
          </div>

          {formData.cost_tracking_enabled && (
            <>
              <div className="row">
                <div className="col-md-6">
                  <div className="mb-3">
                    <label>Input Price per 1K Tokens ($)</label>
                    <input
                      type="number"
                      className="form-control"
                      value={formData.input_price_per_1k}
                      onChange={e => {
                        const val = e.target.value === '' ? 0 : parseFloat(e.target.value);
                        handleInputChange('input_price_per_1k', val);
                      }}
                      min={0}
                      step={0.00001}
                    />
                  </div>
                </div>

                <div className="col-md-6">
                  <div className="mb-3">
                    <label>Output Price per 1K Tokens ($)</label>
                    <input
                      type="number"
                      className="form-control"
                      value={formData.output_price_per_1k}
                      onChange={e => {
                        const val = e.target.value === '' ? 0 : parseFloat(e.target.value);
                        handleInputChange('output_price_per_1k', val);
                      }}
                      min={0}
                      step={0.00001}
                    />
                  </div>
                </div>
              </div>

              <div className="alert alert-success mt-3">
                <i className="fas fa-calculator me-2"></i>
                <strong>Pricing Example</strong>
                <p className="mb-0 mt-2">
                  For a request with 1,000 input tokens and 500 output tokens: $
                  {(formData.input_price_per_1k * 1 + formData.output_price_per_1k * 0.5).toFixed(
                    5
                  )}
                </p>
              </div>
            </>
          )}
        </div>
      </div>
    </>
  );
};

export default CostTrackingTab;
