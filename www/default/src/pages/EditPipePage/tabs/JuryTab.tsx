import React from 'react';
import { JuryConfig } from '../../../components/shared/jurorModel';

export type { JuryConfig };

interface JuryTabProps {
  formData: {
    jury?: JuryConfig | null;
    [key: string]: any;
  };
  handleInputChange: (field: string, value: any) => void;
  setIsModified: (value: boolean) => void;
  /** Hide the header enable/disable toggle (it lives in the node properties). */
  hideEnableToggle?: boolean;
  /** Close the editor tab (renders a header control when provided). */
  onClose?: () => void;
}

const JuryTab: React.FC<JuryTabProps> = ({
  formData,
  handleInputChange,
  setIsModified,
  hideEnableToggle,
  onClose,
}) => {
  const jury = formData.jury || null;
  const isEnabled = jury?.enabled ?? false;

  const updateJury = (updates: Partial<JuryConfig>) => {
    const current: JuryConfig = jury || {
      enabled: false,
      mode: 'parallel',
      jurors: [],
    };
    handleInputChange('jury', { ...current, ...updates });
    setIsModified(true);
  };

  const handleToggle = () => {
    if (!jury) {
      handleInputChange('jury', {
        enabled: true,
        mode: 'parallel',
        jurors: [],
      } as JuryConfig);
    } else {
      updateJury({ enabled: !isEnabled });
    }
    setIsModified(true);
  };

  return (
    <div>
      <div className="card shadow-sm mb-4">
        <div className="card-header bg-light d-flex justify-content-between align-items-center">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-gavel me-2"></i>
            Negative Verdict Handling
          </h6>
          {(!hideEnableToggle || onClose) && (
            <div className="d-flex align-items-center gap-3">
              {!hideEnableToggle && (
                <div className="form-check m-0">
                  <input
                    className="form-check-input"
                    type="checkbox"
                    id="jury-enabled"
                    checked={isEnabled}
                    onChange={handleToggle}
                  />
                  <label
                    className="form-check-label"
                    htmlFor="jury-enabled"
                    style={{
                      color: isEnabled ? 'var(--gray-900)' : 'var(--gray-500)',
                    }}
                  >
                    Enabled
                  </label>
                </div>
              )}
              {onClose && (
                <button
                  type="button"
                  className="btn btn-sm btn-outline-secondary"
                  onClick={onClose}
                >
                  <i className="fas fa-times me-1"></i>
                  Close tab
                </button>
              )}
            </div>
          )}
        </div>

        {!isEnabled && (
          <div className="card-body">
            <div className="alert alert-info mb-0">
              <i className="fas fa-info-circle me-2"></i>
              <strong>Jury</strong> sends the processing LLM's response to one or more LLMs for
              validation before returning it to the caller. Supports parallel, serial, and majority
              voting modes. Enable to configure.
            </div>
          </div>
        )}

        {isEnabled && (
          <div className="card-body">
            {/* Redrive policy */}
            <div className="mb-4">
              <label className="form-label fw-semibold mb-1" htmlFor="jury-redrive-policy">
                Redrive policy
              </label>
              <p className="text-muted small mb-2">
                What happens when the jury returns a negative verdict on the LLM&apos;s response.
              </p>
              <div className="row g-3">
                <div className="col-md-4">
                  <select
                    id="jury-redrive-policy"
                    className="form-control dropdown-styling"
                    value={jury?.max_retries ?? 0}
                    onChange={e => updateJury({ max_retries: parseInt(e.target.value) || 0 })}
                  >
                    <option value={0}>Return verdict immediately</option>
                    <option value={1}>Redrive once with jury feedback</option>
                    <option value={2}>Redrive twice with jury feedback</option>
                    <option value={3}>Redrive three times with jury feedback</option>
                  </select>
                </div>
                {(jury?.max_retries ?? 0) > 0 && (
                  <div className="col-md-8">
                    <label
                      className="form-label small text-muted mb-1"
                      htmlFor="jury-redrive-prompt"
                    >
                      Redrive prompt template
                    </label>
                    <textarea
                      id="jury-redrive-prompt"
                      className="form-control font-monospace"
                      rows={2}
                      value={
                        jury?.retry_prompt ??
                        'Your previous response did not pass quality and safety review: {reason}. Please revise your response to address these concerns.'
                      }
                      onChange={e => updateJury({ retry_prompt: e.target.value })}
                      style={{ fontSize: '12px' }}
                    />
                    <small className="text-muted">
                      Use <code>{'{reason}'}</code> as a placeholder for the jury&apos;s verdict
                      reason.
                    </small>
                  </div>
                )}
              </div>
            </div>

            {/* What happens on a negative verdict — immediate and redrive variants */}
            <div className="alert alert-info py-2 mb-4" style={{ fontSize: '13px' }}>
              <i className="fas fa-info-circle me-1"></i>
              {(jury?.max_retries ?? 0) > 0 ? (
                <span>
                  The LLM&apos;s response and the verdict feedback are appended to the conversation
                  and sent back to the LLM &mdash; up to <strong>{jury?.max_retries}</strong>{' '}
                  {(jury?.max_retries ?? 0) === 1 ? 'time' : 'times'}. If the verdict is still
                  negative after all redrives, the final response below is returned to the caller.
                </span>
              ) : (
                <span>
                  The response is <strong>not retried</strong>. As soon as the jury returns a
                  negative verdict, the final response below is returned to the caller.
                </span>
              )}
            </div>

            {/* Final negative-verdict response */}
            <div>
              <label className="form-label fw-semibold mb-1">Final negative-verdict response</label>
              <p className="text-muted small mb-2">
                Returned to the caller when the jury verdict is negative
                {(jury?.max_retries ?? 0) > 0 ? ' after all redrives are exhausted' : ''}.
              </p>
              <div className="row g-3">
                <div className="col-md-3">
                  <label className="form-label small text-muted mb-1" htmlFor="jury-status-code">
                    HTTP status code
                  </label>
                  <input
                    id="jury-status-code"
                    type="number"
                    className="form-control"
                    value={jury?.rejection?.status_code || 403}
                    onChange={e =>
                      updateJury({
                        rejection: {
                          ...(jury?.rejection || {
                            status_code: 403,
                            body: '',
                            content_type: 'application/json',
                          }),
                          status_code: parseInt(e.target.value) || 403,
                        },
                      })
                    }
                    min={400}
                    max={599}
                  />
                </div>
                <div className="col-md-3">
                  <label className="form-label small text-muted mb-1" htmlFor="jury-content-type">
                    Content-Type
                  </label>
                  <input
                    id="jury-content-type"
                    type="text"
                    className="form-control"
                    value={jury?.rejection?.content_type || 'application/json'}
                    onChange={e =>
                      updateJury({
                        rejection: {
                          ...(jury?.rejection || {
                            status_code: 403,
                            body: '',
                            content_type: 'application/json',
                          }),
                          content_type: e.target.value,
                        },
                      })
                    }
                  />
                </div>
                <div className="col-md-6">
                  <label className="form-label small text-muted mb-1" htmlFor="jury-response-body">
                    Response body
                  </label>
                  <textarea
                    id="jury-response-body"
                    className="form-control font-monospace"
                    rows={3}
                    value={
                      jury?.rejection?.body ||
                      '{"error":{"message":"Jury verdict: response did not pass evaluation","type":"jury_violation","code":"content_policy_violation"}}'
                    }
                    onChange={e =>
                      updateJury({
                        rejection: {
                          ...(jury?.rejection || {
                            status_code: 403,
                            body: '',
                            content_type: 'application/json',
                          }),
                          body: e.target.value,
                        },
                      })
                    }
                    style={{ fontSize: '12px' }}
                  />
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default JuryTab;
