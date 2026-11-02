import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../api';
import { validateUrl } from '../utils/urlValidation';

const AddWebhookWizardPage: React.FC = () => {
  const navigate = useNavigate();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [url, setUrl] = useState('');
  const [secret, setSecret] = useState('');
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Generate a random UUID for the secret
  const generateSecret = () => {
    return crypto.randomUUID();
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    // Validation
    if (!name.trim()) {
      setError('Webhook name is required');
      return;
    }

    const urlCheck = validateUrl(url);
    if (!urlCheck.valid) {
      setError(`Webhook URL: ${urlCheck.error}`);
      return;
    }

    try {
      setIsSubmitting(true);

      const payload = {
        name: name.trim(),
        description: description.trim(),
        url: url.trim(),
        secret: secret.trim() || undefined,
      };

      const response = await apiClient.post('/webhooks', payload);

      // Navigate to the integrations page
      navigate('/integrations', { replace: true });
    } catch (err: any) {
      console.error('Failed to create webhook:', err);
      setError(err.response?.data?.message || err.message || 'Failed to create webhook');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleCancel = () => {
    navigate('/integrations');
  };

  return (
    <div className="container-fluid">
      <div className="mb-3">
        <button className="btn btn-sm btn-secondary" onClick={handleCancel} disabled={isSubmitting}>
          <i className="fas fa-arrow-left"></i>
        </button>
      </div>
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <div>
          <h1 className="h3 mb-0 text-gray-800">
            <i className="fas fa-webhook me-2"></i>
            Add Webhook
          </h1>
          <p className="text-muted mt-2">
            Create a new webhook to receive HTTP notifications from connection points
          </p>
        </div>
      </div>

      <div className="row">
        <div className="col-lg-8">
          <div className="card shadow">
            <div className="card-header py-3">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-info-circle me-2"></i>
                Webhook Details
              </h6>
            </div>
            <div className="card-body">
              {error && (
                <div className="alert alert-danger" role="alert">
                  <i className="fas fa-exclamation-triangle me-2"></i>
                  {error}
                </div>
              )}

              <form onSubmit={handleSubmit}>
                <div className="mb-3">
                  <label htmlFor="name" className="form-label">
                    Webhook Name *
                  </label>
                  <input
                    type="text"
                    id="name"
                    className="form-control"
                    value={name}
                    onChange={e => setName(e.target.value)}
                    placeholder="e.g., Customer Service Webhook"
                    disabled={isSubmitting}
                    required
                  />
                  <small className="form-text text-muted">
                    A friendly name to identify this webhook
                  </small>
                </div>

                <div className="mb-3">
                  <label htmlFor="description" className="form-label">
                    Description
                  </label>
                  <input
                    id="description"
                    className="form-control"
                    value={description}
                    onChange={e => setDescription(e.target.value)}
                    placeholder="Describe the purpose of this webhook..."
                    disabled={isSubmitting}
                  />
                  <small className="form-text text-muted">
                    Optional description of what this webhook is used for
                  </small>
                </div>

                <div className="mb-3">
                  <label htmlFor="url" className="form-label">
                    Webhook URL *
                  </label>
                  <input
                    type="url"
                    id="url"
                    className="form-control"
                    value={url}
                    onChange={e => setUrl(e.target.value)}
                    placeholder="https://example.com/webhook"
                    disabled={isSubmitting}
                    required
                  />
                  <small className="form-text text-muted">
                    HTTP endpoint to POST messages to when they arrive on connection points
                  </small>
                </div>

                <div className="mb-3">
                  <label htmlFor="secret" className="form-label">
                    Webhook Secret (Recommended)
                  </label>
                  <div className="input-group">
                    <input
                      type="text"
                      id="secret"
                      className="form-control font-monospace"
                      value={secret}
                      onChange={e => setSecret(e.target.value)}
                      placeholder="Enter or generate a secret..."
                      disabled={isSubmitting}
                    />
                    <button
                      type="button"
                      className="btn btn-outline-secondary"
                      onClick={() => setSecret(generateSecret())}
                      title="Generate new secret"
                      disabled={isSubmitting}
                    >
                      <i className="fas fa-sync-alt"></i>
                    </button>
                  </div>
                  <small className="form-text text-muted">
                    <i className="fas fa-lock me-1"></i>
                    Used to sign webhook payloads with HMAC-SHA256. The signature is sent in the
                    X-Webhook-Signature header.
                  </small>
                </div>

                <div className="alert alert-info mb-4">
                  <i className="fas fa-info-circle me-2"></i>
                  <strong>Webhook Payload:</strong> Messages will be POSTed as JSON with details
                  including message ID, type, body, and metadata. Includes automatic retry with
                  exponential backoff.
                </div>

                <div className="d-flex justify-content-between">
                  <button
                    type="button"
                    className="btn btn-outline-secondary"
                    onClick={handleCancel}
                    disabled={isSubmitting}
                  >
                    <i className="fas fa-arrow-left"></i>
                  </button>
                  <button type="submit" className="btn btn-primary" disabled={isSubmitting}>
                    {isSubmitting ? (
                      <>
                        <span
                          className="spinner-border spinner-border-sm me-2"
                          role="status"
                          aria-hidden="true"
                        ></span>
                        Creating...
                      </>
                    ) : (
                      <>
                        <i className="fas fa-plus me-1"></i> Create Webhook
                      </>
                    )}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>

        <div className="col-lg-4">
          <div className="card shadow mb-4">
            <div className="card-header py-3">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-question-circle me-2"></i>
                What are Webhooks?
              </h6>
            </div>
            <div className="card-body">
              <p className="mb-2">
                Webhooks allow you to receive real-time HTTP notifications when messages arrive on
                your connection points.
              </p>
              <hr />
              <h6 className="font-weight-bold">Features:</h6>
              <ul className="mb-0">
                <li>Automatic retry with exponential backoff</li>
                <li>HMAC-SHA256 signature verification</li>
                <li>JSON payload with full message details</li>
                <li>Configurable timeout (30 seconds)</li>
              </ul>
            </div>
          </div>

          <div className="card shadow">
            <div className="card-header py-3">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-shield-alt me-2"></i>
                Security
              </h6>
            </div>
            <div className="card-body">
              <p className="mb-0">
                <strong>Webhook Secret:</strong> When provided, each webhook payload will be signed
                using HMAC-SHA256. Verify the signature in the <code>X-Webhook-Signature</code>{' '}
                header to ensure authenticity.
              </p>
            </div>
          </div>
        </div>
      </div>
      <br />
    </div>
  );
};

export default AddWebhookWizardPage;
