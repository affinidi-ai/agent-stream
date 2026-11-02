import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { apiClient } from '../api';
import { DeleteButton } from '../components/shared/DeleteButton';
import { validateUrl } from '../utils/urlValidation';

interface Webhook {
  id: string;
  name: string;
  description: string;
  url: string;
  secret: string | null;
  created_at: string;
  updated_at: string;
}

const EditWebhookPage: React.FC = () => {
  const navigate = useNavigate();
  const { id } = useParams<{ id: string }>();
  const [webhook, setWebhook] = useState<Webhook | null>(null);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [url, setUrl] = useState('');
  const [secret, setSecret] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);

  // Generate a random UUID for the secret
  const generateSecret = () => {
    return crypto.randomUUID();
  };

  useEffect(() => {
    fetchWebhook();
  }, [id]);

  const fetchWebhook = async () => {
    try {
      setLoading(true);
      const response = await apiClient.get(`/webhooks/${id}`);
      const webhookData = response.data;
      setWebhook(webhookData);
      setName(webhookData.name);
      setDescription(webhookData.description);
      setUrl(webhookData.url);
      setSecret(webhookData.secret || '');
    } catch (err: any) {
      console.error('Failed to fetch webhook:', err);
      setError(err.response?.data?.message || err.message || 'Failed to load webhook');
    } finally {
      setLoading(false);
    }
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

      await apiClient.put(`/webhooks/${id}`, payload);

      // Navigate back to integrations page
      navigate('/integrations', { replace: true });
    } catch (err: any) {
      console.error('Failed to update webhook:', err);
      setError(err.response?.data?.message || err.message || 'Failed to update webhook');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDelete = async () => {
    try {
      setIsDeleting(true);
      await apiClient.delete(`/webhooks/${id}`);
      navigate('/integrations', { replace: true });
    } catch (err: any) {
      console.error('Failed to delete webhook:', err);
      setError(err.response?.data?.message || err.message || 'Failed to delete webhook');
    } finally {
      setIsDeleting(false);
    }
  };

  const handleCancel = () => {
    navigate('/integrations');
  };

  if (loading) {
    return (
      <div className="container-fluid">
        <div
          style={{
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            minHeight: '60vh',
          }}
        >
          <div className="spinner-border text-primary" role="status">
            <span className="visually-hidden"></span>
          </div>
        </div>
      </div>
    );
  }

  if (error && !webhook) {
    return (
      <div className="container-fluid">
        <div className="alert alert-danger" role="alert">
          <i className="fas fa-exclamation-triangle me-2"></i>
          {error}
        </div>
        <button className="btn btn-secondary" onClick={() => navigate('/integrations')}>
          <i className="fas fa-arrow-left me-1"></i>
          Back to Integrations
        </button>
      </div>
    );
  }

  return (
    <div className="container-fluid">
      <div className="mb-3">
        <button className="btn btn-sm btn-secondary" onClick={() => navigate('/integrations')}>
          <i className="fas fa-arrow-left"></i>
        </button>
      </div>
      <div className="row mb-4">
        <div className="col">
          <h1 className="h3 mb-0 text-gray-800">
            <i className="fas fa-webhook me-2"></i>
            Edit Webhook
          </h1>
          <p className="text-muted mt-2">Update webhook configuration</p>
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
                  <label className="form-label text-muted">Webhook ID</label>
                  <input
                    type="text"
                    className="form-control font-monospace"
                    value={webhook?.id || ''}
                    disabled
                    readOnly
                  />
                </div>

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
                  <textarea
                    id="description"
                    className="form-control"
                    rows={3}
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
                  <div>
                    <button
                      type="button"
                      className="btn btn-outline-secondary me-2"
                      onClick={handleCancel}
                      disabled={isSubmitting || isDeleting}
                    >
                      <i className="fas fa-times me-1"></i>
                      Cancel
                    </button>
                    &nbsp;
                    <DeleteButton
                      onDelete={handleDelete}
                      disabled={isSubmitting || isDeleting}
                      variant="danger"
                    >
                      {isDeleting ? 'Deleting...' : 'Delete'}
                    </DeleteButton>
                  </div>
                  <button
                    type="submit"
                    className="btn btn-primary"
                    disabled={isSubmitting || isDeleting}
                  >
                    {isSubmitting ? (
                      <>
                        <span
                          className="spinner-border spinner-border-sm me-2"
                          role="status"
                          aria-hidden="true"
                        ></span>
                        Saving...
                      </>
                    ) : (
                      <>
                        <i className="fas fa-save me-1"></i>
                        Save Changes
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
                <i className="fas fa-clock me-2"></i>
                Metadata
              </h6>
            </div>
            <div className="card-body">
              <p className="mb-2">
                <strong>Created:</strong>
                <br />
                {webhook?.created_at ? new Date(webhook.created_at).toLocaleString() : 'N/A'}
              </p>
              <p className="mb-0">
                <strong>Last Updated:</strong>
                <br />
                {webhook?.updated_at ? new Date(webhook.updated_at).toLocaleString() : 'N/A'}
              </p>
            </div>
          </div>

          <div className="card shadow">
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
        </div>
      </div>
    </div>
  );
};

export default EditWebhookPage;
