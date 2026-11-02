import React, { useCallback, useState } from 'react';
import { apiClient, ApiKeyCreated, ApiKeyMeta } from '../api';
import { DeleteButton } from '../components/shared/DeleteButton';

// Modal component for displaying one-time secret
const SecretModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  keyData: ApiKeyCreated | null;
  title: string;
}> = ({ isOpen, onClose, keyData, title }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    if (keyData?.secret) {
      try {
        await navigator.clipboard.writeText(keyData.secret);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      } catch (err) {
        console.error('Failed to copy:', err);
      }
    }
  };

  if (!isOpen || !keyData) return null;

  return (
    <div
      className="modal fade show"
      style={{ display: 'block', backgroundColor: 'rgba(0,0,0,0.5)' }}
    >
      <div className="modal-dialog modal-lg">
        <div className="modal-content">
          <div className="modal-header">
            <h5 className="modal-title">{title}</h5>
            <button type="button" className="btn-close" onClick={onClose} aria-label="Close" />
          </div>
          <div className="modal-body">
            <div className="alert alert-warning">
              <i className="fas fa-exclamation-triangle me-2"></i>
              <strong>Important:</strong> This is the only time the API key secret will be
              displayed. Copy it now and store it securely.
            </div>

            <div className="mb-3">
              <label>
                <strong>Key ID</strong>
              </label>
              <input type="text" className="form-control" value={keyData.key_id} readOnly />
            </div>

            <div className="mb-3">
              <label>
                <strong>Client ID</strong>
              </label>
              <input type="text" className="form-control" value={keyData.client_id} readOnly />
            </div>

            <div className="mb-3">
              <label>
                <strong>API Key Secret</strong>
              </label>
              <div className="input-group">
                <input
                  type="text"
                  className="form-control font-monospace"
                  value={keyData.secret}
                  readOnly
                  style={{ fontFamily: 'monospace', fontSize: '0.9rem' }}
                />
                <div className="input-group-append">
                  <button
                    className={`btn ${copied ? 'btn-success' : 'btn-outline-secondary'}`}
                    onClick={handleCopy}
                    type="button"
                  >
                    <i className={`fas ${copied ? 'fa-check' : 'fa-copy'}`}></i>
                    {copied ? ' Copied!' : ' Copy'}
                  </button>
                </div>
              </div>
            </div>

            <div className="mb-3">
              <label>
                <strong>Created At</strong>
              </label>
              <code className="d-block p-2 bg-light rounded">
                {new Date(keyData.created_at).toLocaleString()}
              </code>
            </div>
          </div>
          <div className="modal-footer">
            <button type="button" className="btn btn-primary" onClick={onClose}>
              I've saved the key
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

// Create API Key Modal
const CreateKeyModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  agentId: string;
  onCreate: (
    clientId: string,
    labels: Record<string, string>,
    expiresInSeconds: number | null
  ) => Promise<void>;
}> = ({ isOpen, onClose, agentId, onCreate }) => {
  const [clientId, setClientId] = useState('');
  const [labelKey, setLabelKey] = useState('');
  const [labelValue, setLabelValue] = useState('');
  const [labels, setLabels] = useState<Record<string, string>>({});
  const [expiresInSeconds, setExpiresInSeconds] = useState<number | null>(null);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleAddLabel = () => {
    if (labelKey && labelValue) {
      setLabels(prev => ({ ...prev, [labelKey]: labelValue }));
      setLabelKey('');
      setLabelValue('');
    }
  };

  const handleRemoveLabel = (key: string) => {
    setLabels(prev => {
      const newLabels = { ...prev };
      delete newLabels[key];
      return newLabels;
    });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!clientId.trim()) {
      setError('Client ID is required');
      return;
    }

    setCreating(true);
    setError(null);
    try {
      await onCreate(clientId.trim(), labels, expiresInSeconds);
      setClientId('');
      setLabels({});
      setExpiresInSeconds(null);
      onClose();
    } catch (err: any) {
      setError(err.message || 'Failed to create API key');
    } finally {
      setCreating(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div
      className="modal fade show"
      style={{ display: 'block', backgroundColor: 'rgba(0,0,0,0.5)' }}
      data-testid="apikey-create-modal"
    >
      <div className="modal-dialog">
        <div className="modal-content">
          <div className="modal-header">
            <h5 className="modal-title">Create API Key</h5>
            <button type="button" className="btn-close" onClick={onClose} aria-label="Close" />
          </div>
          <form onSubmit={handleSubmit}>
            <div className="modal-body">
              {error && <div className="alert alert-danger">{error}</div>}

              <div className="mb-3">
                <label>
                  <strong>Agent ID</strong>
                </label>
                <input type="text" className="form-control" value={agentId} readOnly />
              </div>

              <div className="mb-3">
                <label>
                  <strong>Client ID</strong> <span className="text-danger">*</span>
                </label>
                <input
                  type="text"
                  className="form-control"
                  value={clientId}
                  onChange={e => setClientId(e.target.value)}
                  placeholder="e.g., my-service, external-partner"
                  required
                />
                <small className="form-text text-muted">
                  Identifies the client/application using this key
                </small>
              </div>

              <div className="mb-3">
                <label>
                  <strong>Labels</strong> (optional)
                </label>
                <div className="input-group mb-2">
                  <input
                    type="text"
                    className="form-control"
                    placeholder="Key"
                    value={labelKey}
                    onChange={e => setLabelKey(e.target.value)}
                  />
                  <input
                    type="text"
                    className="form-control"
                    placeholder="Value"
                    value={labelValue}
                    onChange={e => setLabelValue(e.target.value)}
                  />
                  <div className="input-group-append">
                    <button
                      type="button"
                      className="btn btn-outline-secondary"
                      onClick={handleAddLabel}
                      disabled={!labelKey || !labelValue}
                    >
                      <i className="fas fa-plus"></i>
                    </button>
                  </div>
                </div>
                {Object.entries(labels).length > 0 && (
                  <div className="mt-2">
                    {Object.entries(labels).map(([key, value]) => (
                      <span
                        key={key}
                        className="badge text-bg-secondary me-1 mb-1"
                        style={{ fontSize: '0.85rem' }}
                      >
                        {key}: {value}
                        <button
                          type="button"
                          className="btn btn-link btn-sm p-0 ms-1 text-white"
                          onClick={() => handleRemoveLabel(key)}
                          style={{ fontSize: '0.75rem' }}
                        >
                          <i className="fas fa-times"></i>
                        </button>
                      </span>
                    ))}
                  </div>
                )}
              </div>

              <div className="mb-3">
                <label>
                  <strong>Expiry</strong> (optional)
                </label>
                <select
                  className="form-control"
                  value={expiresInSeconds ?? ''}
                  onChange={e =>
                    setExpiresInSeconds(e.target.value ? Number(e.target.value) : null)
                  }
                >
                  <option value="">Never expires</option>
                  <option value={7 * 24 * 3600}>7 days</option>
                  <option value={30 * 24 * 3600}>30 days</option>
                  <option value={90 * 24 * 3600}>90 days</option>
                  <option value={180 * 24 * 3600}>180 days</option>
                  <option value={365 * 24 * 3600}>1 year</option>
                </select>
                <small className="form-text text-muted">
                  After this period the key stops authenticating. Rotating preserves the same
                  lifetime.
                </small>
              </div>
            </div>
            <div className="modal-footer">
              <button type="button" className="btn btn-secondary" onClick={onClose}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={creating}>
                {creating ? (
                  <>
                    <span className="spinner-border spinner-border-sm me-1"></span>
                    Creating...
                  </>
                ) : (
                  <>
                    <i className="fas fa-plus me-1"></i>
                    Create Key
                  </>
                )}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

// Confirmation Modal for Revoke/Rotate actions
const ConfirmModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => Promise<void>;
  title: string;
  message: string;
  confirmText: string;
  confirmVariant?: 'danger' | 'warning' | 'primary';
}> = ({ isOpen, onClose, onConfirm, title, message, confirmText, confirmVariant = 'danger' }) => {
  const [processing, setProcessing] = useState(false);

  const handleConfirm = async () => {
    setProcessing(true);
    try {
      await onConfirm();
      onClose();
    } finally {
      setProcessing(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div
      className="modal fade show"
      style={{ display: 'block', backgroundColor: 'rgba(0,0,0,0.5)' }}
      data-testid="apikey-confirm-modal"
    >
      <div className="modal-dialog">
        <div className="modal-content">
          <div className="modal-header">
            <h5 className="modal-title">{title}</h5>
            <button type="button" className="btn-close" onClick={onClose} aria-label="Close" />
          </div>
          <div className="modal-body">
            <p>{message}</p>
          </div>
          <div className="modal-footer">
            <button type="button" className="btn btn-secondary" onClick={onClose}>
              Cancel
            </button>
            <button
              type="button"
              className={`btn btn-${confirmVariant}`}
              onClick={handleConfirm}
              disabled={processing}
            >
              {processing ? (
                <>
                  <span className="spinner-border spinner-border-sm me-1"></span>
                  Processing...
                </>
              ) : (
                confirmText
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

const ApiKeysPage: React.FC = () => {
  const [agentId, setAgentId] = useState<string>('');
  const [agentIdInput, setAgentIdInput] = useState<string>('');
  const [keys, setKeys] = useState<ApiKeyMeta[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');

  // Modal states
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showSecretModal, setShowSecretModal] = useState(false);
  const [secretModalTitle, setSecretModalTitle] = useState('');
  const [createdKey, setCreatedKey] = useState<ApiKeyCreated | null>(null);
  const [showRevokeModal, setShowRevokeModal] = useState(false);
  const [showRotateModal, setShowRotateModal] = useState(false);
  const [selectedKey, setSelectedKey] = useState<ApiKeyMeta | null>(null);

  const loadKeys = useCallback(async (id: string) => {
    if (!id) return;

    console.log('[ApiKeysPage] Loading keys for agent:', id);
    setLoading(true);
    setError(null);
    try {
      const data = await apiClient.listApiKeys(id);
      console.log('[ApiKeysPage] Loaded keys:', data.length, 'keys');
      setKeys(data);
    } catch (err: any) {
      console.error('[ApiKeysPage] Failed to load API keys:', err);
      setError(err.message || 'Failed to load API keys');
      setKeys([]);
    } finally {
      setLoading(false);
    }
  }, []);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (agentIdInput.trim()) {
      console.log('[ApiKeysPage] Searching for agent:', agentIdInput.trim());
      setAgentId(agentIdInput.trim());
      loadKeys(agentIdInput.trim());
    }
  };

  const handleCreateKey = async (
    clientId: string,
    labels: Record<string, string>,
    expiresInSeconds: number | null
  ) => {
    console.log('[ApiKeysPage] Creating key for agent:', agentId, 'client:', clientId);
    const created = await apiClient.createApiKey(agentId, clientId, labels, expiresInSeconds);
    console.log('[ApiKeysPage] Key created:', created.key_id);
    setCreatedKey(created);
    setSecretModalTitle('API Key Created');
    setShowSecretModal(true);
    loadKeys(agentId);
  };

  const handleRevokeKey = async () => {
    if (!selectedKey) return;
    await apiClient.revokeApiKey(agentId, selectedKey.key_id);
    loadKeys(agentId);
  };

  const handleRotateKey = async () => {
    if (!selectedKey) return;
    const created = await apiClient.rotateApiKey(agentId, selectedKey.key_id);
    setCreatedKey(created);
    setSecretModalTitle('API Key Rotated');
    setShowRotateModal(false);
    setShowSecretModal(true);
    loadKeys(agentId);
  };

  const handleDeleteKey = async (keyId: string) => {
    try {
      await apiClient.deleteApiKey(agentId, keyId);
      loadKeys(agentId);
    } catch (err: any) {
      console.error('Failed to delete API key:', err);
      setError(err.message || 'Failed to delete API key');
    }
  };

  const filteredKeys = keys.filter(key => {
    const trimmedSearch = searchTerm.trim().toLowerCase();
    if (!trimmedSearch) return true;

    return (
      key.key_id.toLowerCase().includes(trimmedSearch) ||
      key.client_id.toLowerCase().includes(trimmedSearch) ||
      (key.prefix ?? '').toLowerCase().includes(trimmedSearch) ||
      Object.entries(key.labels ?? {}).some(
        ([k, v]) =>
          k.toLowerCase().includes(trimmedSearch) || v.toLowerCase().includes(trimmedSearch)
      )
    );
  });

  const formatDate = (dateStr?: string) => {
    if (!dateStr) return '-';
    return new Date(dateStr).toLocaleString();
  };

  return (
    <div className="container-fluid" data-testid="page-api-keys">
      {/* Agent ID Search */}
      <div className="row mb-4">
        <div className="col-12">
          <div className="card shadow">
            <div className="card-header py-3">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-search"></i> Select Agent
              </h6>
            </div>
            <div className="card-body">
              <form onSubmit={handleSearch}>
                <div className="input-group">
                  <input
                    type="text"
                    className="form-control"
                    placeholder="Enter Agent ID (e.g., did:web:example.com or agent-uuid)"
                    value={agentIdInput}
                    onChange={e => setAgentIdInput(e.target.value)}
                  />
                  <div className="input-group-append">
                    <button
                      type="submit"
                      className="btn btn-primary"
                      disabled={!agentIdInput.trim()}
                    >
                      <i className="fas fa-search me-1"></i>
                      Load Keys
                    </button>
                  </div>
                </div>
              </form>
            </div>
          </div>
        </div>
      </div>

      {/* API Keys List */}
      {agentId && (
        <div className="row">
          <div className="col-12">
            <div className="card shadow mb-4">
              <div className="card-header py-3 d-flex justify-content-between align-items-center">
                <div className="d-flex align-items-center">
                  <h6 className="m-0 font-weight-bold text-primary">
                    <i className="fas fa-key"></i> API Keys for {agentId}
                    <span
                      className="badge text-bg-primary ms-2"
                      style={{ verticalAlign: 'middle' }}
                    >
                      {filteredKeys.length}
                      {searchTerm ? ` of ${keys.length}` : ''}
                    </span>
                  </h6>
                  {keys.length > 0 && (
                    <div
                      style={{
                        position: 'relative',
                        display: 'inline-block',
                        marginLeft: '0.75rem',
                      }}
                    >
                      <i
                        className="fas fa-search"
                        style={{
                          position: 'absolute',
                          left: '0.75rem',
                          top: '50%',
                          transform: 'translateY(-50%)',
                          color: 'var(--gray-500)',
                          fontSize: '0.875rem',
                          pointerEvents: 'none',
                        }}
                      ></i>
                      <input
                        type="text"
                        className="form-control form-control-sm"
                        placeholder="Filter keys..."
                        value={searchTerm}
                        onChange={e => setSearchTerm(e.target.value)}
                        style={{
                          width: '200px',
                          paddingLeft: '2.25rem',
                          backgroundColor: 'rgba(255, 255, 255, 0.3)',
                          border: 'none',
                        }}
                      />
                    </div>
                  )}
                </div>
                <button
                  className="btn btn-sm btn-primary"
                  onClick={() => setShowCreateModal(true)}
                  data-testid="apikey-create-button"
                >
                  <i className="fas fa-plus"></i> Create Key
                </button>
              </div>
              <div className="card-body">
                {error && <div className="alert alert-danger">{error}</div>}

                {loading ? (
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'center',
                      alignItems: 'center',
                      minHeight: '200px',
                    }}
                  >
                    <div className="spinner-border text-primary" role="status">
                      <span className="visually-hidden"></span>
                    </div>
                  </div>
                ) : (
                  <div className="table-responsive">
                    <table className="table table-hover">
                      <thead>
                        <tr>
                          <th>Key ID</th>
                          <th>Client ID</th>
                          <th>Prefix</th>
                          <th>Status</th>
                          <th>Labels</th>
                          <th>Created</th>
                          <th>Expires</th>
                          <th>Last Used</th>
                          <th>Uses</th>
                          <th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredKeys.map(key => (
                          <tr key={key.key_id} data-testid={`apikey-row-${key.key_id}`}>
                            <td>
                              <code className="text-muted">{key.key_id.substring(0, 8)}...</code>
                            </td>
                            <td>
                              <strong>{key.client_id}</strong>
                            </td>
                            <td>
                              <code>{key.prefix ?? key.key_id.slice(0, 8)}</code>
                            </td>
                            <td>
                              <span
                                className={`badge badge-${key.status === 'active' ? 'success' : 'danger'}`}
                              >
                                {key.status}
                              </span>
                              {key.needs_rotation && (
                                <span className="badge text-bg-warning ms-1">Rotate required</span>
                              )}
                            </td>
                            <td>
                              {Object.entries(key.labels).length > 0 ? (
                                Object.entries(key.labels).map(([k, v]) => (
                                  <span key={k} className="badge text-bg-secondary me-1">
                                    {k}: {v}
                                  </span>
                                ))
                              ) : (
                                <span className="text-muted">-</span>
                              )}
                            </td>
                            <td>
                              <small>{formatDate(key.created_at)}</small>
                            </td>
                            <td>
                              {key.expires_at ? (
                                <small
                                  className={
                                    new Date(key.expires_at).getTime() <= Date.now()
                                      ? 'text-danger'
                                      : undefined
                                  }
                                >
                                  {formatDate(key.expires_at)}
                                  {new Date(key.expires_at).getTime() <= Date.now()
                                    ? ' (expired)'
                                    : ''}
                                </small>
                              ) : (
                                <small className="text-muted">Never</small>
                              )}
                            </td>
                            <td>
                              <small>{formatDate(key.last_used_at)}</small>
                            </td>
                            <td>{key.use_count ?? '-'}</td>
                            <td>
                              <div className="btn-group btn-group-sm">
                                {key.status === 'active' && (
                                  <>
                                    <button
                                      className="btn btn-outline-warning"
                                      title="Rotate key"
                                      onClick={() => {
                                        setSelectedKey(key);
                                        setShowRotateModal(true);
                                      }}
                                    >
                                      <i className="fas fa-sync-alt"></i>
                                    </button>
                                    <button
                                      className="btn btn-outline-danger"
                                      title="Revoke key"
                                      onClick={() => {
                                        setSelectedKey(key);
                                        setShowRevokeModal(true);
                                      }}
                                    >
                                      <i className="fas fa-ban"></i>
                                    </button>
                                  </>
                                )}
                                <DeleteButton
                                  onDelete={() => handleDeleteKey(key.key_id)}
                                  className="btn-sm"
                                  title="Delete key permanently"
                                />
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {filteredKeys.length === 0 && (
                      <div className="text-center text-muted py-4">
                        {searchTerm
                          ? 'No API keys match your search'
                          : 'No API keys found. Create your first key to get started.'}
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Modals */}
      <CreateKeyModal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        agentId={agentId}
        onCreate={handleCreateKey}
      />

      <SecretModal
        isOpen={showSecretModal}
        onClose={() => {
          setShowSecretModal(false);
          setCreatedKey(null);
        }}
        keyData={createdKey}
        title={secretModalTitle}
      />

      <ConfirmModal
        isOpen={showRevokeModal}
        onClose={() => {
          setShowRevokeModal(false);
          setSelectedKey(null);
        }}
        onConfirm={handleRevokeKey}
        title="Revoke API Key"
        message={`Are you sure you want to revoke key "${selectedKey?.key_id.substring(0, 8)}..." for client "${selectedKey?.client_id}"? This action cannot be undone and the key will no longer be valid for authentication.`}
        confirmText="Revoke Key"
        confirmVariant="danger"
      />

      <ConfirmModal
        isOpen={showRotateModal}
        onClose={() => {
          setShowRotateModal(false);
          setSelectedKey(null);
        }}
        onConfirm={handleRotateKey}
        title="Rotate API Key"
        message={`Are you sure you want to rotate key "${selectedKey?.key_id.substring(0, 8)}..." for client "${selectedKey?.client_id}"? The current key will be revoked and a new key will be generated.`}
        confirmText="Rotate Key"
        confirmVariant="warning"
      />
    </div>
  );
};

export default ApiKeysPage;
