import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useLimitGuard } from '../hooks/useLimitGuard';
import { Tab, Tabs } from 'react-bootstrap';
import { DeleteButton } from '../components/shared/DeleteButton';
import { AppButton } from '../components/shared/AppButton';
import { Badge } from '../components/shared/Badge';
import { EmptyState } from '../components/shared/EmptyState';
import { apiClient, ApiKeyMeta, ApiKeyCreated } from '../api';
import SearchInput from '../components/shared/SearchInput';
import { formatDateTime } from '../utils/stringUtils';
import { CertificateKind, CERTIFICATE_KIND_LABEL } from '../types';
import { showToast } from '../utils/toaster';
import { apiKeySurfaceOptions, type ApiKeySurfaceOption } from './SecretsPage/apiKeySurfaceOptions';
import AccessTokensTab from './SecretsPage/AccessTokensTab';

interface Secret {
  id: string;
  name: string;
  secret_id: string;
  description?: string;
  secret_type?: string;
  tags: string[];
  created_at: string;
  updated_at: string;
}

interface Certificate {
  id: string;
  name: string;
  certificate_id: string;
  description?: string;
  tags: string[];
  created_at: string;
  updated_at: string;
  expires_at?: string;
  active: boolean;
  kind?: CertificateKind;
}

const PAGE_SIZE = 10;

const SecretsPage: React.FC = () => {
  const navigate = useNavigate();
  const { guard, balloonNode } = useLimitGuard();
  const [searchParams, setSearchParams] = useSearchParams();

  type TabKey = 'secrets' | 'api-keys' | 'certificates' | 'access-tokens';
  const [activeTab, setActiveTab] = useState<TabKey>(
    (searchParams.get('tab') as TabKey) || 'secrets'
  );

  const [secrets, setSecrets] = useState<Secret[]>([]);
  const [apiKeys, setApiKeys] = useState<ApiKeyMeta[]>([]);
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');

  // Pagination state
  const [secretsPage, setSecretsPage] = useState(1);
  const [apiKeysPage, setApiKeysPage] = useState(1);
  const [certsPage, setCertsPage] = useState(1);

  // Certificate kind filter
  const [certKindFilter, setCertKindFilter] = useState<'all' | CertificateKind>('all');

  // Surface name lookup (loaded once)
  const [surfaceNameMap, setSurfaceNameMap] = useState<Record<string, string>>({});
  const [surfaces, setSurfaces] = useState<ApiKeySurfaceOption[]>([]);

  // Create modal state
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [createSurfaceId, setCreateSurfaceId] = useState('');
  const [createClientId, setCreateClientId] = useState('');
  const [creating, setCreating] = useState(false);

  // Secret display modal state
  const [createdKey, setCreatedKey] = useState<ApiKeyCreated | null>(null);
  const [secretCopied, setSecretCopied] = useState(false);

  const loadSurfaces = async () => {
    try {
      const response = await apiClient.fetch('/api/v1/pipes');
      if (!response.ok) {
        throw new Error(`Failed to load surfaces: ${response.status}`);
      }
      const list = apiKeySurfaceOptions(await response.json());
      setSurfaces(list);
      const map: Record<string, string> = {};
      for (const s of list) {
        map[s.id] = s.name;
      }
      setSurfaceNameMap(map);
    } catch (error) {
      console.error('Failed to load surfaces for API key creation:', error);
      setSurfaces([]);
      setSurfaceNameMap({});
    }
  };

  const loadAllData = async () => {
    setLoading(true);
    await Promise.all([loadSecrets(), loadApiKeys(), loadCertificates()]);
    setLoading(false);
  };

  useEffect(() => {
    loadSurfaces();
    loadAllData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const loadSecrets = async () => {
    try {
      const response = await apiClient.fetch('/api/v1/secrets/');
      if (response.ok) {
        const data = await response.json();
        setSecrets(data);
      }
    } catch (error) {
      console.error('Failed to load secrets:', error);
    }
  };

  const loadApiKeys = async () => {
    try {
      const data = await apiClient.listAllApiKeys();
      setApiKeys(data);
    } catch (error) {
      console.error('Failed to load API keys:', error);
    }
  };

  const loadCertificates = async () => {
    try {
      const response = await apiClient.fetch('/api/v1/certificates/');
      if (response.ok) {
        const data = await response.json();
        setCertificates(data);
      }
    } catch (error) {
      console.error('Failed to load certificates:', error);
      // Set empty array if endpoint doesn't exist yet
      setCertificates([]);
    }
  };

  const handleDelete = async (secretId: string) => {
    try {
      const response = await apiClient.fetch(`/api/v1/secrets/${secretId}`, {
        method: 'DELETE',
      });

      if (response.ok) {
        loadSecrets();
      }
    } catch (error) {
      console.error('Failed to delete secret:', error);
    }
  };

  const handleDeleteApiKey = async (agentId: string, keyId: string) => {
    try {
      await apiClient.deleteApiKey(agentId, keyId);
      loadApiKeys();
    } catch (error) {
      console.error('Failed to delete API key:', error);
    }
  };

  const handleRevokeApiKey = async (agentId: string, keyId: string) => {
    try {
      await apiClient.revokeApiKey(agentId, keyId, 'dashboard');
      showToast('success', 'API key revoked');
      loadApiKeys();
    } catch (error) {
      console.error('Failed to revoke API key:', error);
    }
  };

  const handleRotateApiKey = async (agentId: string, keyId: string) => {
    try {
      const created = await apiClient.rotateApiKey(agentId, keyId, 'dashboard');
      setCreatedKey(created);
      setSecretCopied(false);
      showToast('success', 'API key rotated');
      loadApiKeys();
    } catch (error) {
      console.error('Failed to rotate API key:', error);
    }
  };

  const handleCreateApiKey = async () => {
    if (!createSurfaceId || !createClientId) return;
    setCreating(true);
    try {
      const created = await apiClient.createApiKey(createSurfaceId, createClientId);
      setCreatedKey(created);
      setSecretCopied(false);
      setShowCreateModal(false);
      setCreateSurfaceId('');
      setCreateClientId('');
      showToast('success', 'API key created');
      loadApiKeys();
    } catch (error) {
      console.error('Failed to create API key:', error);
    } finally {
      setCreating(false);
    }
  };

  const handleDeleteCertificate = async (certId: string) => {
    try {
      const response = await apiClient.fetch(`/api/v1/certificates/${certId}`, {
        method: 'DELETE',
      });

      if (response.ok) {
        loadCertificates();
      }
    } catch (error) {
      console.error('Failed to delete certificate:', error);
    }
  };

  const filteredSecrets = secrets.filter(secret => {
    const trimmedSearch = searchTerm.trim();
    if (!trimmedSearch) return true;

    const searchLower = trimmedSearch.toLowerCase();
    return (
      secret.name.toLowerCase().includes(searchLower) ||
      secret.description?.toLowerCase().includes(searchLower) ||
      secret.secret_id.toLowerCase().includes(searchLower) ||
      secret.tags.some(tag => tag.toLowerCase().includes(searchLower))
    );
  });

  const filteredApiKeys = apiKeys.filter(key => {
    const trimmedSearch = searchTerm.trim();
    if (!trimmedSearch) return true;

    const searchLower = trimmedSearch.toLowerCase();
    const surfaceName = surfaceNameMap[key.agent_id] || key.agent_id;
    return (
      key.client_id.toLowerCase().includes(searchLower) ||
      key.key_id.toLowerCase().includes(searchLower) ||
      surfaceName.toLowerCase().includes(searchLower) ||
      key.status.toLowerCase().includes(searchLower) ||
      Object.values(key.labels || {}).some(v => v.toLowerCase().includes(searchLower))
    );
  });

  const filteredCertificates = certificates.filter(cert => {
    const certKind: CertificateKind = cert.kind ?? 'server_leaf';
    if (certKindFilter !== 'all' && certKind !== certKindFilter) return false;

    const trimmedSearch = searchTerm.trim();
    if (!trimmedSearch) return true;

    const searchLower = trimmedSearch.toLowerCase();
    return (
      cert.name.toLowerCase().includes(searchLower) ||
      cert.description?.toLowerCase().includes(searchLower) ||
      cert.tags.some(tag => tag.toLowerCase().includes(searchLower))
    );
  });

  // Pagination helpers
  const paginate = <T,>(items: T[], page: number) => {
    const start = (page - 1) * PAGE_SIZE;
    return items.slice(start, start + PAGE_SIZE);
  };

  const totalPages = (count: number) => Math.max(1, Math.ceil(count / PAGE_SIZE));

  const pagedSecrets = paginate(filteredSecrets, secretsPage);
  const pagedApiKeys = paginate(filteredApiKeys, apiKeysPage);
  const pagedCertificates = paginate(filteredCertificates, certsPage);

  const PaginationControls: React.FC<{
    currentPage: number;
    total: number;
    onPageChange: (p: number) => void;
  }> = ({ currentPage, total, onPageChange }) => {
    const pages = totalPages(total);
    if (pages <= 1) return null;
    return (
      <div className="d-flex justify-content-between align-items-center mt-2 px-1">
        <small className="text-muted">
          {(currentPage - 1) * PAGE_SIZE + 1}–{Math.min(currentPage * PAGE_SIZE, total)} of {total}
        </small>
        <nav>
          <ul className="pagination pagination-sm mb-0">
            <li className={`page-item ${currentPage <= 1 ? 'disabled' : ''}`}>
              <button className="page-link" onClick={() => onPageChange(currentPage - 1)}>
                &lsaquo;
              </button>
            </li>
            {Array.from({ length: pages }, (_, i) => i + 1)
              .filter(p => p === 1 || p === pages || Math.abs(p - currentPage) <= 1)
              .reduce<(number | '...')[]>((acc, p, idx, arr) => {
                if (idx > 0 && p - (arr[idx - 1] as number) > 1) acc.push('...');
                acc.push(p);
                return acc;
              }, [])
              .map((p, idx) =>
                p === '...' ? (
                  <li key={`ellipsis-${idx}`} className="page-item disabled">
                    <span className="page-link">…</span>
                  </li>
                ) : (
                  <li key={p} className={`page-item ${p === currentPage ? 'active' : ''}`}>
                    <button className="page-link" onClick={() => onPageChange(p as number)}>
                      {p}
                    </button>
                  </li>
                )
              )}
            <li className={`page-item ${currentPage >= pages ? 'disabled' : ''}`}>
              <button className="page-link" onClick={() => onPageChange(currentPage + 1)}>
                &rsaquo;
              </button>
            </li>
          </ul>
        </nav>
      </div>
    );
  };

  const filterActive = searchTerm.trim().length > 0;
  const tabBadge = (count: number) => {
    if (!filterActive) return null;
    return (
      <span className="badge text-bg-primary ms-2" style={{ verticalAlign: 'middle' }}>
        {count}
      </span>
    );
  };

  return (
    <div className="container-fluid">
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <div className="d-flex align-items-center">
          <SearchInput
            value={searchTerm}
            onChange={setSearchTerm}
            placeholder="Filter Secrets, API Keys, Certificates, Access Tokens..."
            width="384px"
          />
        </div>
      </div>

      <Tabs
        activeKey={activeTab}
        onSelect={k => {
          const next = (k as TabKey) || 'secrets';
          setActiveTab(next);
          setSearchParams({ tab: next }, { replace: true });
        }}
        className="mb-4 custom-channel-tabs"
      >
        <Tab
          eventKey="secrets"
          title={
            <>
              <i className="fas fa-key"></i> Secrets {tabBadge(filteredSecrets.length)}
            </>
          }
        >
          <div className="card shadow mb-4">
            <div className="card-header py-3 d-flex justify-content-between align-items-center">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-key"></i> Secrets
                {secrets.length > 0 && (
                  <Badge
                    value={filteredSecrets.length}
                    suffix={searchTerm ? ` of ${secrets.length}` : undefined}
                    className="ms-2"
                    ariaLabel={`${filteredSecrets.length}${searchTerm ? ` of ${secrets.length}` : ''} secrets`}
                  />
                )}
              </h6>
              {secrets.length > 0 && (
                <>
                  <AppButton
                    variant="primary"
                    size="sm"
                    onClick={e => guard('secrets.secret', () => navigate('/secrets/new'), e)}
                    iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
                  >
                    New Secret
                  </AppButton>
                  {balloonNode}
                </>
              )}
            </div>
            <div className="card-body">
              {loading ? (
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
              ) : secrets.length === 0 && !searchTerm ? (
                <EmptyState
                  icon="fa-key"
                  title="Add your first secret"
                  body="Store sensitive values the gateway needs at runtime."
                  ctaLabel="New Secret"
                  ctaIcon="fa-plus"
                  onCtaClick={() => navigate('/secrets/new')}
                />
              ) : filteredSecrets.length === 0 ? (
                <div className="text-center text-muted py-5">
                  <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
                  <p className={secrets.length === 0 ? 'mb-3' : 'mb-0'}>
                    No secrets match your search.
                  </p>
                  {secrets.length === 0 && (
                    <AppButton
                      variant="primary"
                      size="sm"
                      onClick={() => navigate('/secrets/new')}
                      iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
                    >
                      New Secret
                    </AppButton>
                  )}
                </div>
              ) : (
                <div className="table-responsive">
                  <table className="table table-hover table-sm">
                    <thead>
                      <tr>
                        <th>Name</th>
                        <th>Secret ID</th>
                        <th>Description</th>
                        <th>Tags</th>
                        <th>Type</th>
                        <th>Created</th>
                        <th>Updated</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {pagedSecrets.map(secret => (
                        <tr
                          key={secret.id}
                          style={{ cursor: 'pointer' }}
                          onClick={() => navigate(`/secrets/${secret.id}`)}
                        >
                          <td>
                            <strong>{secret.name}</strong>
                          </td>
                          <td>
                            <code className="text-muted">{secret.secret_id}</code>
                          </td>
                          <td>{secret.description || '-'}</td>
                          <td>
                            {secret.tags.length > 0 ? (
                              secret.tags.map(tag => (
                                <span key={tag} className="badge text-bg-secondary me-1">
                                  {tag}
                                </span>
                              ))
                            ) : (
                              <span className="text-muted">-</span>
                            )}
                          </td>
                          <td>
                            <span className="badge text-bg-info">
                              {secret.secret_type || 'General'}
                            </span>
                          </td>
                          <td>
                            <small>{formatDateTime(secret.created_at)}</small>
                          </td>
                          <td>
                            <small>{formatDateTime(secret.updated_at)}</small>
                          </td>
                          <td>
                            <DeleteButton
                              onDelete={() => handleDelete(secret.id)}
                              className="btn-sm"
                              title="Delete secret"
                            />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  <PaginationControls
                    currentPage={secretsPage}
                    total={filteredSecrets.length}
                    onPageChange={setSecretsPage}
                  />
                </div>
              )}
            </div>
          </div>
        </Tab>

        <Tab
          eventKey="api-keys"
          title={
            <>
              <i className="fas fa-key"></i> API Keys {tabBadge(filteredApiKeys.length)}
            </>
          }
        >
          {/* API Keys Card */}
          <div className="card shadow mb-4">
            <div className="card-header py-3 d-flex justify-content-between align-items-center">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-key"></i> API Keys
                {apiKeys.length > 0 && (
                  <Badge
                    value={filteredApiKeys.length}
                    suffix={searchTerm ? ` of ${apiKeys.length}` : undefined}
                    className="ms-2"
                    ariaLabel={`${filteredApiKeys.length}${searchTerm ? ` of ${apiKeys.length}` : ''} API keys`}
                  />
                )}
              </h6>
              {apiKeys.length > 0 && (
                <AppButton
                  variant="primary"
                  size="sm"
                  onClick={() => setShowCreateModal(true)}
                  iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
                >
                  New API Key
                </AppButton>
              )}
            </div>
            <div className="card-body">
              {loading ? (
                <div className="text-center py-5">
                  <div className="spinner-border text-primary" role="status"></div>
                </div>
              ) : apiKeys.length === 0 && !searchTerm ? (
                <EmptyState
                  icon="fa-key"
                  title="Create your first API key"
                  body="Let external clients authenticate to your surfaces."
                  ctaLabel="New API Key"
                  ctaIcon="fa-plus"
                  onCtaClick={() => setShowCreateModal(true)}
                />
              ) : filteredApiKeys.length === 0 ? (
                <div className="text-center text-muted py-5">
                  <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
                  <p className={apiKeys.length === 0 ? 'mb-3' : 'mb-0'}>
                    No API keys match your search.
                  </p>
                  {apiKeys.length === 0 && (
                    <AppButton
                      variant="primary"
                      size="sm"
                      onClick={() => setShowCreateModal(true)}
                      iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
                    >
                      New API Key
                    </AppButton>
                  )}
                </div>
              ) : (
                <div className="table-responsive">
                  <table className="table table-hover table-sm">
                    <thead>
                      <tr>
                        <th>Client ID</th>
                        <th>Key ID</th>
                        <th>Surface</th>
                        <th>Status</th>
                        <th>Created</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredApiKeys.map(apiKey => (
                        <tr
                          key={apiKey.key_id}
                          style={{ cursor: 'pointer' }}
                          onClick={() => navigate(`/api-keys/${apiKey.agent_id}/${apiKey.key_id}`)}
                        >
                          <td>
                            <strong>{apiKey.client_id}</strong>
                          </td>
                          <td>
                            <code className="text-muted">{apiKey.key_id}</code>
                          </td>
                          <td>{surfaceNameMap[apiKey.agent_id] || apiKey.agent_id}</td>
                          <td>
                            <span
                              className={`badge ${apiKey.status === 'active' ? 'text-bg-success' : 'text-bg-danger'}`}
                            >
                              {apiKey.status === 'active' ? 'Active' : 'Revoked'}
                            </span>
                            {apiKey.needs_rotation && (
                              <span className="badge text-bg-warning ms-1">Rotate required</span>
                            )}
                          </td>
                          <td>
                            <small>{new Date(apiKey.created_at).toLocaleDateString()}</small>
                          </td>
                          <td onClick={e => e.stopPropagation()}>
                            {apiKey.status === 'active' && (
                              <>
                                <button
                                  className="btn btn-outline-warning btn-sm me-1"
                                  title="Revoke"
                                  onClick={() => handleRevokeApiKey(apiKey.agent_id, apiKey.key_id)}
                                >
                                  <i className="fas fa-ban"></i>
                                </button>
                                <button
                                  className="btn btn-outline-primary btn-sm me-1"
                                  title="Rotate"
                                  onClick={() => handleRotateApiKey(apiKey.agent_id, apiKey.key_id)}
                                >
                                  <i className="fas fa-sync-alt"></i>
                                </button>
                              </>
                            )}
                            <DeleteButton
                              onDelete={() => handleDeleteApiKey(apiKey.agent_id, apiKey.key_id)}
                              className="btn-sm"
                              title="Delete API key"
                            />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>

          {/* Create API Key Modal */}
          {showCreateModal && (
            <div className="modal d-block" style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}>
              <div className="modal-dialog">
                <div className="modal-content">
                  <div className="modal-header">
                    <h5 className="modal-title">Create API Key</h5>
                    <button
                      type="button"
                      className="btn-close"
                      onClick={() => setShowCreateModal(false)}
                    ></button>
                  </div>
                  <div className="modal-body">
                    <div className="mb-3">
                      <label className="form-label">Surface</label>
                      <select
                        className="form-select"
                        value={createSurfaceId}
                        onChange={e => setCreateSurfaceId(e.target.value)}
                      >
                        <option value="">Select a surface...</option>
                        {surfaces.map(s => (
                          <option key={s.id} value={s.id}>
                            {s.name}
                          </option>
                        ))}
                      </select>
                    </div>
                    <div className="mb-3">
                      <label className="form-label">Client ID</label>
                      <input
                        type="text"
                        className="form-control"
                        value={createClientId}
                        onChange={e => setCreateClientId(e.target.value)}
                        placeholder="e.g. my-app, partner-service"
                      />
                      <div className="form-text">
                        Identifies the external client using this key.
                      </div>
                    </div>
                  </div>
                  <div className="modal-footer">
                    <button className="btn btn-secondary" onClick={() => setShowCreateModal(false)}>
                      Cancel
                    </button>
                    <button
                      className="btn btn-primary"
                      onClick={handleCreateApiKey}
                      disabled={!createSurfaceId || !createClientId || creating}
                    >
                      {creating ? 'Creating...' : 'Create'}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Secret Display Modal */}
          {createdKey && (
            <div className="modal d-block" style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}>
              <div className="modal-dialog">
                <div className="modal-content">
                  <div className="modal-header">
                    <h5 className="modal-title">API Key Created</h5>
                    <button
                      type="button"
                      className="btn-close"
                      onClick={() => setCreatedKey(null)}
                    ></button>
                  </div>
                  <div className="modal-body">
                    <div className="alert alert-warning">
                      <i className="fas fa-exclamation-triangle me-2"></i>
                      This is the only time this API key secret will be displayed. Copy it now and
                      store it securely.
                    </div>
                    <div className="mb-3">
                      <label className="form-label fw-bold">Key ID</label>
                      <div>
                        <code>{createdKey.key_id}</code>
                      </div>
                    </div>
                    <div className="mb-3">
                      <label className="form-label fw-bold">Secret</label>
                      <div className="input-group">
                        <input
                          type="text"
                          className="form-control font-monospace"
                          value={createdKey.secret}
                          readOnly
                        />
                        <button
                          className="btn btn-outline-secondary"
                          onClick={() => {
                            navigator.clipboard.writeText(createdKey.secret);
                            setSecretCopied(true);
                          }}
                        >
                          {secretCopied ? (
                            <i className="fas fa-check"></i>
                          ) : (
                            <i className="fas fa-copy"></i>
                          )}
                        </button>
                      </div>
                    </div>
                    <div className="mb-3">
                      <label className="form-label fw-bold">Client ID</label>
                      <div>{createdKey.client_id}</div>
                    </div>
                    <div className="mb-3">
                      <label className="form-label fw-bold">Surface</label>
                      <div>{surfaceNameMap[createdKey.agent_id] || createdKey.agent_id}</div>
                    </div>
                    {createdKey.rotated_from && (
                      <div className="mb-3">
                        <label className="form-label fw-bold">Rotated From</label>
                        <div>
                          <code>{createdKey.rotated_from}</code>
                        </div>
                      </div>
                    )}
                  </div>
                  <div className="modal-footer">
                    <button className="btn btn-primary" onClick={() => setCreatedKey(null)}>
                      Done
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </Tab>

        <Tab
          eventKey="certificates"
          title={
            <>
              <i className="fas fa-certificate"></i> Certificates{' '}
              {tabBadge(filteredCertificates.length)}
            </>
          }
        >
          {/* Client Certificates Card */}
          <div className="card shadow mb-4">
            <div className="card-header py-3 d-flex justify-content-between align-items-center">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-certificate"></i> Client Certificates
                {certificates.length > 0 && (
                  <Badge
                    value={filteredCertificates.length}
                    suffix={
                      searchTerm || certKindFilter !== 'all'
                        ? ` of ${certificates.length}`
                        : undefined
                    }
                    className="ms-2"
                    ariaLabel={`${filteredCertificates.length}${
                      searchTerm || certKindFilter !== 'all' ? ` of ${certificates.length}` : ''
                    } certificates`}
                  />
                )}
              </h6>
              {certificates.length > 0 && (
                <div className="d-flex align-items-center gap-2">
                  <label htmlFor="cert-kind-filter" className="text-muted small mb-0 me-1">
                    Kind:
                  </label>
                  <select
                    id="cert-kind-filter"
                    className="form-select form-select-sm"
                    style={{ width: 'auto' }}
                    value={certKindFilter}
                    onChange={e => setCertKindFilter(e.target.value as 'all' | CertificateKind)}
                  >
                    <option value="all">All</option>
                    <option value="server_leaf">{CERTIFICATE_KIND_LABEL.server_leaf}</option>
                    <option value="client_leaf">{CERTIFICATE_KIND_LABEL.client_leaf}</option>
                    <option value="ca">{CERTIFICATE_KIND_LABEL.ca}</option>
                  </select>
                  <AppButton
                    variant="primary"
                    size="sm"
                    onClick={() => navigate('/certificates/new')}
                    iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
                  >
                    New Certificate
                  </AppButton>
                </div>
              )}
            </div>
            <div className="card-body">
              {loading ? (
                <div className="text-center py-5">
                  <div className="spinner-border text-primary" role="status"></div>
                </div>
              ) : certificates.length === 0 && !searchTerm && certKindFilter === 'all' ? (
                <EmptyState
                  icon="fa-certificate"
                  title="Add your first certificate"
                  body="Used for mutual-TLS connections."
                  ctaLabel="New Certificate"
                  ctaIcon="fa-plus"
                  onCtaClick={() => navigate('/certificates/new')}
                />
              ) : filteredCertificates.length === 0 ? (
                <div className="text-center text-muted py-5">
                  <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
                  <p className={certificates.length === 0 ? 'mb-3' : 'mb-0'}>
                    No certificates match your search.
                  </p>
                  {certificates.length === 0 && (
                    <AppButton
                      variant="primary"
                      size="sm"
                      onClick={() => navigate('/certificates/new')}
                      iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
                    >
                      New Certificate
                    </AppButton>
                  )}
                </div>
              ) : (
                <div className="table-responsive">
                  <table className="table table-hover table-sm">
                    <thead>
                      <tr>
                        <th>Name</th>
                        <th>Kind</th>
                        <th>Certificate ID</th>
                        <th>Description</th>
                        <th>Tags</th>
                        <th>Status</th>
                        <th>Created</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {pagedCertificates.map(cert => (
                        <tr
                          key={cert.id}
                          style={{ cursor: 'pointer' }}
                          onClick={() => navigate(`/certificates/${cert.id}`)}
                        >
                          <td>
                            <strong>{cert.name}</strong>
                          </td>
                          <td>
                            <span className="badge text-bg-info">
                              {CERTIFICATE_KIND_LABEL[cert.kind ?? 'server_leaf']}
                            </span>
                          </td>
                          <td>
                            <code className="text-muted">{cert.certificate_id}</code>
                          </td>
                          <td>{cert.description || '-'}</td>
                          <td>
                            {cert.tags.length > 0 ? (
                              cert.tags.map(tag => (
                                <span key={tag} className="badge text-bg-secondary me-1">
                                  {tag}
                                </span>
                              ))
                            ) : (
                              <span className="text-muted">-</span>
                            )}
                          </td>
                          <td>
                            <div>
                              <span
                                className={`badge ${cert.active ? 'text-bg-success' : 'text-bg-warning'}`}
                              >
                                {cert.active ? 'Active' : 'Inactive'}
                              </span>
                              {cert.expires_at && (
                                <div className="text-muted" style={{ fontSize: '0.85rem' }}>
                                  Expires: {formatDateTime(cert.expires_at)}
                                </div>
                              )}
                            </div>
                          </td>
                          <td>
                            <small>{formatDateTime(cert.created_at)}</small>
                          </td>
                          <td>
                            <DeleteButton
                              onDelete={() => handleDeleteCertificate(cert.id)}
                              className="btn-sm"
                              title="Delete certificate"
                            />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  <PaginationControls
                    currentPage={certsPage}
                    total={filteredCertificates.length}
                    onPageChange={setCertsPage}
                  />
                </div>
              )}
            </div>
          </div>
        </Tab>

        <Tab
          eventKey="access-tokens"
          title={
            <>
              <i className="fas fa-user-lock"></i> Access Tokens (PAT)
            </>
          }
        >
          <AccessTokensTab searchTerm={searchTerm} />
        </Tab>
      </Tabs>
    </div>
  );
};

export default SecretsPage;
