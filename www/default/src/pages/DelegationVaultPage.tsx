import React, { useState, useEffect, useMemo } from 'react';
import { usePermissions } from '../context/PermissionsContext';
import { apiClient } from '../api';
import SearchInput from '../components/shared/SearchInput';
import { DeleteButton } from '../components/shared/DeleteButton';
import { showToast } from '../utils/toaster';

interface DelegationTokenListItem {
  id: string;
  agent_did: string;
  user_identity_hash: string;
  provider_id: string;
  scopes: string[];
  expires_at: string | null;
  consent_granted_at: string;
  last_used_at: string | null;
  is_expired: boolean;
  can_refresh: boolean;
}

const DelegationVaultPage: React.FC = () => {
  const { hasPermission } = usePermissions();
  const [tokens, setTokens] = useState<DelegationTokenListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');

  const canEdit = hasPermission('settings.edit');

  useEffect(() => {
    loadTokens();
  }, []);

  const loadTokens = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await apiClient.fetch('/api/v1/delegation-vault');
      if (!response.ok) {
        throw new Error(`Failed to load: ${response.statusText}`);
      }
      const data: DelegationTokenListItem[] = await response.json();
      setTokens(data);
    } catch (e: any) {
      setError(e.message ?? 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  const handleRevoke = async (token: DelegationTokenListItem) => {
    try {
      const response = await apiClient.fetch(
        `/api/v1/delegation-vault/${encodeURIComponent(token.id)}`,
        { method: 'DELETE' }
      );
      if (!response.ok) {
        throw new Error(`Revoke failed: ${response.statusText}`);
      }
      setTokens(prev => prev.filter(t => t.id !== token.id));
      showToast('success', 'Delegation revoked');
    } catch (e: any) {
      alert(`Failed to revoke: ${e.message}`);
    }
  };

  const handleRevokeByUser = async (userHash: string) => {
    if (!window.confirm(`Revoke ALL delegations for user ${userHash.substring(0, 16)}…?`)) {
      return;
    }
    try {
      const response = await apiClient.fetch(
        `/api/v1/delegation-vault/by-user/${encodeURIComponent(userHash)}`,
        { method: 'DELETE' }
      );
      if (!response.ok) {
        throw new Error(`Bulk revoke failed: ${response.statusText}`);
      }
      setTokens(prev => prev.filter(t => t.user_identity_hash !== userHash));
      showToast('success', 'All delegations for user revoked');
    } catch (e: any) {
      alert(`Failed to revoke: ${e.message}`);
    }
  };

  const filtered = useMemo(
    () =>
      tokens.filter(t => {
        if (!searchTerm.trim()) return true;
        const s = searchTerm.toLowerCase();
        return (
          t.provider_id.toLowerCase().includes(s) ||
          t.agent_did.toLowerCase().includes(s) ||
          t.user_identity_hash.toLowerCase().includes(s) ||
          t.scopes.some(scope => scope.toLowerCase().includes(s))
        );
      }),
    [tokens, searchTerm]
  );

  const getStatusBadge = (token: DelegationTokenListItem) => {
    if (token.is_expired && token.can_refresh) {
      return <span className="badge text-bg-warning">Expired (refreshable)</span>;
    }
    if (token.is_expired) {
      return <span className="badge text-bg-danger">Expired</span>;
    }
    return <span className="badge text-bg-success">Active</span>;
  };

  const truncate = (s: string, len: number) => (s.length > len ? s.substring(0, len) + '…' : s);

  const formatDate = (d: string | null) => (d ? new Date(d).toLocaleString() : '—');

  return (
    <div className="container-fluid">
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <h1 className="h3 mb-0 text-gray-800">
          <i className="fas fa-vault me-2"></i>Delegation Vault
        </h1>
        <div className="d-flex align-items-center gap-2">
          <SearchInput
            value={searchTerm}
            onChange={setSearchTerm}
            placeholder="Filter by provider, agent, or user..."
          />
          <button className="btn btn-outline-secondary btn-sm" onClick={loadTokens}>
            <i className="fas fa-sync-alt fa-sm me-1"></i> Refresh
          </button>
        </div>
      </div>

      <div className="row mb-4">
        <div className="col-xl-3 col-md-6 mb-4">
          <div className="card border-left-primary shadow h-100 py-2">
            <div className="card-body">
              <div className="row no-gutters align-items-center">
                <div className="col mr-2">
                  <div className="text-xs font-weight-bold text-primary text-uppercase mb-1">
                    Total Delegations
                  </div>
                  <div className="h5 mb-0 font-weight-bold text-gray-800">{tokens.length}</div>
                </div>
                <div className="col-auto">
                  <i className="fas fa-handshake fa-2x text-gray-300"></i>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div className="col-xl-3 col-md-6 mb-4">
          <div className="card border-left-success shadow h-100 py-2">
            <div className="card-body">
              <div className="row no-gutters align-items-center">
                <div className="col mr-2">
                  <div className="text-xs font-weight-bold text-success text-uppercase mb-1">
                    Active
                  </div>
                  <div className="h5 mb-0 font-weight-bold text-gray-800">
                    {tokens.filter(t => !t.is_expired).length}
                  </div>
                </div>
                <div className="col-auto">
                  <i className="fas fa-check-circle fa-2x text-gray-300"></i>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div className="col-xl-3 col-md-6 mb-4">
          <div className="card border-left-warning shadow h-100 py-2">
            <div className="card-body">
              <div className="row no-gutters align-items-center">
                <div className="col mr-2">
                  <div className="text-xs font-weight-bold text-warning text-uppercase mb-1">
                    Expired (refreshable)
                  </div>
                  <div className="h5 mb-0 font-weight-bold text-gray-800">
                    {tokens.filter(t => t.is_expired && t.can_refresh).length}
                  </div>
                </div>
                <div className="col-auto">
                  <i className="fas fa-redo fa-2x text-gray-300"></i>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div className="col-xl-3 col-md-6 mb-4">
          <div className="card border-left-danger shadow h-100 py-2">
            <div className="card-body">
              <div className="row no-gutters align-items-center">
                <div className="col mr-2">
                  <div className="text-xs font-weight-bold text-danger text-uppercase mb-1">
                    Expired (no refresh)
                  </div>
                  <div className="h5 mb-0 font-weight-bold text-gray-800">
                    {tokens.filter(t => t.is_expired && !t.can_refresh).length}
                  </div>
                </div>
                <div className="col-auto">
                  <i className="fas fa-times-circle fa-2x text-gray-300"></i>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-lock me-2"></i>Delegation Tokens
            <span className="badge text-bg-primary ms-2" style={{ verticalAlign: 'middle' }}>
              {filtered.length}
              {searchTerm ? ` of ${tokens.length}` : ''}
            </span>
          </h6>
        </div>
        <div className="card-body">
          {loading && (
            <div className="text-center py-4">
              <div className="spinner-border text-primary" role="status" />
            </div>
          )}

          {error && (
            <div className="alert alert-danger">
              <i className="fas fa-exclamation-triangle me-2"></i>
              {error}
              <button className="btn btn-sm btn-outline-danger ms-3" onClick={loadTokens}>
                Retry
              </button>
            </div>
          )}

          {!loading && !error && filtered.length === 0 && (
            <div className="text-center text-muted py-5">
              <i className="fas fa-lock fa-3x mb-3 d-block"></i>
              {tokens.length === 0
                ? 'No delegation tokens in the vault. Tokens appear after users consent to OAuth providers through channels with outbound credential bindings.'
                : 'No tokens match your search.'}
            </div>
          )}

          {!loading && !error && filtered.length > 0 && (
            <div className="table-responsive">
              <table className="table table-hover">
                <thead>
                  <tr>
                    <th>Provider</th>
                    <th>Agent</th>
                    <th>User</th>
                    <th>Scopes</th>
                    <th>Status</th>
                    <th>Consented</th>
                    <th>Last Used</th>
                    <th>Expires</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(token => (
                    <tr key={token.id}>
                      <td>
                        <strong>{token.provider_id}</strong>
                      </td>
                      <td>
                        <code className="text-muted" title={token.agent_did}>
                          {truncate(token.agent_did, 30)}
                        </code>
                      </td>
                      <td>
                        <code className="text-muted" title={token.user_identity_hash}>
                          {truncate(token.user_identity_hash, 16)}
                        </code>
                        {canEdit && (
                          <button
                            className="btn btn-link btn-sm p-0 ms-1"
                            title="Revoke all for this user"
                            onClick={() => handleRevokeByUser(token.user_identity_hash)}
                          >
                            <i className="fas fa-ban text-warning fa-xs"></i>
                          </button>
                        )}
                      </td>
                      <td>
                        {token.scopes.map(scope => (
                          <span key={scope} className="badge text-bg-secondary me-1">
                            {scope}
                          </span>
                        ))}
                      </td>
                      <td>{getStatusBadge(token)}</td>
                      <td>
                        <small>{formatDate(token.consent_granted_at)}</small>
                      </td>
                      <td>
                        <small>{formatDate(token.last_used_at)}</small>
                      </td>
                      <td>
                        <small>{formatDate(token.expires_at)}</small>
                      </td>
                      <td>
                        {canEdit && (
                          <DeleteButton
                            onDelete={() => handleRevoke(token)}
                            className="btn-sm"
                            title="Revoke delegation"
                          />
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default DelegationVaultPage;
