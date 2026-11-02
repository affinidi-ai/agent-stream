import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useLimitGuard } from '../hooks/useLimitGuard';
import { usePermissions } from '../context/PermissionsContext';
import { apiClient } from '../api';

export interface JwksSource {
  type: 'remote' | 'static';
  jwks_uri?: string;
  jwks?: any[];
}

export interface JwtVerificationStrategy {
  id: string;
  name: string;
  expected_issuer: string;
  jwks_source: JwksSource;
  created_at: string;
  updated_at: string;
}

const JwtVerificationStrategiesPage: React.FC = () => {
  const navigate = useNavigate();
  const { guard, balloonNode } = useLimitGuard();
  const { hasPermission } = usePermissions();
  const [strategies, setStrategies] = useState<JwtVerificationStrategy[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const canEdit = hasPermission('jwt_verification_strategies.edit');
  const canDelete = hasPermission('jwt_verification_strategies.delete');

  useEffect(() => {
    loadStrategies();
  }, []);

  const loadStrategies = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await apiClient.fetch('/api/v1/jwt-verification-strategies');
      if (!response.ok) {
        throw new Error(`Failed to load strategies: ${response.statusText}`);
      }
      const data: JwtVerificationStrategy[] = await response.json();
      setStrategies(data);
    } catch (e: any) {
      setError(e.message ?? 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (strategy: JwtVerificationStrategy) => {
    if (
      !window.confirm(
        `Delete JWT verification strategy "${strategy.name}"?\n\nWarning: any channel or pipe still referencing this strategy will return 403.`
      )
    ) {
      return;
    }
    setDeletingId(strategy.id);
    try {
      const response = await apiClient.fetch(
        `/api/v1/jwt-verification-strategies/${encodeURIComponent(strategy.id)}`,
        { method: 'DELETE' }
      );
      if (!response.ok) {
        throw new Error(`Delete failed: ${response.statusText}`);
      }
      setStrategies(prev => prev.filter(s => s.id !== strategy.id));
    } catch (e: any) {
      alert(`Failed to delete strategy: ${e.message}`);
    } finally {
      setDeletingId(null);
    }
  };

  const filtered = strategies.filter(
    s =>
      s.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      s.expected_issuer.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="container-fluid">
      {/* Page Heading */}
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <h1 className="h3 mb-0 text-gray-800">
          <i className="fas fa-id-badge me-2"></i>JWT Verification Strategies
        </h1>
        {canEdit && (
          <>
            <button
              className="btn btn-primary btn-sm shadow-sm"
              onClick={e =>
                guard('credentials.jwt', () => navigate('/jwt-verification-strategies/new'), e)
              }
            >
              <i className="fas fa-plus fa-sm me-1"></i> Add Strategy
            </button>
            {balloonNode}
          </>
        )}
      </div>

      {/* Search */}
      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <div className="input-group">
            <input
              type="text"
              className="form-control bg-light border-0 small"
              placeholder="Search by name or expected issuer…"
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
            />
            <div className="input-group-append">
              <button className="btn btn-primary" type="button">
                <i className="fas fa-search fa-sm"></i>
              </button>
            </div>
          </div>
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
              <button className="btn btn-sm btn-outline-danger ms-3" onClick={loadStrategies}>
                Retry
              </button>
            </div>
          )}

          {!loading && !error && filtered.length === 0 && (
            <div className="text-center text-muted py-5">
              <i className="fas fa-id-badge fa-3x mb-3 d-block"></i>
              {strategies.length === 0
                ? 'No JWT verification strategies configured yet.'
                : 'No strategies match your search.'}
              {canEdit && strategies.length === 0 && (
                <div className="mt-3">
                  <button
                    className="btn btn-primary"
                    onClick={() => navigate('/jwt-verification-strategies/new')}
                  >
                    <i className="fas fa-plus me-1"></i> Add your first strategy
                  </button>
                </div>
              )}
            </div>
          )}

          {!loading && !error && filtered.length > 0 && (
            <div className="table-responsive">
              <table className="table table-bordered table-hover" width="100%" cellSpacing="0">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Expected Issuer</th>
                    <th>JWKS Source</th>
                    <th>Updated</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(strategy => (
                    <tr key={strategy.id}>
                      <td>
                        <strong>{strategy.name}</strong>
                        <div>
                          <small className="text-muted font-monospace">{strategy.id}</small>
                        </div>
                      </td>
                      <td>
                        <code>{strategy.expected_issuer}</code>
                      </td>
                      <td>
                        <span
                          className={`badge badge-${strategy.jwks_source.type === 'remote' ? 'info' : 'secondary'}`}
                        >
                          {strategy.jwks_source.type.toUpperCase()}
                        </span>
                        {strategy.jwks_source.type === 'remote' &&
                          strategy.jwks_source.jwks_uri && (
                            <div>
                              <small className="text-muted">
                                <code>{strategy.jwks_source.jwks_uri}</code>
                              </small>
                            </div>
                          )}
                        {strategy.jwks_source.type === 'static' && (
                          <div>
                            <small className="text-muted">
                              {strategy.jwks_source.jwks?.length ?? 0} key(s)
                            </small>
                          </div>
                        )}
                      </td>
                      <td>
                        <small>{new Date(strategy.updated_at).toLocaleString()}</small>
                      </td>
                      <td>
                        {canEdit && (
                          <button
                            className="btn btn-sm btn-outline-primary me-1"
                            onClick={() => navigate(`/jwt-verification-strategies/${strategy.id}`)}
                            title="Edit"
                          >
                            <i className="fas fa-edit"></i>
                          </button>
                        )}
                        {canDelete && (
                          <button
                            className="btn btn-sm btn-outline-danger"
                            onClick={() => handleDelete(strategy)}
                            disabled={deletingId === strategy.id}
                            title="Delete"
                          >
                            {deletingId === strategy.id ? (
                              <span className="spinner-border spinner-border-sm" />
                            ) : (
                              <i className="fas fa-trash"></i>
                            )}
                          </button>
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

export default JwtVerificationStrategiesPage;
