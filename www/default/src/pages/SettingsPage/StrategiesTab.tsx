import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../../api';
import { usePermissions } from '../../context/PermissionsContext';
import { formatDateTime, topAndTail } from '../../utils/stringUtils';
import { Badge } from '../../components/shared/Badge';
import { AppButton } from '../../components/shared/AppButton';
import { EmptyState } from '../../components/shared/EmptyState';

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

interface StrategiesTabProps {
  externalSearchTerm?: string;
  onFilteredCountChange?: (n: number) => void;
}

const StrategiesTab: React.FC<StrategiesTabProps> = ({
  externalSearchTerm,
  onFilteredCountChange,
}) => {
  const navigate = useNavigate();
  const { hasPermission } = usePermissions();
  const [strategies, setStrategies] = useState<JwtVerificationStrategy[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [internalSearchTerm, setInternalSearchTerm] = useState('');
  const externalProvided = externalSearchTerm !== undefined;
  const searchTerm = externalProvided ? externalSearchTerm! : internalSearchTerm;
  const setSearchTerm = setInternalSearchTerm;
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

  useEffect(() => {
    onFilteredCountChange?.(filtered.length);
  }, [filtered.length, onFilteredCountChange]);

  return (
    <>
      {/* Search + Add */}
      <div className="card shadow mb-4">
        <div className="card-header py-3 d-flex justify-content-between align-items-center">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-id-badge"></i> JWT Verification Strategies
            {strategies.length > 0 && (
              <Badge
                value={filtered.length}
                suffix={searchTerm ? ` of ${strategies.length}` : undefined}
                className="ms-2"
                ariaLabel={`${filtered.length}${searchTerm ? ` of ${strategies.length}` : ''} JWT verification strategies`}
              />
            )}
          </h6>
          {canEdit && strategies.length > 0 && (
            <AppButton
              variant="primary"
              size="sm"
              className="shadow-sm"
              onClick={() => navigate('/jwt-verification-strategies/new')}
              iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
            >
              Add Strategy
            </AppButton>
          )}
        </div>

        <div className="card-body">
          {!externalProvided && (
            <div className="input-group mb-3">
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
          )}

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

          {!loading && !error && strategies.length === 0 && !searchTerm && (
            <EmptyState
              icon="fa-id-badge"
              title="Add your first verification strategy"
              body="Validate bearer tokens from an identity provider."
              ctaLabel={canEdit ? 'Add Strategy' : undefined}
              ctaIcon="fa-plus"
              onCtaClick={canEdit ? () => navigate('/jwt-verification-strategies/new') : undefined}
            />
          )}

          {!loading && !error && filtered.length === 0 && (strategies.length > 0 || searchTerm) && (
            <div className="text-center text-muted py-5">
              <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
              <p className={strategies.length === 0 && canEdit ? 'mb-3' : 'mb-0'}>
                No strategies match your search.
              </p>
              {strategies.length === 0 && canEdit && (
                <AppButton
                  variant="primary"
                  size="sm"
                  onClick={() => navigate('/jwt-verification-strategies/new')}
                  iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
                >
                  Add Strategy
                </AppButton>
              )}
            </div>
          )}

          {!loading && !error && filtered.length > 0 && (
            <div className="table-responsive">
              <table className="table table-hover table-sm" width="100%" cellSpacing="0">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Details</th>
                    <th>Updated</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(strategy => (
                    <tr
                      key={strategy.id}
                      onClick={() => navigate(`/jwt-verification-strategies/${strategy.id}`)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td>
                        <strong>{strategy.name}</strong>
                        <div>
                          <small className="text-muted">
                            {topAndTail(strategy.expected_issuer, 30, 20)}
                          </small>
                        </div>
                      </td>
                      <td>
                        <div>
                          <small>
                            <span className="badge badge-secondary mr-1">Issuer</span>{' '}
                            <code>{topAndTail(strategy.expected_issuer, 25, 40)}</code>
                          </small>
                        </div>
                        <div>
                          <small>
                            <span className="badge badge-secondary mr-1">JWKS</span>
                            {strategy.jwks_source.type === 'remote' &&
                              strategy.jwks_source.jwks_uri && (
                                <>
                                  <code>{topAndTail(strategy.jwks_source.jwks_uri, 25, 40)}</code>
                                  <a
                                    href={strategy.jwks_source.jwks_uri}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="ml-1"
                                    onClick={e => e.stopPropagation()}
                                    title="Open JWKS URI"
                                  >
                                    <i className="fas fa-external-link-alt fa-xs"></i>
                                  </a>
                                </>
                              )}
                            {strategy.jwks_source.type === 'static' && (
                              <>{strategy.jwks_source.jwks?.length ?? 0} key(s)</>
                            )}
                          </small>
                        </div>
                      </td>
                      <td>
                        <small>{formatDateTime(strategy.updated_at, true)}</small>
                      </td>
                      <td style={{ whiteSpace: 'nowrap' }}>
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
    </>
  );
};

export default StrategiesTab;
