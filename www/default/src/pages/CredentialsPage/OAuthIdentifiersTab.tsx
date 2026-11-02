import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useLimitGuard } from '../../hooks/useLimitGuard';
import { apiClient } from '../../api';
import { usePermissions } from '../../context/PermissionsContext';
import { formatDateTime, topAndTail } from '../../utils/stringUtils';
import { Badge } from '../../components/shared/Badge';
import { AppButton } from '../../components/shared/AppButton';
import { EmptyState } from '../../components/shared/EmptyState';

/**
 * List tab for **OAuth Identifiers** inside the Credentials page. Mirrors the
 * JWT Verification `StrategiesTab`: card + table, filter-aware count badge, row
 * click / edit / delete, "Add" button. Each row shows a **shape badge** (Entra
 * / Okta / OIDC) since the identifier schema is provider-shaped.
 */

type Shape = 'entra' | 'okta' | 'oidc';

export interface OAuthIdentifier {
  id: string;
  name: string;
  description?: string;
  provider: Shape;
  tenant_id?: string;
  domain?: string;
  authorization_server_id?: string;
  issuer?: string;
  client_id: string;
  scopes: string[];
  created_at: string;
  updated_at: string;
}

const SHAPE_META: Record<Shape, { label: string; badge: string }> = {
  entra: { label: 'Entra', badge: 'badge-info' },
  okta: { label: 'Okta', badge: 'badge-primary' },
  oidc: { label: 'OIDC', badge: 'badge-secondary' },
};

/** Human-readable authority summary shown in the Details column. */
function authoritySummary(p: OAuthIdentifier): string {
  if (p.provider === 'entra') return p.tenant_id ? `tenant ${p.tenant_id}` : '(no tenant)';
  if (p.provider === 'okta') {
    const asid = p.authorization_server_id?.trim() || 'default';
    return p.domain ? `${p.domain} / ${asid}` : '(no domain)';
  }
  return p.issuer || '(no issuer)';
}

interface OAuthIdentifiersTabProps {
  externalSearchTerm?: string;
  onFilteredCountChange?: (n: number) => void;
}

const OAuthIdentifiersTab: React.FC<OAuthIdentifiersTabProps> = ({
  externalSearchTerm,
  onFilteredCountChange,
}) => {
  const navigate = useNavigate();
  const { guard, balloonNode } = useLimitGuard();
  const { hasPermission } = usePermissions();
  const [profiles, setProfiles] = useState<OAuthIdentifier[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [internalSearchTerm, setInternalSearchTerm] = useState('');
  const externalProvided = externalSearchTerm !== undefined;
  const searchTerm = externalProvided ? externalSearchTerm! : internalSearchTerm;
  const setSearchTerm = setInternalSearchTerm;
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const canEdit = hasPermission('oauth_identifiers.edit');
  const canDelete = hasPermission('oauth_identifiers.delete');

  useEffect(() => {
    loadProfiles();
  }, []);

  const loadProfiles = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await apiClient.fetch('/api/v1/oauth-identifiers');
      if (!response.ok) {
        throw new Error(`Failed to load OAuth Identifiers: ${response.statusText}`);
      }
      const data: OAuthIdentifier[] = await response.json();
      setProfiles(data);
    } catch (e: any) {
      setError(e.message ?? 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (profile: OAuthIdentifier) => {
    if (
      !window.confirm(
        `Delete OAuth Identifier "${profile.name}"?\n\nWarning: any surface still referencing this profile will fall back to its own inline sign-in settings (or none).`
      )
    ) {
      return;
    }
    setDeletingId(profile.id);
    try {
      const response = await apiClient.fetch(
        `/api/v1/oauth-identifiers/${encodeURIComponent(profile.id)}`,
        { method: 'DELETE' }
      );
      if (!response.ok) {
        throw new Error(`Delete failed: ${response.statusText}`);
      }
      setProfiles(prev => prev.filter(p => p.id !== profile.id));
    } catch (e: any) {
      alert(`Failed to delete profile: ${e.message}`);
    } finally {
      setDeletingId(null);
    }
  };

  const filtered = profiles.filter(p => {
    const q = searchTerm.toLowerCase();
    return (
      p.name.toLowerCase().includes(q) ||
      p.client_id.toLowerCase().includes(q) ||
      authoritySummary(p).toLowerCase().includes(q)
    );
  });

  useEffect(() => {
    onFilteredCountChange?.(filtered.length);
  }, [filtered.length, onFilteredCountChange]);

  return (
    <>
      <div className="card shadow mb-4">
        <div className="card-header py-3 d-flex justify-content-between align-items-center">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-fingerprint"></i> OAuth Identifiers
            {profiles.length > 0 && (
              <Badge
                value={filtered.length}
                suffix={searchTerm ? ` of ${profiles.length}` : undefined}
                className="ms-2"
                ariaLabel={`${filtered.length}${searchTerm ? ` of ${profiles.length}` : ''} OAuth identifiers`}
              />
            )}
          </h6>
          {canEdit && profiles.length > 0 && (
            <>
              <AppButton
                variant="primary"
                size="sm"
                className="shadow-sm"
                onClick={e =>
                  guard('credentials.oauth', () => navigate('/oauth-identifiers/new'), e)
                }
                iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
              >
                Add Identifier
              </AppButton>
              {balloonNode}
            </>
          )}
        </div>

        <div className="card-body">
          {!externalProvided && (
            <div className="input-group mb-3">
              <input
                type="text"
                className="form-control bg-light border-0 small"
                placeholder="Search by name, client id, or authority…"
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

          <div className="alert alert-info small">
            <i className="fas fa-info-circle me-2"></i>
            Public OAuth sign-in identifiers (authority, client id, scopes) — never secrets.
            Referenced by IDE front-door sign-in, member upstream sign-in, and the sandbox; edit
            once and every referencing surface follows.
          </div>

          {loading && (
            <div className="text-center py-4">
              <div className="spinner-border text-primary" role="status" />
            </div>
          )}

          {error && (
            <div className="alert alert-danger">
              <i className="fas fa-exclamation-triangle me-2"></i>
              {error}
              <button className="btn btn-sm btn-outline-danger ms-3" onClick={loadProfiles}>
                Retry
              </button>
            </div>
          )}

          {!loading && !error && profiles.length === 0 && !searchTerm && (
            <EmptyState
              icon="fa-fingerprint"
              title="Add your first OAuth identifier"
              body="Verify inbound access tokens."
              ctaLabel={canEdit ? 'Add Identifier' : undefined}
              ctaIcon="fa-plus"
              onCtaClick={canEdit ? () => navigate('/oauth-identifiers/new') : undefined}
            />
          )}

          {!loading && !error && filtered.length === 0 && (profiles.length > 0 || searchTerm) && (
            <div className="text-center text-muted py-5">
              <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
              <p className={profiles.length === 0 && canEdit ? 'mb-3' : 'mb-0'}>
                No OAuth identifiers match your search.
              </p>
              {profiles.length === 0 && canEdit && (
                <AppButton
                  variant="primary"
                  size="sm"
                  onClick={() => navigate('/oauth-identifiers/new')}
                  iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
                >
                  Add Identifier
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
                    <th>Shape</th>
                    <th>Details</th>
                    <th>Updated</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(profile => {
                    const meta = SHAPE_META[profile.provider] ?? SHAPE_META.oidc;
                    return (
                      <tr
                        key={profile.id}
                        onClick={() => navigate(`/oauth-identifiers/${profile.id}`)}
                        style={{ cursor: 'pointer' }}
                      >
                        <td>
                          <strong>{profile.name}</strong>
                          {profile.description && (
                            <div>
                              <small className="text-muted">
                                {topAndTail(profile.description, 40, 20)}
                              </small>
                            </div>
                          )}
                        </td>
                        <td>
                          <span className={`badge ${meta.badge}`}>{meta.label}</span>
                        </td>
                        <td>
                          <div>
                            <small>
                              <span className="badge badge-secondary mr-1">Authority</span>{' '}
                              <code>{topAndTail(authoritySummary(profile), 28, 24)}</code>
                            </small>
                          </div>
                          <div>
                            <small>
                              <span className="badge badge-secondary mr-1">Client</span>{' '}
                              <code>{topAndTail(profile.client_id, 20, 12)}</code>
                            </small>
                          </div>
                          <div>
                            <small className="text-muted">
                              {profile.scopes?.length ?? 0} scope(s)
                            </small>
                          </div>
                        </td>
                        <td>
                          <small>{formatDateTime(profile.updated_at, true)}</small>
                        </td>
                        <td style={{ whiteSpace: 'nowrap' }}>
                          {canEdit && (
                            <button
                              className="btn btn-sm btn-outline-primary me-1"
                              onClick={() => navigate(`/oauth-identifiers/${profile.id}`)}
                              title="Edit"
                            >
                              <i className="fas fa-edit"></i>
                            </button>
                          )}
                          {canDelete && (
                            <button
                              className="btn btn-sm btn-outline-danger"
                              onClick={e => {
                                e.stopPropagation();
                                handleDelete(profile);
                              }}
                              disabled={deletingId === profile.id}
                              title="Delete"
                            >
                              {deletingId === profile.id ? (
                                <span className="spinner-border spinner-border-sm" />
                              ) : (
                                <i className="fas fa-trash"></i>
                              )}
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </>
  );
};

export default OAuthIdentifiersTab;
