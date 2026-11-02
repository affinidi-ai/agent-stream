import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../../api';
import { AppButton } from '../../components/shared/AppButton';
import { Badge } from '../../components/shared/Badge';
import { EmptyState } from '../../components/shared/EmptyState';
import TablePager from '../../components/shared/TablePager';
import { usePermissions } from '../../context/PermissionsContext';
import { showToast } from '../../utils/toaster';
import type { AccessTokenMeta } from '../../types';
import AccessTokenRow from './AccessTokenRow';

const PAGE_SIZE = 10;

interface AccessTokensTabProps {
  searchTerm: string;
}

/**
 * The Access Tokens (PAT) tab of the Secrets page: lists management personal
 * access tokens with their scopes and status, with revoke + navigate-to-edit.
 * Self-contained (fetches `/access-tokens`); the search box is shared via prop.
 */
const AccessTokensTab: React.FC<AccessTokensTabProps> = ({ searchTerm }) => {
  const navigate = useNavigate();
  const { hasPermission } = usePermissions();
  const canEdit = hasPermission('access_tokens.edit');
  const canDelete = hasPermission('access_tokens.delete');
  const [tokens, setTokens] = useState<AccessTokenMeta[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [showRevoked, setShowRevoked] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const { data } = await apiClient.get<{ access_tokens: AccessTokenMeta[] }>('/access-tokens');
      setTokens(data.access_tokens ?? []);
    } catch {
      setTokens([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => setPage(1), [searchTerm, showRevoked]);

  const handleRevoke = async (id: string) => {
    try {
      await apiClient.delete(`/access-tokens/${id}`);
      showToast('success', 'Access token revoked');
      load();
    } catch (e) {
      showToast('error', e instanceof Error ? e.message : 'Failed to revoke token');
    }
  };

  const term = searchTerm.trim().toLowerCase();
  const filtered = tokens.filter(t => {
    if (!showRevoked && t.revoked_at) return false;
    if (!term) return true;
    return (
      t.name.toLowerCase().includes(term) ||
      t.id.toLowerCase().includes(term) ||
      t.scopes.some(s => s.toLowerCase().includes(term))
    );
  });
  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const current = Math.min(page, totalPages);
  const paged = filtered.slice((current - 1) * PAGE_SIZE, current * PAGE_SIZE);

  return (
    <div className="card shadow mb-4">
      <div className="card-header py-3 d-flex justify-content-between align-items-center">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-user-lock"></i> Access Tokens (PAT)
          {tokens.length > 0 && (
            <Badge
              value={filtered.length}
              suffix={searchTerm ? ` of ${tokens.length}` : undefined}
              className="ms-2"
              ariaLabel={`${filtered.length}${searchTerm ? ` of ${tokens.length}` : ''} access tokens`}
            />
          )}
        </h6>
        {tokens.length > 0 && (
          <div className="d-flex align-items-center gap-3">
            <div className="form-check form-switch m-0">
              <input
                className="form-check-input"
                type="checkbox"
                role="switch"
                id="access-token-show-revoked"
                checked={showRevoked}
                onChange={e => setShowRevoked(e.target.checked)}
                data-testid="access-token-show-revoked"
              />
              <label
                className="form-check-label small text-muted"
                htmlFor="access-token-show-revoked"
              >
                Show revoked
              </label>
            </div>
            {canEdit && (
              <AppButton
                variant="primary"
                size="sm"
                onClick={() => navigate('/access-tokens/new')}
                iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
              >
                New Access Token
              </AppButton>
            )}
          </div>
        )}
      </div>
      <div className="card-body">
        {loading ? (
          <div className="text-center py-5">
            <div className="spinner-border text-primary" role="status"></div>
          </div>
        ) : tokens.length === 0 && !searchTerm ? (
          <EmptyState
            icon="fa-user-lock"
            title="Mint your first access token"
            body="Personal access tokens let a service account call the management API without an interactive session."
            ctaLabel={canEdit ? 'New Access Token' : undefined}
            ctaIcon="fa-plus"
            onCtaClick={canEdit ? () => navigate('/access-tokens/new') : undefined}
          />
        ) : filtered.length === 0 ? (
          <div className="text-center text-muted py-5">
            <i
              className={`fas ${searchTerm ? 'fa-search' : 'fa-user-lock'} fa-3x mb-3`}
              aria-hidden="true"
            />
            <p className="mb-0">
              {searchTerm
                ? 'No access tokens match your search.'
                : 'All access tokens are revoked. Enable “Show revoked” to see them.'}
            </p>
          </div>
        ) : (
          <div className="table-responsive">
            <table className="table table-hover table-sm align-middle">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Scopes</th>
                  <th>Status</th>
                  <th>Last used</th>
                  <th>Expires</th>
                  <th>Created</th>
                  {canDelete && <th>Actions</th>}
                </tr>
              </thead>
              <tbody>
                {paged.map(t => (
                  <AccessTokenRow
                    key={t.id}
                    token={t}
                    canDelete={canDelete}
                    onOpen={() => navigate(`/access-tokens/${t.id}`)}
                    onRevoke={() => handleRevoke(t.id)}
                  />
                ))}
              </tbody>
            </table>
            <TablePager
              page={current}
              pageSize={PAGE_SIZE}
              total={filtered.length}
              onPage={setPage}
            />
          </div>
        )}
      </div>
    </div>
  );
};

export default AccessTokensTab;
