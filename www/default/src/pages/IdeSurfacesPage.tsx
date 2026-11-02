import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useLimitGuard } from '../hooks/useLimitGuard';
import { useApp } from '../context/AppContext';
import { usePermissions } from '../context/PermissionsContext';
import { WS_DASHBOARD, WS_NONE } from '../utils/wsSubscriptions';
import { apiClient } from '../api';
import { showToast } from '../utils/toaster';
import { DeleteButton } from '../components/shared/DeleteButton';
import SearchInput from '../components/shared/SearchInput';
import { AppButton } from '../components/shared/AppButton';
import { Badge } from '../components/shared/Badge';
import { EmptyState } from '../components/shared/EmptyState';

interface IdeSurface {
  id: string;
  name: string;
  description?: string;
  status: 'enabled' | 'disabled' | 'deleted';
  route?: string;
  listen_address?: string;
  pipe_type: {
    type: string;
    config?: {
      members?: Array<{ pipe_id?: string; expose?: boolean }>;
    };
  };
}

function memberCounts(surface: IdeSurface): { total: number; exposed: number } {
  const members = surface.pipe_type?.config?.members ?? [];
  const valid = members.filter(m => !!m.pipe_id);
  return {
    total: valid.length,
    exposed: valid.filter(m => m.expose !== false).length,
  };
}

const IdeSurfacesPage: React.FC = () => {
  const navigate = useNavigate();
  const { guard, balloonNode } = useLimitGuard();
  const { actions } = useApp();
  const { hasPermission } = usePermissions();
  const [surfaces, setSurfaces] = useState<IdeSurface[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    loadSurfaces();
  }, []);

  useEffect(() => {
    actions.setWsSubscription(WS_DASHBOARD);
    return () => {
      actions.setWsSubscription(WS_NONE);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const loadSurfaces = async () => {
    setLoading(true);
    try {
      const response = await apiClient.fetch('/api/v1/pipes');
      if (response.ok) {
        const data = await response.json();
        const list: IdeSurface[] = (Array.isArray(data) ? data : []).filter(
          (p: IdeSurface) => p?.pipe_type?.type === 'ide_catalog'
        );
        setSurfaces(list);
      }
    } catch (error) {
      console.error('Failed to load IDE surfaces:', error);
    }
    setLoading(false);
  };

  const handleDelete = async (id: string) => {
    try {
      const response = await apiClient.fetch(`/api/v1/pipes/${id}`, { method: 'DELETE' });
      if (response.ok) {
        loadSurfaces();
      } else {
        const error = await response.json().catch(() => ({}));
        showToast('error', `Failed to delete: ${error.error || 'Unknown error'}`);
      }
    } catch (error) {
      console.error('Failed to delete IDE surface:', error);
      showToast('error', 'Failed to delete IDE surface');
    }
  };

  const filtered = surfaces.filter(s => {
    const trimmed = searchTerm.trim().toLowerCase();
    if (!trimmed) return true;
    return (
      s.name.toLowerCase().includes(trimmed) ||
      s.description?.toLowerCase().includes(trimmed) ||
      s.id.toLowerCase().includes(trimmed) ||
      (s.route ?? '').toLowerCase().includes(trimmed)
    );
  });

  const renderList = () => (
    <div className="card shadow mb-4">
      <div className="card-header py-3 d-flex justify-content-between align-items-center">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-laptop-code"></i> IDE Surfaces
          {surfaces.length > 0 && (
            <Badge
              value={filtered.length}
              suffix={searchTerm ? ` of ${surfaces.length}` : undefined}
              className="ms-2"
              ariaLabel={`${filtered.length}${searchTerm ? ` of ${surfaces.length}` : ''} IDE surfaces`}
            />
          )}
        </h6>
        {hasPermission('pipes.edit') && surfaces.length > 0 && (
          <>
            <AppButton
              variant="primary"
              size="sm"
              onClick={e => guard('surfaces.ide', () => navigate('/ide/new'), e)}
              iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
            >
              Add IDE Surface
            </AppButton>
            {balloonNode}
          </>
        )}
      </div>
      <div className="card-body">
        {surfaces.length === 0 && !searchTerm ? (
          <EmptyState
            icon="fa-laptop-code"
            title="Add your first IDE surface"
            body="Give your IDE a governed path to models."
            ctaLabel={hasPermission('pipes.edit') ? 'Add IDE Surface' : undefined}
            ctaIcon="fa-plus"
            onCtaClick={hasPermission('pipes.edit') ? () => navigate('/ide/new') : undefined}
          />
        ) : filtered.length === 0 ? (
          <div className="text-center text-muted py-5">
            <i className="fas fa-search fa-3x text-muted mb-3"></i>
            <p className={surfaces.length === 0 && hasPermission('pipes.edit') ? 'mb-3' : 'mb-0'}>
              No IDE Surfaces match your filter
            </p>
            {surfaces.length === 0 && hasPermission('pipes.edit') && (
              <AppButton
                variant="primary"
                size="sm"
                onClick={() => navigate('/ide/new')}
                iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
              >
                Add IDE Surface
              </AppButton>
            )}
          </div>
        ) : (
          <div className="table-responsive">
            <table className="table table-hover table-sm">
              <thead>
                <tr>
                  <th style={{ width: '26%' }}>Name</th>
                  <th style={{ width: '30%' }}>Route</th>
                  <th style={{ width: '16%' }}>Models</th>
                  <th style={{ width: '12%' }}>Status</th>
                  <th style={{ width: '16%' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(surface => {
                  const counts = memberCounts(surface);
                  return (
                    <tr
                      key={surface.id}
                      onClick={() => navigate(`/ide/${surface.id}`)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td>
                        <strong>{surface.name}</strong>
                        {surface.description && (
                          <small className="d-block text-muted">{surface.description}</small>
                        )}
                      </td>
                      <td>
                        {surface.route ? (
                          <code style={{ fontSize: '0.8rem' }}>{surface.route}</code>
                        ) : (
                          <span className="text-muted fst-italic" style={{ fontSize: '0.8rem' }}>
                            No route configured
                          </span>
                        )}
                      </td>
                      <td>
                        <span
                          className="badge"
                          style={{
                            fontSize: '0.75rem',
                            fontWeight: 'normal',
                            backgroundColor: 'transparent',
                            color: 'var(--accent-blue)',
                            border: '1px solid var(--accent-blue)',
                          }}
                        >
                          <i className="fas fa-brain me-1"></i>
                          {counts.exposed} exposed
                          {counts.total !== counts.exposed && ` / ${counts.total} total`}
                        </span>
                      </td>
                      <td>
                        {surface.status === 'enabled' ? (
                          <span className="badge text-bg-success">Enabled</span>
                        ) : (
                          <span className="badge text-bg-secondary">Disabled</span>
                        )}
                      </td>
                      <td className="align-middle">
                        <div className="d-flex gap-2 align-items-center">
                          <button
                            className="btn btn-sm btn-primary"
                            onClick={e => {
                              e.stopPropagation();
                              navigate(`/ide/${surface.id}`);
                            }}
                            title="Edit IDE surface"
                          >
                            <i className="fas fa-edit"></i>
                          </button>
                          <DeleteButton
                            onDelete={() => handleDelete(surface.id)}
                            className="btn-sm"
                            title="Delete IDE surface"
                          />
                        </div>
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
  );

  return (
    <div className="container-fluid">
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <SearchInput
          value={searchTerm}
          onChange={setSearchTerm}
          placeholder="Filter IDE surfaces..."
          width="384px"
        />
      </div>

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
      ) : (
        <>{renderList()}</>
      )}
    </div>
  );
};

export default IdeSurfacesPage;
