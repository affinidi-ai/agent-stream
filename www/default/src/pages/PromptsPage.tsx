import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useLimitGuard } from '../hooks/useLimitGuard';
import { apiClient } from '../api';
import { DeleteButton } from '../components/shared/DeleteButton';
import SearchInput from '../components/shared/SearchInput';
import { AppButton } from '../components/shared/AppButton';
import { Badge } from '../components/shared/Badge';
import { EmptyState } from '../components/shared/EmptyState';
import { usePermissions } from '../context/PermissionsContext';
import { promptLabel, type Prompt } from './EditPromptPage/promptHelpers';

const PAGE_SIZE = 10;

const PromptsPage: React.FC = () => {
  const navigate = useNavigate();
  const { guard, balloonNode } = useLimitGuard();
  const { hasPermission } = usePermissions();
  const canEdit = hasPermission('prompts.edit');
  const canDelete = hasPermission('prompts.delete');

  const [prompts, setPrompts] = useState<Prompt[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [page, setPage] = useState(1);

  const fetchPrompts = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await apiClient.get<Prompt[]>('/prompts');
      setPrompts(response.data);
    } catch (err: any) {
      setError(err.message || 'Failed to load prompts');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchPrompts();
  }, [fetchPrompts]);

  const handleDelete = useCallback(
    async (prompt: Prompt) => {
      try {
        await apiClient.delete(`/prompts/${encodeURIComponent(prompt.id)}`);
        fetchPrompts();
      } catch (err: any) {
        setError(err.message || 'Failed to delete prompt');
      }
    },
    [fetchPrompts]
  );

  const filtered = useMemo(() => {
    const trimmed = searchTerm.trim().toLowerCase();
    if (!trimmed) return prompts;
    return prompts.filter(
      p =>
        promptLabel(p).toLowerCase().includes(trimmed) ||
        p.id.toLowerCase().includes(trimmed) ||
        (p.description ?? '').toLowerCase().includes(trimmed)
    );
  }, [prompts, searchTerm]);

  useEffect(() => {
    setPage(1);
  }, [searchTerm]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  const paged = filtered.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

  return (
    <div className="container-fluid">
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <SearchInput
          value={searchTerm}
          onChange={setSearchTerm}
          placeholder="Filter prompts..."
          width="384px"
        />
      </div>

      {error && (
        <div className="alert alert-danger alert-dismissible fade show" role="alert">
          {error}
          <button
            type="button"
            className="btn-close"
            onClick={() => setError(null)}
            aria-label="Close"
          />
        </div>
      )}

      <div className="card shadow mb-4">
        <div className="card-header py-3 d-flex justify-content-between align-items-center">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-comment-dots"></i> Prompt Management
            {prompts.length > 0 && (
              <Badge
                value={filtered.length}
                suffix={searchTerm ? ` of ${prompts.length}` : undefined}
                className="ms-2"
                ariaLabel={`${filtered.length}${searchTerm ? ` of ${prompts.length}` : ''} prompts`}
              />
            )}
          </h6>
          {canEdit && prompts.length > 0 && (
            <>
              <AppButton
                variant="primary"
                size="sm"
                onClick={e => guard('prompts', () => navigate('/prompts/new'), e)}
                iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
              >
                Add Prompt
              </AppButton>
              {balloonNode}
            </>
          )}
        </div>
        <div className="card-body">
          {loading ? (
            <div className="text-center py-5">
              <div className="spinner-border text-primary" role="status">
                <span className="visually-hidden">Loading…</span>
              </div>
            </div>
          ) : prompts.length === 0 && !searchTerm ? (
            <EmptyState
              icon="fa-comment-dots"
              title="Create your first prompt"
              body="Reusable, versioned prompt templates."
              ctaLabel={canEdit ? 'Add Prompt' : undefined}
              ctaIcon="fa-plus"
              onCtaClick={canEdit ? () => navigate('/prompts/new') : undefined}
            />
          ) : filtered.length === 0 ? (
            <div className="text-center text-muted py-5">
              <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
              <p className={prompts.length === 0 && canEdit ? 'mb-3' : 'mb-0'}>
                No prompts match your search.
              </p>
              {prompts.length === 0 && canEdit && (
                <AppButton
                  variant="primary"
                  size="sm"
                  onClick={() => navigate('/prompts/new')}
                  iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
                >
                  Add Prompt
                </AppButton>
              )}
            </div>
          ) : (
            <>
              <div className="table-responsive">
                <table className="table table-hover table-sm">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>ID</th>
                      <th>Versions</th>
                      <th>Default</th>
                      <th>Status</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {paged.map(p => (
                      <tr
                        key={p.id}
                        style={{ cursor: 'pointer' }}
                        onClick={() => navigate(`/prompts/${encodeURIComponent(p.id)}`)}
                      >
                        <td>{promptLabel(p)}</td>
                        <td>
                          <code>{p.id}</code>
                        </td>
                        <td>{p.versions?.length ?? 0}</td>
                        <td>{p.default_version ?? '—'}</td>
                        <td>
                          <span
                            className={`badge ${p.status === 'enabled' ? 'text-bg-success' : 'text-bg-secondary'}`}
                          >
                            {p.status}
                          </span>
                        </td>
                        <td onClick={e => e.stopPropagation()}>
                          {canEdit && (
                            <AppButton
                              variant="outline-primary"
                              size="sm"
                              className="me-2"
                              onClick={() => navigate(`/prompts/${encodeURIComponent(p.id)}`)}
                            >
                              <i className="fas fa-edit"></i>
                            </AppButton>
                          )}
                          {canDelete && (
                            <DeleteButton
                              onDelete={() => handleDelete(p)}
                              className="btn-sm"
                              title="Delete prompt"
                            />
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {totalPages > 1 && (
                <div className="d-flex justify-content-between align-items-center mt-2 px-1">
                  <small className="text-muted">
                    {(currentPage - 1) * PAGE_SIZE + 1}–
                    {Math.min(currentPage * PAGE_SIZE, filtered.length)} of {filtered.length}
                  </small>
                  <nav>
                    <ul className="pagination pagination-sm mb-0">
                      <li className={`page-item ${currentPage <= 1 ? 'disabled' : ''}`}>
                        <button className="page-link" onClick={() => setPage(currentPage - 1)}>
                          &lsaquo;
                        </button>
                      </li>
                      <li className={`page-item ${currentPage >= totalPages ? 'disabled' : ''}`}>
                        <button className="page-link" onClick={() => setPage(currentPage + 1)}>
                          &rsaquo;
                        </button>
                      </li>
                    </ul>
                  </nav>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default PromptsPage;
