import React, { useState, useEffect, useMemo } from 'react';
import { useApp } from '../context/AppContext';
import { useLimitGuard } from '../hooks/useLimitGuard';
import { WS_NONE, WS_DASHBOARD } from '../utils/wsSubscriptions';
import { useNavigate } from 'react-router-dom';
import { usePermissions } from '../context/PermissionsContext';
import { apiClient } from '../api';
import { timeAgo } from '../utils/stringUtils';
import { DeleteButton } from '../components/shared/DeleteButton';
import SearchInput from '../components/shared/SearchInput';
import { AppButton } from '../components/shared/AppButton';
import { Badge } from '../components/shared/Badge';
import { EmptyState } from '../components/shared/EmptyState';
import {
  useTableSort,
  SortableHeader,
  SortSegment,
  type TableSort,
} from '../components/shared/tableSort';
import { ideSurfacesLinkingPipe } from './EditPipePage/hooks/usePipeSave';
interface PipeConfig {
  id: string;
  name: string;
  description?: string;
  status: 'enabled' | 'disabled' | 'deleted';
  /** Front-door access-point path this surface listens on. */
  route?: string;
  /** Listener the access-point route is bound to. */
  listen_address?: string;
  pipe_type: {
    type: string;
    provider?: {
      provider_type: string;
      // OpenAI-style providers carry the model in `model`; the `custom`
      // provider carries it in `name`, and Azure OpenAI in `deployment_name`.
      model?: string;
      name?: string;
      deployment_name?: string;
      [key: string]: any;
    };
    server_endpoint?: string;
    wallet_id?: string;
    max_amount?: number;
    max_retries?: number;
  };
  rate_limit?: {
    enabled?: boolean;
    requests_per_minute?: number;
    tokens_per_minute?: number;
  };
  cost_tracking?: {
    enabled: boolean;
    input_price_per_1k?: number;
    output_price_per_1k?: number;
  };
  override_policy?: Record<string, string>;
  prompt_guard?: {
    request?: Array<{ regex: { action: string; rules: any[] } }>;
    response?: Array<{ regex: { action: string; rules: any[] } }>;
  };
  judge?: {
    enabled?: boolean;
    mode?: string;
    llm?: { provider_type?: string; model?: string };
    rules?: any[];
  };
  jury?: {
    enabled?: boolean;
    mode?: string;
    jurors?: any[];
  };
  created_at: string;
  updated_at?: string;
}

// Resolve the display model name across provider shapes: OpenAI-style providers
// store it in `model`, the `custom` provider in `name`, and Azure in
// `deployment_name`.
const providerModelName = (provider?: PipeConfig['pipe_type']['provider']): string =>
  provider?.model || provider?.name || provider?.deployment_name || '';

const PROVIDER_DISPLAY_NAMES: Record<string, string> = {
  openai: 'OpenAI',
  anthropic: 'Anthropic',
  bedrock: 'AWS Bedrock',
  azure_openai: 'Azure OpenAI',
  gemini: 'Google Gemini',
};

const providerDisplayName = (pipe: PipeConfig): string => {
  const providerType = pipe.pipe_type.provider?.provider_type || 'unknown';
  return PROVIDER_DISPLAY_NAMES[providerType] || providerType;
};

const hasPromptGuard = (pipe: PipeConfig): boolean =>
  (pipe.prompt_guard?.request?.length || 0) + (pipe.prompt_guard?.response?.length || 0) > 0;

const hasJudge = (pipe: PipeConfig): boolean => !!pipe.judge?.enabled;

const hasJury = (pipe: PipeConfig): boolean => !!pipe.jury?.enabled;

type SortColumn =
  | 'name'
  | 'accessPoint'
  | 'provider'
  | 'model'
  | 'promptGuard'
  | 'judge'
  | 'jury'
  | 'lastUsed';

const SORT_COLUMNS: SortColumn[] = [
  'name',
  'accessPoint',
  'provider',
  'model',
  'promptGuard',
  'judge',
  'jury',
  'lastUsed',
];

const SORT_TESTID: Record<SortColumn, string> = {
  name: 'surfaces-sort-name',
  accessPoint: 'surfaces-sort-access-point',
  provider: 'surfaces-sort-provider',
  model: 'surfaces-sort-model',
  promptGuard: 'surfaces-sort-prompt-guard',
  judge: 'surfaces-sort-judge',
  jury: 'surfaces-sort-jury',
  lastUsed: 'surfaces-sort-last-used',
};

const DEFAULT_SURFACE_SORT: TableSort<SortColumn> = { column: 'name', direction: 'asc' };
const SURFACE_SORT_STORAGE_KEY = 'llm-surfaces-sort';
const PAGE_SIZE = 10;

const compareSurfaces = (
  a: PipeConfig,
  b: PipeConfig,
  column: SortColumn,
  lastActivityOf: (pipe: PipeConfig) => string | null
): number => {
  switch (column) {
    case 'name':
      return a.name.localeCompare(b.name);
    case 'accessPoint':
      return (a.route ?? '').localeCompare(b.route ?? '');
    case 'provider':
      return providerDisplayName(a).localeCompare(providerDisplayName(b));
    case 'model':
      return providerModelName(a.pipe_type.provider).localeCompare(
        providerModelName(b.pipe_type.provider)
      );
    case 'promptGuard':
      return Number(hasPromptGuard(a)) - Number(hasPromptGuard(b));
    case 'judge':
      return Number(hasJudge(a)) - Number(hasJudge(b));
    case 'jury':
      return Number(hasJury(a)) - Number(hasJury(b));
    case 'lastUsed': {
      const at = lastActivityOf(a);
      const bt = lastActivityOf(b);
      return (at ? new Date(at).getTime() : 0) - (bt ? new Date(bt).getTime() : 0);
    }
    default:
      return 0;
  }
};

const PipesPage: React.FC = () => {
  const navigate = useNavigate();
  const { guard, balloonNode } = useLimitGuard();
  const { actions, getCurrentStats } = useApp();
  const { hasPermission } = usePermissions();
  const [pipes, setPipes] = useState<PipeConfig[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [recentOnly, setRecentOnly] = useState(false);
  const { sort, toggleSort } = useTableSort(
    SORT_COLUMNS,
    DEFAULT_SURFACE_SORT,
    SURFACE_SORT_STORAGE_KEY
  );
  const [page, setPage] = useState(1);

  useEffect(() => {
    setPage(1);
  }, [searchTerm, sort, recentOnly]);

  const sortHeaderProps = (column: SortColumn) => ({
    active: sort.column === column,
    direction: sort.direction,
    onSort: () => toggleSort(column),
    testId: SORT_TESTID[column],
  });

  useEffect(() => {
    loadPipes();
  }, []);

  // Subscribe to everything except logs to reduce WS payload size
  useEffect(() => {
    actions.setWsSubscription(WS_DASHBOARD);
    return () => {
      actions.setWsSubscription(WS_NONE);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const loadPipes = async () => {
    setLoading(true);
    try {
      const response = await apiClient.fetch('/api/v1/pipes');
      if (response.ok) {
        const data = await response.json();
        setPipes(data);
      }
    } catch (error) {
      console.error('Failed to load pipes:', error);
    }
    setLoading(false);
  };

  const handleDelete = async (pipeId: string) => {
    const linkedBy = ideSurfacesLinkingPipe(pipes, pipeId);
    if (linkedBy.length > 0) {
      const names = linkedBy.map(n => `\u2022 ${n}`).join('\n');
      const proceed = window.confirm(
        `This LLM surface is linked by ${linkedBy.length} IDE surface${
          linkedBy.length === 1 ? '' : 's'
        }:\n\n${names}\n\nDeleting it will break those IDE catalogue entries. Delete anyway?`
      );
      if (!proceed) return;
    }
    try {
      const response = await apiClient.fetch(`/api/v1/pipes/${pipeId}`, {
        method: 'DELETE',
      });

      if (response.ok) {
        loadPipes();
      } else {
        const error = await response.json();
        alert(`Failed to delete pipe: ${error.error || 'Unknown error'}`);
      }
    } catch (error) {
      console.error('Failed to delete pipe:', error);
      alert('Failed to delete pipe');
    }
  };

  const editPipe = (pipe: PipeConfig) => {
    navigate(`/llm/${pipe.id}`);
  };

  // Separate LLM pipes from other pipe types
  const llmPipes = pipes.filter(pipe => pipe.pipe_type.type === 'llm');

  // Last-activity per surface is not on the pipe payload; it lives in the
  // runtime `pipe_stats` metrics keyed by `pipe_id`. Merge it in so the
  // "Last used" column and the clock "recent activity" filter work.
  const stats = getCurrentStats();
  const lastActivityByPipe = useMemo(() => {
    const map: Record<string, string> = {};
    for (const ps of stats?.metrics?.pipe_stats ?? []) {
      if (ps.last_activity) map[ps.pipe_id] = ps.last_activity;
    }
    return map;
  }, [stats]);
  const lastActivityOf = (pipe: PipeConfig): string | null => lastActivityByPipe[pipe.id] ?? null;

  const searchedPipes = llmPipes.filter(pipe => {
    const trimmedSearch = searchTerm.trim();
    if (!trimmedSearch) return true;

    const searchLower = trimmedSearch.toLowerCase();
    return (
      pipe.name.toLowerCase().includes(searchLower) ||
      pipe.description?.toLowerCase().includes(searchLower) ||
      pipe.id.toLowerCase().includes(searchLower) ||
      (pipe.route ?? '').toLowerCase().includes(searchLower) ||
      (pipe.listen_address ?? '').toLowerCase().includes(searchLower) ||
      pipe.pipe_type.provider?.provider_type.toLowerCase().includes(searchLower) ||
      providerModelName(pipe.pipe_type.provider).toLowerCase().includes(searchLower)
    );
  });

  const filteredPipes = recentOnly
    ? searchedPipes.filter(pipe => {
        const la = lastActivityOf(pipe);
        return !!la && new Date(la) >= new Date(Date.now() - 5 * 60 * 1000);
      })
    : searchedPipes;

  const sortDir = sort.direction === 'asc' ? 1 : -1;
  const sortedPipes = [...filteredPipes].sort((a, b) => {
    const primary = compareSurfaces(a, b, sort.column, lastActivityOf);
    if (primary !== 0) return primary * sortDir;
    return a.name.localeCompare(b.name);
  });

  const totalPages = Math.max(1, Math.ceil(sortedPipes.length / PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  const pagedPipes = sortedPipes.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

  const renderPagination = () => {
    if (totalPages <= 1) return null;
    const pages = Array.from({ length: totalPages }, (_, i) => i + 1)
      .filter(p => p === 1 || p === totalPages || Math.abs(p - currentPage) <= 1)
      .reduce<(number | '...')[]>((acc, p, idx, arr) => {
        if (idx > 0 && p - (arr[idx - 1] as number) > 1) acc.push('...');
        acc.push(p);
        return acc;
      }, []);
    return (
      <div className="d-flex justify-content-between align-items-center mt-2 px-1">
        <small className="text-muted">
          {(currentPage - 1) * PAGE_SIZE + 1}–
          {Math.min(currentPage * PAGE_SIZE, sortedPipes.length)} of {sortedPipes.length}
        </small>
        <nav aria-label="LLM Surfaces pages">
          <ul className="pagination pagination-sm mb-0">
            <li className={`page-item ${currentPage <= 1 ? 'disabled' : ''}`}>
              <button
                className="page-link"
                onClick={() => setPage(currentPage - 1)}
                data-testid="surfaces-pagination-prev"
              >
                &lsaquo;
              </button>
            </li>
            {pages.map((p, idx) =>
              p === '...' ? (
                <li key={`ellipsis-${idx}`} className="page-item disabled">
                  <span className="page-link">…</span>
                </li>
              ) : (
                <li key={p} className={`page-item ${p === currentPage ? 'active' : ''}`}>
                  <button
                    className="page-link"
                    onClick={() => setPage(p as number)}
                    data-testid={`surfaces-pagination-page-${p}`}
                  >
                    {p}
                  </button>
                </li>
              )
            )}
            <li className={`page-item ${currentPage >= totalPages ? 'disabled' : ''}`}>
              <button
                className="page-link"
                onClick={() => setPage(currentPage + 1)}
                data-testid="surfaces-pagination-next"
              >
                &rsaquo;
              </button>
            </li>
          </ul>
        </nav>
      </div>
    );
  };

  const renderLLMPipesList = () => (
    <div className="card shadow mb-4">
      <div className="card-header py-3 d-flex justify-content-between align-items-center">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-brain"></i> LLM Surfaces
          {llmPipes.length > 0 && (
            <Badge
              value={filteredPipes.length}
              suffix={searchTerm || recentOnly ? ` of ${llmPipes.length}` : undefined}
              className="ms-2"
              ariaLabel={`${filteredPipes.length}${
                searchTerm || recentOnly ? ` of ${llmPipes.length}` : ''
              } LLM surfaces`}
            />
          )}
        </h6>
        <span className="d-flex align-items-center gap-2">
          {llmPipes.length > 0 && (
            <i
              className={`fas fa-clock ${recentOnly ? 'text-primary' : 'text-muted'}`}
              style={{ cursor: 'pointer', fontSize: '1.2rem' }}
              onClick={() => setRecentOnly(prev => !prev)}
              title={
                recentOnly ? 'Show all surfaces' : 'Show only surfaces active in the last 5 minutes'
              }
              data-testid="surfaces-recent-toggle"
            ></i>
          )}
          {hasPermission('pipes.edit') && llmPipes.length > 0 && (
            <>
              <AppButton
                variant="primary"
                size="sm"
                onClick={e => guard('surfaces.llm', () => navigate('/llm/new'), e)}
                iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
              >
                Add LLM Surface
              </AppButton>
              {balloonNode}
            </>
          )}
        </span>
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
        ) : llmPipes.length === 0 && !searchTerm && !recentOnly ? (
          <EmptyState
            icon="fa-brain"
            title="Add your first LLM surface"
            body="Govern how requests reach your models."
            ctaLabel={hasPermission('pipes.edit') ? 'Add LLM Surface' : undefined}
            ctaIcon="fa-plus"
            onCtaClick={hasPermission('pipes.edit') ? () => navigate('/llm/new') : undefined}
          />
        ) : filteredPipes.length === 0 ? (
          <div className="text-center text-muted py-5">
            <i className={`fas ${recentOnly ? 'fa-clock' : 'fa-search'} fa-3x text-muted mb-3`}></i>
            <p className={llmPipes.length === 0 && hasPermission('pipes.edit') ? 'mb-3' : 'mb-0'}>
              {recentOnly
                ? 'No LLM Surfaces were active in the last 5 minutes.'
                : 'No LLM Surfaces match your filter'}
            </p>
            {llmPipes.length === 0 && hasPermission('pipes.edit') && (
              <AppButton
                variant="primary"
                size="sm"
                onClick={() => navigate('/llm/new')}
                iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
              >
                Add LLM Surface
              </AppButton>
            )}
          </div>
        ) : (
          <div className="table-responsive">
            <table className="table table-hover table-sm">
              <thead>
                <tr>
                  <SortableHeader label="Name" width="14%" {...sortHeaderProps('name')} />
                  <SortableHeader
                    label="Access Point"
                    width="14%"
                    {...sortHeaderProps('accessPoint')}
                  />
                  <SortableHeader label="Provider" width="10%" {...sortHeaderProps('provider')} />
                  <SortableHeader label="Model" width="10%" {...sortHeaderProps('model')} />
                  <th style={{ width: '7%' }}>Status</th>
                  <th style={{ width: '24%' }}>
                    <SortSegment label="Prompt Guard" {...sortHeaderProps('promptGuard')} />
                    {' / '}
                    <SortSegment label="Judge" {...sortHeaderProps('judge')} />
                    {' / '}
                    <SortSegment label="Jury" {...sortHeaderProps('jury')} />
                  </th>
                  <SortableHeader label="Last used" width="10%" {...sortHeaderProps('lastUsed')} />
                  <th style={{ width: '11%' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {pagedPipes.map(pipe => (
                  <tr key={pipe.id} onClick={() => editPipe(pipe)} style={{ cursor: 'pointer' }}>
                    <td>
                      <strong>{pipe.name}</strong>
                      {pipe.description && (
                        <small className="d-block text-muted">{pipe.description}</small>
                      )}
                    </td>
                    <td>
                      {pipe.route ? (
                        <code style={{ fontSize: '0.8rem' }}>{pipe.route}</code>
                      ) : (
                        <span className="text-muted fst-italic" style={{ fontSize: '0.8rem' }}>
                          No route configured
                        </span>
                      )}
                    </td>
                    <td>{providerDisplayName(pipe)}</td>
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
                        {providerModelName(pipe.pipe_type.provider) || 'Unknown'}
                      </span>
                    </td>
                    <td>
                      {pipe.status === 'enabled' ? (
                        <span className="badge text-bg-success">Enabled</span>
                      ) : (
                        <span className="badge text-bg-secondary">Disabled</span>
                      )}
                    </td>
                    <td>
                      <div className="d-flex flex-column gap-1 align-items-start">
                        {(() => {
                          const pg = pipe.prompt_guard;
                          const reqCount = pg?.request?.length || 0;
                          const resCount = pg?.response?.length || 0;
                          const total = reqCount + resCount;
                          if (total === 0) return null;
                          const parts: string[] = [];
                          if (reqCount > 0) {
                            const action = pg!.request![0].regex?.action || 'reject';
                            parts.push(`${reqCount} req · ${action}`);
                          }
                          if (resCount > 0) {
                            const action = pg!.response![0].regex?.action || 'reject';
                            parts.push(`${resCount} res · ${action}`);
                          }
                          return (
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
                              <i className="fas fa-shield-alt me-1"></i>
                              {parts.join(', ')}
                            </span>
                          );
                        })()}
                        {(() => {
                          const j = pipe.judge;
                          if (!j?.enabled) return null;
                          const mode = j.mode === 'moderation' ? 'moderation' : 'llm';
                          const provider = j.llm?.provider_type || '';
                          const providerLabel: Record<string, string> = {
                            openai: 'openai',
                            anthropic: 'anthropic',
                            gemini: 'gemini',
                            bedrock: 'bedrock',
                            azure_openai: 'azure',
                            ollama: 'ollama',
                          };
                          const label =
                            mode === 'moderation'
                              ? `moderation · ${providerLabel[provider] || provider}`
                              : `llm · ${providerLabel[provider] || provider}`;
                          return (
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
                              <i className="fas fa-gavel me-1"></i>
                              {label}
                            </span>
                          );
                        })()}
                        {(() => {
                          const jury = pipe.jury;
                          if (!jury?.enabled) return null;
                          const jurorCount = jury.jurors?.length || 0;
                          const mode = jury.mode || 'parallel';
                          return (
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
                              <i className="fas fa-users me-1"></i>
                              {mode} · {jurorCount} juror{jurorCount !== 1 ? 's' : ''}
                            </span>
                          );
                        })()}
                        {!pipe.prompt_guard?.request?.length &&
                          !pipe.prompt_guard?.response?.length &&
                          !pipe.judge?.enabled &&
                          !pipe.jury?.enabled && (
                            <span className="text-muted fst-italic" style={{ fontSize: '0.8rem' }}>
                              No content moderation features enabled
                            </span>
                          )}
                      </div>
                    </td>
                    <td>
                      <div style={{ fontSize: '0.8rem' }}>
                        {(() => {
                          const la = lastActivityOf(pipe);
                          return la ? (
                            <span title={new Date(la).toLocaleString()}>{timeAgo(la)}</span>
                          ) : (
                            <span className="text-muted">Never</span>
                          );
                        })()}
                      </div>
                    </td>
                    <td className="align-middle">
                      <div className="d-flex gap-2 align-items-center">
                        <button
                          className="btn btn-sm btn-primary"
                          onClick={e => {
                            e.stopPropagation();
                            editPipe(pipe);
                          }}
                          title="Edit pipe"
                        >
                          <i className="fas fa-edit"></i>
                        </button>
                        <DeleteButton
                          onDelete={() => handleDelete(pipe.id)}
                          className="btn-sm"
                          title="Delete pipe"
                        />
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {renderPagination()}
      </div>
    </div>
  );

  return (
    <div className="container-fluid">
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <SearchInput
          value={searchTerm}
          onChange={setSearchTerm}
          placeholder="Filter surfaces..."
          width="384px"
        />
      </div>

      {renderLLMPipesList()}
    </div>
  );
};

export default PipesPage;
