import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useLimitGuard } from '../hooks/useLimitGuard';
import { apiClient } from '../api';
import CapUsageBar from '../components/usage/CapUsageBar';
import {
  fetchSeries,
  indexByKey,
  monthToDateWindow,
  sumWindow,
  teamKey,
  type WindowTotals,
} from '../components/usage/usageSeries';
import { DeleteButton } from '../components/shared/DeleteButton';
import SearchInput from '../components/shared/SearchInput';
import { AppButton } from '../components/shared/AppButton';
import { Badge } from '../components/shared/Badge';
import { EmptyState } from '../components/shared/EmptyState';
import { SortableHeader, useTableSort, type TableSort } from '../components/shared/tableSort';
import { usePermissions } from '../context/PermissionsContext';
import { type Team } from './EditTeamPage/teamHelpers';

const PAGE_SIZE = 10;

type TeamSortColumn = 'name' | 'members' | 'budget' | 'tokens';

const TEAM_SORT_COLUMNS: TeamSortColumn[] = ['name', 'members', 'budget', 'tokens'];

const TEAM_SORT_TESTID: Record<TeamSortColumn, string> = {
  name: 'teams-sort-name',
  members: 'teams-sort-members',
  budget: 'teams-sort-budget',
  tokens: 'teams-sort-tokens',
};

const DEFAULT_TEAM_SORT: TableSort<TeamSortColumn> = { column: 'name', direction: 'asc' };
const TEAM_SORT_STORAGE_KEY = 'teams-sort';

const compareTeams = (
  a: Team,
  b: Team,
  column: TeamSortColumn,
  usage: Record<string, WindowTotals>
): number => {
  switch (column) {
    case 'name':
      return a.name.localeCompare(b.name);
    case 'members':
      return a.members.length - b.members.length;
    case 'budget':
      return (usage[a.id]?.cost ?? 0) - (usage[b.id]?.cost ?? 0);
    case 'tokens':
      return (usage[a.id]?.tokens ?? 0) - (usage[b.id]?.tokens ?? 0);
    default:
      return 0;
  }
};

interface TeamsListPageProps {
  searchTerm?: string;
  onFilteredCountChange?: (count: number) => void;
}

const TeamsListPage: React.FC<TeamsListPageProps> = ({
  searchTerm: controlledSearch,
  onFilteredCountChange,
}) => {
  const navigate = useNavigate();
  const { guard, balloonNode } = useLimitGuard();
  const { hasPermission } = usePermissions();
  const canEdit = hasPermission('teams.edit');
  const canDelete = hasPermission('teams.delete');

  const [teams, setTeams] = useState<Team[]>([]);
  const [usage, setUsage] = useState<Record<string, WindowTotals>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [internalSearch, setInternalSearch] = useState('');
  const controlled = controlledSearch !== undefined;
  const searchTerm = controlled ? controlledSearch : internalSearch;
  const [page, setPage] = useState(1);
  const { sort, toggleSort } = useTableSort(
    TEAM_SORT_COLUMNS,
    DEFAULT_TEAM_SORT,
    TEAM_SORT_STORAGE_KEY
  );

  const fetchTeams = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await apiClient.get<Team[]>('/teams');
      setTeams(response.data);
    } catch (err: any) {
      setError(err.message || 'Failed to load teams');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchTeams();
  }, [fetchTeams]);

  useEffect(() => {
    if (teams.length === 0) return;
    const controller = new AbortController();
    const keys = teams.map(t => teamKey(t.id));
    fetchSeries(keys, monthToDateWindow(), 400, 'auto', controller.signal)
      .then(series => {
        const byKey = indexByKey(series);
        const next: Record<string, WindowTotals> = {};
        for (const t of teams) next[t.id] = sumWindow(byKey.get(teamKey(t.id)));
        setUsage(next);
      })
      .catch(() => {
        /* usage bars simply stay at zero on error */
      });
    return () => controller.abort();
  }, [teams]);

  const handleDelete = useCallback(
    async (team: Team) => {
      try {
        await apiClient.delete(`/teams/${encodeURIComponent(team.id)}`);
        fetchTeams();
      } catch (err: any) {
        setError(err.message || 'Failed to delete team');
      }
    },
    [fetchTeams]
  );

  const filteredTeams = useMemo(() => {
    const trimmed = searchTerm.trim().toLowerCase();
    if (!trimmed) return teams;
    return teams.filter(
      t => t.name.toLowerCase().includes(trimmed) || t.id.toLowerCase().includes(trimmed)
    );
  }, [teams, searchTerm]);

  useEffect(() => {
    onFilteredCountChange?.(filteredTeams.length);
  }, [filteredTeams.length, onFilteredCountChange]);

  const sortedTeams = useMemo(() => {
    const dir = sort.direction === 'asc' ? 1 : -1;
    return [...filteredTeams].sort((a, b) => {
      const primary = compareTeams(a, b, sort.column, usage);
      if (primary !== 0) return primary * dir;
      return a.name.localeCompare(b.name);
    });
  }, [filteredTeams, sort, usage]);

  useEffect(() => {
    setPage(1);
  }, [searchTerm, sort]);

  const totalPages = Math.max(1, Math.ceil(sortedTeams.length / PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  const pagedTeams = sortedTeams.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

  const teamSortProps = (column: TeamSortColumn) => ({
    active: sort.column === column,
    direction: sort.direction,
    onSort: () => toggleSort(column),
    testId: TEAM_SORT_TESTID[column],
  });

  const PaginationControls: React.FC = () => {
    if (totalPages <= 1) return null;
    return (
      <div className="d-flex justify-content-between align-items-center mt-2 px-1">
        <small className="text-muted">
          {(currentPage - 1) * PAGE_SIZE + 1}–
          {Math.min(currentPage * PAGE_SIZE, filteredTeams.length)} of {filteredTeams.length}
        </small>
        <nav>
          <ul className="pagination pagination-sm mb-0">
            <li className={`page-item ${currentPage <= 1 ? 'disabled' : ''}`}>
              <button className="page-link" onClick={() => setPage(currentPage - 1)}>
                &lsaquo;
              </button>
            </li>
            {Array.from({ length: totalPages }, (_, i) => i + 1)
              .filter(p => p === 1 || p === totalPages || Math.abs(p - currentPage) <= 1)
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
                    <button className="page-link" onClick={() => setPage(p as number)}>
                      {p}
                    </button>
                  </li>
                )
              )}
            <li className={`page-item ${currentPage >= totalPages ? 'disabled' : ''}`}>
              <button className="page-link" onClick={() => setPage(currentPage + 1)}>
                &rsaquo;
              </button>
            </li>
          </ul>
        </nav>
      </div>
    );
  };

  return (
    <div className={controlled ? undefined : 'container-fluid'}>
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
            <i className="fas fa-users"></i> Team Management
            {teams.length > 0 && (
              <Badge
                value={filteredTeams.length}
                suffix={searchTerm ? ` of ${teams.length}` : undefined}
                className="ms-2"
                ariaLabel={`${filteredTeams.length}${searchTerm ? ` of ${teams.length}` : ''} teams`}
              />
            )}
          </h6>
          <div className="d-flex align-items-center gap-2">
            {!controlled && (
              <SearchInput
                value={internalSearch}
                onChange={setInternalSearch}
                placeholder="Filter Teams...."
              />
            )}
            {canEdit && teams.length > 0 && (
              <>
                <AppButton
                  variant="primary"
                  size="sm"
                  onClick={e => guard('teams', () => navigate('/teams/new'), e)}
                  iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
                >
                  Add Team
                </AppButton>
                {balloonNode}
              </>
            )}
          </div>
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
                <span className="visually-hidden">Loading…</span>
              </div>
            </div>
          ) : teams.length === 0 && !searchTerm ? (
            <EmptyState
              icon="fa-users"
              title="Create your first team"
              body="Group members to organize access."
              ctaLabel={canEdit ? 'Add Team' : undefined}
              ctaIcon="fa-plus"
              onCtaClick={canEdit ? () => navigate('/teams/new') : undefined}
            />
          ) : filteredTeams.length === 0 ? (
            <div className="text-center text-muted py-5">
              <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
              <p className={teams.length === 0 && canEdit ? 'mb-3' : 'mb-0'}>
                No teams match your search.
              </p>
              {teams.length === 0 && canEdit && (
                <AppButton
                  variant="primary"
                  size="sm"
                  onClick={() => navigate('/teams/new')}
                  iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
                >
                  Add Team
                </AppButton>
              )}
            </div>
          ) : (
            <>
              <div className="table-responsive">
                <table className="table table-hover table-sm">
                  <thead>
                    <tr>
                      <SortableHeader label="Name" {...teamSortProps('name')} />
                      <SortableHeader label="Members" {...teamSortProps('members')} />
                      <SortableHeader label="Team Budget" {...teamSortProps('budget')} />
                      <SortableHeader label="Team Tokens" {...teamSortProps('tokens')} />
                      <th>Status</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {pagedTeams.map(team => (
                      <tr
                        key={team.id}
                        onClick={() => navigate(`/teams/${encodeURIComponent(team.id)}`)}
                        style={{ cursor: 'pointer' }}
                      >
                        <td>
                          <strong>{team.name}</strong>
                          <div className="text-muted">
                            <small>{team.description}</small>
                          </div>
                        </td>
                        <td>
                          <span className="badge text-bg-info">{team.members.length}</span>
                        </td>
                        <td>
                          <CapUsageBar
                            used={usage[team.id]?.cost ?? 0}
                            cap={team.monthly_budget_usd}
                            kind="usd"
                            compact
                          />
                        </td>
                        <td>
                          <CapUsageBar
                            used={usage[team.id]?.tokens ?? 0}
                            cap={team.monthly_token_cap}
                            kind="tokens"
                            compact
                          />
                        </td>
                        <td>
                          <span
                            className={`badge ${team.status === 'enabled' ? 'text-bg-success' : 'text-bg-secondary'}`}
                          >
                            {team.status === 'enabled' ? 'ENABLED' : 'DISABLED'}
                          </span>
                        </td>
                        <td onClick={e => e.stopPropagation()}>
                          <div className="d-flex flex-column flex-lg-row gap-2 align-items-start align-items-lg-center">
                            <AppButton
                              variant="primary"
                              size="sm"
                              onClick={() => navigate(`/teams/${encodeURIComponent(team.id)}`)}
                              title={canEdit ? 'Edit team' : 'View team'}
                            >
                              <i className={`fas ${canEdit ? 'fa-edit' : 'fa-eye'}`}></i>
                            </AppButton>
                            {canDelete && !team.system && (
                              <DeleteButton
                                onDelete={() => handleDelete(team)}
                                className="btn-sm"
                                title="Delete team permanently"
                              />
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <PaginationControls />
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default TeamsListPage;
