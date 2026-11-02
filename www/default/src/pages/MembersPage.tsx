import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useLimitGuard } from '../hooks/useLimitGuard';
import { apiClient } from '../api';
import CapUsageBar from '../components/usage/CapUsageBar';
import {
  fetchSeries,
  indexByKey,
  memberKey,
  monthToDateWindow,
  sumWindow,
  type WindowTotals,
} from '../components/usage/usageSeries';
import { DeleteButton } from '../components/shared/DeleteButton';
import SearchInput from '../components/shared/SearchInput';
import { AppButton } from '../components/shared/AppButton';
import { Badge } from '../components/shared/Badge';
import { EmptyState } from '../components/shared/EmptyState';
import { SortableHeader, useTableSort, type TableSort } from '../components/shared/tableSort';
import { usePermissions } from '../context/PermissionsContext';
import {
  IDENTIFIER_LABELS,
  identifierValue,
  memberIdentifiers,
  memberLabel,
  primaryIdentifier,
  primaryIdentifierValue,
  type Member,
} from './EditMemberPage/memberHelpers';

const PAGE_SIZE = 10;

type MemberSortColumn = 'name' | 'identity' | 'budget' | 'tokens';

const MEMBER_SORT_COLUMNS: MemberSortColumn[] = ['name', 'identity', 'budget', 'tokens'];

const MEMBER_SORT_TESTID: Record<MemberSortColumn, string> = {
  name: 'members-sort-name',
  identity: 'members-sort-identity',
  budget: 'members-sort-budget',
  tokens: 'members-sort-tokens',
};

const DEFAULT_MEMBER_SORT: TableSort<MemberSortColumn> = { column: 'name', direction: 'asc' };
const MEMBER_SORT_STORAGE_KEY = 'members-sort';

const compareMembers = (
  a: Member,
  b: Member,
  column: MemberSortColumn,
  usage: Record<string, WindowTotals>
): number => {
  switch (column) {
    case 'name':
      return memberLabel(a).localeCompare(memberLabel(b));
    case 'identity':
      return primaryIdentifierValue(a).localeCompare(primaryIdentifierValue(b));
    case 'budget':
      return (usage[a.id]?.cost ?? 0) - (usage[b.id]?.cost ?? 0);
    case 'tokens':
      return (usage[a.id]?.tokens ?? 0) - (usage[b.id]?.tokens ?? 0);
    default:
      return 0;
  }
};

interface MembersPageProps {
  searchTerm?: string;
  onFilteredCountChange?: (count: number) => void;
}

const MembersPage: React.FC<MembersPageProps> = ({
  searchTerm: controlledSearch,
  onFilteredCountChange,
}) => {
  const navigate = useNavigate();
  const { guard, balloonNode } = useLimitGuard();
  const { hasPermission } = usePermissions();
  const canEdit = hasPermission('members.edit');
  const canDelete = hasPermission('members.delete');

  const [members, setMembers] = useState<Member[]>([]);
  const [usage, setUsage] = useState<Record<string, WindowTotals>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [internalSearch, setInternalSearch] = useState('');
  const controlled = controlledSearch !== undefined;
  const searchTerm = controlled ? controlledSearch : internalSearch;
  const [page, setPage] = useState(1);
  const { sort, toggleSort } = useTableSort(
    MEMBER_SORT_COLUMNS,
    DEFAULT_MEMBER_SORT,
    MEMBER_SORT_STORAGE_KEY
  );

  const fetchMembers = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await apiClient.get<Member[]>('/members');
      setMembers(response.data);
    } catch (err: any) {
      setError(err.message || 'Failed to load members');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchMembers();
  }, [fetchMembers]);

  useEffect(() => {
    if (members.length === 0) return;
    const controller = new AbortController();
    const keys = members.map(m => memberKey(m.id));
    fetchSeries(keys, monthToDateWindow(), 400, 'auto', controller.signal)
      .then(series => {
        const byKey = indexByKey(series);
        const next: Record<string, WindowTotals> = {};
        for (const m of members) next[m.id] = sumWindow(byKey.get(memberKey(m.id)));
        setUsage(next);
      })
      .catch(() => {
        /* usage bars simply stay at zero on error */
      });
    return () => controller.abort();
  }, [members]);

  const handleDelete = useCallback(
    async (member: Member) => {
      try {
        await apiClient.delete(`/members/${encodeURIComponent(member.id)}`);
        fetchMembers();
      } catch (err: any) {
        setError(err.message || 'Failed to delete member');
      }
    },
    [fetchMembers]
  );

  const filteredMembers = useMemo(() => {
    const trimmed = searchTerm.trim().toLowerCase();
    if (!trimmed) return members;
    return members.filter(
      m =>
        memberLabel(m).toLowerCase().includes(trimmed) ||
        memberIdentifiers(m).some(i => identifierValue(i).toLowerCase().includes(trimmed)) ||
        m.id.toLowerCase().includes(trimmed)
    );
  }, [members, searchTerm]);

  useEffect(() => {
    onFilteredCountChange?.(filteredMembers.length);
  }, [filteredMembers.length, onFilteredCountChange]);

  const sortedMembers = useMemo(() => {
    const dir = sort.direction === 'asc' ? 1 : -1;
    return [...filteredMembers].sort((a, b) => {
      const primary = compareMembers(a, b, sort.column, usage);
      if (primary !== 0) return primary * dir;
      return memberLabel(a).localeCompare(memberLabel(b));
    });
  }, [filteredMembers, sort, usage]);

  useEffect(() => {
    setPage(1);
  }, [searchTerm, sort]);

  const totalPages = Math.max(1, Math.ceil(sortedMembers.length / PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  const pagedMembers = sortedMembers.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

  const memberSortProps = (column: MemberSortColumn) => ({
    active: sort.column === column,
    direction: sort.direction,
    onSort: () => toggleSort(column),
    testId: MEMBER_SORT_TESTID[column],
  });

  const PaginationControls: React.FC = () => {
    if (totalPages <= 1) return null;
    return (
      <div className="d-flex justify-content-between align-items-center mt-2 px-1">
        <small className="text-muted">
          {(currentPage - 1) * PAGE_SIZE + 1}–
          {Math.min(currentPage * PAGE_SIZE, filteredMembers.length)} of {filteredMembers.length}
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
      ) : (
        <div className="card shadow mb-4">
          <div className="card-header py-3 d-flex justify-content-between align-items-center">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-user-friends"></i> Member Management
              {members.length > 0 && (
                <Badge
                  value={filteredMembers.length}
                  suffix={searchTerm ? ` of ${members.length}` : undefined}
                  className="ms-2"
                  ariaLabel={`${filteredMembers.length}${searchTerm ? ` of ${members.length}` : ''} members`}
                />
              )}
            </h6>
            <div className="d-flex align-items-center gap-2">
              {!controlled && (
                <SearchInput
                  value={internalSearch}
                  onChange={setInternalSearch}
                  placeholder="Filter Members...."
                />
              )}
              {canEdit && members.length > 0 && (
                <>
                  <AppButton
                    variant="primary"
                    size="sm"
                    onClick={e => guard('members', () => navigate('/members/new'), e)}
                    iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
                  >
                    Add Member
                  </AppButton>
                  {balloonNode}
                </>
              )}
            </div>
          </div>
          <div className="card-body">
            {members.length === 0 && !searchTerm ? (
              <EmptyState
                icon="fa-user-friends"
                title="Add your first member"
                body="The people and clients that reach your models."
                ctaLabel={canEdit ? 'Add Member' : undefined}
                ctaIcon="fa-plus"
                onCtaClick={canEdit ? () => navigate('/members/new') : undefined}
              />
            ) : filteredMembers.length === 0 ? (
              <div className="text-center text-muted py-5">
                <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
                <p className={members.length === 0 && canEdit ? 'mb-3' : 'mb-0'}>
                  No members match your search.
                </p>
                {members.length === 0 && canEdit && (
                  <AppButton
                    variant="primary"
                    size="sm"
                    onClick={() => navigate('/members/new')}
                    iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
                  >
                    Add Member
                  </AppButton>
                )}
              </div>
            ) : (
              <>
                <div className="table-responsive">
                  <table className="table table-hover table-sm">
                    <thead>
                      <tr>
                        <SortableHeader label="Name" {...memberSortProps('name')} />
                        <SortableHeader label="Identity" {...memberSortProps('identity')} />
                        <SortableHeader label="Budget" {...memberSortProps('budget')} />
                        <SortableHeader label="Tokens" {...memberSortProps('tokens')} />
                        <th>Status</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {pagedMembers.map(member => (
                        <tr
                          key={member.id}
                          onClick={() => navigate(`/members/${encodeURIComponent(member.id)}`)}
                          style={{ cursor: 'pointer' }}
                        >
                          <td>
                            <strong>{member.name || primaryIdentifierValue(member)}</strong>
                            {member.auto_provisioned && (
                              <span
                                className="badge text-bg-info ms-2"
                                title="Created automatically on first sight"
                              >
                                <i className="fas fa-bolt me-1"></i>Auto
                              </span>
                            )}
                            <div className="text-muted">
                              <small>{member.id}</small>
                            </div>
                          </td>
                          <td>
                            <span className="badge text-bg-secondary me-1">
                              {primaryIdentifier(member)
                                ? IDENTIFIER_LABELS[primaryIdentifier(member)!.kind]
                                : '—'}
                            </span>
                            <small>{primaryIdentifierValue(member)}</small>
                            {memberIdentifiers(member).length > 1 && (
                              <span className="badge text-bg-light ms-1 text-muted">
                                +{memberIdentifiers(member).length - 1}
                              </span>
                            )}
                          </td>
                          <td>
                            <CapUsageBar
                              used={usage[member.id]?.cost ?? 0}
                              cap={member.monthly_budget_usd}
                              kind="usd"
                              compact
                            />
                          </td>
                          <td>
                            <CapUsageBar
                              used={usage[member.id]?.tokens ?? 0}
                              cap={member.monthly_token_cap}
                              kind="tokens"
                              compact
                            />
                          </td>
                          <td>
                            <span
                              className={`badge ${member.status === 'enabled' ? 'text-bg-success' : 'text-bg-secondary'}`}
                            >
                              {member.status === 'enabled' ? 'ENABLED' : 'DISABLED'}
                            </span>
                          </td>
                          <td onClick={e => e.stopPropagation()}>
                            <div className="d-flex flex-column flex-lg-row gap-2 align-items-start align-items-lg-center">
                              <AppButton
                                variant="primary"
                                size="sm"
                                onClick={() =>
                                  navigate(`/members/${encodeURIComponent(member.id)}`)
                                }
                                title={canEdit ? 'Edit member' : 'View member'}
                              >
                                <i className={`fas ${canEdit ? 'fa-edit' : 'fa-eye'}`}></i>
                              </AppButton>
                              {canDelete && !member.system && (
                                <DeleteButton
                                  onDelete={() => handleDelete(member)}
                                  className="btn-sm"
                                  title="Delete member permanently"
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
      )}
    </div>
  );
};

export default MembersPage;
