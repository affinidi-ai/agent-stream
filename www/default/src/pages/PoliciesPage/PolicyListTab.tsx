import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useLimitGuard } from '../../hooks/useLimitGuard';
import { AppButton } from '../../components/shared/AppButton';
import { Badge } from '../../components/shared/Badge';
import EmptyState from '../../components/shared/EmptyState';
import SearchInput from '../../components/shared/SearchInput';
import { apiClient } from '../../api';
import { usePermissions } from '../../context/PermissionsContext';
import PolicyRow from './PolicyRow';
import { useGlobalPolicyAssignments } from './useGlobalPolicyAssignments';

export interface PolicyDefinition {
  id: string;
  name: string;
  description: string;
  policy_type: 'appliance' | 'llm' | 'ide';
  policy: string;
  enabled: boolean;
  created_at: string;
  updated_at?: string;
}

interface PolicyListTabProps {
  policyType: 'appliance' | 'llm' | 'ide';
  label: string;
  icon: string;
  externalSearchTerm?: string;
  onFilteredCountChange?: (n: number) => void;
}

const PolicyListTab: React.FC<PolicyListTabProps> = ({
  policyType,
  label,
  icon,
  externalSearchTerm,
  onFilteredCountChange,
}) => {
  const navigate = useNavigate();
  const { guard, balloonNode } = useLimitGuard();
  const [policies, setPolicies] = useState<PolicyDefinition[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [internalSearchTerm, setInternalSearchTerm] = useState('');
  const externalProvided = externalSearchTerm !== undefined;
  const searchTerm = externalProvided ? externalSearchTerm! : internalSearchTerm;

  // Appliance-wide (global) enforcement applies to every surface type, including
  // the appliance (Trust Fabric / gateway) layer.
  const { hasPermission } = usePermissions();
  const showGlobal = true;
  const canPublish = hasPermission('policies.publish');
  const {
    isEnforced,
    isMonitorOnly,
    setEnforcement,
    saving: savingGlobal,
    error: globalError,
    clearError: clearGlobalError,
  } = useGlobalPolicyAssignments(showGlobal);

  const handleToggleGlobal = useCallback(
    (policyId: string, enforced: boolean, monitorOnly: boolean) => {
      // Errors surface via `globalError`; swallow the rejection here.
      setEnforcement(policyType, policyId, enforced, monitorOnly).catch(() => undefined);
    },
    [policyType, setEnforcement]
  );

  const fetchPolicies = useCallback(async () => {
    try {
      const resp = await apiClient.fetch('/api/v1/policy-definitions');
      if (!resp.ok) throw new Error(`Failed to load policies: ${resp.statusText}`);
      const data: PolicyDefinition[] = await resp.json();
      setPolicies(data.filter(p => p.policy_type === policyType));
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [policyType]);

  useEffect(() => {
    fetchPolicies();
  }, [fetchPolicies]);

  const handleDelete = useCallback(async (id: string) => {
    try {
      const resp = await apiClient.fetch(`/api/v1/policy-definitions/${encodeURIComponent(id)}`, {
        method: 'DELETE',
      });
      if (!resp.ok) throw new Error(`Failed to delete: ${resp.statusText}`);
      setPolicies(prev => prev.filter(p => p.id !== id));
    } catch (e: any) {
      setError(e.message);
    }
  }, []);

  const filtered = useMemo(() => {
    const q = searchTerm.trim().toLowerCase();
    if (!q) return policies;
    return policies.filter(
      p =>
        p.name.toLowerCase().includes(q) ||
        p.description.toLowerCase().includes(q) ||
        p.id.toLowerCase().includes(q)
    );
  }, [policies, searchTerm]);

  useEffect(() => {
    onFilteredCountChange?.(filtered.length);
  }, [filtered.length, onFilteredCountChange]);

  return (
    <div className="card shadow mb-4">
      <div className="card-header py-3 d-flex justify-content-between align-items-center">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className={`fas ${icon}`}></i> {label} Policies
          {policies.length > 0 && (
            <Badge
              value={filtered.length}
              suffix={searchTerm ? ` of ${policies.length}` : undefined}
              className="ms-2"
              ariaLabel={`${filtered.length}${searchTerm ? ` of ${policies.length}` : ''} ${label} policies`}
            />
          )}
        </h6>
        <div className="d-flex align-items-center gap-2">
          {!externalProvided && (
            <SearchInput
              value={internalSearchTerm}
              onChange={setInternalSearchTerm}
              placeholder={`Filter ${label.toLowerCase()} policies...`}
            />
          )}
          {policies.length > 0 && (
            <>
              <AppButton
                variant="primary"
                size="sm"
                onClick={e =>
                  guard(
                    policyType === 'appliance'
                      ? 'policies.fabric'
                      : policyType === 'llm'
                        ? 'policies.llm'
                        : 'policies.ide',
                    () => navigate(`/policy-definitions/new?type=${policyType}`),
                    e
                  )
                }
                iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
              >
                Define {label} Policy
              </AppButton>
              {balloonNode}
            </>
          )}
        </div>
      </div>
      <div className="card-body">
        {error && (
          <div className="alert alert-danger alert-dismissible fade show mb-3">
            <i className="fas fa-exclamation-triangle me-2"></i>
            {error}
            <button
              type="button"
              className="btn-close"
              onClick={() => setError(null)}
              aria-label="Close"
            />
          </div>
        )}
        {globalError && (
          <div className="alert alert-danger alert-dismissible fade show mb-3">
            <i className="fas fa-exclamation-triangle me-2"></i>
            {globalError}
            <button
              type="button"
              className="btn-close"
              onClick={clearGlobalError}
              aria-label="Close"
            />
          </div>
        )}
        {loading ? (
          <div className="text-center py-5">
            <div className="spinner-border text-primary" role="status">
              <span className="visually-hidden">Loading…</span>
            </div>
          </div>
        ) : policies.length === 0 && !searchTerm ? (
          <EmptyState
            icon={icon}
            title={`Define your first ${label} policy`}
            body={
              label === 'Agent Stream'
                ? 'Control what this layer allows.'
                : `Control what ${label} traffic is allowed.`
            }
            ctaLabel={`Define ${label} Policy`}
            ctaIcon="fa-plus"
            onCtaClick={() => navigate(`/policy-definitions/new?type=${policyType}`)}
          />
        ) : filtered.length === 0 ? (
          <div className="text-center text-muted py-5">
            <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
            <p className={policies.length === 0 ? 'mb-3' : 'mb-0'}>
              No {label.toLowerCase()} policies match your search.
            </p>
            {policies.length === 0 && (
              <AppButton
                variant="primary"
                size="sm"
                onClick={() => navigate(`/policy-definitions/new?type=${policyType}`)}
                iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
              >
                Define {label} Policy
              </AppButton>
            )}
          </div>
        ) : (
          <div className="table-responsive">
            <table className="table table-hover table-sm mb-0">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Description</th>
                  <th style={{ width: '80px' }}>Status</th>
                  {showGlobal && (
                    <th style={{ width: '170px', whiteSpace: 'nowrap' }} className="text-center">
                      Global
                    </th>
                  )}
                  <th style={{ width: '100px' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(p => (
                  <PolicyRow
                    key={p.id}
                    policy={p}
                    showGlobal={showGlobal}
                    enforced={isEnforced(policyType, p.id)}
                    monitorOnly={isMonitorOnly(policyType, p.id)}
                    canPublish={canPublish}
                    savingGlobal={savingGlobal}
                    onEdit={() => navigate(`/policy-definitions/${p.id}`)}
                    onDelete={() => handleDelete(p.id)}
                    onEnableGlobal={() => setEnforcement(policyType, p.id, true, false)}
                    onToggleGlobal={(enforced, monitorOnly) =>
                      handleToggleGlobal(p.id, enforced, monitorOnly)
                    }
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default PolicyListTab;
