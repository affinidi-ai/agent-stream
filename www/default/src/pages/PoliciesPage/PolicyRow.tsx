import React, { useRef, useState } from 'react';
import { apiClient } from '../../api';
import type { PolicyDefinition } from './PolicyListTab';
import PolicyConfirmPopover from './PolicyConfirmPopover';

interface PolicyRowProps {
  policy: PolicyDefinition;
  showGlobal: boolean;
  enforced: boolean;
  monitorOnly: boolean;
  canPublish: boolean;
  savingGlobal: boolean;
  onEdit: () => void;
  onDelete: () => Promise<void>;
  onEnableGlobal: () => Promise<void>;
  onToggleGlobal: (enforced: boolean, monitorOnly: boolean) => void;
}

/**
 * A single policy row: name, description, status, an optional appliance-wide
 * enforcement toggle (all policy types, including the Trust Fabric gateway
 * layer), and edit/delete actions. Both deleting and enabling global
 * enforcement open a blast-radius confirmation popover anchored to the row
 * (spinner → affected-count → confirm). The global controls are read-only
 * without the `policies.publish` permission.
 */
const PolicyRow: React.FC<PolicyRowProps> = ({
  policy,
  showGlobal,
  enforced,
  monitorOnly,
  canPublish,
  savingGlobal,
  onEdit,
  onDelete,
  onEnableGlobal,
  onToggleGlobal,
}) => {
  const [popover, setPopover] = useState<'delete' | 'enable-global' | null>(null);
  const [phase, setPhase] = useState<'loading' | 'ready'>('loading');
  const [impactCount, setImpactCount] = useState<number | null>(null);
  const [impactError, setImpactError] = useState<string | null>(null);
  const [committing, setCommitting] = useState(false);
  const globalAnchorRef = useRef<HTMLDivElement>(null);
  const deleteAnchorRef = useRef<HTMLButtonElement>(null);

  // A policy is only referenced by objects of its own type, so the blast-radius
  // count names just that scope.
  const scopeNoun =
    policy.policy_type === 'appliance'
      ? 'Trust Fabric connection'
      : policy.policy_type === 'ide'
        ? 'IDE surface'
        : 'LLM surface';

  const openPopover = async (action: 'delete' | 'enable-global') => {
    setPopover(action);
    setPhase('loading');
    setImpactError(null);
    setImpactCount(null);
    try {
      const resp = await apiClient.fetch(
        `/api/v1/policy-definitions/${encodeURIComponent(policy.id)}/impact`
      );
      if (!resp.ok) throw new Error(`Failed to load impact: ${resp.statusText}`);
      const data = await resp.json();
      setImpactCount(policy.policy_type === 'appliance' ? data.gateways : data.pipes);
    } catch {
      setImpactError('Impact unavailable');
    } finally {
      setPhase('ready');
    }
  };

  const closePopover = () => {
    setPopover(null);
    setPhase('loading');
    setImpactCount(null);
    setImpactError(null);
  };

  const commit = async () => {
    setCommitting(true);
    try {
      if (popover === 'delete') await onDelete();
      else if (popover === 'enable-global') await onEnableGlobal();
    } catch {
      // surfaced by the parent's error / global-error alerts
    } finally {
      setCommitting(false);
      closePopover();
    }
  };

  const count = impactCount ?? 0;
  const anchorEl =
    popover === 'delete'
      ? deleteAnchorRef.current
      : popover === 'enable-global'
        ? globalAnchorRef.current
        : null;

  return (
    <>
      <tr data-testid={`policy-row-${policy.id}`} onClick={onEdit} style={{ cursor: 'pointer' }}>
        <td>
          <strong>{policy.name}</strong>
        </td>
        <td className="text-muted">{policy.description || '—'}</td>
        <td className="text-center">
          {policy.enabled ? (
            <span className="badge text-bg-success">Enabled</span>
          ) : (
            <span className="badge text-bg-secondary">Disabled</span>
          )}
        </td>
        {showGlobal && (
          <td className="text-center" style={{ whiteSpace: 'nowrap' }}>
            <div className="d-flex flex-column align-items-center gap-1">
              <div
                ref={globalAnchorRef}
                className="form-check form-switch m-0"
                title={
                  canPublish
                    ? 'Enforce this policy appliance-wide'
                    : 'Requires the policies.publish permission'
                }
              >
                <input
                  className="form-check-input"
                  type="checkbox"
                  role="switch"
                  id={`global-${policy.id}`}
                  checked={enforced || popover === 'enable-global'}
                  disabled={!canPublish || savingGlobal || popover === 'enable-global'}
                  onChange={() =>
                    enforced ? onToggleGlobal(false, monitorOnly) : openPopover('enable-global')
                  }
                  data-testid={`policy-global-toggle-${policy.id}`}
                />
              </div>
              {enforced && (
                <>
                  <span className={`badge ${monitorOnly ? 'text-bg-warning' : 'text-bg-info'}`}>
                    {monitorOnly ? 'Monitor' : 'Global'}
                  </span>
                  <div
                    className="form-check m-0"
                    title="Evaluate and record the decision but never block"
                  >
                    <input
                      className="form-check-input"
                      type="checkbox"
                      id={`monitor-${policy.id}`}
                      checked={monitorOnly}
                      disabled={!canPublish || savingGlobal}
                      onChange={() => onToggleGlobal(true, !monitorOnly)}
                      data-testid={`policy-monitor-toggle-${policy.id}`}
                    />
                    <label
                      className="form-check-label small text-muted"
                      htmlFor={`monitor-${policy.id}`}
                    >
                      Monitor only
                    </label>
                  </div>
                </>
              )}
            </div>
          </td>
        )}
        <td className="text-center" style={{ whiteSpace: 'nowrap' }}>
          <button className="btn btn-sm btn-outline-primary me-1" title="Edit" onClick={onEdit}>
            <i className="fas fa-edit"></i>
          </button>
          <button
            ref={deleteAnchorRef}
            className="btn btn-sm btn-danger"
            title="Delete"
            onClick={() => openPopover('delete')}
            data-testid={`policy-delete-${policy.id}`}
          >
            <i className="fas fa-trash"></i>
          </button>
        </td>
      </tr>
      {popover && anchorEl && (
        <PolicyConfirmPopover
          anchor={anchorEl}
          title={popover === 'delete' ? 'Delete policy' : 'Enforce globally'}
          confirmLabel={popover === 'delete' ? 'Delete' : 'Continue'}
          confirmVariant={popover === 'delete' ? 'danger' : 'primary'}
          confirmDisabled={phase === 'loading'}
          busy={committing}
          onConfirm={commit}
          onCancel={closePopover}
        >
          {phase === 'loading' ? (
            <div className="text-center py-1">
              <span className="spinner-border spinner-border-sm text-primary" role="status" />
            </div>
          ) : popover === 'delete' ? (
            <>
              Delete <strong>{policy.name}</strong>?{' '}
              {impactError
                ? impactError
                : `${count} ${scopeNoun}${count === 1 ? '' : 's'} reference it and will fail closed.`}
            </>
          ) : (
            <>
              Enforce <strong>{policy.name}</strong> on every {scopeNoun}?{' '}
              {impactError
                ? impactError
                : `${count} ${scopeNoun}${count === 1 ? '' : 's'} affected.`}
            </>
          )}
        </PolicyConfirmPopover>
      )}
    </>
  );
};

export default PolicyRow;
