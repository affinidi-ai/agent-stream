import React, { useEffect, useRef, useState } from 'react';
import { Settings } from '../../types';
import { showToast } from '../../utils/toaster';

interface VpAuditTabProps {
  settings: Settings | null;
  updateSettings: (settings: Partial<Settings>) => Promise<void>;
}

/**
 * Policy-decision audit toggle.
 *
 * Agent Stream records exactly one audit category — OPA policy decisions — so
 * this is a single switch. It maps to the backend `audit_enabled` +
 * `audit_categories.policies` gate (both set together).
 */
const VpAuditTab: React.FC<VpAuditTabProps> = ({ settings, updateSettings }) => {
  const isOn = (s: Settings | null) =>
    (s?.audit_enabled ?? false) && (s?.audit_categories?.policies ?? false);

  const [auditEnabled, setAuditEnabled] = useState(isOn(settings));
  const [isSaving, setIsSaving] = useState(false);
  const initialized = useRef(false);

  useEffect(() => {
    // Sync from settings once on mount so a parent re-render with a stale
    // settings object can't clobber an in-progress edit.
    if (initialized.current || settings === null) return;
    initialized.current = true;
    setAuditEnabled(isOn(settings));
  }, [settings]);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    showToast('loading', 'Saving audit settings...');
    try {
      await updateSettings({
        audit_enabled: auditEnabled,
        audit_categories: { policies: auditEnabled },
      });
      showToast('success', 'Audit settings saved!');
    } catch (error) {
      const msg = error instanceof Error ? error.message : 'Failed to save';
      showToast('error', msg);
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="card shadow mb-3">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-file-contract"></i> Audit Log
        </h6>
      </div>
      <div className="card-body">
        <p className="text-muted mb-3">
          Records a durable, redacted entry for every allow/deny policy decision (pipe, IDE,
          gateway, and surface), viewable on the Audit page. Off by default; structured logs and
          metrics are always emitted regardless.
        </p>
        <form onSubmit={handleSave}>
          <div className="mb-3">
            <div className="custom-control custom-switch">
              <input
                type="checkbox"
                className="custom-control-input"
                id="audit_enabled"
                data-testid="policy-audit-enabled-toggle"
                checked={auditEnabled}
                onChange={e => setAuditEnabled(e.target.checked)}
              />
              <label className="custom-control-label" htmlFor="audit_enabled">
                Record policy decisions to the audit log
              </label>
            </div>
          </div>

          <button
            type="submit"
            className="btn btn-primary btn-sm"
            data-testid="policy-audit-save-button"
            disabled={isSaving}
          >
            {isSaving ? (
              <>
                <i className="fas fa-spinner fa-spin"></i> Saving...
              </>
            ) : (
              <>
                <i className="fas fa-save"></i> Save
              </>
            )}
          </button>
        </form>
      </div>
    </div>
  );
};

export default VpAuditTab;
