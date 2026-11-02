import React, { useCallback, useEffect, useState } from 'react';
import { apiClient } from '../../api';
import { usePermissions } from '../../context/PermissionsContext';
import DefaultsEditor from './DefaultsEditor';
import IdentifierRulesEditor from './IdentifierRulesEditor';
import ProvisioningPreviewPanel from './ProvisioningPreviewPanel';
import TeamRulesEditor from './TeamRulesEditor';
import { emptyConfig, type MemberProvisioningConfig } from './provisioningHelpers';

const MembershipPage: React.FC = () => {
  const { hasPermission } = usePermissions();
  const canEdit = hasPermission('membership.edit');

  const [config, setConfig] = useState<MemberProvisioningConfig>(emptyConfig());
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [savedAt, setSavedAt] = useState<string | null>(null);

  const fetchConfig = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await apiClient.get<MemberProvisioningConfig>('/member-provisioning');
      setConfig({ ...emptyConfig(), ...response.data });
    } catch (err: any) {
      setError(err.message || 'Failed to load provisioning config');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchConfig();
  }, [fetchConfig]);

  const patch = (next: Partial<MemberProvisioningConfig>) => {
    setConfig(prev => ({ ...prev, ...next }));
    setSavedAt(null);
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setSaving(true);
      setError(null);
      const response = await apiClient.put<MemberProvisioningConfig>(
        '/member-provisioning',
        config
      );
      setConfig({ ...emptyConfig(), ...response.data });
      setSavedAt(new Date().toLocaleTimeString());
    } catch (err: any) {
      setError(err.message || 'Failed to save provisioning config');
    } finally {
      setSaving(false);
    }
  };

  const disabled = !canEdit || saving;

  return (
    <div className="container-fluid">
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <h1 className="h3 mb-0 text-gray-800">
          <i className="fas fa-users-cog"></i> Membership
        </h1>
      </div>

      <p className="text-muted">
        Auto-provisioning mints appliance <strong>members</strong> the first time a verified caller
        appears — from a JWT claim, an mTLS certificate, or a named API key — and assigns them to
        teams by rule. A surface still has to opt in before any caller is provisioned through it.
      </p>

      {loading ? (
        <div className="text-center py-5">
          <div className="spinner-border text-primary" role="status">
            <span className="visually-hidden">Loading…</span>
          </div>
        </div>
      ) : (
        <div className="row">
          <div className="col-lg-8">
            <form onSubmit={handleSave}>
              <div className="card shadow mb-4">
                <div className="card-header py-3 d-flex align-items-center justify-content-between">
                  <h6 className="m-0 font-weight-bold text-primary">
                    <i className="fas fa-bolt"></i> Auto-provisioning rules
                  </h6>
                  {config.enabled ? (
                    <span className="badge text-bg-success">Enabled</span>
                  ) : (
                    <span className="badge text-bg-secondary">Disabled</span>
                  )}
                </div>
                <div className="card-body">
                  {error && (
                    <div className="alert alert-danger" role="alert">
                      {error}
                    </div>
                  )}

                  <div className="form-check form-switch mb-3">
                    <input
                      className="form-check-input"
                      type="checkbox"
                      id="provisioning-enabled"
                      checked={config.enabled}
                      disabled={disabled}
                      data-testid="provisioning-enabled"
                      onChange={e => patch({ enabled: e.target.checked })}
                    />
                    <label className="form-check-label fw-bold" htmlFor="provisioning-enabled">
                      Enable auto-provisioning
                    </label>
                  </div>

                  <IdentifierRulesEditor
                    rules={config.identifier_rules}
                    disabled={disabled}
                    onChange={identifier_rules => patch({ identifier_rules })}
                  />

                  <hr />

                  <TeamRulesEditor
                    rules={config.team_rules}
                    disabled={disabled}
                    onChange={team_rules => patch({ team_rules })}
                  />

                  <hr />

                  <DefaultsEditor config={config} disabled={disabled} onChange={patch} />

                  <div className="d-flex align-items-center gap-2 mt-3">
                    <button
                      type="submit"
                      className="btn btn-primary"
                      disabled={disabled}
                      data-testid="provisioning-save"
                    >
                      {saving ? 'Saving…' : 'Save changes'}
                    </button>
                    {savedAt && (
                      <span className="text-success small">
                        <i className="fas fa-check me-1"></i>Saved at {savedAt}
                      </span>
                    )}
                    {!canEdit && (
                      <span className="text-muted small">Read-only — requires membership.edit</span>
                    )}
                  </div>
                </div>
              </div>
            </form>
          </div>

          <div className="col-lg-4">
            <ProvisioningPreviewPanel />
          </div>
        </div>
      )}
    </div>
  );
};

export default MembershipPage;
