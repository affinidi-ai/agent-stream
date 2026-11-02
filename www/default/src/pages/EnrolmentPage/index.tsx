import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../../api';
import { showToast } from '../../utils/toaster';
import {
  confirmDiscardIfDirty,
  useUnsavedChangesPrompt,
} from '../../components/builder/hooks/useUnsavedChangesPrompt';
import { setNavGuard } from '../../utils/navGuard';
import { usePermissions } from '../../context/PermissionsContext';
import DefaultsEditor from './DefaultsEditor';
import IdentifierRulesEditor from './IdentifierRulesEditor';
import InfoTooltip from './InfoTooltip';
import ProvisioningPreviewPanel from './ProvisioningPreviewPanel';
import TeamRulesEditor from './TeamRulesEditor';
import { emptyConfig, type MemberProvisioningConfig } from './provisioningHelpers';

const DIRTY_MESSAGE =
  'You have unsaved changes to the enrolment configuration. Leave anyway and lose your edits?';

const EnrolmentPage: React.FC = () => {
  const navigate = useNavigate();
  const { hasPermission } = usePermissions();
  const canEdit = hasPermission('enrolment.edit');

  const [config, setConfig] = useState<MemberProvisioningConfig>(emptyConfig());
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isModified, setIsModified] = useState(false);

  const fetchConfig = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await apiClient.get<MemberProvisioningConfig>('/member-provisioning');
      setConfig({ ...emptyConfig(), ...response.data });
      setIsModified(false);
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
    setIsModified(true);
  };

  const handleSave = useCallback(
    async (e?: React.FormEvent) => {
      e?.preventDefault();
      try {
        setSaving(true);
        setError(null);
        const response = await apiClient.put<MemberProvisioningConfig>(
          '/member-provisioning',
          config
        );
        setConfig({ ...emptyConfig(), ...response.data });
        setIsModified(false);
        showToast('success', 'Provisioning configuration saved.');
      } catch (err: any) {
        setError(err.message || 'Failed to save provisioning config');
      } finally {
        setSaving(false);
      }
    },
    [config]
  );

  const disabled = !canEdit || saving;

  useUnsavedChangesPrompt(isModified);

  useEffect(() => {
    setNavGuard(() => confirmDiscardIfDirty(isModified, DIRTY_MESSAGE));
    return () => setNavGuard(null);
  }, [isModified]);

  useEffect(() => {
    const handleKeyboardSave = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key === 's') {
        event.preventDefault();
        if (!disabled) void handleSave();
      }
    };
    document.addEventListener('keydown', handleKeyboardSave);
    return () => document.removeEventListener('keydown', handleKeyboardSave);
  }, [handleSave, disabled]);

  return (
    <div className="container-fluid">
      <div className="mb-3">
        <button
          className="btn btn-sm btn-secondary"
          onClick={() => {
            if (confirmDiscardIfDirty(isModified, DIRTY_MESSAGE)) navigate(-1);
          }}
          disabled={saving}
        >
          <i className="fas fa-arrow-left"></i>
        </button>
      </div>

      <div className="mb-4">
        <h1 className="h3 mb-0 text-gray-800">
          <i className="fas fa-users-cog me-2"></i>
          Enrolment
        </h1>
        <p className="text-muted mt-2 mb-0">
          Enrolment auto-provisions Agent Stream members the first time a verified caller appears,
          as identified by a JWT claim, an mTLS certificate, or a named API key. New members are
          assigned to teams by rules you can define here. A Surface still has to opt-in for
          automatic enrolment before any caller is provisioned through it.
        </p>
      </div>

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
                    <InfoTooltip
                      title="Auto-provisioning"
                      text="Master switch. When on, a verified caller with no existing member is created as one on first request — but only on Surfaces that opt in via their own 'Auto-provision' toggle. When off, unrecognised callers fall back to the anonymous member."
                    />
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

                  <hr />

                  <div className="d-flex justify-content-between align-items-center">
                    {!canEdit && (
                      <span className="text-muted small">Read-only — requires enrolment.edit</span>
                    )}
                    <div className="ms-auto">
                      <button
                        type="submit"
                        className="btn btn-sm btn-primary"
                        disabled={disabled}
                        data-testid="provisioning-save"
                      >
                        {saving ? (
                          <>
                            <span
                              className="spinner-border spinner-border-sm me-2"
                              role="status"
                              aria-hidden="true"
                            ></span>
                            Saving...
                          </>
                        ) : (
                          <>
                            <i className="fas fa-save me-1"></i> Save
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </form>
          </div>

          <div className="col-lg-4">
            <ProvisioningPreviewPanel config={config} />
          </div>
        </div>
      )}
    </div>
  );
};

export default EnrolmentPage;
