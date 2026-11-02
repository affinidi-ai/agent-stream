import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { apiClient } from '../../api';
import PolicySimulatePanel, { POLICY_SIMULATE_DEFAULT_INPUT } from './PolicySimulatePanel';
import PolicyVersionHistory from './PolicyVersionHistory';

interface PolicyDefinition {
  id: string;
  name: string;
  description: string;
  policy_type: 'appliance' | 'llm' | 'ide';
  policy: string;
  enabled: boolean;
  created_at: string;
  updated_at?: string;
  sample_input?: string;
}

/** Rego package name for each policy type. Query path is `data.<pkg>.allow`. */
const PACKAGE_FOR_TYPE: Record<PolicyDefinition['policy_type'], string> = {
  appliance: 'agentstream.policy',
  llm: 'llm.policy',
  ide: 'ide.policy',
};

/** Starter Rego template for a newly-created policy of the given type. */
const defaultPolicyFor = (type: PolicyDefinition['policy_type']): string =>
  `package ${PACKAGE_FOR_TYPE[type]}

# Allow all traffic by default
default allow = true`;

/** True when `policy` is still an untouched starter template (any type). */
const isPristineTemplate = (policy: string): boolean =>
  (Object.keys(PACKAGE_FOR_TYPE) as PolicyDefinition['policy_type'][]).some(
    t => defaultPolicyFor(t) === policy
  );

const EditPolicyDefinitionPage: React.FC = () => {
  const navigate = useNavigate();
  const { id } = useParams<{ id: string }>();
  const [searchParams] = useSearchParams();
  const isCreateMode = !id || id === 'new';
  const typeFromQuery = searchParams.get('type') as 'appliance' | 'llm' | 'ide' | null;
  const initialType = typeFromQuery || 'appliance';

  const [form, setForm] = useState<PolicyDefinition>({
    id: '',
    name: '',
    description: '',
    policy_type: initialType,
    policy: defaultPolicyFor(initialType),
    enabled: true,
    created_at: new Date().toISOString(),
  });

  const [loading, setLoading] = useState(!isCreateMode);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [isModified, setIsModified] = useState(false);
  const [isValidating, setIsValidating] = useState(false);
  const [policyValid, setPolicyValid] = useState(true);
  const [policyErrors, setPolicyErrors] = useState<string[]>([]);
  const [versionRefreshKey, setVersionRefreshKey] = useState(0);

  useEffect(() => {
    if (!isCreateMode && id) {
      apiClient
        .fetch(`/api/v1/policy-definitions/${encodeURIComponent(id)}`)
        .then(r => {
          if (!r.ok) throw new Error(`Failed to load: ${r.statusText}`);
          return r.json();
        })
        .then((data: PolicyDefinition) => {
          setForm(data);
          setLoading(false);
        })
        .catch(e => {
          setError(e.message);
          setLoading(false);
        });
    }
  }, [id, isCreateMode]);

  // Debounced policy validation
  useEffect(() => {
    if (!form.policy?.trim()) {
      setPolicyValid(true);
      setPolicyErrors([]);
      return;
    }
    const timer = setTimeout(async () => {
      setIsValidating(true);
      try {
        const response = await apiClient.post('/surfaces/validate-policy', {
          policy: form.policy,
        });
        setPolicyValid((response as any).data.valid);
        setPolicyErrors((response as any).data.error ? [(response as any).data.error] : []);
      } catch {
        setPolicyValid(true);
        setPolicyErrors([]);
      } finally {
        setIsValidating(false);
      }
    }, 500);
    return () => clearTimeout(timer);
  }, [form.policy]);

  const handleSave = useCallback(async () => {
    if (!form.name.trim()) {
      setError('Name is required');
      return;
    }
    if (!policyValid) {
      setError('Fix the policy errors before saving.');
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const payload = {
        ...form,
        id: isCreateMode ? crypto.randomUUID() : form.id,
        created_at: isCreateMode ? new Date().toISOString() : form.created_at,
      };
      const url = isCreateMode
        ? `/api/v1/policy-definitions`
        : `/api/v1/policy-definitions/${encodeURIComponent(form.id)}`;
      const resp = await apiClient.fetch(url, {
        method: isCreateMode ? 'POST' : 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!resp.ok) {
        const errData = await resp.json().catch(() => ({ error: resp.statusText }));
        throw new Error(errData.error || resp.statusText);
      }
      const saved = (await resp.json().catch(() => null)) as PolicyDefinition | null;
      setSuccess(isCreateMode ? 'Policy created!' : 'Policy updated!');
      setIsModified(false);
      setTimeout(() => setSuccess(null), 2500);
      if (isCreateMode) {
        // Stay in the editor for the just-created policy, now addressable by id.
        navigate(`/policy-definitions/${encodeURIComponent(payload.id)}`, { replace: true });
      } else {
        if (saved) setForm(saved);
        // Reload the version history so the new revision shows immediately.
        setVersionRefreshKey(k => k + 1);
      }
    } catch (e: any) {
      setError(e.message || 'Failed to save policy');
    } finally {
      setSaving(false);
    }
  }, [form, isCreateMode, navigate, policyValid]);

  // Keyboard shortcut Ctrl+S / Cmd+S
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        e.preventDefault();
        const noChanges = !isCreateMode && !isModified;
        if (!saving && !noChanges) handleSave();
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [saving, handleSave, isCreateMode, isModified]);

  if (loading) {
    return (
      <div className="container-fluid">
        <div className="text-center py-5">
          <div className="spinner-border text-primary" role="status" />
        </div>
      </div>
    );
  }

  const saveDisabled = saving || (!isCreateMode && !isModified);

  return (
    <div className="container-fluid">
      <div className="mb-3">
        <button
          className="btn btn-sm btn-secondary"
          onClick={() => navigate(`/policies?tab=${form.policy_type}`)}
        >
          <i className="fas fa-arrow-left"></i>
        </button>
      </div>
      <div className="card shadow mb-4 channel-editor-card">
        <form
          onSubmit={e => {
            e.preventDefault();
            handleSave();
          }}
        >
          <div className="card-header py-3 d-flex justify-content-between align-items-center">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-shield-alt"></i>{' '}
              {isCreateMode ? 'Create Policy Definition' : `Edit Policy: ${form.name}`}
            </h6>
            <div className="d-flex align-items-center">
              {/* Wrapper span shows the not-allowed cursor on hover — a disabled
                <button> has pointer-events:none, so it can't show a cursor. */}
              <span
                className="d-inline-block me-2"
                style={saveDisabled ? { cursor: 'not-allowed' } : undefined}
              >
                <button
                  type="submit"
                  className={`btn btn-sm btn-primary ${saveDisabled ? 'disabled' : ''}`}
                  disabled={saveDisabled}
                  style={saveDisabled ? { pointerEvents: 'none' } : undefined}
                >
                  <i className={`fas ${saving ? 'fa-spinner fa-spin' : 'fa-save'}`}></i>
                  {saving ? ' Saving...' : isCreateMode ? ' Create' : ' Save'}
                </button>
              </span>
            </div>
          </div>

          <div className="card-body-channel-editor p-3">
            {error && (
              <div className="alert alert-danger alert-dismissible fade show">
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
            {success && (
              <div className="alert alert-success alert-dismissible fade show">
                <i className="fas fa-check-circle me-2"></i>
                {success}
                <button
                  type="button"
                  className="btn-close"
                  onClick={() => setSuccess(null)}
                  aria-label="Close"
                />
              </div>
            )}

            <div className="row">
              <div className="col-md-6">
                <div className="mb-3 mb-3">
                  <label className="font-weight-bold">
                    Name <span className="text-danger">*</span>
                  </label>
                  <input
                    type="text"
                    className="form-control form-control-sm"
                    value={form.name}
                    onChange={e => {
                      setForm({ ...form, name: e.target.value });
                      setIsModified(true);
                    }}
                    placeholder="e.g. Require Authentication"
                    required
                  />
                </div>
              </div>
              <div className="col-md-3">
                <div className="mb-3 mb-3">
                  <label className="font-weight-bold">
                    Type <span className="text-danger">*</span>
                  </label>
                  <select
                    className="form-control form-control-sm dropdown-styling"
                    value={form.policy_type}
                    disabled={!isCreateMode}
                    title={
                      !isCreateMode ? "A policy's type can't be changed after creation" : undefined
                    }
                    onChange={e => {
                      const nextType = e.target.value as 'appliance' | 'llm' | 'ide';
                      setForm(prev => ({
                        ...prev,
                        policy_type: nextType,
                        // Swap the starter package only while the body is still an
                        // untouched template — never clobber hand-edited Rego.
                        policy: isPristineTemplate(prev.policy)
                          ? defaultPolicyFor(nextType)
                          : prev.policy,
                      }));
                      setIsModified(true);
                    }}
                  >
                    <option value="appliance">Trust Fabric</option>
                    <option value="llm">LLM</option>
                    <option value="ide">IDE</option>
                  </select>
                  {!isCreateMode && (
                    <small className="form-text text-muted">
                      A policy's type is fixed once created.
                    </small>
                  )}
                </div>
              </div>
              <div className="col-md-3">
                <div className="mb-3 mb-3">
                  <label className="font-weight-bold">Status</label>
                  <div className="form-check mt-1">
                    <input
                      className="form-check-input"
                      type="checkbox"
                      id="policy-enabled"
                      checked={form.enabled}
                      onChange={e => {
                        setForm({ ...form, enabled: e.target.checked });
                        setIsModified(true);
                      }}
                    />
                    <label className="form-check-label" htmlFor="policy-enabled">
                      Enabled
                    </label>
                  </div>
                </div>
              </div>
            </div>

            <div className="mb-3 mb-3">
              <label className="font-weight-bold">Description</label>
              <input
                type="text"
                className="form-control form-control-sm"
                value={form.description}
                onChange={e => {
                  setForm({ ...form, description: e.target.value });
                  setIsModified(true);
                }}
                placeholder="What does this policy do?"
              />
            </div>

            {/* Rego Editor */}
            <div className="mb-3">
              <label className="font-weight-bold">
                Policy Content (Rego)
                {isValidating && (
                  <span className="ms-2 text-muted small">
                    <i className="fas fa-spinner fa-spin"></i> Validating...
                  </span>
                )}
                {!isValidating && form.policy.trim() && policyValid && (
                  <span className="ms-2 text-success small">
                    <i className="fas fa-check-circle"></i> Valid
                  </span>
                )}
                {!isValidating && form.policy.trim() && !policyValid && (
                  <span className="ms-2 text-danger small">
                    <i className="fas fa-times-circle"></i> Invalid
                  </span>
                )}
              </label>
              <textarea
                className={`form-control font-monospace small ${policyValid ? '' : 'is-invalid'}`}
                rows={16}
                style={{ fontSize: '0.875rem' }}
                value={form.policy}
                onChange={e => {
                  setForm({ ...form, policy: e.target.value });
                  setIsModified(true);
                }}
                placeholder="...add policy here..."
              />
              {policyErrors.length > 0 && (
                <div className="invalid-feedback d-block">
                  {policyErrors.map((err, idx) => (
                    <div key={idx}>{err}</div>
                  ))}
                </div>
              )}
              {!isValidating && form.policy.trim() && policyValid && (
                <small className="form-text text-success">
                  <i className="fas fa-check-circle"></i> Policy syntax is valid
                </small>
              )}
              <small className="form-text text-muted">
                Leave empty to allow all traffic. Policy is evaluated with JWT claims, HTTP context,
                and routing information.
              </small>
            </div>

            {!isCreateMode && (
              <>
                <PolicySimulatePanel
                  policyId={form.id}
                  policyType={form.policy_type}
                  draftPolicy={form.policy}
                  sampleInput={form.sample_input ?? POLICY_SIMULATE_DEFAULT_INPUT}
                  onSampleInputChange={value => {
                    setForm(f => ({ ...f, sample_input: value }));
                    setIsModified(true);
                  }}
                />
                <PolicyVersionHistory
                  policyId={form.id}
                  name={form.name}
                  description={form.description}
                  refreshKey={versionRefreshKey}
                />
              </>
            )}
          </div>
        </form>
      </div>
    </div>
  );
};

export default EditPolicyDefinitionPage;
