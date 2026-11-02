import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { apiClient } from '../api';
import { usePermissions } from '../context/PermissionsContext';
import {
  EMPTY_PROMPT,
  isValidPromptId,
  nextVersionNumber,
  versionVariables,
  type Prompt,
  type PromptMessage,
  type PromptVersion,
} from './EditPromptPage/promptHelpers';

const ROLES = ['system', 'user', 'assistant'];

const EditPromptPage: React.FC = () => {
  const navigate = useNavigate();
  const { promptId } = useParams<{ promptId: string }>();
  const isNew = !promptId;
  const { hasPermission } = usePermissions();
  const canDelete = hasPermission('prompts.delete');

  const [prompt, setPrompt] = useState<Prompt>(EMPTY_PROMPT());
  const [loading, setLoading] = useState(!isNew);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Playground state.
  const [pgVersion, setPgVersion] = useState<number | null>(null);
  const [pgVars, setPgVars] = useState<Record<string, string>>({});
  const [pgResult, setPgResult] = useState<PromptMessage[] | null>(null);
  const [pgError, setPgError] = useState<string | null>(null);

  const fetchPrompt = useCallback(async () => {
    if (!promptId) return;
    try {
      setLoading(true);
      setError(null);
      const response = await apiClient.get<Prompt>(`/prompts/${encodeURIComponent(promptId)}`);
      setPrompt(response.data);
    } catch (err: any) {
      setError(err.message || 'Failed to load prompt');
    } finally {
      setLoading(false);
    }
  }, [promptId]);

  useEffect(() => {
    if (!isNew) fetchPrompt();
  }, [isNew, fetchPrompt]);

  const update = useCallback(
    (patch: Partial<Prompt>) => setPrompt(prev => ({ ...prev, ...patch })),
    []
  );

  const updateVersion = (idx: number, patch: Partial<PromptVersion>) =>
    update({ versions: prompt.versions.map((v, i) => (i === idx ? { ...v, ...patch } : v)) });

  const updateMessage = (vIdx: number, mIdx: number, patch: Partial<PromptMessage>) =>
    updateVersion(vIdx, {
      messages: prompt.versions[vIdx].messages.map((m, i) => (i === mIdx ? { ...m, ...patch } : m)),
    });

  const addVersion = () =>
    update({
      versions: [
        ...prompt.versions,
        {
          version: nextVersionNumber(prompt),
          messages: [{ role: 'system', content: '' }],
          label: '',
        },
      ],
    });

  const removeVersion = (idx: number) =>
    update({ versions: prompt.versions.filter((_, i) => i !== idx) });

  const addMessage = (vIdx: number) =>
    updateVersion(vIdx, {
      messages: [...prompt.versions[vIdx].messages, { role: 'user', content: '' }],
    });

  const removeMessage = (vIdx: number, mIdx: number) =>
    updateVersion(vIdx, { messages: prompt.versions[vIdx].messages.filter((_, i) => i !== mIdx) });

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setError(null);
      if (!prompt.name.trim()) {
        setError('A name is required');
        return;
      }
      if (isNew && !isValidPromptId(prompt.id.trim())) {
        setError('Id must be 1–128 characters of letters, digits, "_" or "-"');
        return;
      }
      const payload: Prompt = {
        ...prompt,
        id: prompt.id.trim(),
        name: prompt.name.trim(),
        description: prompt.description?.trim() || null,
        default_version: prompt.default_version ?? null,
      };
      try {
        setSaving(true);
        if (isNew) {
          await apiClient.post('/prompts', payload);
        } else {
          await apiClient.put(`/prompts/${encodeURIComponent(prompt.id)}`, payload);
        }
        navigate('/prompts');
      } catch (err: any) {
        setError(err.message || 'Failed to save prompt');
      } finally {
        setSaving(false);
      }
    },
    [prompt, isNew, navigate]
  );

  const handleDelete = useCallback(async () => {
    if (!promptId) return;
    try {
      setSaving(true);
      await apiClient.delete(`/prompts/${encodeURIComponent(promptId)}`);
      navigate('/prompts');
    } catch (err: any) {
      setError(err.message || 'Failed to delete prompt');
    } finally {
      setSaving(false);
    }
  }, [promptId, navigate]);

  // The version the playground previews and the variables it declares.
  const pgSelected = useMemo(
    () => prompt.versions.find(v => v.version === pgVersion) ?? prompt.versions[0],
    [prompt.versions, pgVersion]
  );
  const pgVarNames = useMemo(() => versionVariables(pgSelected), [pgSelected]);

  const runPlayground = useCallback(async () => {
    setPgError(null);
    setPgResult(null);
    if (isNew) {
      setPgError('Save the prompt before running the playground.');
      return;
    }
    try {
      const response = await apiClient.post<{ messages: PromptMessage[] }>(
        `/prompts/${encodeURIComponent(prompt.id)}/render`,
        { version: pgSelected?.version, variables: pgVars }
      );
      setPgResult(response.data.messages ?? []);
    } catch (err: any) {
      setPgError(err.message || 'Render failed');
    }
  }, [isNew, prompt.id, pgSelected, pgVars]);

  if (loading) {
    return (
      <div className="container mt-4">
        <div className="text-center py-4">
          <div className="spinner-border text-primary" role="status">
            <span className="visually-hidden">Loading…</span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="container-fluid">
      <div className="mb-3">
        <button className="btn btn-sm btn-secondary" onClick={() => navigate('/prompts')}>
          <i className="fas fa-arrow-left"></i>
        </button>
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

      <form onSubmit={handleSubmit}>
        <div className="card shadow mb-4">
          <div className="card-header py-3">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-comment-dots"></i> {isNew ? 'New Prompt' : 'Edit Prompt'}
            </h6>
          </div>
          <div className="card-body">
            <div className="row">
              <div className="col-md-6 mb-3">
                <label className="form-label">Name</label>
                <input
                  className="form-control"
                  value={prompt.name}
                  onChange={e => update({ name: e.target.value })}
                  placeholder="Customer greeter"
                />
              </div>
              <div className="col-md-6 mb-3">
                <label className="form-label">Id (slug)</label>
                <input
                  className="form-control"
                  value={prompt.id}
                  disabled={!isNew}
                  onChange={e => update({ id: e.target.value })}
                  placeholder="customer-greeter"
                />
                <small className="text-muted">
                  Referenced by callers; letters, digits, "_", "-".
                </small>
              </div>
            </div>
            <div className="mb-3">
              <label className="form-label">Description</label>
              <input
                className="form-control"
                value={prompt.description ?? ''}
                onChange={e => update({ description: e.target.value })}
              />
            </div>
            <div className="row">
              <div className="col-md-6 mb-3">
                <label className="form-label">Default version</label>
                <select
                  className="form-select"
                  value={prompt.default_version ?? ''}
                  onChange={e =>
                    update({ default_version: e.target.value ? Number(e.target.value) : null })
                  }
                >
                  <option value="">Highest version</option>
                  {prompt.versions.map(v => (
                    <option key={v.version} value={v.version}>
                      Version {v.version}
                      {v.label ? ` (${v.label})` : ''}
                    </option>
                  ))}
                </select>
              </div>
              <div className="col-md-6 mb-3">
                <label className="form-label d-block">Status</label>
                <div className="form-check form-switch">
                  <input
                    className="form-check-input"
                    type="checkbox"
                    role="switch"
                    id="prompt-enabled"
                    checked={prompt.status === 'enabled'}
                    onChange={e => update({ status: e.target.checked ? 'enabled' : 'disabled' })}
                  />
                  <label className="form-check-label" htmlFor="prompt-enabled">
                    Enabled
                  </label>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="card shadow mb-4">
          <div className="card-header py-3 d-flex justify-content-between align-items-center">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-layer-group"></i> Versions
            </h6>
            <button type="button" className="btn btn-sm btn-outline-primary" onClick={addVersion}>
              <i className="fas fa-plus"></i> Add version
            </button>
          </div>
          <div className="card-body">
            {prompt.versions.map((v, vIdx) => (
              <div key={vIdx} className="border rounded p-3 mb-3">
                <div className="d-flex justify-content-between align-items-center mb-2">
                  <div className="d-flex align-items-center gap-2">
                    <span className="badge text-bg-secondary">Version {v.version}</span>
                    <input
                      className="form-control form-control-sm"
                      style={{ width: 180 }}
                      value={v.label ?? ''}
                      onChange={e => updateVersion(vIdx, { label: e.target.value })}
                      placeholder="label (optional)"
                    />
                  </div>
                  {prompt.versions.length > 1 && (
                    <button
                      type="button"
                      className="btn btn-sm btn-outline-danger"
                      onClick={() => removeVersion(vIdx)}
                    >
                      <i className="fas fa-trash"></i>
                    </button>
                  )}
                </div>
                {v.messages.map((m, mIdx) => (
                  <div key={mIdx} className="row g-2 mb-2 align-items-start">
                    <div className="col-2">
                      <select
                        className="form-select form-select-sm"
                        value={m.role}
                        onChange={e => updateMessage(vIdx, mIdx, { role: e.target.value })}
                      >
                        {ROLES.map(r => (
                          <option key={r} value={r}>
                            {r}
                          </option>
                        ))}
                      </select>
                    </div>
                    <div className="col">
                      <textarea
                        className="form-control form-control-sm"
                        rows={2}
                        value={m.content}
                        onChange={e => updateMessage(vIdx, mIdx, { content: e.target.value })}
                        placeholder="Message content — use {{variable}} placeholders"
                      />
                    </div>
                    <div className="col-auto">
                      {v.messages.length > 1 && (
                        <button
                          type="button"
                          className="btn btn-sm btn-outline-danger"
                          onClick={() => removeMessage(vIdx, mIdx)}
                        >
                          <i className="fas fa-times"></i>
                        </button>
                      )}
                    </div>
                  </div>
                ))}
                <button
                  type="button"
                  className="btn btn-sm btn-outline-secondary"
                  onClick={() => addMessage(vIdx)}
                >
                  <i className="fas fa-plus"></i> Add message
                </button>
                {versionVariables(v).length > 0 && (
                  <div className="mt-2 small text-muted">
                    Variables:{' '}
                    {versionVariables(v).map(n => (
                      <code key={n} className="me-1">{`{{${n}}}`}</code>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        <div className="d-flex gap-2 mb-4">
          <button type="submit" className="btn btn-primary" disabled={saving}>
            {saving ? 'Saving…' : 'Save Prompt'}
          </button>
          {!isNew && canDelete && (
            <button
              type="button"
              className="btn btn-outline-danger"
              disabled={saving}
              onClick={handleDelete}
            >
              Delete
            </button>
          )}
        </div>
      </form>

      {/* Playground */}
      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-play"></i> Playground
          </h6>
        </div>
        <div className="card-body">
          {isNew ? (
            <p className="text-muted mb-0">Save the prompt to preview a rendered version.</p>
          ) : (
            <>
              <div className="row mb-3">
                <div className="col-md-4">
                  <label className="form-label">Version</label>
                  <select
                    className="form-select"
                    value={pgSelected?.version ?? ''}
                    onChange={e => setPgVersion(Number(e.target.value))}
                  >
                    {prompt.versions.map(v => (
                      <option key={v.version} value={v.version}>
                        Version {v.version}
                        {v.label ? ` (${v.label})` : ''}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
              {pgVarNames.length > 0 && (
                <div className="mb-3">
                  <label className="form-label">Variables</label>
                  {pgVarNames.map(name => (
                    <div className="input-group input-group-sm mb-1" key={name}>
                      <span className="input-group-text" style={{ minWidth: 140 }}>
                        {`{{${name}}}`}
                      </span>
                      <input
                        className="form-control"
                        value={pgVars[name] ?? ''}
                        onChange={e => setPgVars(prev => ({ ...prev, [name]: e.target.value }))}
                      />
                    </div>
                  ))}
                </div>
              )}
              <button type="button" className="btn btn-sm btn-primary" onClick={runPlayground}>
                <i className="fas fa-play"></i> Render
              </button>
              {pgError && <div className="alert alert-warning mt-3 mb-0">{pgError}</div>}
              {pgResult && (
                <div className="mt-3">
                  {pgResult.map((m, i) => (
                    <div key={i} className="border rounded p-2 mb-2">
                      <div className="small text-muted text-uppercase">{m.role}</div>
                      <div style={{ whiteSpace: 'pre-wrap' }}>{m.content}</div>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default EditPromptPage;
