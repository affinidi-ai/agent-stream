import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { apiClient } from '../api';
import { formatDateTime } from '../utils/stringUtils';

/**
 * Rich create/edit view for an **OAuth Identifier** — a reusable set of public
 * OAuth 2.0 / OIDC sign-in identifiers (tenant/authority, client id, scopes)
 * referenced by IDE front-door sign-in, member upstream sign-in, and the
 * sandbox. Mirrors the Edit JWT Verification Strategy page. All fields are
 * **public** OAuth identifiers — never secrets.
 */

type Shape = 'entra' | 'okta' | 'oidc';

interface OAuthIdentifierForm {
  name: string;
  description: string;
  provider: Shape;
  // Entra
  tenant_id: string;
  // Okta
  domain: string;
  authorization_server_id: string;
  // OIDC
  issuer: string;
  // Common
  client_id: string;
  scopes: string; // newline-per-scope textarea value
}

const EMPTY_FORM: OAuthIdentifierForm = {
  name: '',
  description: '',
  provider: 'entra',
  tenant_id: '',
  domain: '',
  authorization_server_id: '',
  issuer: '',
  client_id: '',
  scopes: '',
};

const SHAPE_LABELS: Record<Shape, string> = {
  entra: 'Microsoft Entra ID',
  okta: 'Okta',
  oidc: 'Generic OpenID Connect',
};

/** Best-effort authority preview mirroring the backend `authority()` logic. */
function authorityPreview(form: OAuthIdentifierForm): string {
  if (form.provider === 'entra') {
    const t = form.tenant_id.trim();
    return t ? `https://login.microsoftonline.com/${t}` : '';
  }
  if (form.provider === 'okta') {
    const d = form.domain.trim().replace(/\/$/, '');
    if (!d) return '';
    const asid = form.authorization_server_id.trim() || 'default';
    return `https://${d}/oauth2/${asid}`;
  }
  return form.issuer.trim().replace(/\/$/, '');
}

const BACK_URL = '/credentials?tab=oauth-identifiers';

const EditOAuthIdentifierPage: React.FC = () => {
  const navigate = useNavigate();
  const { id } = useParams<{ id: string }>();
  const isNew = !id || id === 'new';

  const [form, setForm] = useState<OAuthIdentifierForm>(EMPTY_FORM);
  const [meta, setMeta] = useState<{ id: string; created_at: string; updated_at: string } | null>(
    null
  );
  const [loading, setLoading] = useState(!isNew);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isNew) {
      loadProfile();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  const loadProfile = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await apiClient.fetch(
        `/api/v1/oauth-identifiers/${encodeURIComponent(id!)}`
      );
      if (!response.ok) {
        throw new Error(`Failed to load profile: ${response.statusText}`);
      }
      const data = await response.json();
      const provider: Shape =
        data.provider === 'okta' || data.provider === 'oidc' ? data.provider : 'entra';
      setMeta({
        id: data.id ?? id!,
        created_at: data.created_at ?? '',
        updated_at: data.updated_at ?? '',
      });
      setForm({
        name: data.name ?? '',
        description: data.description ?? '',
        provider,
        tenant_id: data.tenant_id ?? '',
        domain: data.domain ?? '',
        authorization_server_id: data.authorization_server_id ?? '',
        issuer: data.issuer ?? '',
        client_id: data.client_id ?? '',
        scopes: Array.isArray(data.scopes) ? data.scopes.join('\n') : '',
      });
    } catch (e: any) {
      setError(e.message ?? 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>
  ) => {
    const { name, value } = e.target;
    setForm(prev => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name.trim()) {
      setError('Name is required.');
      return;
    }
    if (!form.client_id.trim()) {
      setError('Client ID is required.');
      return;
    }
    const scopes = form.scopes
      .split('\n')
      .map(s => s.trim())
      .filter(Boolean);
    if (scopes.length === 0) {
      setError('At least one scope is required.');
      return;
    }

    // Shape-specific validation + payload.
    const body: Record<string, unknown> = {
      name: form.name.trim(),
      description: form.description.trim(),
      provider: form.provider,
      client_id: form.client_id.trim(),
      scopes,
    };
    if (form.provider === 'entra') {
      if (!form.tenant_id.trim()) {
        setError('Tenant ID is required for the Entra shape.');
        return;
      }
      body.tenant_id = form.tenant_id.trim();
    } else if (form.provider === 'okta') {
      if (!form.domain.trim()) {
        setError('Okta domain is required for the Okta shape.');
        return;
      }
      body.domain = form.domain.trim();
      if (form.authorization_server_id.trim()) {
        body.authorization_server_id = form.authorization_server_id.trim();
      }
    } else {
      if (!form.issuer.trim()) {
        setError('Issuer is required for the OIDC shape.');
        return;
      }
      body.issuer = form.issuer.trim();
    }

    setSaving(true);
    setError(null);
    try {
      const url = isNew
        ? '/api/v1/oauth-identifiers'
        : `/api/v1/oauth-identifiers/${encodeURIComponent(id!)}`;
      const method = isNew ? 'POST' : 'PUT';
      const response = await apiClient.fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!response.ok) {
        const text = await response.text();
        throw new Error(text || response.statusText);
      }
      navigate(BACK_URL);
    } catch (e: any) {
      setError(e.message ?? 'Save failed');
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="container-fluid text-center py-5">
        <div className="spinner-border text-primary" role="status" />
      </div>
    );
  }

  const authority = authorityPreview(form);

  return (
    <div className="container-fluid">
      <div className="mb-3">
        <button className="btn btn-secondary btn-sm" onClick={() => navigate(BACK_URL)}>
          <i className="fas fa-arrow-left"></i>
        </button>
      </div>
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <h1 className="h3 mb-0 text-gray-800">
          <i className="fas fa-fingerprint me-2"></i>
          {isNew ? 'New OAuth Identifier' : 'Edit OAuth Identifier'}
        </h1>
      </div>

      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-primary">Sign-in Identifiers</h6>
        </div>
        <div className="card-body">
          <div className="alert alert-info">
            <i className="fas fa-info-circle me-2"></i>
            These are <strong>public</strong> OAuth identifiers only (tenant/authority, client id,
            scopes) — never secrets. They are safe to publish to clients, and any surface that
            references this profile follows changes made here.
          </div>

          {error && (
            <div className="alert alert-danger">
              <i className="fas fa-exclamation-triangle me-2"></i>
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit}>
            {/* Read-only identity metadata (existing profiles only) */}
            {!isNew && meta && (
              <div className="mb-3 p-3 bg-light rounded border">
                <div className="row g-3">
                  <div className="col-md-4">
                    <label className="text-muted small mb-1 d-block">OAuth Identifier ID</label>
                    <code className="small">{meta.id}</code>
                  </div>
                  <div className="col-md-4">
                    <label className="text-muted small mb-1 d-block">Created</label>
                    <div className="small">
                      {meta.created_at ? formatDateTime(meta.created_at) : '—'}
                    </div>
                  </div>
                  <div className="col-md-4">
                    <label className="text-muted small mb-1 d-block">Last updated</label>
                    <div className="small">
                      {meta.updated_at ? formatDateTime(meta.updated_at) : '—'}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Name */}
            <div className="mb-3">
              <label htmlFor="name">
                Name <span className="text-danger">*</span>
              </label>
              <input
                id="name"
                name="name"
                type="text"
                className="form-control"
                value={form.name}
                onChange={handleChange}
                placeholder="e.g. Entra – Microsoft 365 Copilot"
                required
              />
              <small className="form-text text-muted">
                Human-readable label shown in the list and in the sign-in pickers that reference
                this profile.
              </small>
            </div>

            {/* Description */}
            <div className="mb-3">
              <label htmlFor="description">Description</label>
              <input
                id="description"
                name="description"
                type="text"
                className="form-control"
                value={form.description}
                onChange={handleChange}
                placeholder="What is this profile for?"
              />
            </div>

            {/* Provider shape */}
            <div className="mb-3">
              <label htmlFor="provider">
                Provider shape <span className="text-danger">*</span>
              </label>
              <select
                id="provider"
                name="provider"
                className="form-select"
                value={form.provider}
                onChange={handleChange}
              >
                {(Object.keys(SHAPE_LABELS) as Shape[]).map(s => (
                  <option key={s} value={s}>
                    {SHAPE_LABELS[s]}
                  </option>
                ))}
              </select>
              <small className="form-text text-muted">
                Each provider expresses its authority differently — <code>tenant_id</code> is
                Entra-only, Okta uses a domain + authorization server, and generic OIDC uses the
                issuer URL.
              </small>
            </div>

            {/* Shape-specific fields */}
            {form.provider === 'entra' && (
              <div className="mb-3">
                <label htmlFor="tenant_id">
                  Tenant ID <span className="text-danger">*</span>
                </label>
                <input
                  id="tenant_id"
                  name="tenant_id"
                  type="text"
                  className="form-control"
                  value={form.tenant_id}
                  onChange={handleChange}
                  placeholder="00000000-0000-0000-0000-000000000000"
                />
                <small className="form-text text-muted">
                  Entra directory (tenant) id — a GUID, a verified domain, or <code>common</code> /{' '}
                  <code>organizations</code>.
                </small>
              </div>
            )}

            {form.provider === 'okta' && (
              <>
                <div className="mb-3">
                  <label htmlFor="domain">
                    Okta domain <span className="text-danger">*</span>
                  </label>
                  <input
                    id="domain"
                    name="domain"
                    type="text"
                    className="form-control"
                    value={form.domain}
                    onChange={handleChange}
                    placeholder="dev-123456.okta.com"
                  />
                  <small className="form-text text-muted">Your Okta org domain (no scheme).</small>
                </div>
                <div className="mb-3">
                  <label htmlFor="authorization_server_id">Authorization server ID</label>
                  <input
                    id="authorization_server_id"
                    name="authorization_server_id"
                    type="text"
                    className="form-control"
                    value={form.authorization_server_id}
                    onChange={handleChange}
                    placeholder="default"
                  />
                  <small className="form-text text-muted">
                    Custom authorization server id. Leave blank to use <code>default</code>.
                  </small>
                </div>
              </>
            )}

            {form.provider === 'oidc' && (
              <div className="mb-3">
                <label htmlFor="issuer">
                  Issuer <span className="text-danger">*</span>
                </label>
                <input
                  id="issuer"
                  name="issuer"
                  type="text"
                  className="form-control"
                  value={form.issuer}
                  onChange={handleChange}
                  placeholder="https://accounts.example.com"
                />
                <small className="form-text text-muted">
                  The provider's issuer URL, used verbatim as the OAuth authority.
                </small>
              </div>
            )}

            {/* Authority preview */}
            {authority && (
              <div className="mb-3">
                <label className="text-muted small mb-1">Resolved authority</label>
                <div>
                  <code>{authority}</code>
                </div>
              </div>
            )}

            {/* Client ID */}
            <div className="mb-3">
              <label htmlFor="client_id">
                Client ID <span className="text-danger">*</span>
              </label>
              <input
                id="client_id"
                name="client_id"
                type="text"
                className="form-control"
                value={form.client_id}
                onChange={handleChange}
                placeholder="Public client (application) id"
                required
              />
              <small className="form-text text-muted">
                The public client (application) id used to request tokens. Public identifier — not a
                secret.
              </small>
            </div>

            {/* Scopes */}
            <div className="mb-3">
              <label htmlFor="scopes">
                Scopes <span className="text-danger">*</span>
              </label>
              <textarea
                id="scopes"
                name="scopes"
                className="form-control font-monospace"
                rows={5}
                value={form.scopes}
                onChange={handleChange}
                placeholder={
                  'api://<api-app-id>/access_as_user\nhttps://graph.microsoft.com/Sites.Read.All'
                }
              />
              <small className="form-text text-muted">One scope per line.</small>
            </div>

            <div className="d-flex gap-2">
              <button type="submit" className="btn btn-primary" disabled={saving}>
                {saving ? (
                  <>
                    <span className="spinner-border spinner-border-sm me-2" role="status" />
                    Saving…
                  </>
                ) : (
                  <>
                    <i className="fas fa-save me-1"></i>
                    {isNew ? 'Create Profile' : 'Save Changes'}
                  </>
                )}
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => navigate(BACK_URL)}
                disabled={saving}
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default EditOAuthIdentifierPage;
