import React, { useEffect, useState } from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { apiClient } from '../api';
import { DeleteButton } from '../components/shared/DeleteButton';
import { usePermissions } from '../context/PermissionsContext';
import { showToast } from '../utils/toaster';
import type { AccessTokenCreated, AccessTokenMeta, RequiredHeader } from '../types';
import AccessTokenDetailsFields from './EditAccessTokenPage/AccessTokenDetailsFields';
import AccessTokenExpiryField from './EditAccessTokenPage/AccessTokenExpiryField';
import AccessTokenScopes from './EditAccessTokenPage/AccessTokenScopes';
import AccessTokenResourceScope from './EditAccessTokenPage/AccessTokenResourceScope';
import AccessTokenSidebar from './EditAccessTokenPage/AccessTokenSidebar';
import AccessTokenCreatedCard from './EditAccessTokenPage/AccessTokenCreatedCard';
import AccessTokenEditHeader from './EditAccessTokenPage/AccessTokenEditHeader';
import {
  ACCESS_TOKEN_LIST_ROUTE,
  accessTokenFormError,
  cleanRequiredHeaders,
} from './EditAccessTokenPage/accessTokenScopeHelpers';
import {
  accessTokenPermalinkQuery,
  accessTokenPrefill,
} from './EditAccessTokenPage/accessTokenPrefill';
import { useAccessTokenExpiry } from './EditAccessTokenPage/useAccessTokenExpiry';

const EditAccessTokenPage: React.FC = () => {
  const navigate = useNavigate();
  const { id } = useParams<{ id: string }>();
  const isEditMode = !!id;
  const { permissions, hasPermission } = usePermissions();
  const [searchParams] = useSearchParams();
  const [prefill] = useState(() =>
    accessTokenPrefill(isEditMode ? new URLSearchParams() : searchParams)
  );
  const availableScopes = Object.entries(permissions ?? {})
    .filter(([, allowed]) => allowed)
    .map(([scope]) => scope);

  const [loading, setLoading] = useState(isEditMode);
  const [saving, setSaving] = useState(false);
  const [validationAttempted, setValidationAttempted] = useState(false);
  const expiry = useAccessTokenExpiry(prefill.expiry);
  const [name, setName] = useState(prefill.name);
  const [description, setDescription] = useState(prefill.description);
  const [scopes, setScopes] = useState<string[]>(prefill.scopes);
  const [resourcePattern, setResourcePattern] = useState(prefill.resourcePattern);
  const [requiredHeaders, setRequiredHeaders] = useState<RequiredHeader[]>(prefill.requiredHeaders);
  const [meta, setMeta] = useState<AccessTokenMeta | null>(null);
  const [created, setCreated] = useState<AccessTokenCreated | null>(null);
  const [linkCopied, setLinkCopied] = useState(false);

  useEffect(() => {
    if (!isEditMode || !id) return;
    (async () => {
      try {
        const { data } = await apiClient.get<AccessTokenMeta>(`/access-tokens/${id}`);
        setMeta(data);
        setName(data.name);
        setDescription(data.description ?? '');
        setScopes(data.scopes);
        setResourcePattern(data.resource_pattern ?? '');
        setRequiredHeaders(data.required_headers ?? []);
      } catch (e) {
        showToast('error', e instanceof Error ? e.message : 'Failed to load access token');
        navigate(ACCESS_TOKEN_LIST_ROUTE);
      } finally {
        setLoading(false);
      }
    })();
  }, [id, isEditMode, navigate]);

  const revoked = !!meta?.revoked_at;
  const unavailableScopes = scopes.filter(scope => !availableScopes.includes(scope));
  const expiryResult = isEditMode ? {} : expiry.validate();
  const formError = accessTokenFormError(
    name,
    resourcePattern,
    requiredHeaders,
    expiryResult.error,
    unavailableScopes
  );

  const handleSubmit = async (e?: React.FormEvent) => {
    e?.preventDefault();
    setValidationAttempted(true);
    if (formError) {
      showToast('error', formError);
      return;
    }
    setSaving(true);
    try {
      if (isEditMode && id) {
        const { data } = await apiClient.put<AccessTokenMeta>(`/access-tokens/${id}`, {
          name: name.trim(),
          description: description.trim(),
          scopes,
          resource_pattern: resourcePattern.trim() || null,
          required_headers: cleanRequiredHeaders(requiredHeaders),
        });
        setMeta(data);
        showToast('success', 'Access token updated');
        navigate(ACCESS_TOKEN_LIST_ROUTE);
      } else {
        const body: Record<string, unknown> = {
          name: name.trim(),
          description: description.trim(),
          scopes,
          resource_pattern: resourcePattern.trim() || null,
          required_headers: cleanRequiredHeaders(requiredHeaders),
        };
        if (expiryResult.expiresAt) body.expires_at = expiryResult.expiresAt;
        const { data } = await apiClient.post<AccessTokenCreated>('/access-tokens', body);
        setCreated(data);
      }
    } catch (err) {
      showToast('error', err instanceof Error ? err.message : 'Failed to save access token');
    } finally {
      setSaving(false);
    }
  };

  const handleCopyLink = async () => {
    if (formError) return;
    const query = accessTokenPermalinkQuery({
      name,
      description,
      scopes,
      resourcePattern,
      requiredHeaders,
      expiry: expiry.form,
    });
    const { origin, pathname } = window.location;
    try {
      await navigator.clipboard.writeText(`${origin}${pathname}${query ? `?${query}` : ''}`);
      setLinkCopied(true);
      setTimeout(() => setLinkCopied(false), 2000);
    } catch {
      showToast('error', 'Failed to copy link');
    }
  };

  const handleRevoke = async () => {
    if (!id) return;
    try {
      await apiClient.delete(`/access-tokens/${id}`);
      showToast('success', 'Access token revoked');
      navigate(ACCESS_TOKEN_LIST_ROUTE);
    } catch (err) {
      showToast('error', err instanceof Error ? err.message : 'Failed to revoke token');
    }
  };

  if (loading) {
    return (
      <div className="container-fluid">
        <div className="text-center py-5">
          <div className="spinner-border text-primary" role="status"></div>
        </div>
      </div>
    );
  }

  if (created) {
    return <AccessTokenCreatedCard created={created} listRoute={ACCESS_TOKEN_LIST_ROUTE} />;
  }

  return (
    <div className="container-fluid" data-testid="page-access-token">
      <AccessTokenEditHeader
        title={isEditMode ? 'Edit Access Token' : 'Create Access Token'}
        subtitle={
          isEditMode
            ? 'Update the token name, description, and scopes'
            : 'Mint a new management API access token'
        }
        onBack={() => navigate(ACCESS_TOKEN_LIST_ROUTE)}
        backDisabled={saving}
        onSave={handleSubmit}
        saving={saving}
        saveDisabled={saving || revoked}
      />

      <div className="row">
        <div className="col-lg-8">
          <div className="card shadow mb-4">
            <div className="card-header py-3">
              <h6 className="m-0 font-weight-bold text-primary">
                {isEditMode ? 'Access Token Details' : 'New Access Token'}
              </h6>
            </div>
            <div className="card-body">
              <form onSubmit={handleSubmit}>
                <AccessTokenDetailsFields
                  isEditMode={isEditMode}
                  meta={meta}
                  revoked={revoked}
                  name={name}
                  description={description}
                  onNameChange={setName}
                  onDescriptionChange={setDescription}
                />

                <div className="mb-3">
                  <label>Scopes</label>
                  <AccessTokenScopes
                    allScopes={availableScopes}
                    selected={scopes}
                    unavailable={unavailableScopes}
                    onChange={setScopes}
                    disabled={revoked}
                  />
                </div>

                <div className="mb-3">
                  <AccessTokenResourceScope
                    pattern={resourcePattern}
                    onPatternChange={setResourcePattern}
                    headers={requiredHeaders}
                    onHeadersChange={setRequiredHeaders}
                    disabled={revoked}
                    showValidation={validationAttempted}
                  />
                </div>

                {!isEditMode && (
                  <AccessTokenExpiryField
                    value={expiry.form}
                    referenceNow={expiry.referenceNow}
                    validationAttempted={validationAttempted}
                    onChange={expiry.setForm}
                  />
                )}

                <hr />

                <div className="d-flex justify-content-between align-items-center">
                  {isEditMode && hasPermission('access_tokens.delete') && !revoked ? (
                    <DeleteButton
                      onDelete={handleRevoke}
                      variant="danger"
                      title="Revoke this token"
                    >
                      Revoke token
                    </DeleteButton>
                  ) : !isEditMode ? (
                    <button
                      className="btn btn-sm btn-outline-primary"
                      type="button"
                      onClick={handleCopyLink}
                      disabled={!!formError}
                      title={
                        formError
                          ? `Fix the form first: ${formError}`
                          : 'Copy a link that opens this form with the current settings'
                      }
                      data-testid="access-token-copy-link-button"
                    >
                      <i
                        className={`fas ${linkCopied ? 'fa-check' : 'fa-link'} me-1`}
                        aria-hidden="true"
                      />
                      {linkCopied ? 'Copied' : 'Copy creation link'}
                    </button>
                  ) : (
                    <span />
                  )}
                  <button
                    className="btn btn-sm btn-primary"
                    type="submit"
                    disabled={saving || revoked}
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
                        <i className="fas fa-save me-1" aria-hidden="true" />
                        {isEditMode ? 'Save Changes' : 'Create Token'}
                      </>
                    )}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>

        <div className="col-lg-4">
          <AccessTokenSidebar meta={meta} />
        </div>
      </div>
    </div>
  );
};

export default EditAccessTokenPage;
