import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { apiClient } from '../../../../api';
import type { ConfigPanelProps } from '../types';
import SecretSelector from '../../../shared/SecretSelector';

interface Certificate {
  id: string;
  name: string;
  active: boolean;
  expires_at?: string;
}

interface JwtVerificationStrategy {
  id: string;
  name: string;
}

interface SecretOption {
  id: string;
  name: string;
  secret_type?: string;
}

type MethodType = 'jwt_bearer' | 'api_key' | 'api_key_provider' | 'mtls';

/**
 * Fullscreen editor for the Caller Auth canvas element. Mirrors the
 * field layout the AP-side "Caller Authentication" editor used to
 * provide — JWT strategy dropdown, audience chips, HTTP/protocol
 * extraction radios, mTLS certificate dropdown — but writes to the
 * caller-auth element's flat config shape (`method_type`,
 * `jwt_strategy_id`, `audiences`, `jwt_allow_missing_audience`,
 * `extraction_source`,
 * `extraction_field`, `api_key_secret_id`, `mtls_certificate_id`). `buildPayload` in `./definition.ts` reshapes
 * those into the runtime `SourceAuthConfig` wire format.
 */
const CallerAuthFullscreen: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  updateFields,
  protocol,
  closeFullscreenEditor,
}) => {
  const { surfaceId } = useParams<{ surfaceId: string }>();
  const method: MethodType = (config.method_type as MethodType) || 'jwt_bearer';
  const [jwtStrategies, setJwtStrategies] = useState<JwtVerificationStrategy[]>([]);
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [loadingCertificates, setLoadingCertificates] = useState(false);
  const [apiKeySecrets, setApiKeySecrets] = useState<SecretOption[]>([]);
  const [loadingSecrets, setLoadingSecrets] = useState(false);
  const [audienceInput, setAudienceInput] = useState('');

  useEffect(() => {
    apiClient
      .fetch('/api/v1/jwt-verification-strategies')
      .then(r => (r.ok ? r.json() : []))
      .then((data: JwtVerificationStrategy[]) => setJwtStrategies(Array.isArray(data) ? data : []))
      .catch(() => setJwtStrategies([]));
  }, []);

  useEffect(() => {
    if (method !== 'mtls') return;
    setLoadingCertificates(true);
    apiClient
      .get('/certificates')
      .then(res => {
        const list: Certificate[] = Array.isArray(res.data) ? res.data : [];
        setCertificates(list.filter(c => c.active));
      })
      .catch(() => setCertificates([]))
      .finally(() => setLoadingCertificates(false));
  }, [method]);

  useEffect(() => {
    if (method !== 'api_key') return;
    setLoadingSecrets(true);
    const selected = typeof config.api_key_secret_id === 'string' ? config.api_key_secret_id : '';
    apiClient
      .get('/secrets/')
      .then(res => {
        const raw: Array<{ id: string; secret_id?: string; name: string; secret_type?: string }> =
          Array.isArray(res.data) ? res.data : [];
        // Option value is the stable secret_id (what the backend resolves by); the name is
        // display-only. Browse ApiKey/typeless secrets, plus keep the already-referenced secret
        // (any type) so a preconfigured key resolves to its name instead of its raw id.
        setApiKeySecrets(
          raw
            .filter(
              s =>
                !s.secret_type || s.secret_type === 'ApiKey' || (s.secret_id ?? s.id) === selected
            )
            .map(s => ({ id: s.secret_id ?? s.id, name: s.name, secret_type: s.secret_type }))
        );
      })
      .catch(() => setApiKeySecrets([]))
      .finally(() => setLoadingSecrets(false));
  }, [method, config.api_key_secret_id]);

  const audiences: string[] = Array.isArray(config.audiences) ? config.audiences : [];
  const allowMissingAudience = config.jwt_allow_missing_audience === true;

  const setType = (newType: MethodType) => {
    if (newType === 'jwt_bearer') {
      updateFields({
        method_type: 'jwt_bearer',
        jwt_strategy_id: config.jwt_strategy_id || '',
        audiences,
        jwt_allow_missing_audience: allowMissingAudience,
        jwt_token_header: config.jwt_token_header || 'Authorization',
        jwt_token_scheme: config.jwt_token_scheme ?? 'Bearer',
      });
    } else if (newType === 'api_key') {
      updateFields({
        method_type: 'api_key',
        extraction_source: config.extraction_source || 'http_header',
        extraction_field: config.extraction_field || 'X-API-Key',
      });
    } else if (newType === 'api_key_provider') {
      updateFields({
        method_type: 'api_key_provider',
        extraction_source: config.extraction_source || 'http_header',
        extraction_field: config.extraction_field || 'X-API-Key',
      });
    } else if (newType === 'mtls') {
      updateFields({
        method_type: 'mtls',
        mtls_certificate_id: config.mtls_certificate_id || '',
      });
    }
  };

  const isProtocolSource =
    config.extraction_source === 'mcp_meta' || config.extraction_source === 'a2a_extension';

  return (
    <div className="card shadow-sm mb-4">
      <div className="card-header">
        <div className="d-flex justify-content-between align-items-center">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-key me-2" /> Caller Context Extraction
          </h6>
          {closeFullscreenEditor && (
            <button
              type="button"
              className="btn btn-sm btn-outline-secondary"
              onClick={closeFullscreenEditor}
            >
              <i className="fas fa-times me-1" /> Close tab
            </button>
          )}
        </div>
      </div>
      <div className="card-body">
        <div className="mb-4">
          <label htmlFor="caller-auth-mode-select" className="form-label fw-bold">
            Authentication Method
          </label>
          <select
            id="caller-auth-mode-select"
            className="form-control dropdown-styling"
            value={method}
            onChange={e => setType(e.target.value as MethodType)}
          >
            <option value="jwt_bearer">JWT Bearer</option>
            <option value="api_key">API Key (secret store)</option>
            <option value="api_key_provider">API Key (provider)</option>
            <option value="mtls">mTLS (Mutual TLS)</option>
          </select>
          <small className="form-text text-muted">
            Select how the Gateway should authenticate incoming requests.
          </small>
        </div>

        {method === 'jwt_bearer' && (
          <>
            <p className="text-muted mb-3">
              Validate incoming requests using a bearer token verified against a configured JWT
              verification strategy. Requests without a valid token will receive{' '}
              <code>403 Forbidden</code>.
            </p>

            <div className="mb-3">
              <label className="form-label fw-bold">
                JWT Verification Strategy <span className="text-danger">*</span>
              </label>
              {jwtStrategies.length === 0 ? (
                <div className="alert alert-warning py-2">
                  <i className="fas fa-exclamation-triangle me-2"></i>
                  No JWT verification strategies configured.{' '}
                  <a href="/jwt-verification-strategies/new" target="_blank" rel="noreferrer">
                    Add a strategy
                  </a>{' '}
                  first.
                </div>
              ) : (
                <select
                  className="form-control dropdown-styling"
                  value={config.jwt_strategy_id || ''}
                  onChange={e => updateField('jwt_strategy_id', e.target.value)}
                >
                  <option value="">— select a strategy —</option>
                  {jwtStrategies.map(s => (
                    <option key={s.id} value={s.id}>
                      {s.name}
                    </option>
                  ))}
                </select>
              )}
              <small className="form-text text-muted">
                The strategy whose JWKS will be used to verify the bearer token signature.
              </small>
            </div>

            <div className="mb-3">
              <label className="form-label fw-bold">Accepted Audiences</label>
              <div className="d-flex flex-wrap gap-2 mb-2">
                {audiences.map((aud, idx) => (
                  <span
                    key={idx}
                    className="bg-light border rounded d-inline-flex align-items-center"
                    style={{
                      fontSize: '0.875rem',
                      padding: '0.35rem 0.6rem',
                      gap: '0.6rem',
                    }}
                  >
                    {aud}
                    <button
                      type="button"
                      className="btn btn-outline-danger p-0"
                      style={{ lineHeight: 1, width: '1.4rem', height: '1.4rem' }}
                      aria-label="Remove"
                      onClick={() =>
                        updateField(
                          'audiences',
                          audiences.filter((_, i) => i !== idx)
                        )
                      }
                    >
                      <i className="fas fa-trash"></i>
                    </button>
                  </span>
                ))}
              </div>
              <div className="input-group">
                <input
                  type="text"
                  className="form-control"
                  placeholder="e.g. https://api.example.com"
                  value={audienceInput}
                  onChange={e => setAudienceInput(e.target.value)}
                  onKeyDown={e => {
                    if (e.key === 'Enter' || e.key === ',') {
                      e.preventDefault();
                      const val = audienceInput.trim();
                      if (val && !audiences.includes(val)) {
                        updateField('audiences', [...audiences, val]);
                      }
                      setAudienceInput('');
                    }
                  }}
                />
                <button
                  type="button"
                  className="btn btn-outline-secondary"
                  onClick={() => {
                    const val = audienceInput.trim();
                    if (val && !audiences.includes(val)) {
                      updateField('audiences', [...audiences, val]);
                    }
                    setAudienceInput('');
                  }}
                >
                  Add
                </button>
              </div>
              {audiences.length === 0 && (
                <div
                  className={`alert ${allowMissingAudience ? 'alert-warning' : 'alert-danger'} py-2 px-2 mt-2 mb-0 small`}
                >
                  <div className="d-flex align-items-start gap-2">
                    <i className="fas fa-exclamation-triangle mt-1"></i>
                    <span>
                      {allowMissingAudience ? (
                        <>
                          No audience configured and <code>aud</code> validation is switched off —{' '}
                          <strong>any</strong> token the issuer signs is accepted, including one
                          minted for a different service. Only keep this for an issuer that emits no{' '}
                          <code>aud</code> claim.
                        </>
                      ) : (
                        <>
                          No audience configured — <strong>the Surface cannot be saved</strong>. Add
                          the <code>aud</code> value your identity provider stamps on the token (for
                          Entra, the API app&apos;s client id, or its <code>api://…</code> App ID
                          URI on v1 tokens).
                        </>
                      )}
                    </span>
                  </div>
                  <div className="form-check mt-2 mb-0 ms-4">
                    <input
                      id="caller-auth-allow-missing-audience"
                      className="form-check-input"
                      type="checkbox"
                      checked={allowMissingAudience}
                      onChange={e => updateField('jwt_allow_missing_audience', e.target.checked)}
                    />
                    <label
                      className="form-check-label"
                      htmlFor="caller-auth-allow-missing-audience"
                    >
                      Accept tokens with no <code>aud</code> claim (skip audience validation)
                    </label>
                  </div>
                </div>
              )}
              <small className="form-text text-muted">
                Required. The token&apos;s <code>aud</code> claim must match at least one of these
                values. Press <kbd>Enter</kbd> or <kbd>,</kbd> to add.
              </small>
            </div>

            <div className="row g-3 mb-3">
              <div className="col-md-7">
                <label htmlFor="caller-auth-jwt-token-header" className="form-label fw-bold">
                  Token Header <span className="text-danger">*</span>
                </label>
                <input
                  id="caller-auth-jwt-token-header"
                  type="text"
                  className="form-control"
                  value={config.jwt_token_header ?? 'Authorization'}
                  onChange={e => updateField('jwt_token_header', e.target.value)}
                  placeholder="Authorization"
                />
                <small className="form-text text-muted">
                  HTTP header that carries the token. Defaults to <code>Authorization</code>.
                </small>
              </div>
              <div className="col-md-5">
                <label htmlFor="caller-auth-jwt-token-scheme" className="form-label fw-bold">
                  Scheme
                </label>
                <input
                  id="caller-auth-jwt-token-scheme"
                  type="text"
                  className="form-control"
                  value={config.jwt_token_scheme ?? 'Bearer'}
                  onChange={e => updateField('jwt_token_scheme', e.target.value)}
                  placeholder="Bearer"
                />
                <small className="form-text text-muted">
                  Prefix stripped from the header value. Leave blank if the header carries the raw
                  token.
                </small>
              </div>
            </div>
          </>
        )}

        {(method === 'api_key' || method === 'api_key_provider') && (
          <>
            <div className="mb-4">
              <label className="form-label fw-bold">API Key Location</label>
              <div className="d-flex gap-3">
                <div className="form-check">
                  <input
                    className="form-check-input"
                    type="radio"
                    name="caller_auth_apikey_location"
                    id="caller-auth-apikey-header"
                    checked={!isProtocolSource}
                    onChange={() =>
                      updateFields({
                        extraction_source: 'http_header',
                        extraction_field: 'X-API-Key',
                      })
                    }
                  />
                  <label className="form-check-label" htmlFor="caller-auth-apikey-header">
                    HTTP Header
                    <small className="d-block text-muted">
                      Transport-level (works with all protocols)
                    </small>
                  </label>
                </div>
                <div className="form-check">
                  <input
                    className="form-check-input"
                    type="radio"
                    name="caller_auth_apikey_location"
                    id="caller-auth-apikey-protocol"
                    checked={isProtocolSource}
                    onChange={() =>
                      updateFields({
                        extraction_source: protocol === 'mcp' ? 'mcp_meta' : 'a2a_extension',
                        extraction_field: 'apiKey',
                      })
                    }
                  />
                  <label className="form-check-label" htmlFor="caller-auth-apikey-protocol">
                    Protocol-Specific
                    <small className="d-block text-muted">
                      MCP _meta or A2A/UCP extension point
                    </small>
                  </label>
                </div>
              </div>
            </div>

            <div className="mb-4">
              <label htmlFor="caller-auth-api-key-field" className="form-label fw-bold">
                {!isProtocolSource ? 'HTTP Header Name' : 'Protocol Field Name'}
              </label>
              <input
                type="text"
                className="form-control"
                id="caller-auth-api-key-field"
                value={config.extraction_field || ''}
                onChange={e => updateField('extraction_field', e.target.value)}
              />
            </div>

            {method === 'api_key' && (
              <div className="mb-4">
                {loadingSecrets ? (
                  <>
                    <label htmlFor="caller-auth-secret-id" className="form-label fw-bold">
                      Secret <span className="text-danger">*</span>
                    </label>
                    <select
                      id="caller-auth-secret-id"
                      className="form-control dropdown-styling"
                      disabled
                      value=""
                      onChange={() => {}}
                    >
                      <option value="">-- Loading secrets... --</option>
                    </select>
                  </>
                ) : apiKeySecrets.length === 0 ? (
                  <>
                    <label className="form-label fw-bold">
                      Secret <span className="text-danger">*</span>
                    </label>
                    <div className="alert alert-warning py-2">
                      <i className="fas fa-exclamation-triangle me-2" />
                      No API-key secrets are configured.{' '}
                      <a href="/secrets/new" target="_blank" rel="noreferrer">
                        Create a secret
                      </a>{' '}
                      of type <code>ApiKey</code> first.
                    </div>
                  </>
                ) : (
                  <SecretSelector
                    secrets={apiKeySecrets}
                    selectedSecretId={config.api_key_secret_id || ''}
                    onChange={secretId => updateField('api_key_secret_id', secretId)}
                    label="Secret"
                    required
                    helpText="The secret whose value is the comma-separated list of valid API keys."
                    testId="caller-auth-secret-id"
                  />
                )}
              </div>
            )}

            {method === 'api_key_provider' && (
              <div className="mb-4">
                <label className="form-label fw-bold">Agent ID</label>
                <input
                  type="text"
                  className="form-control"
                  value={surfaceId || '(assigned when the surface is saved)'}
                  readOnly
                  disabled
                />
                <small className="form-text text-muted">
                  API keys for this surface are managed under its own ID — create them from the API
                  Keys page using this surface as the agent. No configuration is required here.
                </small>
              </div>
            )}
          </>
        )}

        {method === 'mtls' && (
          <div className="mb-4">
            <label htmlFor="caller-auth-mtls-certificate" className="form-label fw-bold">
              Client Certificate
            </label>
            <select
              id="caller-auth-mtls-certificate"
              className="form-control dropdown-styling"
              value={config.mtls_certificate_id || ''}
              onChange={e => updateField('mtls_certificate_id', e.target.value)}
              disabled={loadingCertificates}
            >
              <option value="">
                {loadingCertificates
                  ? '-- Loading certificates... --'
                  : '-- Select a certificate --'}
              </option>
              {certificates.map(cert => (
                <option key={cert.id} value={cert.id}>
                  {cert.name}
                  {cert.expires_at
                    ? ` (Expires: ${new Date(cert.expires_at).toLocaleDateString()})`
                    : ''}
                </option>
              ))}
            </select>
            <small className="form-text text-muted">
              Select the client certificate to validate against for identity verification.
            </small>
          </div>
        )}
      </div>
    </div>
  );
};

export default CallerAuthFullscreen;
