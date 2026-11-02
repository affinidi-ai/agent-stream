import React, { useState, useEffect } from 'react';
import { fieldHasMissingVariables } from '../../utils/fieldValidation';
import { useSecretOptions } from '../../hooks/useSecretOptions';
import {
  NO_PINNED_DESTINATIONS,
  NO_SECRET_REFERENCES,
  SIGNING_SECRET_MIN_LENGTH,
  signingSecretTooShort,
  type HeaderSecretRefs,
  type PinnedDestinations,
} from '../../utils/integrationCredentials';
import UrlCredentialField from './UrlCredentialField';
import SecretHeaderRows, { refsFromRows, rowsFromRefs } from './SecretHeaderRows';

export interface WebhookConfiguration {
  url_secret_id?: string;
  method?: string;
  signing_secret?: string;
  signing_secret_secret_id?: string;
  headers?: Record<string, string | null>;
  headers_secret_id?: HeaderSecretRefs;
}

export const KEEP_SAVED_SIGNING_SECRET_HINT = 'Leave blank to keep the saved signing secret.';
export const SIGNING_SECRET_TOO_SHORT = `The signing secret must be at least ${SIGNING_SECRET_MIN_LENGTH} characters.`;

export interface WebhookContent {
  [key: string]: any;
}

interface WebhookIntegrationFormProps {
  configuration: WebhookConfiguration;
  content: WebhookContent;
  onConfigurationChange: (config: WebhookConfiguration) => void;
  onContentChange: (content: WebhookContent) => void;
  disabled?: boolean;
  validRuntimeVars?: Set<string>;
  isEditMode?: boolean;
  loadedReferences?: ReadonlySet<string>;
  pinnedDestinations?: PinnedDestinations;
}

// Generate a random UUID for the signing secret
const generateSecret = () => {
  return crypto.randomUUID();
};

const WebhookIntegrationForm: React.FC<WebhookIntegrationFormProps> = ({
  configuration,
  content,
  onConfigurationChange,
  onContentChange,
  disabled = false,
  validRuntimeVars = new Set(),
  isEditMode = false,
  loadedReferences = NO_SECRET_REFERENCES,
  pinnedDestinations = NO_PINNED_DESTINATIONS,
}) => {
  const secretOptions = useSecretOptions();
  const [urlSecretId, setUrlSecretId] = useState(configuration.url_secret_id || '');
  const [method, setMethod] = useState(configuration.method || 'POST');
  const [signingSecret, setSigningSecret] = useState(
    configuration.signing_secret || (isEditMode ? '' : generateSecret())
  );
  const [signingSecretRef, setSigningSecretRef] = useState(
    configuration.signing_secret_secret_id || ''
  );
  const keepsSavedSigningSecret = isEditMode && !loadedReferences.has('signing_secret_secret_id');
  const [headerSecretRows, setHeaderSecretRows] = useState(
    rowsFromRefs(configuration.headers_secret_id)
  );
  const [customHeaders, setCustomHeaders] = useState(
    configuration.headers ? JSON.stringify(configuration.headers, null, 2) : '{}'
  );
  const [payloadTemplate, setPayloadTemplate] = useState(JSON.stringify(content, null, 2));
  const [headersError, setHeadersError] = useState('');
  const [payloadError, setPayloadError] = useState('');

  useEffect(() => {
    // Validate and update configuration
    let headers: Record<string, string | null> | undefined;
    try {
      const parsed = JSON.parse(customHeaders);
      if (Object.keys(parsed).length > 0) {
        headers = parsed;
      }
      setHeadersError('');
    } catch (e) {
      setHeadersError('Invalid JSON');
    }

    onConfigurationChange({
      url_secret_id: urlSecretId || undefined,
      method: method || 'POST',
      signing_secret: signingSecret || undefined,
      signing_secret_secret_id: signingSecretRef || undefined,
      headers,
      headers_secret_id: refsFromRows(headerSecretRows),
    });
  }, [urlSecretId, method, signingSecret, signingSecretRef, customHeaders, headerSecretRows]);

  const changeSigningSecret = (value: string) => {
    setSigningSecret(value);
    if (value) setSigningSecretRef('');
  };

  const signingSecretHint = signingSecret
    ? null
    : signingSecretRef
      ? `Signed with the stored secret ${signingSecretRef}. Enter or generate a value to replace it.`
      : keepsSavedSigningSecret
        ? KEEP_SAVED_SIGNING_SECRET_HINT
        : null;

  useEffect(() => {
    // Validate and update content
    try {
      const parsed = JSON.parse(payloadTemplate);
      setPayloadError('');
      onContentChange(parsed);
    } catch (e) {
      setPayloadError('Invalid JSON');
    }
  }, [payloadTemplate]);

  return (
    <div className="webhook-notifier-form">
      <UrlCredentialField
        label="Webhook URL secret"
        secretId={urlSecretId}
        onChange={setUrlSecretId}
        secretOptions={secretOptions}
        pinned={pinnedDestinations.url}
        savedWithoutReference={isEditMode && !loadedReferences.has('url_secret_id')}
        helpText="The secret holding the HTTP endpoint that will receive webhook notifications"
        disabled={disabled}
        testId="webhook-url"
      />

      <div className="mb-3">
        <label className="form-label">HTTP Method</label>
        <select
          className="form-control dropdown-styling"
          value={method}
          onChange={e => setMethod(e.target.value)}
        >
          <option value="POST">POST</option>
          <option value="PUT">PUT</option>
          <option value="PATCH">PATCH</option>
        </select>
        <small className="form-text text-muted">HTTP method to use when sending the webhook</small>
      </div>

      <div className="mb-3">
        <label className="form-label">
          Signing Secret <span className="text-muted">(Optional)</span>
        </label>
        <div className="input-group">
          <input
            type="text"
            className={`form-control font-monospace ${signingSecretTooShort(signingSecret) ? 'is-invalid' : ''}`}
            value={signingSecret}
            onChange={e => changeSigningSecret(e.target.value)}
            placeholder="Auto-generated UUID or enter your own..."
            minLength={SIGNING_SECRET_MIN_LENGTH}
            aria-invalid={signingSecretTooShort(signingSecret)}
            aria-describedby="webhook-signing-secret-help"
            disabled={disabled}
            data-testid="webhook-signing-secret-input"
          />
          <button
            type="button"
            className="btn btn-outline-secondary"
            onClick={() => changeSigningSecret(generateSecret())}
            title="Generate new secret"
            disabled={disabled}
            aria-label="Generate new signing secret"
            data-testid="webhook-signing-secret-generate-button"
          >
            <i className="fas fa-sync-alt"></i>
          </button>
        </div>
        {signingSecretTooShort(signingSecret) && (
          <div className="invalid-feedback d-block" data-testid="webhook-signing-secret-error">
            {SIGNING_SECRET_TOO_SHORT}
          </div>
        )}
        {signingSecretHint && (
          <small className="form-text text-muted d-block" data-testid="webhook-signing-secret-hint">
            {signingSecretHint}
          </small>
        )}
        <small className="form-text text-muted" id="webhook-signing-secret-help">
          <i className="fas fa-shield-alt me-1"></i>
          HMAC-SHA256 signing secret for webhook authentication, at least{' '}
          {SIGNING_SECRET_MIN_LENGTH} characters. The signature will be sent in the{' '}
          <code>X-Webhook-Signature-256</code> header as <code>sha256=&lt;hex&gt;</code>. Timestamp
          is sent in <code>X-Webhook-Timestamp</code> header.
        </small>
      </div>

      <div className="mb-3">
        <label className="form-label">
          Custom Headers <span className="text-muted">(Optional)</span>
        </label>
        <textarea
          className={`form-control font-monospace ${headersError || fieldHasMissingVariables(customHeaders, validRuntimeVars) ? 'is-invalid' : ''}`}
          rows={4}
          value={customHeaders}
          onChange={e => setCustomHeaders(e.target.value)}
          placeholder={`{
  "X-Custom-Header": "value"
}`}
          style={{ fontSize: '0.875rem' }}
          data-testid="webhook-headers-input"
        />
        {headersError && <div className="invalid-feedback">{headersError}</div>}
        <small className="form-text text-muted" data-testid="webhook-headers-hint">
          Additional HTTP headers to include with each webhook request (JSON object). Credential
          headers are any name containing auth, cookie, cred, key, pass, secret, session or token
          (any case, e.g. <code>Authorization</code>, <code>X-Api-Key</code>,{' '}
          <code>X-Password</code>, <code>X-Session-Id</code>). Saved ones are not shown and are kept
          when left out; set one to <code>null</code>, e.g. <code>"Authorization": null</code>, to
          remove it. Credential headers are refused here; add them as secret headers below.
        </small>
      </div>

      <SecretHeaderRows
        rows={headerSecretRows}
        onChange={setHeaderSecretRows}
        secretOptions={secretOptions}
        disabled={disabled}
      />

      <div className="mb-3">
        <label className="form-label">
          Payload Template <span className="text-danger">*</span>
        </label>
        <textarea
          className={`form-control font-monospace ${payloadError || fieldHasMissingVariables(payloadTemplate, validRuntimeVars) ? 'is-invalid' : ''}`}
          rows={16}
          value={payloadTemplate}
          data-testid="webhook-payload-template"
          onChange={e => setPayloadTemplate(e.target.value)}
          style={{ fontSize: '0.875rem' }}
          required
        />
        {payloadError && <div className="invalid-feedback">{payloadError}</div>}
        <small className="form-text text-muted">
          <i className="fas fa-code me-1"></i>
          JSON payload template. Use variables like{' '}
          <code>
            ${'{'}CP_NAME{'}'}
          </code>{' '}
          or{' '}
          <code>
            ${'{'}CP_NAME:Label{'}'}
          </code>{' '}
          for runtime substitution.
        </small>
      </div>

      <div className="alert alert-info">
        <i className="fas fa-info-circle me-2"></i>
        <strong>Webhook Security:</strong> When a signing secret is provided, each request includes:
        <ul className="mb-0 mt-2">
          <li>
            <code>X-Webhook-Signature-256: sha256=&lt;signature&gt;</code> - HMAC-SHA256 signature
          </li>
          <li>
            <code>X-Webhook-Timestamp: &lt;unix_timestamp&gt;</code> - Request timestamp
          </li>
          <li>
            Signature is computed as:{' '}
            <code>HMAC-SHA256(secret, timestamp + "." + payload_json)</code>
          </li>
        </ul>
      </div>
    </div>
  );
};

export default WebhookIntegrationForm;
