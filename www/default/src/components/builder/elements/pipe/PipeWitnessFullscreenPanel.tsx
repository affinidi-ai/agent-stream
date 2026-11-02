import React, { useEffect, useRef, useState } from 'react';
import type { ConfigPanelProps } from '../types';
import SecretSelector from '../../../shared/SecretSelector';
import { usePipePanelData, type PipeSecretRef } from './pipePanelData';
import {
  WitnessConfig,
  WitnessProvider,
  WITNESS_PROVIDERS,
  WITNESS_ENDPOINT_PLACEHOLDERS,
  WITNESS_AUTH_HEADER,
  WITNESS_PROVIDER_HELP,
  endpointForProviderChange,
  makeDefaultWitness,
} from '../../../shared/witnessModel';

/** Header the EnkryptAI AI Proxy uses to select the deployment (and model). */
const ENKRYPT_DEPLOYMENT_HEADER = 'X-Enkrypt-Deployment';
/** Header the EnkryptAI Guardrail detect API uses to select the saved guardrail. */
const ENKRYPT_GUARDRAIL_HEADER = 'X-Enkrypt-Guardrail';
/** Seam-mode header the Guardrail detect API requires; injected by the gateway. */
const ENKRYPT_MODE_HEADER = 'X-Enkrypt-Mode';
/** Header the EnkryptAI Policy Detect API uses to select the saved policy. */
const ENKRYPT_POLICY_HEADER = 'X-Enkrypt-Policy';

/**
 * Full-area editor for an Expert Witness seam node (`pipe-witness-request` /
 * `pipe-witness-response`). Each witness is an external, purpose-trained safety
 * classifier consulted alongside the local regex guards; a flagged verdict
 * blocks the call. The node owns a list of witnesses for its seam
 * (`config.witnesses`); this panel edits each one's provider, endpoint, key,
 * timeout and fail-open behaviour. The seam itself (`check_request` /
 * `check_response`) is fixed by which circle the node is, so it is not shown
 * here — it is stamped on serialization.
 */

function readWitnesses(value: unknown): WitnessConfig[] {
  return Array.isArray(value) ? (value as WitnessConfig[]) : [];
}

const WitnessCard: React.FC<{
  witness: WitnessConfig;
  index: number;
  seam: 'request' | 'response';
  secrets: PipeSecretRef[];
  onUpdate: (index: number, next: WitnessConfig) => void;
  onRemove: (index: number) => void;
}> = ({ witness, index, seam, secrets, onUpdate, onRemove }) => {
  const patch = (p: Partial<WitnessConfig>) => onUpdate(index, { ...witness, ...p });
  const enabled = witness.enabled !== false;
  const isAiProxy = witness.provider === 'enkryptai_ai_proxy';
  const isGuardrail = witness.provider === 'enkryptai_guardrail';
  const isPolicyDetect = witness.provider === 'enkryptai_policy_detect';
  const isAzure =
    witness.provider === 'azure_prompt_shields' || witness.provider === 'azure_content_safety';

  const headers = witness.headers || {};
  const setHeaderValue = (name: string, value: string) =>
    patch({ headers: { ...headers, [name]: value } });
  const removeHeader = (name: string) => {
    const next = { ...headers };
    delete next[name];
    patch({ headers: next });
  };
  const deployment = headers[ENKRYPT_DEPLOYMENT_HEADER] || '';
  const setDeployment = (value: string) => {
    const next = { ...headers };
    if (value) next[ENKRYPT_DEPLOYMENT_HEADER] = value;
    else delete next[ENKRYPT_DEPLOYMENT_HEADER];
    patch({ headers: next });
  };
  const policy = headers[ENKRYPT_POLICY_HEADER] || '';
  const setPolicy = (value: string) => {
    const next = { ...headers };
    if (value) next[ENKRYPT_POLICY_HEADER] = value;
    else delete next[ENKRYPT_POLICY_HEADER];
    patch({ headers: next });
  };
  const guardrail = headers[ENKRYPT_GUARDRAIL_HEADER] || '';
  const setGuardrail = (value: string) => {
    const next = { ...headers };
    if (value) next[ENKRYPT_GUARDRAIL_HEADER] = value;
    else delete next[ENKRYPT_GUARDRAIL_HEADER];
    patch({ headers: next });
  };
  // The dedicated Deployment / Guardrail / Policy fields own their EnkryptAI
  // header, so hide them from the generic custom-headers list to avoid a double
  // editor. The Guardrail seam-mode header is injected by the gateway per seam,
  // so it is never edited here either.
  const customHeaderEntries = Object.entries(headers).filter(
    ([k]) =>
      !(isAiProxy && k === ENKRYPT_DEPLOYMENT_HEADER) &&
      !(isGuardrail && (k === ENKRYPT_GUARDRAIL_HEADER || k === ENKRYPT_MODE_HEADER)) &&
      !(isPolicyDetect && k === ENKRYPT_POLICY_HEADER)
  );
  const [newHeaderName, setNewHeaderName] = useState('');

  return (
    <div className="card shadow-sm mb-4" data-testid={`pipe-witness-${seam}-card-${index}`}>
      <div className="card-header bg-light">
        <div className="d-flex justify-content-between align-items-center">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-user-shield me-1"></i>
            <input
              type="text"
              className="form-control form-control-sm d-inline-block"
              style={{ width: '260px' }}
              value={witness.name || ''}
              onChange={e => patch({ name: e.target.value })}
              placeholder={`Witness ${index + 1}`}
              data-testid={`pipe-witness-${seam}-card-name-${index}`}
            />
          </h6>
          <div className="d-flex align-items-center gap-3">
            <div className="form-check form-switch m-0">
              <input
                className="form-check-input"
                type="checkbox"
                role="switch"
                id={`witness-${seam}-enabled-${index}`}
                checked={enabled}
                onChange={e => patch({ enabled: e.target.checked })}
                data-testid={`pipe-witness-${seam}-enabled-${index}`}
              />
              <label
                className="form-check-label small"
                htmlFor={`witness-${seam}-enabled-${index}`}
              >
                Enabled
              </label>
            </div>
            <button
              type="button"
              className="btn btn-sm btn-outline-danger"
              onClick={() => onRemove(index)}
              title="Remove witness"
              aria-label="Remove witness"
              data-testid={`pipe-witness-${seam}-card-remove-${index}`}
            >
              <i className="fas fa-trash"></i>
            </button>
          </div>
        </div>
      </div>
      <div className="card-body">
        <p className="text-muted" style={{ fontSize: '13px' }}>
          Detect-and-block: a flagged verdict rejects the call on the {seam}. Runs in addition to
          the Surface's Prompt Guards, Judge and Jury if configured.
        </p>
        <div className="row g-3">
          <div className="col-md-6">
            <label className="form-label small fw-bold">Provider</label>
            <select
              className="form-select form-select-sm"
              value={witness.provider}
              onChange={e => {
                const provider = e.target.value as WitnessProvider;
                patch({
                  provider,
                  endpoint_url: endpointForProviderChange(witness.endpoint_url, provider),
                });
              }}
              data-testid={`pipe-witness-${seam}-provider-${index}`}
            >
              {WITNESS_PROVIDERS.map(p => (
                <option key={p.value} value={p.value}>
                  {p.label}
                </option>
              ))}
            </select>
            <small className="text-muted d-block mt-1">
              {WITNESS_PROVIDER_HELP[witness.provider]}
            </small>
          </div>
          <div className="col-md-6">
            <label className="form-label small fw-bold">Timeout (seconds)</label>
            <input
              type="number"
              min={1}
              className="form-control form-control-sm"
              value={witness.timeout_secs}
              onChange={e => patch({ timeout_secs: Math.max(1, Number(e.target.value) || 0) })}
              data-testid={`pipe-witness-${seam}-timeout-${index}`}
            />
          </div>
          <div className="col-12">
            <label className="form-label small fw-bold">Endpoint URL</label>
            <input
              type="text"
              className="form-control form-control-sm"
              placeholder={WITNESS_ENDPOINT_PLACEHOLDERS[witness.provider]}
              value={witness.endpoint_url}
              onChange={e => patch({ endpoint_url: e.target.value })}
              data-testid={`pipe-witness-${seam}-endpoint-${index}`}
            />
            {isAzure && (
              <small className="text-muted d-block mt-1">
                Include the Azure API version, e.g. <code>?api-version=2024-09-01</code>.
              </small>
            )}
          </div>
          <div className="col-12">
            <SecretSelector
              secrets={secrets}
              selectedSecretId={witness.api_key_secret ?? ''}
              onChange={secretId => patch({ api_key_secret: secretId || null })}
              label="API Key Secret"
              emptyLabel="None"
              helpText=""
              testId={`pipe-witness-${seam}-secret-${index}`}
            />
            <small className="text-muted d-block mt-1">
              {witness.api_key_secret ? (
                <>
                  Sent automatically as the <code>{WITNESS_AUTH_HEADER[witness.provider]}</code>{' '}
                  header — you don't add it yourself.
                </>
              ) : (
                <>
                  No auth header is sent. Select a secret to send it as{' '}
                  <code>{WITNESS_AUTH_HEADER[witness.provider]}</code>.
                </>
              )}
            </small>
          </div>
          {isAiProxy && (
            <>
              <div className="col-12">
                <label className="form-label small fw-bold">Deployment</label>
                <input
                  type="text"
                  className="form-control form-control-sm"
                  placeholder="Stream deployment"
                  value={deployment}
                  onChange={e => setDeployment(e.target.value)}
                  data-testid={`pipe-witness-${seam}-deployment-${index}`}
                />
                <small className="text-muted d-block mt-1">
                  Sent as the <code>{ENKRYPT_DEPLOYMENT_HEADER}</code> header. This is the
                  deployment name from your EnkryptAI dashboard — it selects the guardrail policy.
                </small>
              </div>
              <div className="col-12">
                <label className="form-label small fw-bold">Model</label>
                <input
                  type="text"
                  className="form-control form-control-sm"
                  placeholder="Stream test"
                  value={witness.model ?? ''}
                  onChange={e => patch({ model: e.target.value })}
                  data-testid={`pipe-witness-${seam}-model-${index}`}
                />
                <small className="text-muted d-block mt-1">
                  Sent as <code>model</code> in the request body — the model saved-name from your
                  deployment. The AI Proxy requires this; copy it from the deployment's sample code
                  (e.g. <code>model: "Stream test"</code>).
                </small>
              </div>
              <div className="col-12">
                <div className="alert alert-warning py-2 px-3 mb-0 small" role="alert">
                  <i className="fas fa-triangle-exclamation me-1"></i>
                  The AI Proxy runs its own model completion to screen the text, adding latency and
                  a second model charge that the witness discards. For pure screening prefer{' '}
                  <strong>EnkryptAI (Detect API)</strong>.
                </div>
              </div>
            </>
          )}
          {isGuardrail && (
            <div className="col-12">
              <label className="form-label small fw-bold">Guardrail</label>
              <input
                type="text"
                className="form-control form-control-sm"
                placeholder="Stream Guardail"
                value={guardrail}
                onChange={e => setGuardrail(e.target.value)}
                data-testid={`pipe-witness-${seam}-guardrail-${index}`}
              />
              <small className="text-muted d-block mt-1">
                Sent as the <code>{ENKRYPT_GUARDRAIL_HEADER}</code> header. This is the saved
                guardrail name from your EnkryptAI dashboard — it binds which detectors run. The{' '}
                <code>{ENKRYPT_MODE_HEADER}</code> header (<code>prompt</code> on the request seam,{' '}
                <code>response</code> on the response seam) is set automatically. The request body
                carries only the text.
              </small>
            </div>
          )}
          {isPolicyDetect && (
            <div className="col-12">
              <label className="form-label small fw-bold">Policy</label>
              <input
                type="text"
                className="form-control form-control-sm"
                placeholder="Stream Guardail"
                value={policy}
                onChange={e => setPolicy(e.target.value)}
                data-testid={`pipe-witness-${seam}-policy-${index}`}
              />
              <small className="text-muted d-block mt-1">
                Sent as the <code>{ENKRYPT_POLICY_HEADER}</code> header. This is the saved policy
                name from your EnkryptAI dashboard — it binds which detectors run. The request body
                carries only the text. <strong>Legacy:</strong> prefer{' '}
                <strong>EnkryptAI (Guardrail)</strong>, which EnkryptAI now recommends in place of
                saved policies.
              </small>
            </div>
          )}
          <div className="col-12">
            <label className="form-label small fw-bold">Custom headers</label>
            {customHeaderEntries.length === 0 && (
              <p className="text-muted mb-2" style={{ fontSize: '12px' }}>
                Optional static headers sent on every call. Use <code>{'{key}'}</code> in a value to
                inject the resolved API key.
              </p>
            )}
            {customHeaderEntries.map(([name, value]) => (
              <div className="d-flex gap-2 mb-2" key={name}>
                <input
                  type="text"
                  className="form-control form-control-sm"
                  style={{ maxWidth: '240px' }}
                  value={name}
                  readOnly
                  data-testid={`pipe-witness-${seam}-header-name-${index}-${name}`}
                />
                <input
                  type="text"
                  className="form-control form-control-sm"
                  value={value}
                  onChange={e => setHeaderValue(name, e.target.value)}
                  placeholder="value"
                  data-testid={`pipe-witness-${seam}-header-value-${index}-${name}`}
                />
                <button
                  type="button"
                  className="btn btn-sm btn-outline-danger"
                  onClick={() => removeHeader(name)}
                  title="Remove header"
                  aria-label="Remove header"
                  data-testid={`pipe-witness-${seam}-header-remove-${index}-${name}`}
                >
                  <i className="fas fa-trash"></i>
                </button>
              </div>
            ))}
            <div className="d-flex gap-2">
              <input
                type="text"
                className="form-control form-control-sm"
                style={{ maxWidth: '240px' }}
                value={newHeaderName}
                onChange={e => setNewHeaderName(e.target.value)}
                placeholder="Header name"
                data-testid={`pipe-witness-${seam}-header-new-${index}`}
              />
              <button
                type="button"
                className="btn btn-sm btn-outline-primary"
                disabled={!newHeaderName.trim() || newHeaderName in headers}
                onClick={() => {
                  setHeaderValue(newHeaderName.trim(), '');
                  setNewHeaderName('');
                }}
                data-testid={`pipe-witness-${seam}-header-add-${index}`}
              >
                <i className="fas fa-plus me-1"></i>Add header
              </button>
            </div>
          </div>
        </div>
        <div className="form-check form-switch mt-3">
          <input
            className="form-check-input"
            type="checkbox"
            role="switch"
            id={`witness-${seam}-fail-open-${index}`}
            checked={witness.fail_open}
            onChange={e => patch({ fail_open: e.target.checked })}
            data-testid={`pipe-witness-${seam}-fail-open-${index}`}
          />
          <label className="form-check-label small" htmlFor={`witness-${seam}-fail-open-${index}`}>
            Fail open on provider error
          </label>
        </div>
        <p className="text-muted mt-2 mb-0" style={{ fontSize: '12px' }}>
          {witness.fail_open
            ? 'On provider error or timeout the call is allowed through.'
            : 'On provider error or timeout the call is blocked (fail-closed).'}
        </p>
      </div>
    </div>
  );
};

const PipeWitnessFullscreenPanel: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  closeFullscreenEditor,
}) => {
  const { secrets } = usePipePanelData();
  const seam: 'request' | 'response' = config?.direction === 'response' ? 'response' : 'request';
  const witnesses = readWitnesses(config?.witnesses);

  const addWitness = () =>
    updateField('witnesses', [...witnesses, makeDefaultWitness(seam, witnesses.length)]);
  const updateWitness = (index: number, next: WitnessConfig) => {
    const list = witnesses.slice();
    list[index] = next;
    updateField('witnesses', list);
  };
  const removeWitness = (index: number) =>
    updateField(
      'witnesses',
      witnesses.filter((_, i) => i !== index)
    );

  // Land directly in add mode when the editor opens with nothing configured.
  const seededRef = useRef(false);
  useEffect(() => {
    if (seededRef.current) return;
    if (witnesses.length === 0) {
      seededRef.current = true;
      addWitness();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="pipe-witness-editor">
      <div className="d-flex justify-content-between align-items-center mb-3">
        <h5 className="m-0">
          <i className="fas fa-user-shield me-2"></i>
          Expert Witnesses — {seam === 'request' ? 'Request' : 'Response'} seam
        </h5>
        <div className="d-flex gap-2">
          <button
            type="button"
            className="btn btn-sm btn-outline-primary"
            onClick={addWitness}
            data-testid={`pipe-witness-${seam}-card-add`}
          >
            <i className="fas fa-plus me-1"></i>Add witness
          </button>
          {closeFullscreenEditor && (
            <button
              type="button"
              className="btn btn-sm btn-outline-secondary"
              onClick={closeFullscreenEditor}
            >
              <i className="fas fa-times me-1"></i>Close tab
            </button>
          )}
        </div>
      </div>

      {witnesses.length === 0 ? (
        <div
          className="text-center py-4 mb-3"
          style={{
            background: 'rgba(0,0,0,0.02)',
            borderRadius: '8px',
            border: '1px dashed rgba(0,0,0,0.15)',
          }}
        >
          <i className="fas fa-user-shield fa-3x text-muted mb-3 d-block"></i>
          <h6 className="text-muted">No expert witnesses configured</h6>
          <p
            className="text-muted mb-3"
            style={{ fontSize: '13px', maxWidth: '500px', margin: '0 auto' }}
          >
            Add a witness to screen the {seam} with an external, purpose-trained safety classifier.
            Several witnesses (different providers) can sit on the same seam.
          </p>
          <button type="button" className="btn btn-primary btn-sm" onClick={addWitness}>
            <i className="fas fa-plus me-1"></i>Add witness
          </button>
        </div>
      ) : (
        witnesses.map((w, i) => (
          <WitnessCard
            key={w.id || i}
            witness={w}
            index={i}
            seam={seam}
            secrets={secrets}
            onUpdate={updateWitness}
            onRemove={removeWitness}
          />
        ))
      )}
    </div>
  );
};

export default PipeWitnessFullscreenPanel;
