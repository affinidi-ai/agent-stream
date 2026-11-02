import React, { useState } from 'react';
import LLMProviderSelector, {
  LLMProviderFormData,
  LLMProviderInfo,
} from '../../../shared/LLMProviderSelector';
import { Secret } from '../../../shared/SecretSelector';
import { isModelEnabled } from '../../../../utils/modelVisibility';
import { apiClient } from '../../../../api';
import { useOptionalSurfaceMeta } from '../../SurfaceMetaContext';
import WhenDetected, { type HandlingChoice } from './WhenDetected';
import {
  DEFAULT_LLM_PII,
  DEFAULT_REJECTION,
  ENTITY_TYPE_PRESETS,
  type LlmPiiConfig,
  type RejectionConfig,
} from './llmPii';

const SAMPLE_TEXT =
  'John Smith lives at 101 Main Street, Springfield. His email is john.smith@example.com and his phone is (555) 123-4567.';

interface DetectorTestResult {
  ok: boolean;
  entities: { entity_type: string; text: string; group?: string | null }[];
  error?: string | null;
}

/** Preset + custom entity-type picker, rendered as removable pills. */
const EntityTypePills: React.FC<{
  selected: string[];
  onChange: (next: string[]) => void;
}> = ({ selected, onChange }) => {
  const [draft, setDraft] = useState('');
  const normalise = (s: string) => s.trim().toUpperCase().replace(/\s+/g, '_');
  const toggle = (t: string) =>
    onChange(selected.includes(t) ? selected.filter(x => x !== t) : [...selected, t]);
  const addDraft = () => {
    const t = normalise(draft);
    if (t && !selected.includes(t)) onChange([...selected, t]);
    setDraft('');
  };
  const custom = selected.filter(s => !ENTITY_TYPE_PRESETS.includes(s));
  return (
    <div>
      <div className="d-flex flex-wrap gap-2 mb-2">
        {ENTITY_TYPE_PRESETS.map(t => {
          const on = selected.includes(t);
          return (
            <button
              key={t}
              type="button"
              onClick={() => toggle(t)}
              className={`btn btn-sm ${on ? 'btn-primary' : 'btn-outline-secondary'}`}
              style={{ fontSize: '12px', borderRadius: '999px' }}
            >
              <i className={`fas ${on ? 'fa-check' : 'fa-plus'} me-1`}></i>
              {t}
            </button>
          );
        })}
      </div>
      {custom.length > 0 && (
        <div className="d-flex flex-wrap gap-2 mb-2">
          {custom.map(t => (
            <span
              key={t}
              className="badge bg-primary d-inline-flex align-items-center"
              style={{ fontSize: '12px', borderRadius: '999px', padding: '0.4rem 0.7rem' }}
            >
              {t}
              <button
                type="button"
                className="btn-close btn-close-white ms-2"
                style={{ fontSize: '9px' }}
                onClick={() => toggle(t)}
                aria-label={`Remove ${t}`}
              ></button>
            </span>
          ))}
        </div>
      )}
      <div className="input-group input-group-sm" style={{ maxWidth: '340px' }}>
        <input
          type="text"
          className="form-control"
          placeholder="Add custom type (e.g. PATIENT_ID)"
          value={draft}
          onChange={e => setDraft(e.target.value)}
          onKeyDown={e => {
            if (e.key === 'Enter' || e.key === ',') {
              e.preventDefault();
              addDraft();
            }
          }}
        />
        <button type="button" className="btn btn-outline-secondary" onClick={addDraft}>
          Add
        </button>
      </div>
    </div>
  );
};

interface AiDetectorBodyProps {
  detector: LlmPiiConfig;
  llmProviders: LLMProviderInfo[];
  secrets: Secret[];
  idPrefix: string;
  onChange: (patch: Partial<LlmPiiConfig>) => void;
  onTested: () => void;
}

/** Detect-then-act body for an AI Prompt Guard: pick a model + entity types,
 *  then (once the model is chosen) the shared "When detected" control. */
const AiDetectorBody: React.FC<AiDetectorBodyProps> = ({
  detector,
  llmProviders,
  secrets,
  idPrefix,
  onChange,
  onTested,
}) => {
  const surfaceId = useOptionalSurfaceMeta()?.surfaceId;
  // The server sends a stored key only to the endpoint saved with it, so a
  // test with a key needs the saved surface.
  const usesStoredKey = Boolean((detector.api_key_secret ?? '').trim());
  const canTest = !usesStoredKey || Boolean(surfaceId);
  const providerMissing = !(detector.provider_type ?? '').trim();
  const modelMissing = !(detector.model ?? '').trim();
  const detectComplete = !providerMissing && !modelMissing;

  const providerForm: LLMProviderFormData = {
    provider: detector.provider_type ?? '',
    model: detector.model ?? '',
    endpoint_url: detector.endpoint_url ?? '',
    api_key_secret_id: detector.api_key_secret ?? '',
    model_parameters: {},
  };

  // Mirrors DeciderLlmEditor: on provider change, seed the chat endpoint + first
  // enabled model and clear the key; otherwise map the single changed field.
  const handleProviderChange = (field: string, value: any) => {
    if (field === 'provider') {
      const provider = llmProviders.find(p => p.enum_value === value);
      const patch: Partial<LlmPiiConfig> = { provider_type: value, api_key_secret: null };
      const chatEndpoint = provider?.endpoints.find(ep =>
        ep.capabilities?.includes('chat_completions')
      );
      if (chatEndpoint) {
        const baseUrl = provider?.default_base_url || '';
        const versionPrefix = provider?.api_version_prefix || '';
        patch.endpoint_url = `${baseUrl}${versionPrefix}${chatEndpoint.path}`;
      }
      const firstModel = provider?.models?.find(isModelEnabled) ?? provider?.models?.[0];
      if (firstModel) patch.model = firstModel.value;
      onChange(patch);
      return;
    }
    const map: Record<string, keyof LlmPiiConfig> = {
      model: 'model',
      endpoint_url: 'endpoint_url',
      api_key_secret_id: 'api_key_secret',
    };
    const key = map[field];
    if (key)
      onChange({ [key]: value || (key === 'api_key_secret' ? null : '') } as Partial<LlmPiiConfig>);
  };

  const action: HandlingChoice =
    detector.action === 'reject'
      ? 'reject'
      : detector.mask_mode === 'redact'
        ? 'redact'
        : 'pseudonymize';
  const setAction = (choice: HandlingChoice) =>
    choice === 'reject'
      ? onChange({ action: 'reject' })
      : onChange({ action: 'mask', mask_mode: choice });

  const updateRejection = (field: keyof RejectionConfig, value: unknown) => {
    const current = detector.rejection ?? { ...DEFAULT_REJECTION };
    onChange({ rejection: { ...current, [field]: value } as RejectionConfig });
  };

  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<DetectorTestResult | null>(null);
  const runTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const { data } = await apiClient.post<DetectorTestResult>(
        '/prompt-guard/detector-test',
        {
          config: { ...DEFAULT_LLM_PII, ...detector, enabled: true },
          surface_id: surfaceId,
          text: SAMPLE_TEXT,
        },
        { timeout: 30000 }
      );
      setTestResult(data);
    } catch (e) {
      setTestResult({
        ok: false,
        entities: [],
        error: e instanceof Error ? e.message : 'Test request failed',
      });
    } finally {
      setTesting(false);
      onTested();
    }
  };

  return (
    <>
      <div className="mb-2">
        <label className="font-weight-bold" style={{ fontSize: '13px' }}>
          Detect using this AI Model
        </label>
        <div className="alert alert-warning py-2" style={{ fontSize: '12px' }}>
          <i className="fas fa-exclamation-triangle me-1"></i>
          The request text is sent to this model. Use a <strong>trusted</strong> provider — ideally
          self-hosted/local — since it receives the raw content.
        </div>
        <LLMProviderSelector
          llmProviders={llmProviders}
          secrets={secrets}
          value={providerForm}
          onChange={handleProviderChange}
          showEndpoint={true}
          showModelParameters={false}
          compact={true}
          capabilityFilter="chat_completions"
        />
        {(providerMissing || modelMissing) && (
          <div className="text-danger mb-2" style={{ fontSize: '12px' }}>
            <i className="fas fa-exclamation-circle me-1"></i>
            Select a provider and model.
          </div>
        )}
        <div className="mb-3">
          <label style={{ fontSize: '13px' }}>Timeout (seconds)</label>
          <input
            type="number"
            className="form-control form-control-sm"
            style={{ maxWidth: '140px' }}
            value={detector.timeout_secs ?? 30}
            onChange={e => onChange({ timeout_secs: parseInt(e.target.value, 10) || 30 })}
            min={5}
            max={300}
          />
        </div>
        <div className="mb-1">
          <label className="form-label small mb-1">Entity types to detect</label>
          <EntityTypePills
            selected={detector.entity_types ?? []}
            onChange={next => onChange({ entity_types: next })}
          />
          <small className="form-text text-muted">
            The model is told to return exactly these types. Presets are a starting point — add your
            own (stored with this surface).
          </small>
        </div>
      </div>

      {detectComplete && (
        <>
          <WhenDetected
            idPrefix={idPrefix}
            value={action}
            onChange={setAction}
            rejection={detector.rejection}
            onRejectionChange={updateRejection}
            pseudonymizeOptions={
              <>
                <div className="custom-control custom-switch mt-2">
                  <input
                    type="checkbox"
                    className="custom-control-input"
                    id={`${idPrefix}-restore`}
                    checked={detector.restore_in_response === true}
                    onChange={e => onChange({ restore_in_response: e.target.checked })}
                  />
                  <label className="custom-control-label small" htmlFor={`${idPrefix}-restore`}>
                    Restore in response
                  </label>
                  <small className="form-text text-muted">
                    Swap the NER IDs back to the real values in the model&rsquo;s reply before it
                    reaches the caller, so the provider, Judge and Jury only ever see the
                    placeholders. Streamed responses restore message text only, not tool-call
                    arguments.
                  </small>
                </div>
                <div className="custom-control custom-switch mt-2">
                  <input
                    type="checkbox"
                    className="custom-control-input"
                    id={`${idPrefix}-coref`}
                    data-testid="prompt-guard-llm-pii-coref"
                    checked={detector.link_coreferences === true}
                    onChange={e => onChange({ link_coreferences: e.target.checked })}
                  />
                  <label className="custom-control-label small" htmlFor={`${idPrefix}-coref`}>
                    Link coreferences
                  </label>
                  <small className="form-text text-muted">
                    Give every mention of the same person or organisation
                    (e.g.&nbsp;&ldquo;Bob&rdquo; and &ldquo;Robert&nbsp;Smith&rdquo;) one shared NER
                    ID so the model can still tell who&rsquo;s who. Scans the whole prompt rather
                    than each message on its own.
                  </small>
                </div>
              </>
            }
          />

          <div className="mt-3">
            <label className="form-label small mb-1">Behaviour</label>
            <div className="d-flex flex-wrap align-items-center gap-3">
              <div className="custom-control custom-switch">
                <input
                  type="checkbox"
                  className="custom-control-input"
                  id={`${idPrefix}-cache`}
                  data-testid="prompt-guard-llm-pii-cache"
                  checked={detector.cache_detection !== false}
                  onChange={e => onChange({ cache_detection: e.target.checked })}
                />
                <label className="custom-control-label small" htmlFor={`${idPrefix}-cache`}>
                  Cache detections
                </label>
                <small className="form-text text-muted">
                  Reuse recent detection results for text already seen instead of calling the model
                  again, lowering latency and cost on multi-turn chats. Held in memory only, time-
                  and size-bounded, and never written to disk.
                </small>
              </div>
            </div>
            <div className="mt-2" style={{ maxWidth: '360px' }}>
              <label className="form-label small mb-1">If PII detection is unavailable</label>
              <select
                className="form-control form-control-sm"
                data-testid="prompt-guard-llm-pii-fail-mode"
                value={detector.fail_closed === false ? 'open' : 'closed'}
                onChange={e => onChange({ fail_closed: e.target.value === 'closed' })}
              >
                <option value="closed">Reject if PII detection is unavailable</option>
                <option value="open">Continue with regex masking only</option>
              </select>
            </div>
          </div>

          <div className="border-top pt-2 mt-3">
            <button
              type="button"
              className="btn btn-sm btn-outline-primary"
              data-testid="prompt-guard-llm-pii-test"
              disabled={testing || !canTest}
              onClick={runTest}
            >
              {testing ? (
                <>
                  <span
                    className="spinner-border spinner-border-sm me-1"
                    role="status"
                    aria-hidden="true"
                  ></span>
                  Testing detection…
                </>
              ) : (
                <>
                  <i className="fas fa-vial me-1"></i>
                  Test detection
                </>
              )}
            </button>
            {!canTest && (
              <div
                className="text-muted mt-2"
                data-testid="prompt-guard-llm-pii-test-unavailable"
                style={{ fontSize: '12px' }}
              >
                <i className="fas fa-lock me-1"></i>
                Save the surface before testing with a stored API key. The test only sends the key
                to the endpoint saved with it.
              </div>
            )}
            {testResult && (
              <div
                className={`alert py-2 mt-2 mb-0 ${testResult.ok ? 'alert-success' : 'alert-danger'}`}
                data-testid="prompt-guard-llm-pii-test-result"
                style={{ fontSize: '12px' }}
              >
                {testResult.ok ? (
                  testResult.entities.length > 0 ? (
                    <>
                      <i className="fas fa-check-circle me-1"></i>
                      Detected {testResult.entities.length}{' '}
                      {testResult.entities.length === 1 ? 'entity' : 'entities'}:{' '}
                      {testResult.entities.map(en => `${en.entity_type} ("${en.text}")`).join(', ')}
                    </>
                  ) : (
                    <>
                      <i className="fas fa-check-circle me-1"></i>
                      Detector reachable, but it returned no entities for the sample.
                    </>
                  )
                ) : (
                  <>
                    <i className="fas fa-times-circle me-1"></i>
                    {testResult.error ?? 'Detection failed.'}
                  </>
                )}
              </div>
            )}
          </div>
        </>
      )}
    </>
  );
};

export default AiDetectorBody;
