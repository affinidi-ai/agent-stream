import React, { useState, useEffect } from 'react';
import { apiClient } from '../../../api';
import LLMProviderSelector, {
  LLMProviderInfo,
  LLMProviderFormData,
} from '../../../components/shared/LLMProviderSelector';
import { Secret } from '../../../components/shared/SecretSelector';
import DecisionEvaluator, { DecisionConfig } from '../../../components/shared/DecisionEvaluator';
import { fetchMarketplaceProviders } from '../../../utils/marketplaceProviders';
import { isModelEnabled } from '../../../utils/modelVisibility';
import { StrictnessLevel, FOCUS_AREAS } from './JudgeTab';
import {
  JurorConfig,
  buildJurorPrompt,
  DEFAULT_JUROR_PROMPT,
  JURY_STRICTNESS_TEMPERATURES,
} from '../../../components/shared/jurorModel';

interface JurorEditorProps {
  juror: JurorConfig;
  onChange: (updates: Partial<JurorConfig>) => void;
  onBrowseMarketplace?: () => void;
  /** Close the editor tab (renders a header control when provided). */
  onClose?: () => void;
}

/**
 * Full-area editor for a single juror — the complex per-juror config that
 * doesn't fit the sidebar: LLM provider/model/endpoint, strictness, focus
 * areas, confidence threshold, custom instructions, generated system prompt
 * and decision evaluation. Loads its own provider/secret/marketplace data
 * (mirroring JudgeTab/JuryTab) and raises every change through `onChange`,
 * which the juror node's fullscreen panel merges back into its `juror` config
 * slice. Identity (name / enable) lives in the node's sidebar panel.
 */
const JurorEditor: React.FC<JurorEditorProps> = ({
  juror,
  onChange,
  onBrowseMarketplace,
  onClose,
}) => {
  const [llmProviders, setLlmProviders] = useState<LLMProviderInfo[]>([]);
  const [secrets, setSecrets] = useState<Secret[]>([]);

  const loadMarketplaceProviders = async () => {
    const mpProviders = await fetchMarketplaceProviders();
    setLlmProviders(prev => {
      const base = prev.filter((p: any) => !p._marketplace);
      for (const mp of mpProviders) {
        const realType = (mp as any)._marketplace?.real_provider_type;
        if (!realType) continue;
        const realProvider = base.find(p => p.enum_value === realType);
        if (!realProvider) continue;
        for (const mpModel of mp.models) {
          const realModel =
            realProvider.models.find(m => m.value === mpModel.value) || realProvider.models[0];
          if (realModel?.model_parameters && !mpModel.model_parameters) {
            mpModel.model_parameters = realModel.model_parameters;
          }
        }
      }
      return [...base, ...mpProviders];
    });
  };

  useEffect(() => {
    const loadData = async () => {
      try {
        const [configRes, secretsRes] = await Promise.all([
          apiClient.get('/pipes/config'),
          apiClient.get('/secrets/'),
        ]);
        if (configRes.data?.llm?.providers) {
          const realProviders = configRes.data.llm.providers.filter(
            (p: any) => p.api_schema !== 'marketplace'
          );
          setLlmProviders(realProviders);
        }
        const allSecrets = secretsRes.data || [];
        setSecrets(allSecrets.filter((s: any) => s.secret_type === 'ApiKey'));
      } catch (error) {
        console.error('Failed to load juror config data:', error);
      }
      await loadMarketplaceProviders();
    };
    loadData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const jurorToLLMValue = (j: JurorConfig): LLMProviderFormData => ({
    provider: j.llm?.provider_type || '',
    model: j.llm?.model || '',
    endpoint_url: j.llm?.endpoint_url || '',
    api_key_secret_id: j.llm?.api_key_secret || '',
    model_parameters: j.llm?.parameters || {},
  });

  const handleLLMChange = (field: string, value: any) => {
    const currentLLM = juror.llm || { provider_type: '', model: '', endpoint_url: '' };
    const fieldMap: Record<string, string> = {
      provider: 'provider_type',
      model: 'model',
      endpoint_url: 'endpoint_url',
      api_key_secret_id: 'api_key_secret',
      model_parameters: 'parameters',
    };
    const llmField = fieldMap[field] || field;
    const updatedLLM: JurorConfig['llm'] = { ...currentLLM, [llmField]: value };

    if (field === 'provider') {
      const provider = llmProviders.find(p => p.enum_value === value);
      const chatEndpoint = provider?.endpoints.find(ep =>
        ep.capabilities?.includes('chat_completions')
      );
      if (chatEndpoint) {
        const baseUrl = provider?.default_base_url || '';
        const versionPrefix = provider?.api_version_prefix || '';
        updatedLLM.endpoint_url = `${baseUrl}${versionPrefix}${chatEndpoint.path}`;
      }
      if (provider?.models?.[0]) {
        const firstEnabled = provider.models.find(isModelEnabled) ?? provider.models[0];
        updatedLLM.model = firstEnabled.value;
        updatedLLM.capabilities = firstEnabled.capabilities || {};
      }
      updatedLLM.api_schema = provider?.api_schema || 'openai';
      // A secret is provider-specific, so a key picked for the previous
      // provider must not silently carry over (that yields a confusing 401
      // from the new provider). Clear it so the user re-selects a valid one.
      updatedLLM.api_key_secret = '';
    }

    if (field === 'model') {
      const providerEnum = currentLLM.provider_type;
      const provider = llmProviders.find(p => p.enum_value === providerEnum);
      const selectedModel = provider?.models?.find(m => m.value === value);
      updatedLLM.capabilities = selectedModel?.capabilities || {};
    }

    onChange({ llm: updatedLLM });
  };

  const jurorToDecisionValue = (j: JurorConfig): DecisionConfig => ({
    mode: j.decision?.mode || 'json',
    json_field: j.decision?.field || 'decision',
    json_approve_value: j.decision?.approve_value || 'approve',
    approve_pattern: j.decision?.approve_pattern || '',
    reject_pattern: j.decision?.reject_pattern || '',
  });

  const handleDecisionChange = (config: DecisionConfig) => {
    onChange({
      decision: {
        mode: config.mode,
        field: config.json_field,
        approve_value: config.json_approve_value,
        approve_pattern: config.approve_pattern,
        reject_pattern: config.reject_pattern,
      },
    });
  };

  const regeneratePrompt = (overrides: {
    strictness?: StrictnessLevel;
    focusAreas?: string[];
    confidenceThreshold?: number | undefined;
    customInstructions?: string;
  }): string => {
    const s = overrides.strictness ?? juror.strictness ?? 'balanced';
    const f = overrides.focusAreas ?? juror.focus_areas ?? [];
    const c =
      overrides.confidenceThreshold !== undefined
        ? overrides.confidenceThreshold
        : juror.confidence_threshold;
    const ci = overrides.customInstructions ?? juror.custom_instructions ?? '';
    return buildJurorPrompt(s, f, c, ci) || DEFAULT_JUROR_PROMPT;
  };

  const handleStrictnessChange = (level: StrictnessLevel) => {
    const prompt = regeneratePrompt({ strictness: level });
    const currentParams = juror.llm?.parameters || {};
    onChange({
      strictness: level,
      system_prompt: prompt,
      llm: {
        ...(juror.llm || { provider_type: '', model: '', endpoint_url: '' }),
        parameters: { ...currentParams, temperature: JURY_STRICTNESS_TEMPERATURES[level] },
      },
    });
  };

  const handleFocusAreaToggle = (areaId: string) => {
    const current = [...(juror.focus_areas || [])];
    const idx = current.indexOf(areaId);
    if (idx >= 0) current.splice(idx, 1);
    else current.push(areaId);
    const prompt = regeneratePrompt({ focusAreas: current });
    onChange({ focus_areas: current, system_prompt: prompt });
  };

  const handleConfidenceChange = (value: number | undefined) => {
    const prompt = regeneratePrompt({ confidenceThreshold: value });
    onChange({ confidence_threshold: value, system_prompt: prompt });
  };

  const handleCustomInstructionsChange = (text: string) => {
    const prompt = regeneratePrompt({ customInstructions: text });
    onChange({ custom_instructions: text, system_prompt: prompt });
  };

  return (
    <div>
      <div className="card shadow-sm mb-4">
        <div className="card-header bg-light d-flex justify-content-between align-items-center">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-user-tie me-2"></i>
            Juror Configuration
          </h6>
          {(onBrowseMarketplace || onClose) && (
            <div className="d-flex align-items-center gap-2">
              {onBrowseMarketplace && (
                <button
                  type="button"
                  className="btn btn-sm btn-primary"
                  onClick={onBrowseMarketplace}
                >
                  <i className="fas fa-store me-1"></i>
                  Marketplace
                </button>
              )}
              {onClose && (
                <button
                  type="button"
                  className="btn btn-sm btn-outline-secondary"
                  onClick={onClose}
                >
                  <i className="fas fa-times me-1"></i>
                  Close tab
                </button>
              )}
            </div>
          )}
        </div>
        <div className="card-body">
          {/* Identity */}
          <div className="mb-3" style={{ maxWidth: '400px' }}>
            <label style={{ fontSize: '13px' }}>Juror Name</label>
            <input
              type="text"
              className="form-control form-control-sm"
              value={juror.name || ''}
              onChange={e => onChange({ name: e.target.value })}
              placeholder="Juror name..."
            />
          </div>

          <hr className="my-3" />

          {/* LLM Config */}
          <h6 className="text-dark mb-3" style={{ fontSize: '13px' }}>
            <i className="fas fa-robot me-2"></i>
            LLM Configuration
          </h6>
          <LLMProviderSelector
            llmProviders={llmProviders}
            secrets={secrets}
            value={jurorToLLMValue(juror)}
            onChange={(field, value) => handleLLMChange(field, value)}
            showEndpoint={true}
            showModelParameters={true}
            compact={true}
            fieldPrefix=""
            capabilityFilter="chat_completions"
          />
          <div className="mt-2">
            <div className="mb-3 mb-0">
              <label style={{ fontSize: '13px' }}>Timeout (seconds)</label>
              <input
                type="number"
                className="form-control form-control-sm"
                style={{ maxWidth: '140px' }}
                value={juror.llm?.timeout_secs ?? 30}
                onChange={e => {
                  const currentLLM = juror.llm || {
                    provider_type: '',
                    model: '',
                    endpoint_url: '',
                  };
                  onChange({
                    llm: { ...currentLLM, timeout_secs: parseInt(e.target.value) || 30 },
                  });
                }}
                min={5}
                max={300}
              />
              <small className="form-text text-muted">
                Max time to wait for this juror's LLM response
              </small>
            </div>
          </div>

          {/* Disable Thinking toggle */}
          <div className="mt-2">
            <div className="d-flex align-items-center">
              <div className="custom-control custom-switch">
                <input
                  type="checkbox"
                  className="custom-control-input"
                  id="juror-disable-thinking"
                  checked={juror.disable_thinking === true}
                  onChange={e => onChange({ disable_thinking: e.target.checked || undefined })}
                />
                <label
                  className="custom-control-label"
                  htmlFor="juror-disable-thinking"
                  style={{ fontSize: '13px' }}
                >
                  <i className="fas fa-brain me-1"></i>
                  Disable Thinking
                </label>
              </div>
            </div>
            <small className="form-text text-muted">
              Suppress chain-of-thought for reasoning models (qwen3, DeepSeek-R1). Auto-retry still
              works when off.
            </small>
          </div>

          {/* Cost & token tracking */}

          <hr className="my-3" />

          {/* Strictness Level */}
          <h6 className="text-dark mb-2" style={{ fontSize: '13px' }}>
            <i className="fas fa-tachometer-alt me-2"></i>
            Strictness Level
          </h6>
          <div className="btn-group btn-group-sm w-100 mb-2">
            {[
              {
                level: 'strict' as StrictnessLevel,
                icon: 'fa-shield-alt',
                label: 'Strict',
                color: 'var(--danger)',
              },
              {
                level: 'balanced' as StrictnessLevel,
                icon: 'fa-balance-scale',
                label: 'Balanced',
                color: 'var(--warning)',
              },
              {
                level: 'lenient' as StrictnessLevel,
                icon: 'fa-door-open',
                label: 'Lenient',
                color: 'var(--success)',
              },
            ].map(({ level, icon, label, color }) => (
              <label
                key={level}
                className={`btn btn-sm ${(juror.strictness || 'balanced') === level ? 'text-white' : 'btn-outline-secondary'}`}
                style={{
                  cursor: 'pointer',
                  flex: 1,
                  backgroundColor: (juror.strictness || 'balanced') === level ? color : undefined,
                  borderColor: (juror.strictness || 'balanced') === level ? color : undefined,
                  fontSize: '12px',
                }}
              >
                <input
                  type="radio"
                  name="juror_strictness"
                  checked={(juror.strictness || 'balanced') === level}
                  onChange={() => handleStrictnessChange(level)}
                  style={{ display: 'none' }}
                />
                <i className={`fas ${icon} me-1`}></i>
                {label}
              </label>
            ))}
          </div>

          {/* Focus Areas */}
          <h6 className="text-dark mb-2 mt-3" style={{ fontSize: '13px' }}>
            <i className="fas fa-crosshairs me-2"></i>
            Focus Areas
            <small className="text-muted ms-1">
              (optional — leave unchecked for broad coverage)
            </small>
          </h6>
          <div className="row mb-2">
            {FOCUS_AREAS.map(area => (
              <div className="col-md-6 mb-1" key={area.id}>
                <div className="form-check" style={{ fontSize: '12px' }}>
                  <input
                    className="form-check-input"
                    type="checkbox"
                    id={`juror_focus_${area.id}`}
                    checked={(juror.focus_areas || []).includes(area.id)}
                    onChange={() => handleFocusAreaToggle(area.id)}
                  />
                  <label className="form-check-label" htmlFor={`juror_focus_${area.id}`}>
                    {area.label}
                  </label>
                </div>
              </div>
            ))}
          </div>

          {/* Confidence Threshold */}
          <div className="d-flex align-items-center mb-2 mt-2">
            <h6 className="text-dark mb-0 me-2" style={{ fontSize: '13px' }}>
              <i className="fas fa-percentage me-1"></i>
              Confidence Threshold
            </h6>
            <div className="form-check form-check-inline mb-0">
              <input
                className="form-check-input"
                type="checkbox"
                id="juror_conf_enable"
                checked={(juror.confidence_threshold ?? 0) > 0}
                onChange={e => handleConfidenceChange(e.target.checked ? 0.7 : undefined)}
              />
              <label
                className="form-check-label"
                htmlFor="juror_conf_enable"
                style={{ fontSize: '12px' }}
              >
                Enable
              </label>
            </div>
          </div>
          {(juror.confidence_threshold ?? 0) > 0 && (
            <div className="mb-2" style={{ maxWidth: '350px' }}>
              <label style={{ fontSize: '12px' }}>
                Target Confidence:{' '}
                <strong>{((juror.confidence_threshold ?? 0.7) * 100).toFixed(0)}%</strong>
              </label>
              <input
                type="range"
                className="form-control-range"
                value={juror.confidence_threshold ?? 0.7}
                onChange={e => handleConfidenceChange(parseFloat(e.target.value))}
                min={0.1}
                max={1.0}
                step={0.05}
              />
              <small className="form-text text-muted">
                The juror is asked for a confidence score; it never overrides the verdict
              </small>
            </div>
          )}

          {/* Custom Instructions */}
          <h6 className="text-dark mb-2 mt-3" style={{ fontSize: '13px' }}>
            <i className="fas fa-pencil-alt me-2"></i>
            Custom Instructions
            <small className="text-muted ms-1">(optional)</small>
          </h6>
          <textarea
            className="form-control font-monospace mb-2"
            rows={2}
            value={juror.custom_instructions || ''}
            onChange={e => handleCustomInstructionsChange(e.target.value)}
            placeholder="Additional domain-specific instructions for this juror..."
            style={{ fontSize: '12px', lineHeight: '1.4' }}
          />

          {/* Generated System Prompt (collapsible preview) */}
          <details className="mb-3">
            <summary style={{ fontSize: '12px', cursor: 'pointer', color: 'var(--gray-500)' }}>
              <i className="fas fa-eye me-1"></i>
              View Generated System Prompt
            </summary>
            <textarea
              className="form-control font-monospace mt-2"
              rows={6}
              value={juror.system_prompt}
              onChange={e => onChange({ system_prompt: e.target.value })}
              style={{ fontSize: '11px', lineHeight: '1.3' }}
            />
          </details>

          <hr className="my-3" />

          {/* Decision */}
          <h6 className="text-dark mb-2" style={{ fontSize: '13px' }}>
            <i className="fas fa-check-circle me-2"></i>
            Decision Evaluation
          </h6>
          <DecisionEvaluator
            value={jurorToDecisionValue(juror)}
            onChange={config => handleDecisionChange(config)}
            compact={true}
            idPrefix="juror_decision"
          />
        </div>
      </div>
    </div>
  );
};

export default JurorEditor;
