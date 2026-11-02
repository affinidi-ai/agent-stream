import React from 'react';
import LLMProviderSelector, {
  LLMProviderFormData,
  LLMProviderInfo,
} from '../../../components/shared/LLMProviderSelector';
import { Secret } from '../../../components/shared/SecretSelector';
import { DeciderLlm } from '../../../components/shared/deciderModel';
import { isModelEnabled } from '../../../utils/modelVisibility';
import { useLlmTargetCatalog } from './useLlmTargetCatalog';

interface DeciderLlmEditorProps {
  llm: DeciderLlm;
  onChange: (llm: DeciderLlm) => void;
  idPrefix: string;
  /**
   * Pre-loaded provider catalog. When supplied (together with `secrets`) the
   * editor skips its own fetch — used by parents that render many targets and
   * want to load the catalog once. When omitted the editor self-loads.
   */
  providers?: LLMProviderInfo[];
  secrets?: Secret[];
}

/**
 * Reusable LLM-target editor shared by the decider router and each candidate.
 * Wraps {@link LLMProviderSelector} and maps the flat selector form shape to
 * the `DeciderLlm` (provider_type/model/endpoint_url/api_key_secret/parameters)
 * the backend expects, plus the timeout and disable-thinking controls.
 *
 * Provider/secret catalog is supplied via props when available (so a parent
 * rendering N targets fetches once) and otherwise self-loaded.
 */
const DeciderLlmEditor: React.FC<DeciderLlmEditorProps> = props => {
  if (props.providers && props.secrets) {
    return (
      <DeciderLlmEditorView
        llm={props.llm}
        onChange={props.onChange}
        llmProviders={props.providers}
        secrets={props.secrets}
      />
    );
  }
  return <DeciderLlmEditorSelfLoading llm={props.llm} onChange={props.onChange} />;
};

const DeciderLlmEditorSelfLoading: React.FC<{
  llm: DeciderLlm;
  onChange: (llm: DeciderLlm) => void;
}> = ({ llm, onChange }) => {
  const { llmProviders, secrets } = useLlmTargetCatalog();
  return (
    <DeciderLlmEditorView
      llm={llm}
      onChange={onChange}
      llmProviders={llmProviders}
      secrets={secrets}
    />
  );
};

const DeciderLlmEditorView: React.FC<{
  llm: DeciderLlm;
  onChange: (llm: DeciderLlm) => void;
  llmProviders: LLMProviderInfo[];
  secrets: Secret[];
}> = ({ llm, onChange, llmProviders, secrets }) => {
  const llmToValue = (l: DeciderLlm): LLMProviderFormData => ({
    provider: l.provider_type || '',
    model: l.model || '',
    endpoint_url: l.endpoint_url || '',
    api_key_secret_id: l.api_key_secret || '',
    model_parameters: l.parameters || {},
  });

  const handleLLMChange = (field: string, value: any) => {
    const fieldMap: Record<string, string> = {
      provider: 'provider_type',
      model: 'model',
      endpoint_url: 'endpoint_url',
      api_key_secret_id: 'api_key_secret',
      model_parameters: 'parameters',
    };
    const llmField = fieldMap[field] || field;
    const updated: DeciderLlm = { ...llm, [llmField]: value };

    if (field === 'provider') {
      const provider = llmProviders.find(p => p.enum_value === value);
      const chatEndpoint = provider?.endpoints.find(ep =>
        ep.capabilities?.includes('chat_completions')
      );
      if (chatEndpoint) {
        const baseUrl = provider?.default_base_url || '';
        const versionPrefix = provider?.api_version_prefix || '';
        updated.endpoint_url = `${baseUrl}${versionPrefix}${chatEndpoint.path}`;
      }
      if (provider?.models?.[0]) {
        const firstEnabled = provider.models.find(isModelEnabled) ?? provider.models[0];
        updated.model = firstEnabled.value;
        updated.capabilities = firstEnabled.capabilities || {};
      }
      updated.api_schema = provider?.api_schema || 'openai';
      updated.api_key_secret = '';
    }

    if (field === 'model') {
      const provider = llmProviders.find(p => p.enum_value === llm.provider_type);
      const selectedModel = provider?.models?.find(m => m.value === value);
      updated.capabilities = selectedModel?.capabilities || {};
    }

    onChange(updated);
  };

  return (
    <>
      <LLMProviderSelector
        llmProviders={llmProviders}
        secrets={secrets}
        value={llmToValue(llm)}
        onChange={handleLLMChange}
        showEndpoint={true}
        showModelParameters={true}
        compact={true}
        fieldPrefix=""
        capabilityFilter="chat_completions"
      />
      <div className="mt-2 mb-3">
        <label style={{ fontSize: '13px' }}>Timeout (seconds)</label>
        <input
          type="number"
          className="form-control form-control-sm"
          style={{ maxWidth: '140px' }}
          value={llm.timeout_secs ?? 30}
          onChange={e => onChange({ ...llm, timeout_secs: parseInt(e.target.value, 10) || 30 })}
          min={5}
          max={300}
        />
        <small className="form-text text-muted">Max time to wait for this LLM's response</small>
      </div>
    </>
  );
};

export default DeciderLlmEditor;
