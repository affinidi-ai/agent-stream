import React from 'react';
import SecretSelector, { Secret } from './SecretSelector';
import { selectableModels } from '../../utils/modelVisibility';
import { apiKeyValidation } from '../../utils/apiKeyValidation';
import type { SandboxAuthConfig } from '../../utils/sandboxAuth';

// Types matching the pipes config structure
export interface LLMProviderInfo {
  enum_value: string;
  name: string;
  enabled?: boolean;
  api_key_label?: string;
  /** Three-state key policy (`mandatory` | `optional` | `none`). */
  api_key_validation?: string;
  api_key_required?: boolean;
  /** Case-insensitive regex used to filter selectable API-key secrets by tag. */
  filter_tag?: string;
  /** Admin-configured base URL for this provider (e.g. Bedrock gateway URL, Ollama host) */
  default_base_url?: string;
  /** API version prefix for this provider (e.g. "/v1", "/v2"). Combined with endpoint path. */
  api_version_prefix?: string;
  /** API wire format: "openai" (also Azure, Mistral, TogetherAI, Cohere, Ollama, Bedrock, Custom), "anthropic", "gemini", "replicate", "huggingface", "marketplace" */
  api_schema?: string;
  /** When api_schema is "marketplace", the URL of the marketplace site to embed */
  marketplace_url?: string;
  /**
   * Optional OAuth (PKCE) sign-in config for testing surfaces that forward the
   * caller's token (e.g. Microsoft 365 Copilot). Public identifiers only; drives
   * the sandbox "Sign in to test" button. See `src/utils/sandboxAuth.ts`.
   */
  sandbox_auth?: SandboxAuthConfig;
  endpoints: LLMEndpointInfo[];
  models: LLMModelInfo[];
}

export interface ModerationCategoryInfo {
  name: string;
  description?: string;
}

export interface ModerationModelInfo {
  name: string;
  value: string;
}

export interface LLMEndpointInfo {
  name: string;
  path: string;
  description?: string;
  is_default?: boolean;
  capabilities?: string[];
  moderation_models?: ModerationModelInfo[];
  moderation_categories?: ModerationCategoryInfo[];
  endpoint_parameters?: LLMParameterInfo[];
}

export interface LLMModelInfo {
  name: string;
  value: string;
  enabled?: boolean;
  model_parameters?: LLMParameterInfo[];
  cost_per_1k_input?: number;
  cost_per_1k_output?: number;
  capabilities?: {
    supports_json_mode?: boolean;
    [key: string]: any;
  };
}

export interface LLMParameterInfo {
  name: string;
  label: string;
  type: string;
  description?: string;
  default?: any;
  min?: number;
  max?: number;
  step?: number;
  options?: string[];
  applies_to_models?: string[];
}

/** The flat data shape that this component reads/writes */
export interface LLMProviderFormData {
  provider: string;
  model: string;
  endpoint_url: string;
  api_key_secret_id: string;
  model_parameters: Record<string, any>;
}

interface LLMProviderSelectorProps {
  /** Available provider catalog (from GET /pipes/config) */
  llmProviders: LLMProviderInfo[];
  /** Available API key secrets */
  secrets: Secret[];
  /** Current form values */
  value: LLMProviderFormData;
  /** Called when any field changes: onChange(fieldName, newValue) */
  onChange: (field: string, value: any) => void;
  /** Whether to show endpoint selector (default true) */
  showEndpoint?: boolean;
  /** Whether to show model parameter sliders (default true) */
  showModelParameters?: boolean;
  /** Compact mode — used inside Judge/Jury cards (default false) */
  compact?: boolean;
  /** Optional prefix for field names to avoid collisions (e.g. "judge_") */
  fieldPrefix?: string;
  /** Only show chat-completions-compatible endpoints (filters out moderations, embeddings, fine-tuning, etc.) */
  chatOnly?: boolean;
  /** Only show endpoints with this capability (e.g. 'chat_completions' or 'content_moderation'). Takes precedence over chatOnly. */
  capabilityFilter?: string;
}

const LLMProviderSelector: React.FC<LLMProviderSelectorProps> = ({
  llmProviders,
  secrets,
  value,
  onChange,
  showEndpoint = true,
  showModelParameters = true,
  compact = false,
  fieldPrefix = '',
  chatOnly = false,
  capabilityFilter,
}) => {
  const selectedProvider = llmProviders.find(p => p.enum_value === value.provider);
  const selectedModel = selectedProvider?.models.find(m => m.value === value.model);

  // Filter endpoints based on capabilityFilter (takes precedence) or chatOnly
  const NON_CHAT_PATTERNS =
    /\/(moderations|embeddings|fine.tun|audio|images|files|batches|assistants|threads|vector_stores)($|\?)/i;
  const filteredEndpoints =
    capabilityFilter && selectedProvider
      ? selectedProvider.endpoints.filter(ep => ep.capabilities?.includes(capabilityFilter))
      : chatOnly && selectedProvider
        ? selectedProvider.endpoints.filter(ep => !NON_CHAT_PATTERNS.test(ep.path))
        : selectedProvider?.endpoints;

  const selectedEndpoint = filteredEndpoints?.find(e => e.path === value.endpoint_url);

  const handleChange = (field: string, val: any) => {
    onChange(`${fieldPrefix}${field}`, val);
  };

  const colClass = 'col-md-6';

  return (
    <div>
      <div className="row">
        {/* Provider */}
        <div className={colClass}>
          <div className="mb-3">
            <label>Provider *</label>
            <select
              className="form-control dropdown-styling"
              value={value.provider}
              onChange={e => handleChange('provider', e.target.value)}
              required
            >
              <option value="">Select a provider...</option>
              {llmProviders.map(provider => {
                const isEnabled = provider.enabled !== false;
                return (
                  <option
                    key={provider.enum_value}
                    value={provider.enum_value}
                    disabled={!isEnabled}
                    style={{ color: isEnabled ? 'inherit' : 'var(--gray-500)' }}
                  >
                    {provider.name}
                    {(provider as any)._marketplace ? ' ★' : ''}
                    {!isEnabled ? ' (Not Available)' : ''}
                  </option>
                );
              })}
            </select>
          </div>
        </div>

        {/* Endpoint */}
        {showEndpoint && (
          <div className={colClass}>
            <div className="mb-3">
              <label>Endpoint *</label>
              <select
                className="form-control dropdown-styling"
                value={value.endpoint_url}
                onChange={e => handleChange('endpoint_url', e.target.value)}
                required
                disabled={!selectedProvider}
              >
                <option value="">Select an endpoint...</option>
                {filteredEndpoints?.map((ep, idx) => (
                  <option key={idx} value={ep.path}>
                    {ep.name} {ep.is_default && '(Default)'}
                  </option>
                ))}
              </select>
              <small className="form-text text-muted">
                {selectedEndpoint?.description || 'Select an API endpoint'}
              </small>
            </div>
          </div>
        )}
      </div>

      <div className="row">
        {/* Model */}
        <div className={colClass}>
          <div className="mb-3">
            <label>Model *</label>
            <select
              className="form-control dropdown-styling"
              value={value.model}
              onChange={e => handleChange('model', e.target.value)}
              required
              disabled={!selectedProvider}
            >
              <option value="">Select a model...</option>
              {selectableModels(selectedProvider?.models ?? [], value.model).map(model => (
                <option key={model.value} value={model.value}>
                  {model.name}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* API Key Secret */}
        {selectedProvider ? (
          <div className={colClass}>
            <SecretSelector
              secrets={secrets}
              selectedSecretId={value.api_key_secret_id}
              onChange={secretId => handleChange('api_key_secret_id', secretId)}
              label={selectedProvider.api_key_label || 'API Key Secret'}
              filterRegex={selectedProvider.filter_tag}
              required={apiKeyValidation(selectedProvider) === 'mandatory'}
              disabled={apiKeyValidation(selectedProvider) === 'none'}
            />
          </div>
        ) : null}
      </div>

      {/* Dynamic Model Parameters */}
      {showModelParameters &&
        selectedModel?.model_parameters &&
        selectedModel.model_parameters.length > 0 && (
          <>
            {!compact && <hr className="my-3" />}
            <h6
              className={`mb-3 ${compact ? 'mt-2' : ''} text-primary`}
              style={compact ? { fontSize: '13px' } : {}}
            >
              <i className="fas fa-sliders-h me-2"></i>
              Model Parameters
            </h6>
            <div className="row">
              {selectedModel.model_parameters.map(param => (
                <div key={param.name} className={compact ? 'col-6' : 'col-md-6'}>
                  <div className="mb-3">
                    <label style={compact ? { fontSize: '12px' } : {}}>{param.label}</label>
                    {param.type === 'number' && (
                      <input
                        type="number"
                        className="form-control"
                        style={compact ? { fontSize: '12px', padding: '4px 8px' } : {}}
                        value={value.model_parameters[param.name] ?? param.default}
                        onChange={e => {
                          const val =
                            e.target.value === '' ? param.default || 0 : parseFloat(e.target.value);
                          handleChange('model_parameters', {
                            ...value.model_parameters,
                            [param.name]: val,
                          });
                        }}
                        min={param.min}
                        max={param.max}
                        step={param.step || 1}
                      />
                    )}
                    {param.type === 'string' && !param.options && (
                      <input
                        type="text"
                        className="form-control"
                        style={compact ? { fontSize: '12px', padding: '4px 8px' } : {}}
                        value={value.model_parameters[param.name] ?? param.default}
                        onChange={e =>
                          handleChange('model_parameters', {
                            ...value.model_parameters,
                            [param.name]: e.target.value,
                          })
                        }
                      />
                    )}
                    {(param.type === 'select' || (param.type === 'string' && param.options)) &&
                      param.options && (
                        <select
                          className="form-control dropdown-styling"
                          style={compact ? { fontSize: '12px', padding: '4px 8px' } : {}}
                          value={value.model_parameters[param.name] ?? param.default}
                          onChange={e =>
                            handleChange('model_parameters', {
                              ...value.model_parameters,
                              [param.name]: e.target.value,
                            })
                          }
                        >
                          {param.options.map((option: string) => (
                            <option key={option} value={option}>
                              {option}
                            </option>
                          ))}
                        </select>
                      )}
                    {param.type === 'boolean' && (
                      <div className="custom-control custom-switch">
                        <input
                          type="checkbox"
                          className="custom-control-input"
                          id={`${fieldPrefix}param_${param.name}`}
                          checked={value.model_parameters[param.name] ?? param.default}
                          onChange={e =>
                            handleChange('model_parameters', {
                              ...value.model_parameters,
                              [param.name]: e.target.checked,
                            })
                          }
                        />
                        <label
                          className="custom-control-label"
                          htmlFor={`${fieldPrefix}param_${param.name}`}
                        >
                          Enabled
                        </label>
                      </div>
                    )}
                    {param.description && (
                      <small
                        className="form-text text-muted"
                        style={compact ? { fontSize: '11px' } : {}}
                      >
                        {param.description}
                        {param.type === 'number' &&
                          param.min !== undefined &&
                          param.max !== undefined &&
                          !compact &&
                          ` (range: ${param.min} - ${param.max}, default: ${param.default})`}
                      </small>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
    </div>
  );
};

export default LLMProviderSelector;
