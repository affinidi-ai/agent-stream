import React from 'react';
import SecretSelector from '../../../components/shared/SecretSelector';
import { selectableModels } from '../../../utils/modelVisibility';
import { apiKeyValidation } from '../../../utils/apiKeyValidation';

// Types
interface LLMProvider {
  enum_value: string;
  name: string;
  enabled?: boolean;
  api_key_label?: string;
  api_key_validation?: string;
  api_key_required?: boolean;
  filter_tag?: string;
  api_schema?: string;
  marketplace_url?: string;
  endpoints: Endpoint[];
  models: Model[];
  _marketplace?: any;
}

interface Endpoint {
  name: string;
  path: string;
  description?: string;
  is_default?: boolean;
  capabilities?: string[];
  endpoint_parameters?: EndpointParameter[];
}

interface EndpointParameter {
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

interface Model {
  name: string;
  value: string;
  enabled?: boolean;
  model_parameters?: ModelParameter[];
}

interface ModelParameter {
  name: string;
  label: string;
  type: string;
  description?: string;
  default?: any;
  min?: number;
  max?: number;
  step?: number;
  options?: string[];
}

interface Secret {
  id: string;
  name: string;
  tags?: string[];
}

interface UpstreamHeader {
  name: string;
  secret_id: string;
}

interface FormData {
  listen_address: string;
  route: string;
  provider: string;
  endpoint_url: string;
  model: string;
  api_key_secret_id: string;
  model_parameters: Record<string, any>;
  override_policy?: Record<string, string>;
  max_reasoning_tokens?: number | null;
  context_management?: any;
  upstream_headers?: UpstreamHeader[];
}

interface LLMConfigTabProps {
  formData: FormData;
  handleInputChange: (field: string, value: any) => void;
  llmProviders: LLMProvider[];
  selectedProvider: LLMProvider | null;
  selectedModel: Model | null;
  selectedEndpoint: Endpoint | null;
  secrets: Secret[];
  setIsModified: (value: boolean) => void;
  /** Called when the secrets list needs refreshing (e.g. after marketplace purchase) */
  onRefreshSecrets?: () => void;
  /** Called when marketplace providers need refreshing (e.g. after purchase) */
  onRefreshProviders?: () => void;
  /** Navigate to the full-page marketplace browser */
  onBrowseMarketplace?: () => void;
}

const LLMConfigTab: React.FC<LLMConfigTabProps> = ({
  formData,
  handleInputChange,
  llmProviders,
  selectedProvider,
  selectedModel,
  selectedEndpoint,
  secrets,
  setIsModified,
  onRefreshSecrets,
  onRefreshProviders,
  onBrowseMarketplace,
}) => {
  return (
    <>
      {/* Listener Info Box */}
      {formData.listen_address && formData.route && (
        <div className="alert alert-success mb-3" style={{ fontSize: '14px' }}>
          <i className="fas fa-info-circle me-2"></i>
          <strong>Pipe Listener:</strong> {formData.listen_address}
          {formData.route}
          <button
            type="button"
            className="btn btn-xs ms-2"
            style={{ padding: '2px 6px', fontSize: '11px', outline: 'none' }}
            onClick={e => {
              navigator.clipboard.writeText(`${formData.listen_address}${formData.route}`);
              const btn = e.currentTarget as HTMLButtonElement;
              const originalHtml = btn.innerHTML;
              btn.innerHTML = '<i class="fas fa-check"></i>';
              setTimeout(() => {
                btn.innerHTML = originalHtml;
              }, 2000);
            }}
            title="Copy to clipboard"
          >
            <i className="fas fa-copy"></i>
          </button>
        </div>
      )}

      <div className="card shadow-sm mb-4">
        <div className="card-header bg-light">
          <div className="d-flex justify-content-between align-items-center">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-brain"></i> LLM Configuration
            </h6>
            {/* <button type="button" className="btn btn-sm btn-primary" onClick={onBrowseMarketplace}>
              <i className="fas fa-store me-1"></i>
              Browse Marketplace
            </button> */}
          </div>
        </div>
        <div className="card-body">
          <div className="row">
            <div className="col-md-6">
              <div className="mb-3">
                <label>Provider *</label>
                <select
                  className="form-control dropdown-styling"
                  value={formData.provider}
                  onChange={e => handleInputChange('provider', e.target.value)}
                  required
                >
                  <option value="">Select a provider...</option>
                  {llmProviders.map(provider => {
                    const isEnabled = provider.enabled !== false;
                    const isMp = !!provider._marketplace;
                    return (
                      <option
                        key={provider.enum_value}
                        value={provider.enum_value}
                        disabled={!isEnabled}
                        style={{ color: isEnabled ? 'inherit' : 'var(--gray-500)' }}
                      >
                        {provider.name}
                        {isMp ? ' ★' : ''}
                        {!isEnabled ? ' (Not Available)' : ''}
                      </option>
                    );
                  })}
                </select>
              </div>
            </div>

            <div className="col-md-6">
              <div className="mb-3">
                <label>Endpoint *</label>
                <select
                  className="form-control dropdown-styling"
                  value={formData.endpoint_url}
                  onChange={e => handleInputChange('endpoint_url', e.target.value)}
                  required
                  disabled={!selectedProvider}
                >
                  <option value="">Select an endpoint...</option>
                  {selectedProvider?.endpoints
                    .filter(ep => ep.capabilities?.includes('chat_completions'))
                    .map((ep, idx) => (
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
          </div>

          <div className="row">
            <div className="col-md-6">
              <div className="mb-3">
                <label>Model *</label>
                <select
                  className="form-control dropdown-styling"
                  value={formData.model}
                  onChange={e => handleInputChange('model', e.target.value)}
                  required
                  disabled={!selectedProvider}
                >
                  <option value="">Select a model...</option>
                  {selectableModels(selectedProvider?.models ?? [], formData.model).map(model => (
                    <option key={model.value} value={model.value}>
                      {model.name}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div className="col-md-6">
              <div className="mb-3">
                <label>Model Policy</label>
                <select
                  className="form-control dropdown-styling"
                  value={formData.override_policy?.['model'] || 'inject_if_missing'}
                  onChange={e => {
                    const newPolicy = { ...formData.override_policy };
                    newPolicy['model'] = e.target.value;
                    handleInputChange('override_policy', newPolicy);
                  }}
                >
                  <option value="inject_if_missing">Inject If Missing</option>
                  <option value="gateway_wins">Gateway Wins</option>
                  <option value="client_wins">Client Wins</option>
                </select>
                <small className="form-text text-muted">
                  {(formData.override_policy?.['model'] || 'inject_if_missing') ===
                    'gateway_wins' && 'Gateway model always used, client requests ignored'}
                  {(formData.override_policy?.['model'] || 'inject_if_missing') === 'client_wins' &&
                    'Client value passed through as-is'}
                  {(formData.override_policy?.['model'] || 'inject_if_missing') ===
                    'inject_if_missing' && 'Use gateway model only when client omits model'}
                </small>
              </div>
            </div>
          </div>

          <div className="row">
            <div className="col-md-6">
              <SecretSelector
                secrets={secrets}
                selectedSecretId={formData.api_key_secret_id}
                onChange={secretId => handleInputChange('api_key_secret_id', secretId)}
                label={selectedProvider?.api_key_label || 'API Key Secret'}
                filterRegex={selectedProvider?.filter_tag}
                required={apiKeyValidation(selectedProvider) === 'mandatory'}
                disabled={apiKeyValidation(selectedProvider) === 'none'}
                testId="llm-api-key-secret"
              />
            </div>

            <div className="col-md-6">
              <div className="mb-3">
                <label>API Key Policy</label>
                <select
                  className="form-control dropdown-styling"
                  value={formData.override_policy?.['api_key'] || 'gateway_wins'}
                  onChange={e => {
                    const newPolicy = { ...formData.override_policy };
                    newPolicy['api_key'] = e.target.value;
                    handleInputChange('override_policy', newPolicy);
                  }}
                >
                  <option value="gateway_wins">Gateway Wins</option>
                  <option value="client_wins">Client Wins</option>
                  <option value="inject_if_missing">Inject If Missing</option>
                </select>
                <small className="form-text text-muted">
                  {(formData.override_policy?.['api_key'] || 'gateway_wins') === 'gateway_wins' &&
                    'Gateway API key always used, client requests ignored'}
                  {(formData.override_policy?.['api_key'] || 'gateway_wins') === 'client_wins' &&
                    'Client value passed through as-is'}
                  {(formData.override_policy?.['api_key'] || 'gateway_wins') ===
                    'inject_if_missing' && 'Use gateway API key only when client omits key'}
                </small>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Dynamic Endpoint Parameters */}
      {selectedEndpoint?.endpoint_parameters && selectedEndpoint.endpoint_parameters.length > 0 && (
        <div className="card shadow-sm mb-4">
          <div className="card-header bg-light">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-cog"></i> Endpoint Parameters
            </h6>
          </div>
          <div className="card-body">
            {(() => {
              const filteredParams = selectedEndpoint.endpoint_parameters.filter(param => {
                // Filter by applies_to_models if specified
                if (!param.applies_to_models || param.applies_to_models.length === 0) {
                  return true;
                }
                return param.applies_to_models.includes(formData.model);
              });

              if (filteredParams.length === 0) {
                return (
                  <div className="alert alert-success">
                    <i className="fas fa-check-circle me-2"></i>
                    No additional endpoint parameters required for{' '}
                    <strong>{formData.model || 'this model'}</strong>
                  </div>
                );
              } else {
                return (
                  <>
                    <div className="alert alert-info">
                      <i className="fas fa-info-circle me-2"></i>
                      Configure endpoint-specific parameters for{' '}
                      <strong>{selectedEndpoint.name}</strong>
                    </div>
                    <div className="row">
                      {filteredParams.map(param => {
                        return (
                          <div key={param.name} className="col-md-6">
                            <div className="mb-3">
                              <label>{param.label}</label>
                              {param.type === 'number' && (
                                <input
                                  type="number"
                                  className="form-control"
                                  value={formData.model_parameters[param.name] ?? param.default}
                                  onChange={e => {
                                    const val =
                                      e.target.value === ''
                                        ? Number(param.default) || 0
                                        : parseFloat(e.target.value);
                                    handleInputChange('model_parameters', {
                                      ...formData.model_parameters,
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
                                  value={formData.model_parameters[param.name] ?? param.default}
                                  onChange={e =>
                                    handleInputChange('model_parameters', {
                                      ...formData.model_parameters,
                                      [param.name]: e.target.value,
                                    })
                                  }
                                />
                              )}
                              {param.type === 'select' && param.options && (
                                <select
                                  className="form-control dropdown-styling"
                                  value={formData.model_parameters[param.name] ?? param.default}
                                  onChange={e =>
                                    handleInputChange('model_parameters', {
                                      ...formData.model_parameters,
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
                              {param.type === 'string' && param.options && (
                                <select
                                  className="form-control dropdown-styling"
                                  value={formData.model_parameters[param.name] ?? param.default}
                                  onChange={e =>
                                    handleInputChange('model_parameters', {
                                      ...formData.model_parameters,
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
                                    id={`endpoint_param_${param.name}`}
                                    checked={formData.model_parameters[param.name] ?? param.default}
                                    onChange={e =>
                                      handleInputChange('model_parameters', {
                                        ...formData.model_parameters,
                                        [param.name]: e.target.checked,
                                      })
                                    }
                                  />
                                  <label
                                    className="custom-control-label"
                                    htmlFor={`endpoint_param_${param.name}`}
                                  >
                                    Enabled
                                  </label>
                                </div>
                              )}
                              {param.description && (
                                <small className="form-text text-muted">
                                  {param.description}
                                  {param.type === 'number' &&
                                    param.min !== undefined &&
                                    param.max !== undefined &&
                                    ` (range: ${param.min} - ${param.max}, default: ${param.default})`}
                                </small>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </>
                );
              }
            })()}
          </div>
        </div>
      )}

      {/* Dynamic Model Parameters */}
      {selectedModel?.model_parameters && selectedModel.model_parameters.length > 0 && (
        <div className="card shadow-sm mb-4">
          <div className="card-header bg-light">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-sliders-h"></i> Model Parameters & Override Policies
            </h6>
          </div>
          <div className="card-body">
            <div className="row">
              {selectedModel.model_parameters.map(param => {
                const isReasoningEffort = param.name === 'reasoning_effort';
                const isO1Model =
                  formData.model?.toLowerCase().includes('o1') ||
                  formData.model?.toLowerCase().includes('gpt-5');
                const policyDisabled = isReasoningEffort && !isO1Model;

                return (
                  <div key={param.name} className="col-md-12">
                    <div className="mb-3">
                      <label>{param.label}</label>
                      <div className="row">
                        <div className="col-md-6">
                          {param.type === 'number' && (
                            <input
                              type="number"
                              className="form-control"
                              value={formData.model_parameters[param.name] ?? param.default}
                              onChange={e => {
                                const val = e.target.value === '' ? 0 : parseFloat(e.target.value);
                                handleInputChange('model_parameters', {
                                  ...formData.model_parameters,
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
                              value={formData.model_parameters[param.name] ?? param.default}
                              onChange={e =>
                                handleInputChange('model_parameters', {
                                  ...formData.model_parameters,
                                  [param.name]: e.target.value,
                                })
                              }
                            />
                          )}
                          {(param.type === 'select' ||
                            (param.type === 'string' && param.options)) &&
                            param.options && (
                              <select
                                className="form-control dropdown-styling"
                                value={
                                  isReasoningEffort
                                    ? (formData.override_policy?.reasoning_effort_value ??
                                      param.default)
                                    : (formData.model_parameters[param.name] ?? param.default)
                                }
                                disabled={isReasoningEffort && policyDisabled}
                                onChange={e => {
                                  if (isReasoningEffort) {
                                    handleInputChange('override_policy', {
                                      ...formData.override_policy,
                                      reasoning_effort_value: e.target.value,
                                    });
                                  } else {
                                    handleInputChange('model_parameters', {
                                      ...formData.model_parameters,
                                      [param.name]: e.target.value,
                                    });
                                  }
                                }}
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
                                id={`param_${param.name}`}
                                checked={formData.model_parameters[param.name] ?? param.default}
                                onChange={e =>
                                  handleInputChange('model_parameters', {
                                    ...formData.model_parameters,
                                    [param.name]: e.target.checked,
                                  })
                                }
                              />
                              <label
                                className="custom-control-label"
                                htmlFor={`param_${param.name}`}
                              >
                                Enabled
                              </label>
                            </div>
                          )}
                        </div>
                        <div className="col-md-6">
                          <select
                            className="form-control dropdown-styling"
                            value={formData.override_policy?.[param.name] || 'inject_if_missing'}
                            disabled={policyDisabled}
                            onChange={e => {
                              const newPolicy = { ...formData.override_policy };
                              newPolicy[param.name] = e.target.value;
                              handleInputChange('override_policy', newPolicy);
                            }}
                          >
                            <option value="inject_if_missing">Inject If Missing</option>
                            <option value="gateway_wins">Gateway Wins</option>
                            <option value="client_wins">Client Wins</option>
                          </select>
                          {policyDisabled && (
                            <small className="form-text text-muted">
                              Policy only applies to o1/o3/gpt-5 models
                            </small>
                          )}
                          <small
                            className="form-text text-muted"
                            style={{ marginTop: '4px', display: 'block' }}
                          >
                            {(formData.override_policy?.[param.name] || 'inject_if_missing') ===
                              'gateway_wins' &&
                              'Gateway value always used, client SDK requests ignored'}
                            {(formData.override_policy?.[param.name] || 'inject_if_missing') ===
                              'client_wins' && 'Client value passed through as-is'}
                            {(formData.override_policy?.[param.name] || 'inject_if_missing') ===
                              'inject_if_missing' &&
                              'Inject only when client SDK omits this parameter'}
                          </small>
                        </div>
                      </div>
                      {param.description && (
                        <small className="form-text text-muted">
                          {param.description}
                          {param.type === 'number' &&
                            param.min !== undefined &&
                            param.max !== undefined &&
                            ` (range: ${param.min} - ${param.max}, default: ${param.default})`}
                        </small>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
      <div className="card shadow-sm mb-4">
        <div className="card-header bg-light">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-brain"></i> Reasoning Budget Governor
          </h6>
        </div>
        <div className="card-body">
          <label>Max reasoning tokens (per request)</label>
          <input
            type="number"
            className="form-control"
            min={0}
            step={256}
            placeholder="Uncapped"
            value={formData.max_reasoning_tokens ?? ''}
            onChange={e => {
              const raw = e.target.value;
              handleInputChange(
                'max_reasoning_tokens',
                raw === '' ? null : Math.max(0, parseInt(raw, 10) || 0)
              );
            }}
          />
          <small className="form-text text-muted">
            Ceiling for provider &quot;thinking&quot; tokens. A caller&apos;s requested reasoning
            budget is clamped to this value (and the effort level lowered to match), bounding
            Anthropic/Gemini token budgets and OpenAI effort. Leave blank for uncapped.
          </small>
        </div>
      </div>
      {(() => {
        const cm = formData.context_management ?? {
          enabled: false,
          context_window_tokens: null,
          keep_recent_messages: 4,
          reserve_output_tokens: 1024,
        };
        const updateCm = (patch: Partial<typeof cm>) =>
          handleInputChange('context_management', { ...cm, ...patch });
        return (
          <div className="card shadow-sm mb-4">
            <div className="card-header bg-light">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-compress-alt"></i> Context Window Management
              </h6>
            </div>
            <div className="card-body">
              <div className="form-check form-switch mb-3">
                <input
                  className="form-check-input"
                  type="checkbox"
                  role="switch"
                  id="context-management-enabled"
                  checked={cm.enabled === true}
                  onChange={e => updateCm({ enabled: e.target.checked })}
                />
                <label className="form-check-label" htmlFor="context-management-enabled">
                  Auto-compress over-window prompts (middle-out)
                </label>
              </div>
              <label>Context window (tokens)</label>
              <input
                type="number"
                className="form-control mb-3"
                min={0}
                step={1024}
                placeholder="e.g. 128000"
                value={cm.context_window_tokens ?? ''}
                onChange={e => {
                  const raw = e.target.value;
                  updateCm({
                    context_window_tokens: raw === '' ? null : Math.max(0, parseInt(raw, 10) || 0),
                  });
                }}
              />
              <div className="row">
                <div className="col-md-6">
                  <label>Keep recent messages</label>
                  <input
                    type="number"
                    className="form-control"
                    min={1}
                    step={1}
                    value={cm.keep_recent_messages ?? 4}
                    onChange={e =>
                      updateCm({
                        keep_recent_messages: Math.max(1, parseInt(e.target.value, 10) || 4),
                      })
                    }
                  />
                </div>
                <div className="col-md-6">
                  <label>Reserve output tokens</label>
                  <input
                    type="number"
                    className="form-control"
                    min={0}
                    step={256}
                    value={cm.reserve_output_tokens ?? 1024}
                    onChange={e =>
                      updateCm({
                        reserve_output_tokens: Math.max(0, parseInt(e.target.value, 10) || 0),
                      })
                    }
                  />
                </div>
              </div>
              <small className="form-text text-muted d-block mt-2">
                When a prompt exceeds the context window (minus the reserved output headroom), the
                middle of the conversation is dropped — preserving the system prompt and the most
                recent turns — so the request never overflows. A caller can also opt in per request
                with <code>transforms: [&quot;middle-out&quot;]</code> (or opt out with
                <code>transforms: []</code>). Requires the context window to be set.
              </small>
            </div>
          </div>
        );
      })()}
      {(() => {
        const headers: UpstreamHeader[] = formData.upstream_headers ?? [];
        const update = (next: UpstreamHeader[]) => handleInputChange('upstream_headers', next);
        const patchRow = (index: number, patch: Partial<UpstreamHeader>) =>
          update(headers.map((h, i) => (i === index ? { ...h, ...patch } : h)));
        return (
          <div className="card shadow-sm mb-4">
            <div className="card-header bg-light">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-key"></i> Upstream Headers
              </h6>
            </div>
            <div className="card-body">
              {headers.length === 0 && (
                <p className="text-muted mb-3">
                  No extra headers. The upstream receives only this provider&apos;s own credential.
                </p>
              )}
              {headers.map((header, index) => (
                <div className="row align-items-end mb-3" key={index}>
                  <div className="col-md-5">
                    <label>Header name</label>
                    <input
                      type="text"
                      className="form-control"
                      placeholder="x-asp-api-key"
                      value={header.name}
                      onChange={e => patchRow(index, { name: e.target.value })}
                      data-testid={`upstream-header-name-${index}`}
                    />
                  </div>
                  <div className="col-md-6">
                    <SecretSelector
                      secrets={secrets}
                      selectedSecretId={header.secret_id}
                      onChange={secretId => patchRow(index, { secret_id: secretId })}
                      label="Value secret"
                      testId={`upstream-header-secret-${index}`}
                    />
                  </div>
                  <div className="col-md-1">
                    <button
                      type="button"
                      className="btn btn-outline-danger mb-3"
                      onClick={() => update(headers.filter((_, i) => i !== index))}
                      aria-label={`Remove upstream header ${index + 1}`}
                    >
                      <i className="fas fa-trash"></i>
                    </button>
                  </div>
                </div>
              ))}
              <button
                type="button"
                className="btn btn-outline-primary btn-sm"
                onClick={() => update([...headers, { name: '', secret_id: '' }])}
                data-testid="upstream-header-add"
              >
                <i className="fas fa-plus"></i> Add header
              </button>
              <small className="form-text text-muted d-block mt-3">
                Extra headers sent to this surface&apos;s own upstream alongside the provider
                credential, each value read from the secrets store at request time. Use this to
                reach an upstream that authenticates the gateway separately from the model — a mesh
                ingress, a reverse proxy, or a tunnel with its own ingress key. They are never sent
                to a Decider candidate or a failover or load-balancing target. Each variant carries
                its own list: this card edits the active variant&apos;s, and a new variant starts
                with a copy of the headers of the variant it was created from. Header names that
                carry a provider credential (<code>Authorization</code>, <code>x-api-key</code>,{' '}
                <code>api-key</code>, <code>x-goog-api-key</code>) are rejected on save — configure
                those as the provider&apos;s API key secret instead.
              </small>
            </div>
          </div>
        );
      })()}
    </>
  );
};

export default LLMConfigTab;
