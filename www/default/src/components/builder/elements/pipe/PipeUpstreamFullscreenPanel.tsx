import React, { Suspense } from 'react';
import type { ConfigPanelProps } from '../types';
import type { LLMProvider } from '../../../../pages/EditPipePage/types';
import type { FailoverConfig, LoadBalancingConfig } from '../../../shared/resilienceModel';
import { firstEnabledModelValue } from '../../../../utils/modelVisibility';
import { usePipePanelData } from './pipePanelData';
import PipeResilienceEditor from './PipeResilienceEditor';

// Lazily resolved so the element registry (and its unit tests) never pull the
// LLM config tab's dependency graph into module load. The chunk is fetched
// only when the editor actually renders.
const LLMConfigTab = React.lazy(() => import('../../../../pages/EditPipePage/tabs/LLMConfigTab'));

/**
 * Full-area editor for the pipe-upstream (LLM) node — the complete LLM phase
 * configuration: provider / endpoint / model selection, the API-key secret
 * and its injection policy, the model-override policy, dynamic endpoint
 * parameters and the per-parameter model values with their override policies
 * (gateway-wins / client-wins / inject-if-missing). Reuses the existing
 * {@link LLMConfigTab} verbatim, adapting the canvas node config to the tab's
 * flat `formData` shape. The host page's upstream seam propagates the edits
 * back into the pipe's `pipe_type`, `model_parameters` and `override_policy`.
 *
 * The provider catalogue (with full model/endpoint parameter metadata) and
 * the secrets list arrive via {@link usePipePanelData}; the host supplies the
 * complete provider objects, so they are read back through the richer
 * {@link LLMProvider} shape here.
 */
const PipeUpstreamFullscreenPanel: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  updateFields,
}) => {
  const { llmProviders, secrets } = usePipePanelData();
  const providers = llmProviders as unknown as LLMProvider[];

  const provider = typeof config?.provider === 'string' ? config.provider : '';
  const endpointUrl = typeof config?.endpoint === 'string' ? config.endpoint : '';
  const model = typeof config?.model === 'string' ? config.model : '';
  const apiKeySecretId =
    typeof config?.api_key_secret_id === 'string' ? config.api_key_secret_id : '';
  const modelParameters =
    config?.model_parameters && typeof config.model_parameters === 'object'
      ? (config.model_parameters as Record<string, unknown>)
      : {};
  const overridePolicy =
    config?.override_policy && typeof config.override_policy === 'object'
      ? (config.override_policy as Record<string, string>)
      : {};

  const selectedProvider = providers.find(p => p.enum_value === provider) ?? null;
  const selectedModel = selectedProvider?.models.find(m => m.value === model) ?? null;
  const selectedEndpoint = selectedProvider?.endpoints.find(ep => ep.path === endpointUrl) ?? null;

  const formData = {
    listen_address: '',
    route: '',
    provider,
    endpoint_url: endpointUrl,
    model,
    api_key_secret_id: apiKeySecretId,
    model_parameters: modelParameters,
    override_policy: overridePolicy,
  };

  const handleInputChange = (field: string, value: unknown) => {
    if (field === 'provider') {
      const prov = providers.find(p => p.enum_value === value) ?? null;
      const defaultEndpoint =
        prov?.endpoints.find(ep => ep.is_default)?.path || prov?.endpoints[0]?.path || '';
      const firstModel = firstEnabledModelValue(prov?.models ?? []);
      updateFields({
        provider: value,
        endpoint: defaultEndpoint,
        model: firstModel,
        api_key_secret_id: '',
      });
      return;
    }
    if (field === 'endpoint_url') {
      updateField('endpoint', value);
      return;
    }
    updateField(field, value);
  };

  return (
    <Suspense fallback={<div className="p-4 text-muted">Loading LLM editor…</div>}>
      <LLMConfigTab
        formData={formData}
        handleInputChange={handleInputChange}
        llmProviders={providers as never}
        selectedProvider={selectedProvider as never}
        selectedModel={selectedModel as never}
        selectedEndpoint={selectedEndpoint as never}
        secrets={secrets}
        setIsModified={() => {}}
      />
      <PipeResilienceEditor
        failover={(config?.failover as FailoverConfig | null) ?? null}
        loadBalancing={(config?.load_balancing as LoadBalancingConfig | null) ?? null}
        onChange={next =>
          updateFields({ failover: next.failover, load_balancing: next.load_balancing })
        }
      />
    </Suspense>
  );
};

export default PipeUpstreamFullscreenPanel;
