import { useEffect, useState } from 'react';
import type { LLMModel, LLMProvider, PipeFormData, Secret } from '../types';

/**
 * Reproduces the editor's model-parameter and endpoint defaulting effects:
 *  - seed parameter defaults when the selected model changes,
 *  - fill a default endpoint once a provider is chosen,
 *  - auto-populate fields when a marketplace provider is selected.
 */
export function useModelParameterDefaults(
  formData: PipeFormData,
  setFormData: React.Dispatch<React.SetStateAction<PipeFormData>>,
  llmProviders: LLMProvider[],
  secrets: Secret[],
  selectedProvider: LLMProvider | undefined,
  selectedModel: LLMModel | undefined
): void {
  const [initializedModelParams, setInitializedModelParams] = useState<string>('');
  const [lastAutoProvider, setLastAutoProvider] = useState<string>('');

  useEffect(() => {
    if (!selectedModel?.model_parameters) {
      if (Object.keys(formData.model_parameters || {}).length > 0) {
        setFormData(prev => ({
          ...prev,
          model_parameters: {},
        }));
      }
      return;
    }

    const modelKey = `${formData.provider}_${formData.model}`;

    if (initializedModelParams === modelKey) {
      return;
    }

    if (selectedModel.model_parameters.length > 0) {
      const newParams: Record<string, any> = {};
      selectedModel.model_parameters.forEach(param => {
        // Catalog defaults are stored as strings (e.g. "2048"); the backend's
        // pipe config expects a real number for numeric params, so coerce here
        // rather than let a stringly-typed default reach the save payload.
        newParams[param.name] =
          param.type === 'number' && typeof param.default === 'string' && param.default !== ''
            ? Number(param.default)
            : param.default;
      });

      setFormData(prev => ({
        ...prev,
        model_parameters: newParams,
      }));

      setInitializedModelParams(modelKey);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedModel, formData.provider, formData.model]);

  useEffect(() => {
    if (!formData.endpoint_url && formData.provider && llmProviders.length > 0) {
      const provider = llmProviders.find(p => p.enum_value === formData.provider);
      if (provider?.endpoints) {
        const defaultEndpoint = provider.endpoints.find(e => e.is_default) || provider.endpoints[0];
        if (defaultEndpoint) {
          setFormData(prev => ({
            ...prev,
            endpoint_url: defaultEndpoint.path,
          }));
        }
      }
    }
  }, [formData.provider, formData.endpoint_url, llmProviders, setFormData]);

  useEffect(() => {
    if (!selectedProvider?._marketplace || formData.provider === lastAutoProvider) return;
    const mp = selectedProvider._marketplace;
    const updates: Partial<PipeFormData> = {};
    if (mp.api_key_secret_id) {
      const matchingSecret = secrets.find((s: any) => s.secret_id === mp.api_key_secret_id);
      if (matchingSecret) {
        updates.api_key_secret_id = matchingSecret.id;
      }
    }
    if (selectedProvider.models.length === 1) updates.model = selectedProvider.models[0].value;
    const defEp =
      selectedProvider.endpoints.find(e => e.is_default) || selectedProvider.endpoints[0];
    if (defEp) updates.endpoint_url = defEp.path;
    if (Object.keys(updates).length > 0) {
      setFormData(prev => ({ ...prev, ...updates }));
    }
    setLastAutoProvider(formData.provider);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedProvider, formData.provider, secrets]);
}
