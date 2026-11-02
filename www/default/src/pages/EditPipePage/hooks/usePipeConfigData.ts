import { useEffect, useState } from 'react';
import { apiClient } from '../../../api';
import { showToast } from '../../../utils/toaster';
import { fetchMarketplaceProviders } from '../../../utils/marketplaceProviders';
import type { PipePromptGuardPattern } from '../../../components/builder/elements/pipe/pipePanelData';
import {
  DEFAULT_INPUT_MODALITIES,
  EMPTY_AUDIO_STREAMS,
  type AudioStreamsCatalog,
  type InputModalitySupport,
} from '../../../components/builder/elements/pipe/pipePanelData';
import type { LLMModel, LLMProvider, PipesConfig, RoutingConfig, Secret } from '../types';

export interface PipeConfigData {
  llmProviders: LLMProvider[];
  secrets: Secret[];
  routingConfig: RoutingConfig | null;
  promptGuardPatterns: PipePromptGuardPattern[];
  inputModalities: InputModalitySupport;
  audioStreams: AudioStreamsCatalog;
  configLoading: boolean;
}

/**
 * Loads the reference data the pipe editor needs (LLM provider catalogue +
 * marketplace models, API-key secrets, routing config, prompt-guard pattern
 * definitions). Self-contained — runs once on mount.
 */
export function usePipeConfigData(): PipeConfigData {
  const [llmProviders, setLlmProviders] = useState<LLMProvider[]>([]);
  const [secrets, setSecrets] = useState<Secret[]>([]);
  const [routingConfig, setRoutingConfig] = useState<RoutingConfig | null>(null);
  const [promptGuardPatterns, setPromptGuardPatterns] = useState<PipePromptGuardPattern[]>([]);
  const [inputModalities, setInputModalities] =
    useState<InputModalitySupport>(DEFAULT_INPUT_MODALITIES);
  const [audioStreams, setAudioStreams] = useState<AudioStreamsCatalog>(EMPTY_AUDIO_STREAMS);
  const [configLoading, setConfigLoading] = useState(true);

  useEffect(() => {
    const loadPipesConfig = async () => {
      try {
        const response = await apiClient.get('/pipes/config');
        const config: PipesConfig = response.data;
        if (config.llm?.providers && config.llm.providers.length > 0) {
          const realProviders = config.llm.providers.filter(p => p.api_schema !== 'marketplace');
          setLlmProviders(realProviders);
        }
        if (config.input_modalities) {
          setInputModalities(config.input_modalities);
        }
        if (config.audio_streams) {
          setAudioStreams(config.audio_streams);
        }
      } catch (error) {
        console.error('Failed to load pipes config:', error);
      } finally {
        setConfigLoading(false);
      }
    };

    const loadMarketplaceProviders = async () => {
      const mpProviders = await fetchMarketplaceProviders();
      setLlmProviders(prev => {
        const base = prev.filter(p => !p._marketplace);
        for (const mp of mpProviders) {
          const realType = mp._marketplace?.real_provider_type;
          if (!realType) continue;
          const realProvider = base.find(p => p.enum_value === realType);
          if (!realProvider) continue;
          for (const mpModel of mp.models) {
            const realModel =
              realProvider.models.find((m: LLMModel) => m.value === mpModel.value) ||
              realProvider.models[0];
            if (realModel?.model_parameters && !mpModel.model_parameters) {
              mpModel.model_parameters = realModel.model_parameters;
            }
          }
        }
        return [...base, ...mpProviders];
      });
    };

    const loadRoutingConfig = async () => {
      try {
        const response = await apiClient.fetch('/api/v1/config/surface-routing');
        if (!response.ok) {
          throw new Error('Failed to fetch routing configuration');
        }
        const config = await response.json();
        setRoutingConfig(config);
      } catch (error: any) {
        showToast('error', error.message || 'Failed to load routing configuration');
      }
    };

    const loadSecrets = async () => {
      try {
        const response = await apiClient.get('/secrets/');
        const allSecrets = response.data || [];
        const apiKeySecrets = allSecrets.filter((s: any) => s.secret_type === 'ApiKey');
        setSecrets(apiKeySecrets);
      } catch (error) {
        console.error('Failed to load secrets:', error);
      }
    };

    const loadPromptGuardPatterns = async () => {
      try {
        const response = await apiClient.get('/prompt-guard/config');
        const defined = response.data?.defined_patterns;
        if (Array.isArray(defined)) {
          setPromptGuardPatterns(defined);
        }
      } catch (error) {
        console.warn('Failed to load prompt guard definitions:', error);
      }
    };

    const loadAll = async () => {
      await loadPipesConfig();
      await loadMarketplaceProviders();
      await loadRoutingConfig();
      await loadSecrets();
      await loadPromptGuardPatterns();
    };
    loadAll();
  }, []);

  return {
    llmProviders,
    secrets,
    routingConfig,
    promptGuardPatterns,
    inputModalities,
    audioStreams,
    configLoading,
  };
}
