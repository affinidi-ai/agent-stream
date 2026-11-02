import { useEffect, useState } from 'react';
import { apiClient } from '../../../api';
import type { LLMProviderInfo } from '../../../components/shared/LLMProviderSelector';
import type { Secret } from '../../../components/shared/SecretSelector';
import { fetchMarketplaceProviders } from '../../../utils/marketplaceProviders';

export interface LlmTargetCatalog {
  llmProviders: LLMProviderInfo[];
  secrets: Secret[];
}

/**
 * Loads the LLM provider/secret catalog used by every LLM-target editor
 * (`DeciderLlmEditor`). Hoisting this into a hook lets a parent that renders
 * many targets (failover/load-balancing pools) fetch the catalog once and pass
 * it down, instead of each editor instance issuing its own duplicate requests.
 */
export function useLlmTargetCatalog(): LlmTargetCatalog {
  const [llmProviders, setLlmProviders] = useState<LLMProviderInfo[]>([]);
  const [secrets, setSecrets] = useState<Secret[]>([]);

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
        console.error('Failed to load LLM target catalog:', error);
      }
      try {
        const mpProviders = await fetchMarketplaceProviders();
        setLlmProviders(prev => [...prev.filter((p: any) => !p._marketplace), ...mpProviders]);
      } catch {
        // Marketplace is optional; ignore failures.
      }
    };
    loadData();
  }, []);

  return { llmProviders, secrets };
}
