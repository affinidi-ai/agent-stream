import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { apiClient } from '../../api';
import { emptyProvider, normalizeProvider } from './helpers';
import type { LlmProviderForm } from './types';

export interface UseLlmProviderView {
  form: LlmProviderForm;
  loading: boolean;
  error: string | null;
}

export const useLlmProviderForm = (): UseLlmProviderView => {
  const { enumValue } = useParams<{ enumValue: string }>();

  const [form, setForm] = useState<LlmProviderForm>(emptyProvider());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!enumValue) {
      setError('Provider not specified.');
      setLoading(false);
      return;
    }
    let active = true;
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await apiClient.get(`/llm-providers/${encodeURIComponent(enumValue)}`);
        if (active) setForm(normalizeProvider(res.data as Record<string, unknown>));
      } catch (e) {
        if (active) setError(e instanceof Error ? e.message : 'Failed to load provider');
      } finally {
        if (active) setLoading(false);
      }
    })();
    return () => {
      active = false;
    };
  }, [enumValue]);

  return { form, loading, error };
};
