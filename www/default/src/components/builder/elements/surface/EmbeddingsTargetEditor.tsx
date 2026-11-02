import React from 'react';
import SecretSelector, { Secret } from '../../../shared/SecretSelector';
import { selectableModels } from '../../../../utils/modelVisibility';
import type { LLMProvider } from '../../../../pages/EditPipePage/types';

/** The embeddings target (mirrors backend `CacheEmbedder`, `src/pipes/config.rs`). */
export interface EmbeddingsTarget {
  endpoint_url: string;
  model: string;
  api_key_secret?: string;
}

/**
 * Derive the full OpenAI-compatible embeddings endpoint URL for a provider from
 * the catalogue (`default_base_url` + the embeddings endpoint path). The embedder
 * posts `{ model, input }` to this URL, so it only supports providers whose
 * embeddings path is a plain URL (no `{model}` template — that rules out
 * Gemini-style `generateContent` paths). Returns an empty string when the
 * provider has no derivable OpenAI-shaped embeddings endpoint.
 */
export const deriveEmbeddingsUrl = (p: LLMProvider): string => {
  const base = (p.default_base_url ?? '').replace(/\/+$/, '');
  if (!base) return '';
  const ep = (p.endpoints ?? []).find(e => e.capabilities?.includes('embeddings'));
  const path = ep?.path ?? (p.api_schema === 'openai' || !p.api_schema ? '/v1/embeddings' : '');
  if (!path || path.includes('{model}')) return '';
  return `${base}${path.startsWith('/') ? '' : '/'}${path}`;
};

interface EmbeddingsTargetEditorProps {
  value: EmbeddingsTarget | null;
  onChange: (v: EmbeddingsTarget) => void;
  llmProviders: LLMProvider[];
  secrets: Secret[];
  idPrefix?: string;
  disabled?: boolean;
}

/**
 * Choose the embeddings model that measures semantic distance — provider picked
 * from the catalogue (its endpoint URL derived automatically), the model chosen
 * from that provider's catalogue models, and an API-key secret (tag-filtered by
 * the provider's `filter_tag`). The operator never types a raw URL, matching the
 * surface LLM configuration's catalogue-driven selection.
 */
const EmbeddingsTargetEditor: React.FC<EmbeddingsTargetEditorProps> = ({
  value,
  onChange,
  llmProviders,
  secrets,
  idPrefix = 'drift-embedder',
  disabled,
}) => {
  const emb = value ?? { endpoint_url: '', model: '', api_key_secret: undefined };
  const providers = llmProviders.filter(p => deriveEmbeddingsUrl(p) !== '');
  const selected = providers.find(p => deriveEmbeddingsUrl(p) === emb.endpoint_url) ?? null;
  const models = selectableModels(selected?.models ?? [], emb.model);
  const currentModelListed = !emb.model || models.some(m => m.value === emb.model);

  const patch = (next: Partial<EmbeddingsTarget>) => onChange({ ...emb, ...next });

  if (providers.length === 0) {
    return (
      <div className="alert alert-warning py-2 mb-0" style={{ fontSize: '12px' }}>
        No catalogue provider exposes an OpenAI-shaped embeddings endpoint. Add one under{' '}
        <strong>LLM Providers</strong> to measure semantic distance.
      </div>
    );
  }

  return (
    <div className={disabled ? 'opacity-50 pe-none' : undefined}>
      <div className="mb-2">
        <label className="form-label small text-muted mb-1" htmlFor={`${idPrefix}-provider`}>
          Embeddings provider
        </label>
        <select
          className="form-select form-select-sm"
          id={`${idPrefix}-provider`}
          data-testid={`${idPrefix}-provider`}
          value={selected?.enum_value ?? ''}
          disabled={disabled}
          onChange={e => {
            const prov = providers.find(p => p.enum_value === e.target.value);
            patch({ endpoint_url: prov ? deriveEmbeddingsUrl(prov) : '', model: '' });
          }}
        >
          <option value="">Select an embeddings provider…</option>
          {providers.map(p => (
            <option key={p.enum_value} value={p.enum_value}>
              {p.name ?? p.enum_value}
            </option>
          ))}
        </select>
      </div>

      <div className="mb-2">
        <label className="form-label small text-muted mb-1" htmlFor={`${idPrefix}-model`}>
          Embeddings model
        </label>
        <select
          className="form-select form-select-sm"
          id={`${idPrefix}-model`}
          data-testid={`${idPrefix}-model`}
          value={emb.model}
          disabled={disabled || !selected}
          onChange={e => patch({ model: e.target.value })}
        >
          <option value="">
            {selected ? 'Select an embeddings model…' : 'Select a provider first'}
          </option>
          {!currentModelListed && <option value={emb.model}>{emb.model} (custom)</option>}
          {models.map(m => (
            <option key={m.value} value={m.value}>
              {m.name}
            </option>
          ))}
        </select>
      </div>

      {/* Keyed by provider so the picker re-mounts on change, re-defaulting the
          "Filter tags" toggle on (its initial state is seeded once at mount). */}
      <SecretSelector
        key={selected?.enum_value ?? '_none'}
        secrets={secrets}
        selectedSecretId={emb.api_key_secret ?? ''}
        onChange={secretId => patch({ api_key_secret: secretId || undefined })}
        label="API key secret"
        filterRegex={selected?.filter_tag}
        disabled={disabled}
        testId={`${idPrefix}-secret`}
      />
    </div>
  );
};

export default EmbeddingsTargetEditor;
