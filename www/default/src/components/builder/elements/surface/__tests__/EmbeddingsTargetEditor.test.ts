import { deriveEmbeddingsUrl } from '../EmbeddingsTargetEditor';
import type { LLMEndpoint, LLMProvider } from '../../../../../pages/EditPipePage/types';

const embeddingsEndpoint = (path: string): LLMEndpoint => ({
  name: 'Embeddings',
  path,
  description: '',
  capabilities: ['embeddings'],
});

const provider = (overrides: Partial<LLMProvider>): LLMProvider => ({
  name: 'Provider',
  enum_value: 'provider',
  endpoints: [],
  icon: '',
  api_key_label: '',
  models: [],
  ...overrides,
});

describe('deriveEmbeddingsUrl', () => {
  it('inserts the version prefix before a catalogue embeddings path', () => {
    const openai = provider({
      default_base_url: 'https://api.openai.com',
      api_version_prefix: '/v1',
      api_schema: 'openai',
      endpoints: [embeddingsEndpoint('/embeddings')],
    });
    expect(deriveEmbeddingsUrl(openai)).toBe('https://api.openai.com/v1/embeddings');
  });

  it('falls back to /embeddings under the version prefix when no endpoint is listed', () => {
    const groq = provider({
      default_base_url: 'https://api.groq.com/openai',
      api_version_prefix: '/v1',
      api_schema: 'openai',
    });
    expect(deriveEmbeddingsUrl(groq)).toBe('https://api.groq.com/openai/v1/embeddings');
  });

  it('falls back to /v1/embeddings when there is no endpoint and no version prefix', () => {
    const custom = provider({ default_base_url: 'https://llm.example.com/' });
    expect(deriveEmbeddingsUrl(custom)).toBe('https://llm.example.com/v1/embeddings');
  });

  it('uses a catalogue path as-is when the provider has no version prefix', () => {
    const custom = provider({
      default_base_url: 'https://llm.example.com',
      endpoints: [embeddingsEndpoint('embed')],
    });
    expect(deriveEmbeddingsUrl(custom)).toBe('https://llm.example.com/embed');
  });

  it('normalises slashes around the version prefix', () => {
    const custom = provider({
      default_base_url: 'https://llm.example.com/',
      api_version_prefix: 'v2/',
      endpoints: [embeddingsEndpoint('/embeddings')],
    });
    expect(deriveEmbeddingsUrl(custom)).toBe('https://llm.example.com/v2/embeddings');
  });

  it('returns empty for a templated embeddings path', () => {
    const gemini = provider({
      default_base_url: 'https://generativelanguage.googleapis.com',
      api_version_prefix: '/v1beta',
      api_schema: 'gemini',
      endpoints: [embeddingsEndpoint('/models/{model}:embedContent')],
    });
    expect(deriveEmbeddingsUrl(gemini)).toBe('');
  });

  it('returns empty for a non-OpenAI schema without an embeddings endpoint', () => {
    const anthropic = provider({
      default_base_url: 'https://api.anthropic.com',
      api_version_prefix: '/v1',
      api_schema: 'anthropic',
    });
    expect(deriveEmbeddingsUrl(anthropic)).toBe('');
  });

  it('returns empty when the provider has no base URL', () => {
    const azure = provider({ api_schema: 'openai' });
    expect(deriveEmbeddingsUrl(azure)).toBe('');
  });
});
