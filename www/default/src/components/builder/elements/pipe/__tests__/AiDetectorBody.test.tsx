import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import AiDetectorBody from '../AiDetectorBody';
import { DEFAULT_LLM_PII, type LlmPiiConfig } from '../llmPii';
import { apiClient } from '../../../../../api';

jest.mock('../../../../../api', () => ({
  apiClient: {
    post: jest.fn(),
  },
}));

jest.mock('../../../../shared/LLMProviderSelector', () => ({
  __esModule: true,
  default: () => null,
}));

let mockSurfaceId: string | undefined;

jest.mock('../../../SurfaceMetaContext', () => ({
  useOptionalSurfaceMeta: () => ({ surfaceId: mockSurfaceId }),
}));

const mockPost = apiClient.post as jest.Mock;

const detector = (overrides: Partial<LlmPiiConfig> = {}): LlmPiiConfig => ({
  ...DEFAULT_LLM_PII,
  provider_type: 'openai',
  endpoint_url: '/v1/chat/completions',
  model: 'gpt-4o-mini',
  ...overrides,
});

const renderDetector = (config: LlmPiiConfig) =>
  render(
    <AiDetectorBody
      detector={config}
      llmProviders={[]}
      secrets={[]}
      idPrefix="test"
      onChange={jest.fn()}
      onTested={jest.fn()}
    />
  );

describe('AiDetectorBody detector test', () => {
  beforeEach(() => {
    mockSurfaceId = 'saved-surface';
    mockPost.mockReset();
    mockPost.mockResolvedValue({ data: { ok: true, entities: [] } });
  });

  it('runs the test with a stored key on a saved surface', async () => {
    renderDetector(detector({ api_key_secret: 'openai-key' }));

    expect(screen.queryByTestId('prompt-guard-llm-pii-test-unavailable')).not.toBeInTheDocument();
    fireEvent.click(screen.getByTestId('prompt-guard-llm-pii-test'));

    await waitFor(() => expect(mockPost).toHaveBeenCalledTimes(1));
    expect(mockPost.mock.calls[0][0]).toBe('/prompt-guard/detector-test');
    expect(mockPost.mock.calls[0][1].surface_id).toBe('saved-surface');
  });

  it('blocks testing with a stored key until the surface is saved', () => {
    mockSurfaceId = undefined;
    renderDetector(detector({ api_key_secret: 'openai-key' }));

    expect(screen.getByTestId('prompt-guard-llm-pii-test')).toBeDisabled();
    expect(screen.getByTestId('prompt-guard-llm-pii-test-unavailable')).toHaveTextContent(
      'Save the surface before testing'
    );
  });

  it('runs the test without a stored key on an unsaved surface', async () => {
    mockSurfaceId = undefined;
    renderDetector(detector({ api_key_secret: null }));

    expect(screen.queryByTestId('prompt-guard-llm-pii-test-unavailable')).not.toBeInTheDocument();
    fireEvent.click(screen.getByTestId('prompt-guard-llm-pii-test'));

    await waitFor(() => expect(mockPost).toHaveBeenCalledTimes(1));
  });

  it('shows why the server refused the test', async () => {
    mockPost.mockRejectedValue(
      new Error('Save the surface before testing with a stored API key (409)')
    );
    renderDetector(detector({ api_key_secret: 'openai-key' }));

    fireEvent.click(screen.getByTestId('prompt-guard-llm-pii-test'));

    expect(await screen.findByTestId('prompt-guard-llm-pii-test-result')).toHaveTextContent(
      'Save the surface before testing with a stored API key (409)'
    );
  });
});
