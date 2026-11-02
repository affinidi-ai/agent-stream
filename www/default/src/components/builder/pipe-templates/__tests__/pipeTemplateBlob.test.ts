import { resolvePipeTemplateBlob } from '../pipeTemplateBlob';

describe('resolvePipeTemplateBlob', () => {
  it('resolves legacy pipe placeholders from built-in templates', () => {
    const resolved = resolvePipeTemplateBlob(
      {
        name: '$PIPE_NAME',
        route: '$PIPE_ROUTE',
        pipe_type: { provider: { base_url: '$PIPE_ENDPOINT/v1' } },
      },
      {
        name: 'surface-poem-galaxy',
        route: '/llm/poem/galaxy',
        endpoint: 'https://llm.example.com',
      }
    );

    expect(resolved).toEqual({
      name: 'surface-poem-galaxy',
      route: '/llm/poem/galaxy',
      pipe_type: { provider: { base_url: 'https://llm.example.com/v1' } },
    });
  });

  it('clears unresolved legacy pipe placeholders', () => {
    expect(
      resolvePipeTemplateBlob(
        { name: '$PIPE_NAME', route: '$PIPE_ROUTE', endpoint: '$PIPE_ENDPOINT' },
        {}
      )
    ).toEqual({ name: '', route: '', endpoint: '' });
  });
});
