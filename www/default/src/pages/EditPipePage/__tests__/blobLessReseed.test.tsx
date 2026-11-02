import { renderHook } from '@testing-library/react';
import { usePipeBuilder } from '../hooks/usePipeBuilder';
import { buildPipeForCanvas, mapPipeToFormData } from '../pipeMappingHelpers';
import { EMPTY_PIPE_FORM } from '../types';
import type { PipeConfig } from '../types';

const noop = () => {};
const handlers = {
  onSourceChange: noop,
  onUpstreamChange: noop,
  onRateLimitChange: noop,
  onOpaPolicyChange: noop,
  onPromptGuardChange: noop,
  onJudgeChange: noop,
  onJuryChange: noop,
  onDeciderChange: noop,
  onExpertWitnessesChange: noop,
  onUsageLimitsChange: noop,
} as any;

const llmProviders = [
  {
    enum_value: 'mock_llm',
    name: 'Mock LLM',
    api_schema: 'openai',
    api_key_validation: 'none',
    endpoints: [
      {
        name: 'Chat',
        path: '/chat/completions',
        is_default: true,
        capabilities: ['chat_completions'],
      },
    ],
    models: [{ name: 'Mock Large', value: 'mock-large', enabled: true }],
  },
] as any;

const rawPipe = {
  id: 'tk-x',
  pipe_type: {
    type: 'llm',
    provider: { provider_type: 'mock_llm', model: 'mock-large', base_url: 'http://localhost:9000' },
  },
  status: 'enabled',
  listen_address: 'https://host',
  route: '/llm/email-judge-jury',
} as unknown as PipeConfig;

describe('usePipeBuilder blob-less reseed', () => {
  it('projects the loaded config onto the LLM node for a surface with no canvas blob', () => {
    const { formData } = mapPipeToFormData(rawPipe, llmProviders);
    const emptyCanvas = buildPipeForCanvas({ ...EMPTY_PIPE_FORM }, '', '');
    const loadedCanvas = buildPipeForCanvas(formData, '/llm', 'email-judge-jury', true);

    const { result, rerender } = renderHook(
      ({ p, ready }: { p: any; ready: boolean }) => usePipeBuilder(p, handlers, undefined, ready),
      { initialProps: { p: emptyCanvas, ready: false } }
    );

    const beforeLlm = result.current.builder.state.nodes.find(n => n.type === 'pipe-upstream');
    expect(beforeLlm?.config?.provider ?? '').toBe(''); // empty before load

    rerender({ p: loadedCanvas, ready: true });

    const nodes = result.current.builder.state.nodes;
    const llm = nodes.find(n => n.type === 'pipe-upstream');
    const source = nodes.find(n => n.type === 'pipe-source');
    expect(llm?.config?.provider).toBe('mock_llm');
    expect(llm?.config?.model).toBe('mock-large');
    expect(source?.config?.prefix).toBe('/llm');
    expect(source?.config?.custom_path).toBe('email-judge-jury');
  });

  it('waits for the canonical route parse instead of reseeding from a stale canvas source', () => {
    const staleCanvasPipe = {
      ...rawPipe,
      canvas: {
        nodes: [
          {
            id: 'pipe-source',
            type: 'pipe-source',
            config: {
              listen_address: 'https://stale-host',
              prefix: '/stale',
              custom_path: 'old/path',
            },
          },
        ],
      },
    } as unknown as PipeConfig;
    const { formData } = mapPipeToFormData(staleCanvasPipe, llmProviders);
    const emptyCanvas = buildPipeForCanvas({ ...EMPTY_PIPE_FORM }, '', '');
    const awaitingRouteParse = buildPipeForCanvas(formData, '', '');
    const parsedRoute = buildPipeForCanvas(formData, '/llm', 'email-judge-jury', true);

    const { result, rerender } = renderHook(
      ({ p, ready }: { p: any; ready: boolean }) => usePipeBuilder(p, handlers, undefined, ready),
      { initialProps: { p: emptyCanvas, ready: false } }
    );

    rerender({ p: awaitingRouteParse, ready: true });

    let source = result.current.builder.state.nodes.find(n => n.type === 'pipe-source');
    expect(result.current.hydrated).toBe(false);
    expect(source?.config?.prefix ?? '').toBe('');
    expect(source?.config?.custom_path ?? '').toBe('');

    rerender({ p: parsedRoute, ready: true });

    source = result.current.builder.state.nodes.find(n => n.type === 'pipe-source');
    expect(result.current.hydrated).toBe(true);
    expect(source?.config?.listen_address).toBe('https://host');
    expect(source?.config?.prefix).toBe('/llm');
    expect(source?.config?.custom_path).toBe('email-judge-jury');
  });

  it('hydrates instead of spinning forever when a saved route matches no known prefix', () => {
    // A route left over from a since-removed/renamed path prefix — or from
    // an unresolved pipe-template placeholder — will never match any entry
    // in the routing catalogue. `routePrefixResolved: true` models the parse
    // having been *attempted* and coming up empty, as opposed to `false`
    // ("not parsed yet"). The reseed must proceed on the former, not just
    // the latter, or the page is stuck on its loading spinner forever.
    const orphanedRoutePipe = {
      ...rawPipe,
      route: '/removed-prefix/orphan-path',
    } as unknown as PipeConfig;
    const { formData } = mapPipeToFormData(orphanedRoutePipe, llmProviders);
    const emptyCanvas = buildPipeForCanvas({ ...EMPTY_PIPE_FORM }, '', '');
    const unresolvedRoute = buildPipeForCanvas(formData, '', '', true);

    const { result, rerender } = renderHook(
      ({ p, ready }: { p: any; ready: boolean }) => usePipeBuilder(p, handlers, undefined, ready),
      { initialProps: { p: emptyCanvas, ready: false } }
    );

    rerender({ p: unresolvedRoute, ready: true });

    expect(result.current.hydrated).toBe(true);
    const source = result.current.builder.state.nodes.find(n => n.type === 'pipe-source');
    expect(source?.config?.prefix ?? '').toBe('');
  });
});
