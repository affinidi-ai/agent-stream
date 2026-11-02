import type { CanvasNode } from '../../SurfaceCanvas';
import { EMPTY_PIPE_FORM } from '../../../../pages/EditPipePage/types';
import { applyPipeTemplateItems } from '../pipeItemPlacement';
import {
  serializePipeTemplate,
  canSerializePipeNode,
  describePipeNode,
} from '../serializePipeTemplate';

function node(partial: Partial<CanvasNode> & { id: string; type: any }): CanvasNode {
  return {
    label: partial.label ?? partial.id,
    configured: true,
    ...partial,
  } as CanvasNode;
}

describe('serializePipeTemplate', () => {
  it('captures source and upstream config with stable scopes', () => {
    const nodes = [
      node({
        id: 'pipe-source',
        type: 'pipe-source',
        config: { listen_address: 'public', prefix: '/v1', custom_path: 'chat' },
      }),
      node({
        id: 'pipe-upstream',
        type: 'pipe-upstream',
        config: { provider: 'openai', model: 'gpt-4o', endpoint: 'https://api.openai.com' },
      }),
    ];

    const items = serializePipeTemplate(nodes);

    expect(items).toEqual([
      { scope: 'source', kind: 'pipe-source', config: { listen_address: 'public' } },
      {
        scope: 'upstream',
        kind: 'pipe-upstream',
        config: { provider: 'openai', model: 'gpt-4o', endpoint: 'https://api.openai.com' },
      },
    ]);
  });

  it('drops the upstream secret binding by default but keeps it when asked', () => {
    const nodes = [
      node({
        id: 'pipe-upstream',
        type: 'pipe-upstream',
        config: { provider: 'openai', model: 'gpt-4o', api_key_secret_id: 'sk-123' },
      }),
    ];

    expect(serializePipeTemplate(nodes)[0].config.api_key_secret_id).toBeUndefined();
    expect(serializePipeTemplate(nodes, { scrubSecrets: false })[0].config.api_key_secret_id).toBe(
      'sk-123'
    );
  });

  it('restricts capture to the selected node ids', () => {
    const nodes = [
      node({ id: 'pipe-source', type: 'pipe-source', config: { listen_address: 'public' } }),
      node({
        id: 'pipe-rate-limit',
        type: 'pipe-rate-limit',
        config: { enabled: true, requests_per_minute: 30, tokens_per_minute: 5000 },
      }),
    ];

    const items = serializePipeTemplate(nodes, { nodeIds: ['pipe-rate-limit'] });

    expect(items).toHaveLength(1);
    expect(items[0].kind).toBe('pipe-rate-limit');
  });

  it('collapses request and response prompt-guard nodes into one item', () => {
    const nodes = [
      node({
        id: 'pipe-prompt-guard-request',
        type: 'pipe-prompt-guard',
        config: { direction: 'request', request: [{ id: 'a' }], response: [] },
      }),
      node({
        id: 'pipe-prompt-guard-response',
        type: 'pipe-prompt-guard',
        config: { direction: 'response', request: [], response: [{ id: 'b' }] },
      }),
    ];

    const items = serializePipeTemplate(nodes);

    expect(items).toEqual([
      {
        scope: 'middleware',
        kind: 'pipe-prompt-guard',
        config: { request: [{ id: 'a' }], response: [{ id: 'b' }], llm_pii: [] },
      },
    ]);
  });

  it('round-trips through applyPipeTemplateItems', () => {
    const nodes = [
      node({ id: 'pipe-source', type: 'pipe-source', config: { listen_address: 'public' } }),
      node({
        id: 'pipe-upstream',
        type: 'pipe-upstream',
        config: { provider: 'anthropic', model: 'claude', endpoint: 'https://api.anthropic.com' },
      }),
      node({
        id: 'pipe-rate-limit',
        type: 'pipe-rate-limit',
        config: { enabled: true, requests_per_minute: 45, tokens_per_minute: 9000 },
      }),
      node({
        id: 'pipe-cost-tracking',
        type: 'pipe-cost-tracking',
        config: { enabled: true, input_price_per_1k: 1.5, output_price_per_1k: 3 },
      }),
    ];

    const items = serializePipeTemplate(nodes);
    const applied = applyPipeTemplateItems({ ...EMPTY_PIPE_FORM }, items);

    expect(applied.listen_address).toBe('public');
    expect(applied.provider).toBe('anthropic');
    expect(applied.model).toBe('claude');
    expect(applied.endpoint_url).toBe('https://api.anthropic.com');
    expect(applied.rate_limit_enabled).toBe(true);
    expect(applied.requests_per_minute).toBe(45);
    expect(applied.tokens_per_minute).toBe(9000);
    expect(applied.cost_tracking_enabled).toBe(true);
    expect(applied.input_price_per_1k).toBe(1.5);
    expect(applied.output_price_per_1k).toBe(3);
  });

  it('ignores non-templatable nodes such as the response terminus', () => {
    const nodes = [
      node({ id: 'pipe-response', type: 'pipe-response', config: {} }),
      node({ id: 'pipe-source', type: 'pipe-source', config: { listen_address: 'public' } }),
    ];

    expect(canSerializePipeNode(nodes[0])).toBe(false);
    expect(canSerializePipeNode(nodes[1])).toBe(true);
    expect(serializePipeTemplate(nodes).map(i => i.kind)).toEqual(['pipe-source']);
  });

  it('describes a node by its label', () => {
    expect(
      describePipeNode(node({ id: 'pipe-source', type: 'pipe-source', label: 'Source' }))
    ).toBe('Source');
  });

  it('reassembles the jurors array from juror nodes into the jury item', () => {
    const nodes = [
      node({
        id: 'pipe-jury',
        type: 'pipe-jury',
        config: { jury: { enabled: true, mode: 'serial', max_retries: 2 } },
      }),
      node({
        id: 'pipe-juror-1',
        type: 'pipe-juror',
        config: { jurorIndex: 1, juror: { name: 'Second', llm: { provider_type: 'openai' } } },
      }),
      node({
        id: 'pipe-juror-0',
        type: 'pipe-juror',
        config: { jurorIndex: 0, juror: { name: 'First', llm: { provider_type: 'anthropic' } } },
      }),
    ];

    const items = serializePipeTemplate(nodes);
    const juryItem = items.find(i => i.kind === 'pipe-jury');

    expect(juryItem).toBeDefined();
    expect(juryItem!.config.jury).toEqual({
      enabled: true,
      mode: 'serial',
      max_retries: 2,
      jurors: [
        { name: 'First', llm: { provider_type: 'anthropic' } },
        { name: 'Second', llm: { provider_type: 'openai' } },
      ],
    });
  });

  it('captures the jury even when only the jury node is in the selection (jurors follow)', () => {
    const nodes = [
      node({
        id: 'pipe-jury',
        type: 'pipe-jury',
        config: { jury: { enabled: true, mode: 'parallel' } },
      }),
      node({
        id: 'pipe-juror-0',
        type: 'pipe-juror',
        config: { jurorIndex: 0, juror: { name: 'Only', llm: { provider_type: 'openai' } } },
      }),
    ];

    const items = serializePipeTemplate(nodes, { nodeIds: ['pipe-jury'] });
    const juryItem = items.find(i => i.kind === 'pipe-jury');

    expect(juryItem).toBeDefined();
    expect((juryItem!.config.jury as { jurors: unknown[] }).jurors).toEqual([
      { name: 'Only', llm: { provider_type: 'openai' } },
    ]);
  });

  it('reassembles the candidates array from candidate nodes into the decider item', () => {
    const nodes = [
      node({
        id: 'pipe-decider',
        type: 'pipe-decider',
        config: { decider: { enabled: true, system_prompt: 'route', default_candidate_id: 'a' } },
      }),
      node({
        id: 'pipe-candidate-1',
        type: 'pipe-candidate',
        config: {
          candidateIndex: 1,
          candidate: { id: 'b', name: 'Second', llm: { provider_type: 'openai' } },
        },
      }),
      node({
        id: 'pipe-candidate-0',
        type: 'pipe-candidate',
        config: {
          candidateIndex: 0,
          candidate: { id: 'a', name: 'First', llm: { provider_type: 'anthropic' } },
        },
      }),
    ];

    const items = serializePipeTemplate(nodes);
    const deciderItem = items.find(i => i.kind === 'pipe-decider');

    expect(deciderItem).toBeDefined();
    expect(deciderItem!.config.decider).toEqual({
      enabled: true,
      system_prompt: 'route',
      default_candidate_id: 'a',
      candidates: [
        { id: 'a', name: 'First', llm: { provider_type: 'anthropic' } },
        { id: 'b', name: 'Second', llm: { provider_type: 'openai' } },
      ],
    });
  });

  it('preserves the mirror strategy and merger config on the decider item', () => {
    const nodes = [
      node({
        id: 'pipe-decider',
        type: 'pipe-decider',
        config: {
          decider: {
            enabled: true,
            strategy: 'mirror',
            mirror: {
              mode: 'merge',
              merger: {
                provider_type: 'openai',
                model: 'gpt-4o',
                endpoint_url: '/chat/completions',
              },
              merge_system_prompt: 'combine them',
            },
          },
        },
      }),
      node({
        id: 'pipe-candidate-0',
        type: 'pipe-candidate',
        config: {
          candidateIndex: 0,
          candidate: { id: 'a', name: 'First', llm: { provider_type: 'anthropic' } },
        },
      }),
    ];

    const items = serializePipeTemplate(nodes);
    const deciderItem = items.find(i => i.kind === 'pipe-decider');

    expect(deciderItem).toBeDefined();
    const decider = deciderItem!.config.decider as Record<string, unknown>;
    expect(decider.strategy).toBe('mirror');
    expect(decider.mirror).toEqual({
      mode: 'merge',
      merger: { provider_type: 'openai', model: 'gpt-4o', endpoint_url: '/chat/completions' },
      merge_system_prompt: 'combine them',
    });
    expect(decider.candidates).toEqual([
      { id: 'a', name: 'First', llm: { provider_type: 'anthropic' } },
    ]);
  });

  it('captures the decider even when only the decider node is in the selection (candidates follow)', () => {
    const nodes = [
      node({
        id: 'pipe-decider',
        type: 'pipe-decider',
        config: { decider: { enabled: true } },
      }),
      node({
        id: 'pipe-candidate-0',
        type: 'pipe-candidate',
        config: {
          candidateIndex: 0,
          candidate: { id: 'only', name: 'Only', llm: { provider_type: 'openai' } },
        },
      }),
    ];

    const items = serializePipeTemplate(nodes, { nodeIds: ['pipe-decider'] });
    const deciderItem = items.find(i => i.kind === 'pipe-decider');

    expect(deciderItem).toBeDefined();
    expect((deciderItem!.config.decider as { candidates: unknown[] }).candidates).toEqual([
      { id: 'only', name: 'Only', llm: { provider_type: 'openai' } },
    ]);
  });

  it('round-trips the decider through applyPipeTemplateItems', () => {
    const decider = {
      enabled: true,
      system_prompt: 'pick one',
      default_candidate_id: 'fast',
      llm: { provider_type: 'openai', model: 'gpt-4o-mini' },
      candidates: [
        { id: 'fast', name: 'Fast', llm: { provider_type: 'openai', model: 'gpt-4o-mini' } },
        { id: 'smart', name: 'Smart', llm: { provider_type: 'anthropic', model: 'claude' } },
      ],
    };
    const nodes = [
      node({
        id: 'pipe-decider',
        type: 'pipe-decider',
        config: {
          decider: {
            enabled: true,
            system_prompt: 'pick one',
            default_candidate_id: 'fast',
            llm: decider.llm,
          },
        },
      }),
      node({
        id: 'pipe-candidate-0',
        type: 'pipe-candidate',
        config: { candidateIndex: 0, candidate: decider.candidates[0] },
      }),
      node({
        id: 'pipe-candidate-1',
        type: 'pipe-candidate',
        config: { candidateIndex: 1, candidate: decider.candidates[1] },
      }),
    ];

    const items = serializePipeTemplate(nodes);
    const applied = applyPipeTemplateItems({ ...EMPTY_PIPE_FORM }, items);

    expect(applied.decider).toEqual(decider);
  });
});
