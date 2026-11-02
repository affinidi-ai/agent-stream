import type { CanvasNode } from '../../../components/builder/SurfaceCanvas';
import { nodesFromPipe } from '../../../components/builder/elements/pipe/nodesFromPipe';
import {
  readDecider,
  readExpertWitnesses,
  readJury,
  readPromptGuard,
  readUpstream,
  readUsageLimits,
} from '../pipeBuilderHelpers';

function node(partial: Partial<CanvasNode> & { id: string; type: any }): CanvasNode {
  return {
    label: partial.label ?? partial.id,
    configured: true,
    ...partial,
  } as CanvasNode;
}

describe('readJury', () => {
  it('returns absent when there is no jury node', () => {
    expect(readJury([node({ id: 'pipe-source', type: 'pipe-source' })])).toEqual({
      present: false,
      jury: null,
    });
  });

  it('reassembles jurors from juror nodes, ordered by stored index', () => {
    const nodes = [
      node({
        id: 'pipe-jury',
        type: 'pipe-jury',
        config: { jury: { enabled: true, mode: 'serial' } },
      }),
      node({
        id: 'pipe-juror-1',
        type: 'pipe-juror',
        config: { jurorIndex: 1, juror: { name: 'Second' } },
      }),
      node({
        id: 'pipe-juror-0',
        type: 'pipe-juror',
        config: { jurorIndex: 0, juror: { name: 'First' } },
      }),
    ];

    expect(readJury(nodes)).toEqual({
      present: true,
      jury: {
        enabled: true,
        mode: 'serial',
        jurors: [{ name: 'First' }, { name: 'Second' }],
      },
    });
  });

  it('yields an empty jurors array when the jury has no juror nodes', () => {
    const nodes = [
      node({
        id: 'pipe-jury',
        type: 'pipe-jury',
        config: { jury: { enabled: true, mode: 'parallel' } },
      }),
    ];
    expect(readJury(nodes).jury).toEqual({ enabled: true, mode: 'parallel', jurors: [] });
  });

  it('round-trips nodesFromPipe -> readJury without losing jurors or jury settings', () => {
    const jury = {
      enabled: true,
      mode: 'majority',
      max_retries: 2,
      jurors: [
        { name: 'A', llm: { provider_type: 'openai', model: 'gpt-4o' } },
        { name: 'B', llm: { provider_type: 'anthropic', model: 'claude' } },
      ],
    };
    const nodes = nodesFromPipe({ jury });
    expect(readJury(nodes).jury).toEqual(jury);
  });
});

describe('readDecider', () => {
  it('returns absent when there is no decider node', () => {
    expect(readDecider([node({ id: 'pipe-source', type: 'pipe-source' })])).toEqual({
      present: false,
      decider: null,
    });
  });

  it('reassembles candidates from candidate nodes, ordered by stored index', () => {
    const nodes = [
      node({
        id: 'pipe-decider',
        type: 'pipe-decider',
        config: { decider: { enabled: true, system_prompt: 'route it' } },
      }),
      node({
        id: 'pipe-candidate-1',
        type: 'pipe-candidate',
        config: { candidateIndex: 1, candidate: { id: 'smart', name: 'Smart' } },
      }),
      node({
        id: 'pipe-candidate-0',
        type: 'pipe-candidate',
        config: { candidateIndex: 0, candidate: { id: 'fast', name: 'Fast' } },
      }),
    ];

    expect(readDecider(nodes)).toEqual({
      present: true,
      decider: {
        enabled: true,
        system_prompt: 'route it',
        candidates: [
          { id: 'fast', name: 'Fast' },
          { id: 'smart', name: 'Smart' },
        ],
      },
    });
  });

  it('yields an empty candidates array when the decider has no candidate nodes', () => {
    const nodes = [
      node({
        id: 'pipe-decider',
        type: 'pipe-decider',
        config: { decider: { enabled: true } },
      }),
    ];
    expect(readDecider(nodes).decider).toEqual({ enabled: true, candidates: [] });
  });

  it('round-trips nodesFromPipe -> readDecider without losing candidates or decider settings', () => {
    const decider = {
      enabled: true,
      system_prompt: 'pick one',
      default_candidate_id: 'fast',
      llm: { provider_type: 'openai', model: 'gpt-4o-mini', endpoint_url: '/v1/chat' },
      candidates: [
        {
          id: 'fast',
          name: 'Fast',
          description: 'cheap',
          llm: { provider_type: 'openai', model: 'gpt-4o-mini', endpoint_url: '/v1/chat' },
        },
        {
          id: 'smart',
          name: 'Smart',
          description: 'capable',
          llm: { provider_type: 'anthropic', model: 'claude', endpoint_url: '/v1/messages' },
        },
      ],
    };
    const nodes = nodesFromPipe({ decider });
    expect(readDecider(nodes).decider).toEqual(decider);
  });
});

describe('readExpertWitnesses', () => {
  it('returns absent when there is no witness node', () => {
    expect(readExpertWitnesses([node({ id: 'pipe-source', type: 'pipe-source' })])).toEqual({
      present: false,
      witnesses: [],
    });
  });

  it('stamps each seam node and concatenates request before response', () => {
    const nodes = [
      node({
        id: 'pipe-witness-response',
        type: 'pipe-witness-response',
        config: {
          direction: 'response',
          witnesses: [
            {
              id: 'w-resp',
              name: 'Resp',
              enabled: true,
              provider: 'azure_content_safety',
              endpoint_url: 'https://acs.example/analyze',
              api_key_secret: 'acs-key',
              timeout_secs: 8,
              fail_open: false,
              check_request: false,
              check_response: true,
            },
          ],
        },
      }),
      node({
        id: 'pipe-witness-request',
        type: 'pipe-witness-request',
        config: {
          direction: 'request',
          witnesses: [
            {
              id: 'w-req',
              name: 'Req',
              enabled: true,
              provider: 'azure_prompt_shields',
              endpoint_url: 'https://aps.example/shieldPrompt',
              api_key_secret: null,
              timeout_secs: 10,
              fail_open: false,
              check_request: true,
              check_response: false,
            },
          ],
        },
      }),
    ];
    const { present, witnesses } = readExpertWitnesses(nodes);
    expect(present).toBe(true);
    expect(witnesses.map(w => [w.id, w.check_request, w.check_response])).toEqual([
      ['w-req', true, false],
      ['w-resp', false, true],
    ]);
  });

  it('round-trips nodesFromPipe -> readExpertWitnesses across both seams', () => {
    const expert_witnesses = [
      {
        id: 'witness-request-1',
        name: 'Prompt Shields',
        enabled: true,
        provider: 'azure_prompt_shields',
        endpoint_url: 'https://aps.example/shieldPrompt',
        api_key_secret: null,
        timeout_secs: 10,
        fail_open: false,
        check_request: true,
        check_response: false,
        headers: {},
        model: null,
      },
      {
        id: 'witness-response-1',
        name: 'Content Safety',
        enabled: true,
        provider: 'azure_content_safety',
        endpoint_url: 'https://acs.example/analyze',
        api_key_secret: 'acs-key',
        timeout_secs: 8,
        fail_open: true,
        check_request: false,
        check_response: true,
        headers: {},
        model: null,
      },
    ];
    const nodes = nodesFromPipe({ expert_witnesses });
    expect(readExpertWitnesses(nodes).witnesses).toEqual(expert_witnesses);
  });
});

describe('readUsageLimits', () => {
  it('returns an empty list when no node has a usage limit enabled', () => {
    expect(readUsageLimits([node({ id: 'pipe-source', type: 'pipe-source' })])).toEqual({
      limits: [],
    });
  });

  it('reads a stage limit from its LLM node, keeping the caps', () => {
    const nodes = [
      node({
        id: 'pipe-upstream',
        type: 'pipe-upstream',
        config: {
          usage_limit_enabled: true,
          usage_limit_monthly_budget_usd: 25,
          usage_limit_monthly_token_cap: 100000,
        },
      }),
    ];
    expect(readUsageLimits(nodes)).toEqual({
      limits: [
        {
          id: 'usage-limit-llm',
          enabled: true,
          scope: 'stage',
          stage: 'llm',
          monthly_budget_usd: 25,
          monthly_token_cap: 100000,
        },
      ],
    });
  });

  it('reads a per-juror jury limit from each juror node, tagged with its index', () => {
    const nodes = [
      node({
        id: 'pipe-juror-0',
        type: 'pipe-juror',
        config: {
          jurorIndex: 0,
          usage_limit_enabled: true,
          usage_limit_monthly_budget_usd: 50,
        },
      }),
    ];
    expect(readUsageLimits(nodes).limits[0]).toEqual({
      id: 'usage-limit-juror-0',
      enabled: true,
      scope: 'stage',
      stage: 'jury',
      juror_index: 0,
      monthly_budget_usd: 50,
      monthly_token_cap: null,
    });
  });

  it('skips a node whose usage-limit switch is off', () => {
    const nodes = [
      node({
        id: 'pipe-judge',
        type: 'pipe-judge',
        config: { usage_limit_enabled: false, usage_limit_monthly_budget_usd: 10 },
      }),
    ];
    expect(readUsageLimits(nodes).limits).toEqual([]);
  });

  it('reads each stage and per-juror node into one entry per scope', () => {
    const nodes = [
      node({
        id: 'pipe-upstream',
        type: 'pipe-upstream',
        config: { usage_limit_enabled: true, usage_limit_monthly_token_cap: 10 },
      }),
      node({
        id: 'pipe-judge',
        type: 'pipe-judge',
        config: { usage_limit_enabled: true, usage_limit_monthly_budget_usd: 7 },
      }),
      node({
        id: 'pipe-juror-0',
        type: 'pipe-juror',
        config: { jurorIndex: 0, usage_limit_enabled: true, usage_limit_monthly_token_cap: 99 },
      }),
    ];
    const { limits } = readUsageLimits(nodes);
    expect(limits.map(l => [l.id, l.scope, l.stage, l.juror_index ?? null])).toEqual([
      ['usage-limit-llm', 'stage', 'llm', null],
      ['usage-limit-judge', 'stage', 'judge', null],
      ['usage-limit-juror-0', 'stage', 'jury', 0],
    ]);
  });
});

describe('readUpstream cost tracking', () => {
  it('round-trips the cost-tracking flag from pipe to upstream node and back', () => {
    const nodes = nodesFromPipe({
      provider: 'openai',
      model: 'gpt-4o',
      cost_tracking: { enabled: true },
    });
    const upstream = readUpstream(nodes);
    expect(upstream.cost_tracking_enabled).toBe(true);
  });

  it('defaults the tracking flag off when the pipe omits cost_tracking', () => {
    const nodes = nodesFromPipe({ provider: 'openai', model: 'gpt-4o' });
    const upstream = readUpstream(nodes);
    expect(upstream.cost_tracking_enabled).toBe(false);
  });
});

describe('readPromptGuard llm_pii round-trip', () => {
  it('carries request-side AI detectors from the pipe onto the canvas and back', () => {
    const detector = { enabled: true, provider_type: 'openai', model: 'gpt-4o-mini' };
    const nodes = nodesFromPipe({
      prompt_guard: { enabled: true, request: [], response: [], llm_pii: [detector] },
    } as Parameters<typeof nodesFromPipe>[0]);
    const change = readPromptGuard(nodes);
    expect(change.present).toBe(true);
    expect(change.enabled).toBe(true);
    expect(change.llm_pii).toEqual([detector]);
  });

  it('drops a response guard whose direction node is toggled off', () => {
    const rule = { regex: { action: 'reject', rules: [{ builtin: 'email' }] } };
    const nodes = [
      node({
        id: 'pipe-prompt-guard-request',
        type: 'pipe-prompt-guard',
        config: { direction: 'request', enabled: true, request: [rule], response: [], llm_pii: [] },
      }),
      node({
        id: 'pipe-prompt-guard-response',
        type: 'pipe-prompt-guard',
        // Toggled off in the UI — its rules must NOT be compiled.
        config: { direction: 'response', enabled: false, request: [], response: [rule] },
      }),
    ];
    const change = readPromptGuard(nodes);
    expect(change.response).toEqual([]);
    expect(change.request).toEqual([rule]);
    expect(change.enabled).toBe(true);
  });
});
