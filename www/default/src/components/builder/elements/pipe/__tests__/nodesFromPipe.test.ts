import { nodesFromPipe } from '../nodesFromPipe';
import { buildCanvasBlob } from '../../index';

describe('nodesFromPipe canvas overlay', () => {
  it('seeds the default spine when no canvas blob is present', () => {
    const nodes = nodesFromPipe(null);
    expect(nodes.map(n => n.id)).toEqual([
      'pipe-source',
      'pipe-prompt-guard-request',
      'pipe-judge',
      'pipe-upstream',
      'pipe-jury',
      'pipe-prompt-guard-response',
      'pipe-response',
      'pipe-witness-request',
      'pipe-witness-response',
    ]);
    expect(nodes.find(n => n.id === 'pipe-upstream')?.position).toEqual({ x: 0, y: 0 });
    // The decider is off by default, so its node is absent until decider mode
    // is switched on from the LLM panel.
    expect(nodes.some(n => n.id === 'pipe-decider')).toBe(false);
  });

  it('overlays saved positions from the canvas blob onto matching spine nodes', () => {
    const nodes = nodesFromPipe({
      canvas: {
        version: 1,
        nodes: [{ id: 'pipe-upstream', type: 'pipe-upstream', position: { x: 33, y: -42 } }],
      },
    });
    expect(nodes.find(n => n.id === 'pipe-upstream')?.position).toEqual({ x: 33, y: -42 });
  });

  it('restores drag-on decoration nodes that are absent from the default spine', () => {
    const nodes = nodesFromPipe({
      canvas: {
        version: 1,
        nodes: [
          {
            id: 'pipe-rate-limit',
            type: 'pipe-rate-limit',
            label: 'Rate Limit',
            position: { x: 0, y: 140 },
            config: { requests_per_minute: 60 },
          },
        ],
      },
    });
    const deco = nodes.find(n => n.id === 'pipe-rate-limit');
    expect(deco).toBeDefined();
    expect(deco?.position).toEqual({ x: 0, y: 140 });
    expect(deco?.config).toEqual({ requests_per_minute: 60 });
  });

  it('keeps backend-truth config keys when merging blob config onto a spine node', () => {
    const nodes = nodesFromPipe({
      provider: 'openai',
      model: 'gpt-4o',
      api_key_secret_id: 'sk-1',
      pipe_type: { type: 'llm', provider: { endpoint: 'https://api.openai.com' } },
      canvas: {
        version: 1,
        nodes: [
          {
            id: 'pipe-upstream',
            type: 'pipe-upstream',
            config: { provider: 'stale', uiOnly: 'kept' },
          },
        ],
      },
    });
    const llm = nodes.find(n => n.id === 'pipe-upstream');
    expect(llm?.config?.provider).toBe('openai');
    expect(llm?.config?.uiOnly).toBe('kept');
  });

  it('derives one pipe-juror node per jury juror, parented to the jury', () => {
    const nodes = nodesFromPipe({
      jury: {
        enabled: true,
        mode: 'serial',
        max_retries: 1,
        jurors: [
          { name: 'First', llm: { provider_type: 'openai' } },
          { name: 'Second', llm: { provider_type: 'anthropic' } },
        ],
      },
    });
    const jurors = nodes.filter(n => n.type === 'pipe-juror');
    expect(jurors.map(n => n.id)).toEqual(['pipe-juror-0', 'pipe-juror-1']);
    expect(jurors.map(n => n.parentId)).toEqual(['pipe-jury', 'pipe-jury']);
    expect(jurors.map(n => n.label)).toEqual(['First', 'Second']);
    expect(jurors[0].config).toEqual({
      juror: { name: 'First', llm: { provider_type: 'openai' } },
      jurorIndex: 0,
      usage_limit_enabled: false,
      usage_limit_monthly_budget_usd: null,
      usage_limit_monthly_token_cap: null,
    });
    // Serial mode stacks jurors in a vertical column beneath the jury (default
    // x = 140): juror 0 one row down, juror 1 a further row down, same x.
    expect(jurors[0].position).toEqual({ x: 140, y: 130 });
    expect(jurors[1].position).toEqual({ x: 140, y: 230 });
  });

  it('seeds jurors in a horizontal row in parallel mode', () => {
    const nodes = nodesFromPipe({
      jury: {
        enabled: true,
        mode: 'parallel',
        jurors: [
          { name: 'First', llm: { provider_type: 'openai' } },
          { name: 'Second', llm: { provider_type: 'anthropic' } },
        ],
      },
    });
    const jurors = nodes.filter(n => n.type === 'pipe-juror');
    // Parallel fans the jurors across one row beneath the jury (default x =
    // 140): juror 0 directly under it, juror 1 to the right, both at the row y.
    expect(jurors[0].position).toEqual({ x: 140, y: 130 });
    expect(jurors[1].position).toEqual({ x: 230, y: 130 });
  });

  it('strips the jurors array from the jury node config (single source of truth)', () => {
    const nodes = nodesFromPipe({
      jury: {
        enabled: true,
        mode: 'parallel',
        max_retries: 2,
        jurors: [{ name: 'Only', llm: { provider_type: 'openai' } }],
      },
    });
    const juryNode = nodes.find(n => n.id === 'pipe-jury');
    expect(juryNode?.config?.jury).toEqual({ enabled: true, mode: 'parallel', max_retries: 2 });
    expect((juryNode?.config?.jury as { jurors?: unknown }).jurors).toBeUndefined();
  });

  it('labels an unnamed juror positionally', () => {
    const nodes = nodesFromPipe({
      jury: { enabled: true, mode: 'parallel', jurors: [{ llm: { provider_type: 'openai' } }] },
    });
    expect(nodes.find(n => n.type === 'pipe-juror')?.label).toBe('Juror 1');
  });

  it('never resurrects an orphaned pipe-juror node from a stale canvas blob', () => {
    const nodes = nodesFromPipe({
      jury: { enabled: true, mode: 'parallel', jurors: [] },
      canvas: {
        version: 1,
        nodes: [
          {
            id: 'pipe-juror-0',
            type: 'pipe-juror',
            label: 'Ghost',
            position: { x: 140, y: 140 },
            config: { juror: { name: 'Ghost' }, jurorIndex: 0 },
          },
        ],
      },
    });
    expect(nodes.some(n => n.type === 'pipe-juror')).toBe(false);
  });
});

describe('nodesFromPipe decider seeding', () => {
  it('derives one pipe-candidate node per decider candidate, parented to the decider', () => {
    const nodes = nodesFromPipe({
      decider: {
        enabled: true,
        candidates: [
          { id: 'fast', name: 'Fast', llm: { provider_type: 'openai' } },
          { id: 'smart', name: 'Smart', llm: { provider_type: 'anthropic' } },
        ],
      },
    });
    const candidates = nodes.filter(n => n.type === 'pipe-candidate');
    expect(candidates.map(n => n.id)).toEqual(['pipe-candidate-0', 'pipe-candidate-1']);
    expect(candidates.map(n => n.parentId)).toEqual(['pipe-decider', 'pipe-decider']);
    expect(candidates.map(n => n.label)).toEqual(['Fast', 'Smart']);
    expect(candidates[0].config).toEqual({
      candidate: { id: 'fast', name: 'Fast', llm: { provider_type: 'openai' } },
      candidateIndex: 0,
    });
    expect(candidates[0].position).toEqual({ x: 0, y: 270 });
    expect(candidates[1].position).toEqual({ x: 90, y: 270 });
  });

  it('strips the candidates array from the decider node config (single source of truth)', () => {
    const nodes = nodesFromPipe({
      decider: {
        enabled: true,
        system_prompt: 'route',
        default_candidate_id: 'fast',
        candidates: [{ id: 'fast', name: 'Fast', llm: { provider_type: 'openai' } }],
      },
    });
    const deciderNode = nodes.find(n => n.id === 'pipe-decider');
    expect(deciderNode?.config?.decider).toEqual({
      enabled: true,
      system_prompt: 'route',
      default_candidate_id: 'fast',
    });
    expect((deciderNode?.config?.decider as { candidates?: unknown }).candidates).toBeUndefined();
  });

  it('labels an unnamed candidate positionally', () => {
    const nodes = nodesFromPipe({
      decider: { enabled: true, candidates: [{ id: 'x', llm: { provider_type: 'openai' } }] },
    });
    expect(nodes.find(n => n.type === 'pipe-candidate')?.label).toBe('Candidate 1');
  });

  it('never resurrects an orphaned pipe-candidate node from a stale canvas blob', () => {
    const nodes = nodesFromPipe({
      decider: { enabled: true, candidates: [] },
      canvas: {
        version: 1,
        nodes: [
          {
            id: 'pipe-candidate-0',
            type: 'pipe-candidate',
            label: 'Ghost',
            position: { x: 0, y: 240 },
            config: { candidate: { id: 'ghost' }, candidateIndex: 0 },
          },
        ],
      },
    });
    expect(nodes.some(n => n.type === 'pipe-candidate')).toBe(false);
  });

  it('does not seed the decider or candidates when decider mode is off', () => {
    const nodes = nodesFromPipe({
      decider: {
        enabled: false,
        candidates: [{ id: 'fast', name: 'Fast', llm: { provider_type: 'openai' } }],
      },
    });
    expect(nodes.some(n => n.type === 'pipe-decider')).toBe(false);
    expect(nodes.some(n => n.type === 'pipe-candidate')).toBe(false);
  });

  it('never resurrects an orphaned pipe-decider node when decider mode is off', () => {
    const nodes = nodesFromPipe({
      decider: { enabled: false },
      canvas: {
        version: 1,
        nodes: [
          {
            id: 'pipe-decider',
            type: 'pipe-decider',
            label: 'Ghost decider',
            position: { x: 0, y: 140 },
            config: { decider: { enabled: false } },
          },
        ],
      },
    });
    expect(nodes.some(n => n.type === 'pipe-decider')).toBe(false);
  });
});

describe('nodesFromPipe pipe-response caller-arc flag', () => {
  it('round-trips visualize_response_to_caller=false through the canvas blob', () => {
    const seeded = nodesFromPipe(null);
    const edited = seeded.map(n =>
      n.id === 'pipe-response'
        ? { ...n, config: { ...n.config, visualize_response_to_caller: false } }
        : n
    );

    const blob = buildCanvasBlob(edited);
    expect(
      blob.nodes.find(n => n.id === 'pipe-response')?.config?.visualize_response_to_caller
    ).toBe(false);

    const restored = nodesFromPipe({ canvas: blob });
    expect(restored.find(n => n.id === 'pipe-response')?.config?.visualize_response_to_caller).toBe(
      false
    );
  });

  it('leaves the flag unset by default so the caller arc renders', () => {
    const blob = buildCanvasBlob(nodesFromPipe(null));
    expect(
      blob.nodes.find(n => n.id === 'pipe-response')?.config?.visualize_response_to_caller
    ).toBeUndefined();

    const restored = nodesFromPipe({ canvas: blob });
    expect(
      restored.find(n => n.id === 'pipe-response')?.config?.visualize_response_to_caller
    ).toBeUndefined();
  });
});

describe('nodesFromPipe prompt-guard direction defaults', () => {
  const guardNode = (nodes: ReturnType<typeof nodesFromPipe>, id: string) =>
    nodes.find(n => n.id === id);

  it('leaves the response guard off for a request-only config with no canvas blob', () => {
    // What an API client (e.g. Boris) sends: the single master flag on, rules on
    // the request leg only, and no canvas blob because it does not author one.
    const nodes = nodesFromPipe({
      prompt_guard: {
        enabled: true,
        request: [{ regex: { action: 'mask', rules: ['\\d{16}'] } }],
        llm_pii: [],
      },
    } as never);
    expect(guardNode(nodes, 'pipe-prompt-guard-request')?.config?.enabled).toBe(true);
    // Defaulting this on rendered an enabled-but-empty response guard, which
    // then failed its own `incompleteReason` and blocked every later save.
    expect(guardNode(nodes, 'pipe-prompt-guard-response')?.config?.enabled).toBe(false);
  });

  it('turns the response guard on when it actually has rules', () => {
    const nodes = nodesFromPipe({
      prompt_guard: {
        enabled: true,
        request: [],
        response: [{ regex: { action: 'reject', rules: ['secret'] } }],
      },
    } as never);
    expect(guardNode(nodes, 'pipe-prompt-guard-response')?.config?.enabled).toBe(true);
    expect(guardNode(nodes, 'pipe-prompt-guard-request')?.config?.enabled).toBe(false);
  });

  it('an explicit blob value still wins over the rule-derived default', () => {
    // A direction the user switched on in the canvas but has not filled in yet
    // must stay on, so their in-progress edit is not silently reverted.
    const nodes = nodesFromPipe({
      prompt_guard: { enabled: true, request: [], response: [] },
      canvas: { nodes: [{ id: 'pipe-prompt-guard-response', config: { enabled: true } }] },
    } as never);
    expect(guardNode(nodes, 'pipe-prompt-guard-response')?.config?.enabled).toBe(true);
  });

  it('the master flag off keeps both directions off whatever the rules say', () => {
    const nodes = nodesFromPipe({
      prompt_guard: {
        enabled: false,
        request: [{ regex: { action: 'mask', rules: ['x'] } }],
        response: [{ regex: { action: 'mask', rules: ['y'] } }],
      },
    } as never);
    expect(guardNode(nodes, 'pipe-prompt-guard-request')?.config?.enabled).toBe(false);
    expect(guardNode(nodes, 'pipe-prompt-guard-response')?.config?.enabled).toBe(false);
  });
});
