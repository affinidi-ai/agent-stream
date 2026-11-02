import { nodesFromPipe } from '../../../components/builder/elements/pipe/nodesFromPipe';
import { deriveEdges } from '../../../components/builder/elements/edges/deriveEdges';
import { readOpaPolicy, readRateLimit, readUsageLimits } from '../pipeBuilderHelpers';
import {
  buildPipePayload,
  mapPipeToFormData,
  mergeImportedPipeConfig,
  reconcilePipeCanvasGuards,
  realtimeFromCanvas,
  routerEnabledFromCanvas,
  driftHarnessEnabledFromCanvas,
} from '../pipeMappingHelpers';
import { EMPTY_PIPE_FORM } from '../types';
import type { PipeConfig } from '../types';

/** Minimal pipe record — the reconciler only reads rate_limit / opa_policy. */
function pipe(partial: Partial<PipeConfig>): PipeConfig {
  return partial as unknown as PipeConfig;
}

/** A saved canvas blob whose spine carries no guard decoration nodes. */
function spineBlob() {
  return {
    version: 1,
    nodes: [
      { id: 'pipe-source', type: 'pipe-source', parentId: null },
      { id: 'pipe-upstream', type: 'pipe-upstream', parentId: 'pipe-judge' },
      { id: 'pipe-response', type: 'pipe-response', parentId: 'pipe-prompt-guard-response' },
    ],
  };
}

describe('reconcilePipeCanvasGuards', () => {
  it('synthesizes a rate-limit node from an enabled backend block missing from the blob', () => {
    const blob = spineBlob();
    const result: any = reconcilePipeCanvasGuards(
      blob,
      pipe({ rate_limit: { enabled: true, requests_per_minute: 1, tokens_per_minute: 100000 } })
    );

    const rl = result.nodes.find((n: any) => n.type === 'pipe-rate-limit');
    expect(rl).toBeDefined();
    expect(rl.parentId).toBe('pipe-source');
    expect(rl.config).toEqual({
      enabled: true,
      requests_per_minute: 1,
      tokens_per_minute: 100000,
    });
    // Existing spine nodes are preserved untouched.
    expect(result.nodes.filter((n: any) => n.type === 'pipe-source')).toHaveLength(1);
    expect(result.nodes).toHaveLength(blob.nodes.length + 1);
  });

  it('synthesizes an opa-policy node from an enabled backend block missing from the blob', () => {
    const result: any = reconcilePipeCanvasGuards(
      spineBlob(),
      pipe({ opa_policy: { enabled: true, policy_definition_id: 'pol-123' } })
    );

    const opa = result.nodes.find((n: any) => n.type === 'pipe-opa-policy');
    expect(opa).toBeDefined();
    expect(opa.parentId).toBe('pipe-source');
    expect(opa.config).toEqual({
      enabled: true,
      log_decisions: false,
      policy_definition_id: 'pol-123',
    });
  });

  it('synthesizes both guards when both backend blocks are enabled', () => {
    const result: any = reconcilePipeCanvasGuards(
      spineBlob(),
      pipe({
        rate_limit: { enabled: true, requests_per_minute: 5, tokens_per_minute: 200 },
        opa_policy: { enabled: true, policy_definition_id: 'pol-x' },
      })
    );
    const types = result.nodes.map((n: any) => n.type);
    expect(types).toContain('pipe-rate-limit');
    expect(types).toContain('pipe-opa-policy');
  });

  it('falls back to default caps when the enabled block omits values', () => {
    const result: any = reconcilePipeCanvasGuards(
      spineBlob(),
      pipe({ rate_limit: { enabled: true } })
    );
    const rl = result.nodes.find((n: any) => n.type === 'pipe-rate-limit');
    expect(rl.config).toEqual({
      enabled: true,
      requests_per_minute: 60,
      tokens_per_minute: 100000,
    });
  });

  it('creates a blob when none exists but a guard is enabled', () => {
    const result: any = reconcilePipeCanvasGuards(
      undefined,
      pipe({ rate_limit: { enabled: true, requests_per_minute: 9, tokens_per_minute: 100000 } })
    );
    expect(Array.isArray(result.nodes)).toBe(true);
    expect(result.nodes.find((n: any) => n.type === 'pipe-rate-limit')).toBeDefined();
  });

  it('returns the canvas untouched when the block is absent', () => {
    const blob = spineBlob();
    expect(reconcilePipeCanvasGuards(blob, pipe({}))).toBe(blob);
  });

  it('returns the canvas untouched when the block is explicitly disabled', () => {
    const blob = spineBlob();
    expect(
      reconcilePipeCanvasGuards(
        blob,
        pipe({ rate_limit: { enabled: false, requests_per_minute: 5 } })
      )
    ).toBe(blob);
  });

  it('does not duplicate a guard node the blob already carries', () => {
    const blob = {
      version: 1,
      nodes: [
        ...spineBlob().nodes,
        {
          id: 'pipe-rate-limit',
          type: 'pipe-rate-limit',
          config: { enabled: true, requests_per_minute: 42, tokens_per_minute: 100000 },
        },
      ],
    };
    const result = reconcilePipeCanvasGuards(
      blob,
      pipe({ rate_limit: { enabled: true, requests_per_minute: 1, tokens_per_minute: 100000 } })
    );
    expect(result).toBe(blob);
    expect((result as any).nodes.filter((n: any) => n.type === 'pipe-rate-limit')).toHaveLength(1);
  });

  it('leaves a missing canvas undefined when no guard is enabled', () => {
    expect(reconcilePipeCanvasGuards(undefined, pipe({}))).toBeUndefined();
  });

  it('round-trips: a reconciled rate-limit is read back as present by the canvas seam', () => {
    const reconciled = reconcilePipeCanvasGuards(
      spineBlob(),
      pipe({ rate_limit: { enabled: true, requests_per_minute: 1, tokens_per_minute: 100000 } })
    );
    const nodes = nodesFromPipe({ canvas: reconciled });
    expect(readRateLimit(nodes)).toEqual({
      present: true,
      enabled: true,
      requests_per_minute: 1,
      tokens_per_minute: 100000,
    });
  });

  it('round-trips: a reconciled opa-policy is read back as present by the canvas seam', () => {
    const reconciled = reconcilePipeCanvasGuards(
      spineBlob(),
      pipe({ opa_policy: { enabled: true, policy_definition_id: 'pol-123' } })
    );
    const nodes = nodesFromPipe({ canvas: reconciled });
    expect(readOpaPolicy(nodes)).toEqual({
      present: true,
      enabled: true,
      log_decisions: false,
      policy_definition_id: 'pol-123',
    });
  });

  it('synthesizes a pipe-caller-auth node from a backend source_auth block missing from the blob', () => {
    const result: any = reconcilePipeCanvasGuards(
      spineBlob(),
      pipe({
        source_auth: {
          type: 'jwt_bearer',
          jwt_verification_strategy_id: 'strat-1',
        } as any,
      })
    );
    const ca = result.nodes.find((n: any) => n.type === 'pipe-caller-auth');
    expect(ca).toBeDefined();
    expect(ca.parentId).toBe('pipe-source');
    expect(ca.config).toMatchObject({
      method_type: 'jwt_bearer',
      jwt_strategy_id: 'strat-1',
    });
  });

  it('binds a reconciled Caller Context onto the AP→LLM inbound edge', () => {
    const reconciled = reconcilePipeCanvasGuards(
      spineBlob(),
      pipe({
        source_auth: { type: 'jwt_bearer', jwt_verification_strategy_id: 'strat-1' } as any,
      })
    );
    const nodes = nodesFromPipe({ canvas: reconciled });
    const ca = nodes.find(n => n.type === 'pipe-caller-auth');
    expect(ca?.parentId).toBe('pipe-source');
    const inbound = deriveEdges(nodes).find(e => e.archetype === 'pipe-inbound');
    expect(inbound?.slots.get('request:pipe-caller-auth')).toEqual([ca!.id]);
  });

  it('does not synthesize pipe-caller-auth when the blob already carries one', () => {
    const blob = {
      version: 1,
      nodes: [
        ...spineBlob().nodes,
        {
          id: 'pipe-caller-auth',
          type: 'pipe-caller-auth',
          config: { method_type: 'api_key' },
        },
      ],
    };
    const result = reconcilePipeCanvasGuards(
      blob,
      pipe({ source_auth: { type: 'jwt_bearer', jwt_verification_strategy_id: 's' } as any })
    );
    expect(result).toBe(blob);
    expect((result as any).nodes.filter((n: any) => n.type === 'pipe-caller-auth')).toHaveLength(1);
  });

  it('returns the canvas untouched when source_auth is absent', () => {
    const blob = spineBlob();
    expect(reconcilePipeCanvasGuards(blob, pipe({}))).toBe(blob);
  });
});

describe('cost tracking round-trip', () => {
  it('buildPipePayload writes the cost-tracking enabled flag', () => {
    const payload = buildPipePayload({
      formData: {
        ...EMPTY_PIPE_FORM,
        cost_tracking_enabled: true,
      },
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
    });
    expect(payload.cost_tracking).toMatchObject({ enabled: true });
  });

  it('mapPipeToFormData reads the enabled flag from cost_tracking', () => {
    const { formData } = mapPipeToFormData(
      pipe({
        id: 'p',
        name: 'n',
        status: 'enabled',
        pipe_type: {} as PipeConfig['pipe_type'],
        cost_tracking: { enabled: true },
      }),
      []
    );
    expect(formData.cost_tracking_enabled).toBe(true);
  });
});

describe('upstream_pricing round-trip', () => {
  it('carries a declared zero price from load to save', () => {
    const { formData } = mapPipeToFormData(
      pipe({
        id: 'p',
        name: 'n',
        status: 'enabled',
        pipe_type: {} as PipeConfig['pipe_type'],
        upstream_pricing: { input_per_million: 0, output_per_million: 0 },
      } as any),
      []
    );
    expect(formData.upstream_pricing).toEqual({ input_per_million: 0, output_per_million: 0 });

    const payload = buildPipePayload({
      formData,
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
    });
    expect((payload as any).upstream_pricing).toEqual({
      input_per_million: 0,
      output_per_million: 0,
    });
  });

  it('omits upstream_pricing when none was declared', () => {
    const payload = buildPipePayload({
      formData: { ...EMPTY_PIPE_FORM },
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
    });
    expect((payload as any).upstream_pricing).toBeUndefined();
  });
});

describe('accepted ingress formats round-trip', () => {
  const ALL = ['openai_chat', 'anthropic_messages', 'openai_responses'];

  it('buildPipePayload writes a restricted accepted_ingress_schemas list', () => {
    const payload = buildPipePayload({
      formData: { ...EMPTY_PIPE_FORM, accepted_ingress_schemas: ['openai_chat'] },
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
    });
    expect((payload as any).accepted_ingress_schemas).toEqual(['openai_chat']);
  });

  it('buildPipePayload defaults an empty list back to all three dialects', () => {
    const payload = buildPipePayload({
      formData: { ...EMPTY_PIPE_FORM, accepted_ingress_schemas: [] },
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
    });
    expect((payload as any).accepted_ingress_schemas).toEqual(ALL);
  });

  it('mapPipeToFormData preserves a restricted list (guards against reset-on-load)', () => {
    const { formData } = mapPipeToFormData(
      pipe({
        id: 'p',
        name: 'n',
        status: 'enabled',
        pipe_type: {} as PipeConfig['pipe_type'],
        accepted_ingress_schemas: ['anthropic_messages'],
      } as any),
      []
    );
    expect(formData.accepted_ingress_schemas).toEqual(['anthropic_messages']);
  });

  it('mapPipeToFormData defaults to all three when the field is absent', () => {
    const { formData } = mapPipeToFormData(
      pipe({ id: 'p', name: 'n', status: 'enabled', pipe_type: {} as PipeConfig['pipe_type'] }),
      []
    );
    expect(formData.accepted_ingress_schemas).toEqual(ALL);
  });
});

describe('max_reasoning_tokens governor round-trip', () => {
  it('buildPipePayload writes a positive cap', () => {
    const payload = buildPipePayload({
      formData: { ...EMPTY_PIPE_FORM, max_reasoning_tokens: 4096 },
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
    });
    expect((payload as any).max_reasoning_tokens).toBe(4096);
  });

  it('buildPipePayload omits the cap when null or zero', () => {
    const nullPayload = buildPipePayload({
      formData: { ...EMPTY_PIPE_FORM, max_reasoning_tokens: null },
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
    });
    expect((nullPayload as any).max_reasoning_tokens).toBeUndefined();

    const zeroPayload = buildPipePayload({
      formData: { ...EMPTY_PIPE_FORM, max_reasoning_tokens: 0 },
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
    });
    expect((zeroPayload as any).max_reasoning_tokens).toBeUndefined();
  });

  it('mapPipeToFormData reads a numeric cap and defaults to null', () => {
    const withCap = mapPipeToFormData(
      pipe({
        id: 'p',
        name: 'n',
        status: 'enabled',
        pipe_type: {} as PipeConfig['pipe_type'],
        max_reasoning_tokens: 2048,
      } as any),
      []
    );
    expect(withCap.formData.max_reasoning_tokens).toBe(2048);

    const withoutCap = mapPipeToFormData(
      pipe({ id: 'p', name: 'n', status: 'enabled', pipe_type: {} as PipeConfig['pipe_type'] }),
      []
    );
    expect(withoutCap.formData.max_reasoning_tokens).toBeNull();
  });
});

describe('server_tools round-trip', () => {
  function canvasWithTools() {
    return {
      version: 1,
      nodes: [
        { id: 'pipe-source', type: 'pipe-source', parentId: null },
        { id: 'pipe-upstream', type: 'pipe-upstream', parentId: null },
        { id: 'pipe-response', type: 'pipe-response', parentId: null },
        {
          id: 'pipe-web-search',
          type: 'pipe-web-search',
          config: {
            enabled: true,
            engine: 'tavily',
            engine_secret_id: 'sec-123',
            max_results: 7,
            max_iterations: 4,
            domain_policy: 'block_all',
            domain_exceptions: ['example.com'],
          },
        },
        {
          id: 'pipe-web-fetch',
          type: 'pipe-web-fetch',
          config: {
            enabled: true,
            max_content_bytes: 40000,
            domain_policy: 'allow_all',
            domain_exceptions: [],
          },
        },
      ],
    };
  }

  it('buildPipePayload assembles server_tools from the canvas (engine_secret_id → engine_secret)', () => {
    const payload = buildPipePayload({
      formData: { ...EMPTY_PIPE_FORM, canvas: canvasWithTools() } as any,
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
    });
    const st = (payload as any).server_tools;
    expect(st).toBeDefined();
    expect(st.enabled).toBe(true);
    expect(st.max_iterations).toBe(4);
    expect(st.web_search).toEqual({
      enabled: true,
      engine: 'tavily',
      engine_secret: 'sec-123',
      max_results: 7,
      google_cse_id: undefined,
      domain_policy: 'block_all',
      domain_exceptions: ['example.com'],
    });
    expect(st.web_fetch).toEqual({
      enabled: true,
      max_content_bytes: 40000,
      domain_policy: 'allow_all',
      domain_exceptions: [],
    });
  });

  it('buildPipePayload omits server_tools when the canvas has no tool nodes', () => {
    const payload = buildPipePayload({
      formData: { ...EMPTY_PIPE_FORM } as any,
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
    });
    expect((payload as any).server_tools).toBeUndefined();
  });

  it('reconcilePipeCanvasGuards synthesizes tool nodes from a backend server_tools block', () => {
    const blob = {
      version: 1,
      nodes: [
        { id: 'pipe-source', type: 'pipe-source', parentId: null },
        { id: 'pipe-upstream', type: 'pipe-upstream', parentId: null },
        { id: 'pipe-response', type: 'pipe-response', parentId: null },
      ],
    };
    const result: any = reconcilePipeCanvasGuards(
      blob,
      pipe({
        server_tools: {
          enabled: true,
          max_iterations: 5,
          web_search: {
            enabled: true,
            engine: 'brave',
            engine_secret: 'sec-xyz',
            max_results: 3,
          },
          web_fetch: { enabled: true, max_content_bytes: 20000 },
        },
      } as any)
    );
    const search = result.nodes.find((n: any) => n.type === 'pipe-web-search');
    const fetch = result.nodes.find((n: any) => n.type === 'pipe-web-fetch');
    expect(search.config).toEqual({
      enabled: true,
      engine: 'brave',
      engine_secret_id: 'sec-xyz',
      max_results: 3,
      max_iterations: 5,
      google_cse_id: '',
      domain_policy: 'allow_all',
      domain_exceptions: [],
    });
    expect(fetch.config.max_content_bytes).toBe(20000);
    // Tools attach to the LLM node (top-biased tool row), not the surface.
    expect(search.parentId).toBe('pipe-upstream');
    expect(fetch.parentId).toBe('pipe-upstream');
    expect(search.position.y).toBeLessThan(0);
    expect(fetch.position.y).toBeLessThan(0);
  });

  it('mapPipeToFormData carries server_tools onto the form', () => {
    const mapped = mapPipeToFormData(
      pipe({
        id: 'p',
        name: 'n',
        status: 'enabled',
        pipe_type: {} as PipeConfig['pipe_type'],
        server_tools: { enabled: true, web_fetch: { enabled: true } },
      } as any),
      []
    );
    expect(mapped.formData.server_tools).toEqual({ enabled: true, web_fetch: { enabled: true } });
  });
});

describe('context_management round-trip', () => {
  it('buildPipePayload writes an enabled block with a window', () => {
    const payload = buildPipePayload({
      formData: {
        ...EMPTY_PIPE_FORM,
        context_management: {
          enabled: true,
          context_window_tokens: 128000,
          keep_recent_messages: 6,
          reserve_output_tokens: 2048,
        },
      } as any,
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
    });
    expect((payload as any).context_management).toEqual({
      enabled: true,
      context_window_tokens: 128000,
      keep_recent_messages: 6,
      reserve_output_tokens: 2048,
    });
  });

  it('buildPipePayload omits the block when off and no window', () => {
    const payload = buildPipePayload({
      formData: {
        ...EMPTY_PIPE_FORM,
        context_management: {
          enabled: false,
          context_window_tokens: null,
          keep_recent_messages: 4,
          reserve_output_tokens: 1024,
        },
      } as any,
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
    });
    expect((payload as any).context_management).toBeUndefined();
  });

  it('mapPipeToFormData reads the block and defaults to null', () => {
    const withCm = mapPipeToFormData(
      pipe({
        id: 'p',
        name: 'n',
        status: 'enabled',
        pipe_type: {} as PipeConfig['pipe_type'],
        context_management: { enabled: true, context_window_tokens: 200000 },
      } as any),
      []
    );
    expect(withCm.formData.context_management).toEqual({
      enabled: true,
      context_window_tokens: 200000,
      keep_recent_messages: 4,
      reserve_output_tokens: 1024,
    });

    const withoutCm = mapPipeToFormData(
      pipe({ id: 'p', name: 'n', status: 'enabled', pipe_type: {} as PipeConfig['pipe_type'] }),
      []
    );
    expect(withoutCm.formData.context_management).toBeNull();
  });
});

describe('document_ingestion round-trip', () => {
  it('buildPipePayload writes an enabled block', () => {
    const payload = buildPipePayload({
      formData: {
        ...EMPTY_PIPE_FORM,
        document_ingestion: {
          enabled: true,
          allowed_types: ['text', 'docx'],
          max_file_bytes: 2 * 1024 * 1024,
          max_extracted_chars: 50000,
          mode: 'extract',
        },
      } as any,
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
    });
    expect((payload as any).document_ingestion).toEqual({
      enabled: true,
      allowed_types: ['text', 'docx'],
      max_file_bytes: 2 * 1024 * 1024,
      max_extracted_chars: 50000,
      mode: 'extract',
    });
  });

  it('buildPipePayload omits the block when disabled', () => {
    const payload = buildPipePayload({
      formData: {
        ...EMPTY_PIPE_FORM,
        document_ingestion: {
          enabled: false,
          allowed_types: ['text'],
          max_file_bytes: 5 * 1024 * 1024,
          max_extracted_chars: 100000,
          mode: 'auto',
        },
      } as any,
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
    });
    expect((payload as any).document_ingestion).toBeUndefined();
  });

  it('mapPipeToFormData reads the block and defaults to null', () => {
    const withDi = mapPipeToFormData(
      pipe({
        id: 'p',
        name: 'n',
        status: 'enabled',
        pipe_type: {} as PipeConfig['pipe_type'],
        document_ingestion: { enabled: true, mode: 'passthrough' },
      } as any),
      []
    );
    expect(withDi.formData.document_ingestion).toEqual({
      enabled: true,
      allowed_types: ['text', 'markdown', 'csv', 'json', 'docx'],
      max_file_bytes: 5 * 1024 * 1024,
      max_extracted_chars: 100000,
      mode: 'passthrough',
    });

    const withoutDi = mapPipeToFormData(
      pipe({ id: 'p', name: 'n', status: 'enabled', pipe_type: {} as PipeConfig['pipe_type'] }),
      []
    );
    expect(withoutDi.formData.document_ingestion).toBeNull();
  });
});

describe('realtime audio streams round-trip', () => {
  function realtimeCanvas(fillerGuardBandMs: number) {
    return {
      version: 1,
      nodes: [
        {
          id: 'pipe-audio-stream',
          type: 'pipe-audio-stream',
          config: {
            enabled: true,
            audio_streams: {
              filler_guard_band_ms: fillerGuardBandMs,
              filler_tiers: [{ after_ms: 1000, clips: ['tier1'] }],
            },
          },
        },
      ],
    };
  }

  it('serializes a non-default filler guard band', () => {
    expect(realtimeFromCanvas(realtimeCanvas(3000))?.audio_streams).toEqual({
      filler_guard_band_ms: 3000,
      filler_tiers: [{ after_ms: 1000, clips: ['tier1'] }],
    });
  });

  it('omits the default filler guard band', () => {
    expect(realtimeFromCanvas(realtimeCanvas(2000))?.audio_streams).toEqual({
      filler_tiers: [{ after_ms: 1000, clips: ['tier1'] }],
    });
  });
});

describe('router element round-trip', () => {
  it('routerEnabledFromCanvas reads the node enable flag', () => {
    const canvas = (enabled: boolean) => ({
      version: 1,
      nodes: [
        { id: 'pipe-source', type: 'pipe-source', parentId: null },
        { id: 'pipe-router', type: 'pipe-router', config: { enabled } },
        { id: 'pipe-upstream', type: 'pipe-upstream', parentId: null },
      ],
    });
    expect(routerEnabledFromCanvas(canvas(true))).toBe(true);
    expect(routerEnabledFromCanvas(canvas(false))).toBe(false);
  });

  it('routerEnabledFromCanvas returns null when no router node is present', () => {
    expect(routerEnabledFromCanvas(spineBlob())).toBeNull();
  });

  it('reconcilePipeCanvasGuards synthesizes a pipe-router node from routing_rules', () => {
    const result: any = reconcilePipeCanvasGuards(
      spineBlob(),
      pipe({
        routing_enabled: true,
        routing_rules: [
          { match: { kind: 'modality', has: 'image' }, target: { variant: 'vision' } },
        ],
      } as any)
    );
    const router = result.nodes.find((n: any) => n.type === 'pipe-router');
    expect(router).toBeTruthy();
    expect(router.config).toEqual({ enabled: true });
  });

  it('does not synthesize a router when routing is unset', () => {
    const result: any = reconcilePipeCanvasGuards(spineBlob(), pipe({}));
    expect(result.nodes.find((n: any) => n.type === 'pipe-router')).toBeUndefined();
  });
});

describe('drift harness element round-trip', () => {
  const canvasWith = (enabled: boolean) => ({
    version: 1,
    nodes: [
      { id: 'pipe-source', type: 'pipe-source', parentId: null },
      { id: 'pipe-drift-harness', type: 'pipe-drift-harness', config: { enabled } },
      { id: 'pipe-upstream', type: 'pipe-upstream', parentId: null },
    ],
  });

  it('driftHarnessEnabledFromCanvas reads the node enable flag', () => {
    expect(driftHarnessEnabledFromCanvas(canvasWith(true))).toBe(true);
    expect(driftHarnessEnabledFromCanvas(canvasWith(false))).toBe(false);
  });

  it('driftHarnessEnabledFromCanvas returns null when no harness node is present', () => {
    expect(driftHarnessEnabledFromCanvas(spineBlob())).toBeNull();
  });

  it('reconcilePipeCanvasGuards synthesizes a pipe-drift-harness node from drift', () => {
    const result: any = reconcilePipeCanvasGuards(
      spineBlob(),
      pipe({ drift: { enabled: true, sample_rate: 1 } } as any)
    );
    const harness = result.nodes.find((n: any) => n.type === 'pipe-drift-harness');
    expect(harness).toBeTruthy();
    expect(harness.config).toEqual({ enabled: true });
    expect(harness.parentId).toBe('pipe-upstream');
  });

  it('does not synthesize a harness when drift is unset', () => {
    const result: any = reconcilePipeCanvasGuards(spineBlob(), pipe({}));
    expect(result.nodes.find((n: any) => n.type === 'pipe-drift-harness')).toBeUndefined();
  });

  it('form drift block is authoritative for enable even with a harness node present', () => {
    const payload = buildPipePayload({
      formData: {
        ...EMPTY_PIPE_FORM,
        drift: { enabled: true, sample_rate: 0.5 },
        canvas: canvasWith(false),
      } as any,
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
    });
    expect(payload.drift).toMatchObject({ enabled: true, sample_rate: 0.5 });
  });

  it('a freshly dropped harness node persists drift even with no form block', () => {
    const payload = buildPipePayload({
      formData: { ...EMPTY_PIPE_FORM, drift: null, canvas: canvasWith(true) } as any,
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
    });
    expect(payload.drift).toEqual({ enabled: true });
  });

  it('a disabled fresh drop with no form block persists nothing', () => {
    const payload = buildPipePayload({
      formData: { ...EMPTY_PIPE_FORM, drift: null, canvas: canvasWith(false) } as any,
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
    });
    expect(payload.drift).toBeUndefined();
  });
});

describe('governance recording round-trip', () => {
  it('buildPipePayload writes the governance_recording block from formData', () => {
    const payload = buildPipePayload({
      formData: {
        ...EMPTY_PIPE_FORM,
        governance_recording: {
          enabled: true,
          capture_bodies: true,
          include_streaming: false,
          retention_days: 90,
          export: { otel: true, integrations: ['wh-1', 'kafka-2'] },
        },
      },
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
    });
    expect(payload.governance_recording).toMatchObject({
      enabled: true,
      include_streaming: false,
      retention_days: 90,
      export: { otel: true, integrations: ['wh-1', 'kafka-2'] },
    });
  });

  it('buildPipePayload omits governance_recording when absent', () => {
    const payload = buildPipePayload({
      formData: EMPTY_PIPE_FORM,
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
    });
    expect(payload.governance_recording).toBeUndefined();
  });

  it('mapPipeToFormData reads governance_recording from the wire config', () => {
    const { formData } = mapPipeToFormData(
      pipe({
        id: 'p',
        name: 'n',
        status: 'enabled',
        pipe_type: {} as PipeConfig['pipe_type'],
        governance_recording: { enabled: true, capture_bodies: false },
      } as Partial<PipeConfig>),
      []
    );
    expect(formData.governance_recording).toMatchObject({
      enabled: true,
      capture_bodies: false,
    });
  });

  it('survives a map -> build round-trip without dropping the block', () => {
    const { formData } = mapPipeToFormData(
      pipe({
        id: 'p',
        name: 'n',
        status: 'enabled',
        pipe_type: {} as PipeConfig['pipe_type'],
        governance_recording: {
          enabled: true,
          include_streaming: true,
          export: { otel: true },
        },
      } as Partial<PipeConfig>),
      []
    );
    const payload = buildPipePayload({
      formData,
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
    });
    expect(payload.governance_recording).toMatchObject({
      enabled: true,
      include_streaming: true,
      export: { otel: true },
    });
  });

  it('is preserved on a variant-active save (baseSnapshot carries no governance field)', () => {
    const payload = buildPipePayload({
      formData: {
        ...EMPTY_PIPE_FORM,
        governance_recording: { enabled: true },
      },
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
      variantsSlice: {
        variants: [],
        defaultVariantId: null,
        baseSnapshot: { provider: 'openai', model: 'gpt-5' },
      },
    });
    expect(payload.governance_recording).toMatchObject({ enabled: true });
  });
});

describe('drift monitoring round-trip', () => {
  it('buildPipePayload writes the drift block from formData', () => {
    const payload = buildPipePayload({
      formData: { ...EMPTY_PIPE_FORM, drift: { enabled: true, sample_rate: 0.25 } },
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
    });
    expect(payload.drift).toMatchObject({ enabled: true, sample_rate: 0.25 });
  });

  it('buildPipePayload omits drift when absent', () => {
    const payload = buildPipePayload({
      formData: EMPTY_PIPE_FORM,
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
    });
    expect(payload.drift).toBeUndefined();
  });

  it('mapPipeToFormData reads drift from the wire config', () => {
    const { formData } = mapPipeToFormData(
      pipe({
        id: 'p',
        name: 'n',
        status: 'enabled',
        pipe_type: {} as PipeConfig['pipe_type'],
        drift: { enabled: true, sample_rate: 0.5 },
      } as Partial<PipeConfig>),
      []
    );
    expect(formData.drift).toMatchObject({ enabled: true, sample_rate: 0.5 });
  });

  it('is preserved on a variant-active save (baseSnapshot carries no drift field)', () => {
    const payload = buildPipePayload({
      formData: { ...EMPTY_PIPE_FORM, drift: { enabled: true, sample_rate: 1 } },
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
      variantsSlice: {
        variants: [],
        defaultVariantId: null,
        baseSnapshot: { provider: 'openai', model: 'gpt-5' },
      },
    });
    expect(payload.drift).toMatchObject({ enabled: true, sample_rate: 1 });
  });
});

describe('vp evidence round-trip', () => {
  it('buildPipePayload writes the vp_evidence block from formData', () => {
    const payload = buildPipePayload({
      formData: {
        ...EMPTY_PIPE_FORM,
        vp_evidence: {
          enabled: true,
          require_present: true,
          source: 'header',
          header_name: 'X-Agent-Stream-Presentation',
        },
      },
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
    });
    expect(payload.vp_evidence).toMatchObject({
      enabled: true,
      require_present: true,
      source: 'header',
      header_name: 'X-Agent-Stream-Presentation',
    });
  });

  it('buildPipePayload omits vp_evidence when absent', () => {
    const payload = buildPipePayload({
      formData: EMPTY_PIPE_FORM,
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
    });
    expect(payload.vp_evidence).toBeUndefined();
  });

  it('mapPipeToFormData reads vp_evidence from the wire config', () => {
    const { formData } = mapPipeToFormData(
      pipe({
        id: 'p',
        name: 'n',
        status: 'enabled',
        pipe_type: {} as PipeConfig['pipe_type'],
        vp_evidence: { enabled: true, source: 'body' },
      } as Partial<PipeConfig>),
      []
    );
    expect(formData.vp_evidence).toMatchObject({ enabled: true, source: 'body' });
  });

  it('survives a map -> build round-trip without dropping the block', () => {
    const { formData } = mapPipeToFormData(
      pipe({
        id: 'p',
        name: 'n',
        status: 'enabled',
        pipe_type: {} as PipeConfig['pipe_type'],
        vp_evidence: { enabled: true, require_present: true, source: 'header' },
      } as Partial<PipeConfig>),
      []
    );
    const payload = buildPipePayload({
      formData,
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
    });
    expect(payload.vp_evidence).toMatchObject({
      enabled: true,
      require_present: true,
      source: 'header',
    });
  });
});

describe('source_auth round-trip', () => {
  it('buildPipePayload reads source_auth back from a pipe-caller-auth node on the canvas', () => {
    const payload = buildPipePayload({
      formData: {
        ...EMPTY_PIPE_FORM,
        canvas: {
          version: 1,
          nodes: [
            {
              id: 'pipe-caller-auth',
              type: 'pipe-caller-auth',
              config: {
                method_type: 'jwt_bearer',
                jwt_strategy_id: 'strat-1',
              },
            },
          ],
        },
      } as any,
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
    });
    expect(payload.source_auth).toMatchObject({
      type: 'jwt_bearer',
      jwt_verification_strategy_id: 'strat-1',
    });
  });

  it('buildPipePayload omits source_auth when the canvas has no pipe-caller-auth node', () => {
    const payload = buildPipePayload({
      formData: EMPTY_PIPE_FORM,
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
    });
    expect(payload.source_auth).toBeUndefined();
  });

  it('mapPipeToFormData populates formData.source_auth from the wire block', () => {
    const { formData } = mapPipeToFormData(
      pipe({
        id: 'p',
        name: 'n',
        status: 'enabled',
        pipe_type: {} as PipeConfig['pipe_type'],
        source_auth: {
          type: 'jwt_bearer',
          jwt_verification_strategy_id: 'strat-1',
        } as any,
      }),
      []
    );
    expect(formData.source_auth).toMatchObject({
      type: 'jwt_bearer',
      jwt_verification_strategy_id: 'strat-1',
    });
  });
});

describe('custom provider model mapping', () => {
  it('reads the model from the custom provider `name` field and keeps it out of params', () => {
    const { formData } = mapPipeToFormData(
      pipe({
        id: 'p',
        name: 'n',
        status: 'enabled',
        pipe_type: {
          type: 'llm',
          provider: {
            provider_type: 'custom',
            name: 'mock-small',
            endpoint: 'http://localhost:9000/v1/chat/completions',
          },
        } as unknown as PipeConfig['pipe_type'],
      }),
      []
    );
    expect(formData.provider).toBe('custom');
    expect(formData.model).toBe('mock-small');
    // `name` is the custom provider's model id, not a tunable parameter.
    expect(formData.model_parameters).not.toHaveProperty('name');
    expect(formData.model_parameters).not.toHaveProperty('endpoint');
  });

  it('still prefers an explicit `model` field when both are present', () => {
    const { formData } = mapPipeToFormData(
      pipe({
        id: 'p',
        name: 'n',
        status: 'enabled',
        pipe_type: {
          type: 'llm',
          provider: {
            provider_type: 'custom',
            model: 'mock-large',
            name: 'mock-small',
            endpoint: 'http://localhost:9000/v1/chat/completions',
          },
        } as unknown as PipeConfig['pipe_type'],
      }),
      []
    );
    expect(formData.model).toBe('mock-large');
  });
});

describe('stored provider URL round-trip', () => {
  const catalog = [
    { enum_value: 'openai', default_base_url: 'https://api.openai.com', endpoints: [] },
    { enum_value: 'groq', default_base_url: 'https://api.groq.com/openai', endpoints: [] },
    { enum_value: 'mistral', default_base_url: 'https://api.mistral.ai', endpoints: [] },
  ] as unknown as Parameters<typeof mapPipeToFormData>[1];

  function savedProvider(provider: Record<string, unknown>) {
    const { formData } = mapPipeToFormData(
      pipe({
        id: 'p',
        name: 'n',
        status: 'enabled',
        pipe_type: { type: 'llm', provider } as unknown as PipeConfig['pipe_type'],
      }),
      catalog
    );
    return formData;
  }

  function save(formData: typeof EMPTY_PIPE_FORM) {
    return buildPipePayload({
      formData,
      integrations: [],
      llmProviders: catalog,
      isNew: false,
      pipeId: 'p',
    }).pipe_type.provider;
  }

  it('saves a non-default base_url unchanged', () => {
    const formData = savedProvider({
      provider_type: 'openai',
      model: 'gpt-4o',
      api_key_secret: 'k',
      base_url: 'https://gateway.example/v1',
    });
    const provider = save({ ...formData, name: 'Renamed' });
    expect(provider.base_url).toBe('https://gateway.example/v1');
    expect(provider.api_key_secret).toBe('k');
  });

  it('saves a Mistral endpoint unchanged', () => {
    const formData = savedProvider({
      provider_type: 'mistral',
      model: 'mistral-large',
      api_key_secret: 'k',
      endpoint: 'https://mistral.internal.example',
    });
    const provider = save(formData);
    expect(provider.endpoint).toBe('https://mistral.internal.example');
    expect(provider).not.toHaveProperty('base_url');
  });

  it('uses the catalog default once the provider changes', () => {
    const formData = savedProvider({
      provider_type: 'openai',
      model: 'gpt-4o',
      base_url: 'https://gateway.example/v1',
    });
    const provider = save({ ...formData, provider: 'groq', model: 'llama' });
    expect(provider.base_url).toBe('https://api.groq.com/openai');
  });

  it('uses the catalog default for a surface saved without a base_url', () => {
    const formData = savedProvider({ provider_type: 'openai', model: 'gpt-4o' });
    expect(formData.provider_url).toBeNull();
    expect(save(formData).base_url).toBe('https://api.openai.com');
  });

  it("keeps an active variant's URL off a base saved without one", () => {
    const base = savedProvider({ provider_type: 'openai', model: 'gpt-4o', api_key_secret: 'k' });
    const variant = savedProvider({
      provider_type: 'openai',
      model: 'gpt-4o-mini',
      api_key_secret: 'k',
      base_url: 'https://gateway.example/v1',
    });
    const provider = buildPipePayload({
      formData: { ...variant, name: 'Renamed' },
      integrations: [],
      llmProviders: catalog,
      isNew: false,
      pipeId: 'p',
      variantsSlice: { variants: [], defaultVariantId: null, baseSnapshot: base },
    }).pipe_type.provider;
    expect(provider.base_url).toBe('https://api.openai.com');
    expect(provider.model).toBe('gpt-4o');
  });

  it('keeps the base URL on a save while a variant with another URL is active', () => {
    const base = savedProvider({
      provider_type: 'openai',
      model: 'gpt-4o',
      api_key_secret: 'k',
      base_url: 'https://base.example/v1',
    });
    const variant = savedProvider({
      provider_type: 'openai',
      model: 'gpt-4o',
      api_key_secret: 'k',
      base_url: 'https://gateway.example/v1',
    });
    const provider = buildPipePayload({
      formData: variant,
      integrations: [],
      llmProviders: catalog,
      isNew: false,
      pipeId: 'p',
      variantsSlice: { variants: [], defaultVariantId: null, baseSnapshot: base },
    }).pipe_type.provider;
    expect(provider.base_url).toBe('https://base.example/v1');
  });
});

describe('usage limits round-trip', () => {
  it('seeds a stage limit onto its LLM node and reads it back via the canvas seam', () => {
    const nodes = nodesFromPipe({
      usage_limits: [
        {
          id: 'whatever',
          enabled: true,
          scope: 'stage',
          stage: 'judge',
          monthly_budget_usd: 25,
          monthly_token_cap: 100000,
        },
      ],
    });
    const judge = nodes.find(n => n.id === 'pipe-judge');
    expect(judge?.config).toMatchObject({
      usage_limit_enabled: true,
      usage_limit_monthly_budget_usd: 25,
      usage_limit_monthly_token_cap: 100000,
    });
    expect(readUsageLimits(nodes).limits).toEqual([
      {
        id: 'usage-limit-judge',
        enabled: true,
        scope: 'stage',
        stage: 'judge',
        monthly_budget_usd: 25,
        monthly_token_cap: 100000,
      },
    ]);
  });

  it('seeds a per-juror jury limit onto its juror node and reads it back via the canvas seam', () => {
    const nodes = nodesFromPipe({
      jury: {
        enabled: true,
        mode: 'parallel',
        jurors: [
          { name: 'A', llm: { provider_type: 'openai', model: 'gpt-4o' } },
          { name: 'B', llm: { provider_type: 'anthropic', model: 'claude' } },
        ],
      },
      usage_limits: [
        {
          id: 'whatever',
          enabled: true,
          scope: 'stage',
          stage: 'jury',
          juror_index: 1,
          monthly_token_cap: 9000,
        },
      ],
    });
    const juror1 = nodes.find(n => n.id === 'pipe-juror-1');
    expect(juror1?.config).toMatchObject({
      usage_limit_enabled: true,
      usage_limit_monthly_token_cap: 9000,
    });
    const juror0 = nodes.find(n => n.id === 'pipe-juror-0');
    expect(juror0?.config?.usage_limit_enabled).toBe(false);
    expect(readUsageLimits(nodes).limits).toEqual([
      {
        id: 'usage-limit-juror-1',
        enabled: true,
        scope: 'stage',
        stage: 'jury',
        juror_index: 1,
        monthly_budget_usd: null,
        monthly_token_cap: 9000,
      },
    ]);
  });

  it('routes the cumulative limit to surface_usage_limit, not a canvas node', () => {
    const { formData } = mapPipeToFormData(
      pipe({
        id: 'p',
        name: 'n',
        status: 'enabled',
        pipe_type: {} as PipeConfig['pipe_type'],
        usage_limits: [{ id: 'c', enabled: true, scope: 'cumulative', monthly_budget_usd: 100 }],
      }),
      []
    );
    expect(formData.usage_limits).toEqual([]);
    expect(formData.surface_usage_limit).toEqual({
      id: 'c',
      enabled: true,
      scope: 'cumulative',
      stage: null,
      monthly_budget_usd: 100,
      monthly_token_cap: null,
    });
    const nodes = nodesFromPipe({
      usage_limits: [{ id: 'c', enabled: true, scope: 'cumulative', monthly_budget_usd: 100 }],
    });
    const source = nodes.find(n => n.id === 'pipe-source');
    expect(source?.config?.usage_limit_enabled).toBeUndefined();
  });

  it('leaves a stage node unenforced when no backend limit targets it', () => {
    const nodes = nodesFromPipe({ provider: 'openai', model: 'gpt-4o' });
    const llm = nodes.find(n => n.id === 'pipe-upstream');
    expect(llm?.config?.usage_limit_enabled).toBe(false);
    expect(readUsageLimits(nodes).limits).toEqual([]);
  });

  it('buildPipePayload shapes a stage limit and folds in the surface-wide cumulative one', () => {
    const payload = buildPipePayload({
      formData: {
        ...EMPTY_PIPE_FORM,
        usage_limits: [
          {
            id: 'a',
            enabled: true,
            scope: 'stage',
            stage: 'jury',
            juror_index: 0,
            monthly_budget_usd: 25,
            monthly_token_cap: null,
          },
        ],
        surface_usage_limit: {
          id: 'b',
          enabled: true,
          scope: 'cumulative',
          stage: null,
          monthly_budget_usd: null,
          monthly_token_cap: 5000,
        },
      },
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
    });
    expect(payload.usage_limits).toEqual([
      {
        id: 'a',
        enabled: true,
        scope: 'stage',
        stage: 'jury',
        juror_index: 0,
        monthly_budget_usd: 25,
      },
      { id: 'b', enabled: true, scope: 'cumulative', monthly_token_cap: 5000 },
    ]);
  });

  it('buildPipePayload drops a limit that sets neither a budget nor a token cap', () => {
    const payload = buildPipePayload({
      formData: {
        ...EMPTY_PIPE_FORM,
        usage_limits: [
          {
            id: 'empty',
            enabled: true,
            scope: 'stage',
            stage: 'llm',
            monthly_budget_usd: null,
            monthly_token_cap: null,
          },
        ],
      },
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
    });
    expect(payload.usage_limits).toBeUndefined();
  });

  it('mapPipeToFormData reads usage_limits from the backend record', () => {
    const { formData } = mapPipeToFormData(
      pipe({
        id: 'p',
        name: 'n',
        status: 'enabled',
        pipe_type: {} as PipeConfig['pipe_type'],
        usage_limits: [
          {
            id: 'x',
            enabled: true,
            scope: 'stage',
            stage: 'judge',
            monthly_budget_usd: 12,
            monthly_token_cap: null,
          },
        ],
      }),
      []
    );
    expect(formData.usage_limits).toEqual([
      {
        id: 'x',
        enabled: true,
        scope: 'stage',
        stage: 'judge',
        monthly_budget_usd: 12,
        monthly_token_cap: null,
      },
    ]);
  });

  it('mapPipeToFormData reads allowed_teams from team_attribution', () => {
    const { formData } = mapPipeToFormData(
      pipe({
        id: 'p',
        name: 'n',
        status: 'enabled',
        pipe_type: {} as PipeConfig['pipe_type'],
        team_attribution: {
          enabled: true,
          caller_email_source: { type: 'header', name: 'x-user-email' },
          enforce: false,
          allow_individual_overage: false,
          allowed_teams: ['engineering', 'anonymous'],
        },
      } as unknown as Partial<PipeConfig>),
      []
    );
    expect(formData.team_attribution?.allowed_teams).toEqual(['engineering', 'anonymous']);
  });

  it('mapPipeToFormData folds a legacy caller_email_source into caller_identity_sources', () => {
    const { formData } = mapPipeToFormData(
      pipe({
        id: 'p',
        name: 'n',
        status: 'enabled',
        pipe_type: {} as PipeConfig['pipe_type'],
        team_attribution: {
          enabled: true,
          caller_email_source: { type: 'jwt_claim', claim: 'email' },
          allowed_teams: [],
        },
      } as unknown as Partial<PipeConfig>),
      []
    );
    expect(formData.team_attribution?.caller_identity_sources).toEqual([
      { type: 'jwt_claim', claim: 'email' },
    ]);
    expect(formData.team_attribution?.auto_provision).toBe(false);
  });

  it('mapPipeToFormData reads caller_identity_sources array and auto_provision', () => {
    const { formData } = mapPipeToFormData(
      pipe({
        id: 'p',
        name: 'n',
        status: 'enabled',
        pipe_type: {} as PipeConfig['pipe_type'],
        team_attribution: {
          enabled: true,
          caller_identity_sources: [{ type: 'jwt_claim', claim: 'oid' }, { type: 'api_key' }],
          auto_provision: true,
          allowed_teams: [],
        },
      } as unknown as Partial<PipeConfig>),
      []
    );
    expect(formData.team_attribution?.caller_identity_sources).toEqual([
      { type: 'jwt_claim', claim: 'oid' },
      { type: 'api_key' },
    ]);
    expect(formData.team_attribution?.auto_provision).toBe(true);
  });

  it('mapPipeToFormData defaults allowed_teams to [] and drops non-string entries', () => {
    const { formData } = mapPipeToFormData(
      pipe({
        id: 'p',
        name: 'n',
        status: 'enabled',
        pipe_type: {} as PipeConfig['pipe_type'],
        team_attribution: {
          enabled: true,
          caller_email_source: { type: 'header', name: 'x-user-email' },
          allowed_teams: ['engineering', 7, null],
        },
      } as unknown as Partial<PipeConfig>),
      []
    );
    expect(formData.team_attribution?.allowed_teams).toEqual(['engineering']);
  });

  it('buildPipePayload round-trips allowed_teams back to the backend blob', () => {
    const payload = buildPipePayload({
      formData: {
        ...EMPTY_PIPE_FORM,
        team_attribution: {
          enabled: true,
          caller_identity_sources: [{ type: 'header', name: 'x-user-email' }],
          auto_provision: false,
          enforce: true,
          allow_individual_overage: false,
          allowed_teams: ['engineering'],
        },
      },
      integrations: [],
      llmProviders: [],
      isNew: false,
      pipeId: 'p',
    });
    expect((payload.team_attribution as any).allowed_teams).toEqual(['engineering']);
  });
});

describe('mergeImportedPipeConfig', () => {
  const current = {
    ...EMPTY_PIPE_FORM,
    id: 'keep-me',
    name: 'Original',
    description: 'original desc',
    route: '/keep/route',
    listen_address: '0.0.0.0:9000',
    model: 'gpt-4o',
  };

  it('imports name + description but preserves id, route and listener', () => {
    const merged = mergeImportedPipeConfig(
      current,
      {
        name: 'Imported',
        description: 'imported desc',
        model: 'claude-3',
        id: 'other-id',
        route: '/other/route',
        listen_address: '1.2.3.4:1',
      },
      []
    );
    expect(typeof merged).not.toBe('string');
    const form = merged as typeof current;
    expect(form.name).toBe('Imported');
    expect(form.description).toBe('imported desc');
    expect(form.model).toBe('claude-3');
    expect(form.id).toBe('keep-me');
    expect(form.route).toBe('/keep/route');
    expect(form.listen_address).toBe('0.0.0.0:9000');
  });

  it('accepts a wire pipe config (pipe_type present) and maps it to form shape', () => {
    const merged = mergeImportedPipeConfig(
      current,
      {
        id: 'wire-id',
        name: 'Wire Surface',
        description: 'from backend',
        status: 'enabled',
        pipe_type: { type: 'llm', provider: { endpoint: 'https://api.example/v1' } },
      },
      []
    );
    expect(typeof merged).not.toBe('string');
    const form = merged as typeof current;
    expect(form.name).toBe('Wire Surface');
    expect(form.description).toBe('from backend');
    expect(form.id).toBe('keep-me');
    expect(form.listen_address).toBe('0.0.0.0:9000');
  });

  it('rejects a non-object payload with an error string', () => {
    expect(mergeImportedPipeConfig(current, [1, 2, 3], [])).toBe(
      'Configuration must be a JSON object'
    );
    expect(mergeImportedPipeConfig(current, 'nope', [])).toBe(
      'Configuration must be a JSON object'
    );
    expect(mergeImportedPipeConfig(current, null, [])).toBe('Configuration must be a JSON object');
  });
});
