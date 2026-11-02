import { EMPTY_PIPE_FORM } from '../../../pages/EditPipePage/types';
import { LLMProvider, PipeConfig, PipeFormData } from '../../../pages/EditPipePage/types';
import { buildLlmPipeType } from '../../../pages/EditPipePage/pipeMappingHelpers';
import {
  PIPE_VARIANT_FIELDS,
  applySnapshotToFormData,
  snapshotFromFormData,
} from './pipeVariantSnapshot';
import { buildPipeVariantOverrides, parsePipeVariants } from './pipeVariantMapping';

const PROVIDER: LLMProvider = {
  name: 'OpenAI',
  enum_value: 'openai',
  default_base_url: 'https://api.openai.com',
  api_version_prefix: '/v1',
  api_schema: 'openai',
  endpoints: [
    {
      name: 'Chat',
      path: '/chat/completions',
      description: 'chat',
      is_default: true,
      capabilities: ['chat_completions'],
    },
  ],
  icon: 'icon',
  api_key_label: 'API key',
  models: [],
};

function baseForm(overrides: Partial<PipeFormData> & { canvas?: unknown } = {}): PipeFormData {
  const { canvas, ...rest } = overrides;
  const form = {
    ...EMPTY_PIPE_FORM,
    id: 'pipe-1',
    name: 'My Pipe',
    listen_address: '0.0.0.0:8080',
    route: '/llm/openai',
    provider: 'openai',
    model: 'gpt-4o',
    endpoint_url: '/chat/completions',
    api_key_secret_id: 'secret-base',
    rate_limit_enabled: true,
    requests_per_minute: 60,
    tokens_per_minute: 100000,
    cost_tracking_enabled: false,
    variants: [{ id: 'v-1', alias: 'alias1', name: 'Cheap', enabled: true }],
    default_variant_id: 'v-1',
    ...rest,
  } as PipeFormData;
  // `canvas` is carried on the form via a cast in production code, so the
  // fixtures attach it the same way (defaulting when not overridden).
  (form as { canvas?: unknown }).canvas = 'canvas' in overrides ? canvas : { nodes: ['base-node'] };
  return form;
}

describe('snapshotFromFormData', () => {
  it('captures exactly the behavioural slice plus the canvas', () => {
    const form = baseForm();
    const snap = snapshotFromFormData(form);

    for (const field of PIPE_VARIANT_FIELDS) {
      expect(snap[field]).toEqual(form[field]);
    }
    expect(snap.canvas).toEqual({ nodes: ['base-node'] });
    // Identity / routing / catalog fields are not part of the snapshot.
    expect((snap as Record<string, unknown>).id).toBeUndefined();
    expect((snap as Record<string, unknown>).listen_address).toBeUndefined();
    expect((snap as Record<string, unknown>).variants).toBeUndefined();
  });

  it('deep-clones so later form mutations do not leak into the snapshot', () => {
    const form = baseForm({ model_parameters: { temperature: 0.2 } });
    const snap = snapshotFromFormData(form);
    form.model_parameters.temperature = 0.9;
    const canvas = (form as { canvas?: { nodes: string[] } }).canvas!;
    canvas.nodes.push('mutated');

    expect(snap.model_parameters).toEqual({ temperature: 0.2 });
    expect(snap.canvas).toEqual({ nodes: ['base-node'] });
  });
});

describe('applySnapshotToFormData', () => {
  it('swaps the behavioural slice but preserves identity, routing, and catalog', () => {
    const form = baseForm();
    const variantSnap = snapshotFromFormData(
      baseForm({
        provider: 'openai',
        model: 'gpt-4o-mini',
        api_key_secret_id: 'secret-variant',
        requests_per_minute: 5,
        canvas: { nodes: ['variant-node'] },
      })
    );

    const next = applySnapshotToFormData(form, variantSnap);

    // Behavioural slice comes from the snapshot.
    expect(next.model).toBe('gpt-4o-mini');
    expect(next.api_key_secret_id).toBe('secret-variant');
    expect(next.requests_per_minute).toBe(5);
    expect((next as { canvas?: unknown }).canvas).toEqual({ nodes: ['variant-node'] });
    // Identity / routing / catalog stay on the form.
    expect(next.id).toBe('pipe-1');
    expect(next.name).toBe('My Pipe');
    expect(next.listen_address).toBe('0.0.0.0:8080');
    expect(next.route).toBe('/llm/openai');
    expect(next.variants).toEqual(form.variants);
    expect(next.default_variant_id).toBe('v-1');
    // Returns a new object; the input form is untouched.
    expect(next).not.toBe(form);
    expect(form.model).toBe('gpt-4o');
  });

  it('round-trips a snapshot back to its source slice', () => {
    const form = baseForm({
      model: 'gpt-4o-mini',
      api_key_secret_id: 'secret-variant',
      tokens_per_minute: 42,
      override_policy: { foo: 'bar' },
    });
    const snap = snapshotFromFormData(form);
    const restored = applySnapshotToFormData(EMPTY_PIPE_FORM as PipeFormData, snap);

    for (const field of PIPE_VARIANT_FIELDS) {
      expect(restored[field]).toEqual(form[field]);
    }
  });
});

describe('wire variant mapping round-trip', () => {
  it('build → parse resolves an equivalent behavioural snapshot', () => {
    const form = baseForm();
    const variantSnap = snapshotFromFormData(
      baseForm({
        model: 'gpt-4o-mini',
        api_key_secret_id: 'secret-variant',
        requests_per_minute: 10,
        tokens_per_minute: 5000,
        cost_tracking_enabled: true,
        input_price_per_1k: 1.5,
        output_price_per_1k: 3,
        override_policy: { tier: 'cheap' },
        canvas: { nodes: ['variant-node'] },
      })
    );

    const overrides = buildPipeVariantOverrides(variantSnap, [PROVIDER], buildLlmPipeType);

    const pipe = {
      ...form,
      pipe_type: { provider: {} },
      variants: [{ id: 'v-1', alias: 'alias1', name: 'Cheap', enabled: true, overrides }],
      default_variant_id: 'v-1',
    } as unknown as PipeConfig;

    const { variantForms, defaultVariantId } = parsePipeVariants(pipe, form, [PROVIDER]);

    expect(defaultVariantId).toBe('v-1');
    expect(variantForms).toHaveLength(1);
    const resolved = variantForms[0].snapshot;

    expect(resolved.provider).toBe('openai');
    expect(resolved.model).toBe('gpt-4o-mini');
    expect(resolved.api_key_secret_id).toBe('secret-variant');
    expect(resolved.endpoint_url).toBe('/chat/completions');
    expect(resolved.requests_per_minute).toBe(10);
    expect(resolved.tokens_per_minute).toBe(5000);
    expect(resolved.cost_tracking_enabled).toBe(true);
    expect(resolved.input_price_per_1k).toBe(1.5);
    expect(resolved.output_price_per_1k).toBe(3);
    expect(resolved.override_policy).toEqual({ tier: 'cheap' });
    expect(resolved.canvas).toEqual({ nodes: ['variant-node'] });
  });

  it("round-trips a variant's saved base_url instead of the catalog default", () => {
    const form = baseForm();
    const variantSnap = snapshotFromFormData(
      baseForm({ provider_url: { provider: 'openai', url: 'https://gateway.example/v1' } })
    );

    const overrides = buildPipeVariantOverrides(variantSnap, [PROVIDER], buildLlmPipeType);
    expect((overrides.pipe_type as any).provider.base_url).toBe('https://gateway.example/v1');

    const pipe = {
      ...form,
      pipe_type: { provider: {} },
      variants: [{ id: 'v-1', alias: 'alias1', name: 'Cheap', enabled: true, overrides }],
    } as unknown as PipeConfig;
    const { variantForms } = parsePipeVariants(pipe, form, [PROVIDER]);
    expect(variantForms[0].snapshot.provider_url).toEqual({
      provider: 'openai',
      url: 'https://gateway.example/v1',
    });
  });

  it('round-trips per-variant upstream headers, dropping half-filled rows', () => {
    const form = baseForm({
      upstream_headers: [{ name: 'x-asp-api-key', secret_id: 'tunnel-secret' }],
    });
    const variantSnap = snapshotFromFormData(
      baseForm({
        model: 'gpt-4o-mini',
        upstream_headers: [
          { name: ' x-mesh-token ', secret_id: 'mesh-secret' },
          { name: 'x-incomplete', secret_id: '' },
        ],
      })
    );

    const overrides = buildPipeVariantOverrides(variantSnap, [PROVIDER], buildLlmPipeType);
    expect(overrides.upstream_headers).toEqual([
      { name: 'x-mesh-token', secret_id: 'mesh-secret' },
    ]);

    const pipe = {
      ...form,
      pipe_type: { provider: {} },
      variants: [{ id: 'v-1', alias: 'alias1', name: 'Cheap', enabled: true, overrides }],
    } as unknown as PipeConfig;
    const { variantForms } = parsePipeVariants(pipe, form, [PROVIDER]);

    expect(variantForms[0].snapshot.upstream_headers).toEqual([
      { name: 'x-mesh-token', secret_id: 'mesh-secret' },
    ]);
  });

  it('resolves an absent upstream header list the way the backend does', () => {
    const form = baseForm({
      upstream_headers: [{ name: 'x-asp-api-key', secret_id: 'tunnel-secret' }],
    });
    const snap = snapshotFromFormData(baseForm({ upstream_headers: [] }));
    const complete = buildPipeVariantOverrides(snap, [PROVIDER], buildLlmPipeType);
    expect(complete.upstream_headers).toBeUndefined();

    const pipe = {
      ...form,
      pipe_type: { provider: {} },
      variants: [
        {
          id: 'v-complete',
          alias: 'complete',
          name: 'Complete',
          enabled: true,
          overrides: complete,
        },
        {
          id: 'v-swap',
          alias: 'swap',
          name: 'Swap',
          enabled: true,
          overrides: { complete: false, pipe_type: complete.pipe_type },
        },
        {
          id: 'v-sparse',
          alias: 'sparse',
          name: 'Sparse',
          enabled: true,
          overrides: { complete: false, rate_limit: { enabled: false } },
        },
      ],
    } as unknown as PipeConfig;
    const { variantForms } = parsePipeVariants(pipe, form, [PROVIDER]);

    // A complete snapshot or an upstream swap without its own list sends none.
    expect(variantForms[0].snapshot.upstream_headers).toEqual([]);
    expect(variantForms[1].snapshot.upstream_headers).toEqual([]);
    // A sparse variant on the same upstream inherits the base's headers.
    expect(variantForms[2].snapshot.upstream_headers).toEqual(form.upstream_headers);
  });

  it('keeps endpoint_path single-prefixed across repeated build → parse cycles', () => {
    const form = baseForm();
    let snap = snapshotFromFormData(baseForm({ model: 'gpt-4o-mini' }));

    // Simulate several edit/save cycles: build the wire overrides, then parse
    // them straight back into a snapshot, feeding that into the next save.
    for (let i = 0; i < 4; i++) {
      const overrides = buildPipeVariantOverrides(snap, [PROVIDER], buildLlmPipeType);
      expect((overrides.pipe_type as { endpoint_path: string }).endpoint_path).toBe(
        '/v1/chat/completions'
      );
      const pipe = {
        ...form,
        pipe_type: { provider: {} },
        variants: [{ id: 'v-1', alias: 'alias1', name: 'Cheap', enabled: true, overrides }],
        default_variant_id: 'v-1',
      } as unknown as PipeConfig;
      snap = parsePipeVariants(pipe, form, [PROVIDER]).variantForms[0].snapshot;
      expect(snap.endpoint_url).toBe('/chat/completions');
    }
  });

  it('self-heals an endpoint_path that already accumulated duplicate prefixes', () => {
    const form = baseForm();
    const overrides = {
      complete: true,
      pipe_type: {
        type: 'llm',
        provider: {
          provider_type: 'openai',
          model: 'gpt-4o-mini',
          base_url: 'https://api.openai.com',
        },
        endpoint_path: '/v1/v1/v1/v1/chat/completions',
      },
    };

    const pipe = {
      ...form,
      pipe_type: { provider: {} },
      variants: [{ id: 'v-1', alias: 'alias1', name: 'Cheap', enabled: true, overrides }],
      default_variant_id: 'v-1',
    } as unknown as PipeConfig;

    const resolved = parsePipeVariants(pipe, form, [PROVIDER]).variantForms[0].snapshot;
    expect(resolved.endpoint_url).toBe('/chat/completions');

    // Re-saving the healed snapshot produces a single-prefixed path.
    const rebuilt = buildPipeVariantOverrides(resolved, [PROVIDER], buildLlmPipeType);
    expect((rebuilt.pipe_type as { endpoint_path: string }).endpoint_path).toBe(
      '/v1/chat/completions'
    );
  });

  it('parses variant metadata and defaults enabled to true', () => {
    const form = baseForm();
    const pipe = {
      ...form,
      pipe_type: { provider: {} },
      variants: [{ id: 'v-2', alias: 'alias2', name: 'Premium' }],
      default_variant_id: 'v-1',
    } as unknown as PipeConfig;

    const { variantForms } = parsePipeVariants(pipe, form, [PROVIDER]);

    expect(variantForms[0].meta).toEqual({
      id: 'v-2',
      alias: 'alias2',
      name: 'Premium',
      description: undefined,
      enabled: true,
    });
  });
});
