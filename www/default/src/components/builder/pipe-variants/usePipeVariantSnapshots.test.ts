import { act, renderHook } from '@testing-library/react';
import { EMPTY_PIPE_FORM, LLMProvider, PipeFormData } from '../../../pages/EditPipePage/types';
import { buildLlmPipeType } from '../../../pages/EditPipePage/pipeMappingHelpers';
import { buildPipeVariantOverrides } from './pipeVariantMapping';
import { snapshotFromFormData } from './pipeVariantSnapshot';
import { BASE_VARIANT_ID, usePipeVariantSnapshots } from './usePipeVariantSnapshots';

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

function form(overrides: Partial<PipeFormData> & { canvas?: unknown } = {}): PipeFormData {
  const { canvas, ...rest } = overrides;
  const f = {
    ...EMPTY_PIPE_FORM,
    id: 'pipe-1',
    name: 'My Pipe',
    listen_address: '0.0.0.0:8080',
    route: '/llm/openai',
    provider: 'openai',
    model: 'gpt-5',
    endpoint_url: '/chat/completions',
    api_key_secret_id: 'secret-base',
    requests_per_minute: 60,
  } as PipeFormData;
  Object.assign(f, rest);
  (f as { canvas?: unknown }).canvas = 'canvas' in overrides ? canvas : { nodes: ['base'] };
  return f;
}

const adapter = {
  buildOverrides: (snap: Parameters<typeof buildPipeVariantOverrides>[0]) =>
    buildPipeVariantOverrides(snap, [PROVIDER], buildLlmPipeType),
};

const META = { id: 'v-1', alias: 'alias1', name: 'Cheap', enabled: true };

describe('buildPipeVariantOverrides modality / realtime', () => {
  it('derives the realtime block from a variant canvas Audio Stream node', () => {
    const snap = snapshotFromFormData(
      form({
        canvas: {
          version: 1,
          nodes: [
            {
              id: 'pipe-audio-stream',
              type: 'pipe-audio-stream',
              config: { enabled: true, max_session_secs: 900 },
            },
          ],
        },
      })
    );
    const ov = buildPipeVariantOverrides(snap, [PROVIDER], buildLlmPipeType);
    expect((ov.realtime as { enabled?: boolean; max_session_secs?: number })?.enabled).toBe(true);
    expect((ov.realtime as { max_session_secs?: number })?.max_session_secs).toBe(900);
  });

  it('omits realtime for a chat variant canvas (cleared under the complete snapshot)', () => {
    const snap = snapshotFromFormData(form({ canvas: { version: 1, nodes: [] } }));
    const ov = buildPipeVariantOverrides(snap, [PROVIDER], buildLlmPipeType);
    expect(ov.realtime).toBeUndefined();
  });
});

describe('usePipeVariantSnapshots save flow', () => {
  it('saving while a non-base variant is active never overwrites the base snapshot', () => {
    const { result } = renderHook(() => usePipeVariantSnapshots(adapter));

    const baseForm = form({ model: 'gpt-5', requests_per_minute: 60 });
    const aliasSnap = snapshotFromFormData(
      form({ model: 'gpt-5-mini', requests_per_minute: 5, canvas: { nodes: ['alias'] } })
    );

    act(() => {
      result.current.hydrate(baseForm, [{ meta: META, snapshot: aliasSnap }], null);
    });
    expect(result.current.activeVariantId).toBe(BASE_VARIANT_ID);

    let aliasForm: PipeFormData;
    act(() => {
      aliasForm = result.current.switchVariant('v-1', baseForm);
    });
    expect(result.current.activeVariantId).toBe('v-1');

    // User edits the alias1 form on the canvas, then saves from alias1.
    const editedAlias = { ...aliasForm!, model: 'gpt-5-nano', requests_per_minute: 3 };
    const slice = result.current.buildVariantsWireSlice(editedAlias);

    // Base must keep its own values, not absorb the active variant's edits.
    expect(slice.baseSnapshot.model).toBe('gpt-5');
    expect(slice.baseSnapshot.requests_per_minute).toBe(60);
    // The active variant carries the edits.
    const variant = slice.variants.find(v => v.id === 'v-1');
    const pt = variant?.overrides?.pipe_type as { provider?: { model?: string } } | undefined;
    expect(pt?.provider?.model).toBe('gpt-5-nano');
  });

  it('editing the base while base is active writes the live base form (not a stale snapshot)', () => {
    const { result } = renderHook(() => usePipeVariantSnapshots(adapter));
    const baseForm = form({ model: 'gpt-5' });
    const aliasSnap = snapshotFromFormData(form({ model: 'gpt-5-mini' }));

    act(() => {
      result.current.hydrate(baseForm, [{ meta: META, snapshot: aliasSnap }], null);
    });
    expect(result.current.activeVariantId).toBe(BASE_VARIANT_ID);

    const editedBase = { ...baseForm, model: 'gpt-5.5' };
    const slice = result.current.buildVariantsWireSlice(editedBase);
    expect(slice.baseSnapshot.model).toBe('gpt-5.5');
  });

  it('preserves the active variant across a reload (hydrate with preserveActiveId)', () => {
    const { result } = renderHook(() => usePipeVariantSnapshots(adapter));
    const baseForm = form();
    const aliasSnap = snapshotFromFormData(form({ model: 'gpt-5-mini' }));

    act(() => {
      result.current.hydrate(baseForm, [{ meta: META, snapshot: aliasSnap }], null);
    });
    act(() => {
      result.current.switchVariant('v-1', baseForm);
    });
    expect(result.current.activeVariantId).toBe('v-1');

    // Simulate the post-save reload: re-hydrate, preserving the active id.
    act(() => {
      result.current.hydrate(baseForm, [{ meta: META, snapshot: aliasSnap }], null, {
        preserveActiveId: 'v-1',
      });
    });
    expect(result.current.activeVariantId).toBe('v-1');
  });

  it('falls back to default/base when the preserved id no longer exists', () => {
    const { result } = renderHook(() => usePipeVariantSnapshots(adapter));
    const baseForm = form();
    const aliasSnap = snapshotFromFormData(form({ model: 'gpt-5-mini' }));

    act(() => {
      result.current.hydrate(baseForm, [{ meta: META, snapshot: aliasSnap }], null, {
        preserveActiveId: 'deleted-id',
      });
    });
    expect(result.current.activeVariantId).toBe(BASE_VARIANT_ID);
  });
});
