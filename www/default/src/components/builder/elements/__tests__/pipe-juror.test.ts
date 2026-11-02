import { registry } from '../index';
import { pipeJurorDefinition } from '../pipe/definitions';
import type { SurfaceContext } from '../types';

/**
 * Unit tests for the Juror element's context-aware "missing API key" fault.
 *
 * `incompleteReason` can only see the juror's own fields (provider, model,
 * endpoint) — it cannot know whether the chosen provider requires an API key,
 * because that is catalogue knowledge supplied at runtime. The missing-key
 * fault therefore lives in `featureDependencies`, evaluated live against the
 * provider catalogue threaded onto `SurfaceContext.llmProviders`.
 *
 * These tests pin the contract that the canvas marching-ants ring, the
 * elements-list status badge, and the save gate all rely on:
 *
 *   - An enabled juror (under an enabled jury) whose provider requires a key
 *     but has none selected is in error.
 *   - The error clears when the key is present, the provider opts out of keys,
 *     the juror is disabled, or the parent jury is disabled.
 */

function jurorConfig(overrides: {
  enabled?: boolean;
  provider_type?: string;
  api_key_secret?: string;
}) {
  return {
    juror: {
      enabled: overrides.enabled ?? true,
      llm: {
        provider_type: overrides.provider_type ?? 'anthropic',
        model: 'claude-3-5-sonnet',
        endpoint_url: 'https://api.anthropic.com',
        api_key_secret: overrides.api_key_secret ?? '',
      },
    },
  };
}

function ctx(opts: {
  juryEnabled?: boolean;
  providers?: Array<{
    enum_value: string;
    api_key_required?: boolean;
    api_key_validation?: string;
  }>;
}): SurfaceContext {
  const jury =
    opts.juryEnabled === undefined
      ? []
      : [{ id: 'jury', type: 'pipe-jury', config: { jury: { enabled: opts.juryEnabled } } }];
  return {
    protocol: 'a2a',
    accessPoint: {},
    target: {},
    allNodes: jury as any,
    llmProviders: opts.providers ?? [{ enum_value: 'anthropic' }],
  };
}

describe('pipe-juror missing API key dependency', () => {
  it('is registered with a single error-severity feature dependency', () => {
    const def = registry.get('pipe-juror');
    expect(def).toBeDefined();
    expect(def!.featureDependencies).toHaveLength(1);
    expect(def!.featureDependencies![0].severity).toBe('error');
  });

  it('flags an enabled juror whose provider needs a key but has none', () => {
    const warnings = registry.getDependencyWarnings(
      'pipe-juror',
      jurorConfig({ api_key_secret: '' }),
      ctx({ juryEnabled: true })
    );
    expect(warnings).toHaveLength(1);
    expect(warnings[0].severity).toBe('error');
    expect(warnings[0].message).toMatch(/api key secret/i);
  });

  it('clears once an API key secret is selected', () => {
    const warnings = registry.getDependencyWarnings(
      'pipe-juror',
      jurorConfig({ api_key_secret: 'secret-1' }),
      ctx({ juryEnabled: true })
    );
    expect(warnings).toEqual([]);
  });

  it('does not flag a provider that opts out of API keys (api_key_required: false)', () => {
    const warnings = registry.getDependencyWarnings(
      'pipe-juror',
      jurorConfig({ provider_type: 'ollama', api_key_secret: '' }),
      ctx({
        juryEnabled: true,
        providers: [{ enum_value: 'ollama', api_key_required: false }],
      })
    );
    expect(warnings).toEqual([]);
  });

  it('does not flag a disabled juror', () => {
    const warnings = registry.getDependencyWarnings(
      'pipe-juror',
      jurorConfig({ enabled: false, api_key_secret: '' }),
      ctx({ juryEnabled: true })
    );
    expect(warnings).toEqual([]);
  });

  it('does not flag when the parent jury is disabled', () => {
    const warnings = registry.getDependencyWarnings(
      'pipe-juror',
      jurorConfig({ api_key_secret: '' }),
      ctx({ juryEnabled: false })
    );
    expect(warnings).toEqual([]);
  });

  it('does not flag when the provider is unknown to the catalogue', () => {
    const warnings = registry.getDependencyWarnings(
      'pipe-juror',
      jurorConfig({ provider_type: 'mystery', api_key_secret: '' }),
      ctx({ juryEnabled: true, providers: [{ enum_value: 'anthropic' }] })
    );
    expect(warnings).toEqual([]);
  });

  it('does not flag when the catalogue has not loaded yet (no providers)', () => {
    const warnings = registry.getDependencyWarnings(
      'pipe-juror',
      jurorConfig({ api_key_secret: '' }),
      ctx({ juryEnabled: true, providers: [] })
    );
    expect(warnings).toEqual([]);
  });

  it('treats a provider with no api_key_required flag as requiring a key', () => {
    const dep = pipeJurorDefinition.featureDependencies![0];
    const config = jurorConfig({ api_key_secret: '' });
    const context = ctx({ juryEnabled: true, providers: [{ enum_value: 'anthropic' }] });
    expect(dep.condition(config, context)).toBe(true);
    expect(dep.check(config, context)).toBe(false);
  });

  it('leaves incompleteReason catalogue-blind (provider/model/endpoint only)', () => {
    // A fully-keyed-but-endpoint-missing juror is still incomplete; a
    // provider/model/endpoint-complete juror with no key is NOT incomplete
    // (the missing-key fault is the dependency above, not incompleteReason).
    expect(
      pipeJurorDefinition.incompleteReason({
        juror: { enabled: true, llm: { provider_type: 'anthropic', model: 'm' } },
      })
    ).toMatch(/provider, model and endpoint/i);
    expect(pipeJurorDefinition.incompleteReason(jurorConfig({ api_key_secret: '' }))).toBeNull();
  });

  it('honours the three-state api_key_validation field', () => {
    const mandatory = registry.getDependencyWarnings(
      'pipe-juror',
      jurorConfig({ provider_type: 'openai', api_key_secret: '' }),
      ctx({
        juryEnabled: true,
        providers: [{ enum_value: 'openai', api_key_validation: 'mandatory' }],
      })
    );
    expect(mandatory).toHaveLength(1);

    const optional = registry.getDependencyWarnings(
      'pipe-juror',
      jurorConfig({ provider_type: 'openai', api_key_secret: '' }),
      ctx({
        juryEnabled: true,
        providers: [{ enum_value: 'openai', api_key_validation: 'optional' }],
      })
    );
    expect(optional).toEqual([]);

    const none = registry.getDependencyWarnings(
      'pipe-juror',
      jurorConfig({ provider_type: 'ollama', api_key_secret: '' }),
      ctx({ juryEnabled: true, providers: [{ enum_value: 'ollama', api_key_validation: 'none' }] })
    );
    expect(none).toEqual([]);
  });
});
