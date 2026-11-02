import { registry } from '../index';
import { pipeCandidateDefinition } from '../pipe/definitions';
import type { SurfaceContext } from '../types';

/**
 * Unit tests for the Candidate element's context-aware "missing API key" fault.
 *
 * Like the juror, a candidate's `incompleteReason` can only see its own fields
 * (provider, model, endpoint). Whether the chosen provider requires an API key
 * is catalogue knowledge supplied at runtime, so the missing-key fault lives in
 * `featureDependencies`, evaluated live against `SurfaceContext.llmProviders`.
 *
 * These tests pin the contract the canvas marching-ants ring, the elements-list
 * status badge, and the save gate all rely on:
 *
 *   - A candidate (under an enabled decider) whose provider requires a key but
 *     has none selected is in error.
 *   - The error clears when the key is present, the provider opts out of keys,
 *     or the parent decider is disabled.
 */

function candidateConfig(overrides: { provider_type?: string; api_key_secret?: string }) {
  return {
    candidate: {
      id: 'fast',
      name: 'Fast',
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
  deciderEnabled?: boolean;
  providers?: Array<{
    enum_value: string;
    api_key_required?: boolean;
    api_key_validation?: string;
  }>;
}): SurfaceContext {
  const decider =
    opts.deciderEnabled === undefined
      ? []
      : [
          {
            id: 'pipe-decider',
            type: 'pipe-decider',
            config: { decider: { enabled: opts.deciderEnabled } },
          },
        ];
  return {
    protocol: 'a2a',
    accessPoint: {},
    target: {},
    allNodes: decider as any,
    llmProviders: opts.providers ?? [{ enum_value: 'anthropic' }],
  };
}

describe('pipe-candidate missing API key dependency', () => {
  it('is registered with a single error-severity feature dependency', () => {
    const def = registry.get('pipe-candidate');
    expect(def).toBeDefined();
    expect(def!.featureDependencies).toHaveLength(1);
    expect(def!.featureDependencies![0].severity).toBe('error');
  });

  it('flags a candidate whose provider needs a key but has none', () => {
    const warnings = registry.getDependencyWarnings(
      'pipe-candidate',
      candidateConfig({ api_key_secret: '' }),
      ctx({ deciderEnabled: true })
    );
    expect(warnings).toHaveLength(1);
    expect(warnings[0].severity).toBe('error');
    expect(warnings[0].message).toMatch(/api key secret/i);
  });

  it('clears once an API key secret is selected', () => {
    const warnings = registry.getDependencyWarnings(
      'pipe-candidate',
      candidateConfig({ api_key_secret: 'secret-1' }),
      ctx({ deciderEnabled: true })
    );
    expect(warnings).toEqual([]);
  });

  it('does not flag a provider that opts out of API keys (api_key_required: false)', () => {
    const warnings = registry.getDependencyWarnings(
      'pipe-candidate',
      candidateConfig({ provider_type: 'ollama', api_key_secret: '' }),
      ctx({
        deciderEnabled: true,
        providers: [{ enum_value: 'ollama', api_key_required: false }],
      })
    );
    expect(warnings).toEqual([]);
  });

  it('does not flag when the parent decider is disabled', () => {
    const warnings = registry.getDependencyWarnings(
      'pipe-candidate',
      candidateConfig({ api_key_secret: '' }),
      ctx({ deciderEnabled: false })
    );
    expect(warnings).toEqual([]);
  });

  it('does not flag when the provider is unknown to the catalogue', () => {
    const warnings = registry.getDependencyWarnings(
      'pipe-candidate',
      candidateConfig({ provider_type: 'mystery', api_key_secret: '' }),
      ctx({ deciderEnabled: true, providers: [{ enum_value: 'anthropic' }] })
    );
    expect(warnings).toEqual([]);
  });

  it('does not flag when the catalogue has not loaded yet (no providers)', () => {
    const warnings = registry.getDependencyWarnings(
      'pipe-candidate',
      candidateConfig({ api_key_secret: '' }),
      ctx({ deciderEnabled: true, providers: [] })
    );
    expect(warnings).toEqual([]);
  });

  it('treats a provider with no api_key_required flag as requiring a key', () => {
    const dep = pipeCandidateDefinition.featureDependencies![0];
    const condition = dep.condition!(
      candidateConfig({ provider_type: 'anthropic', api_key_secret: '' }),
      ctx({ deciderEnabled: true, providers: [{ enum_value: 'anthropic' }] })
    );
    expect(condition).toBe(true);
  });

  it('honours the three-state api_key_validation field', () => {
    const mandatory = registry.getDependencyWarnings(
      'pipe-candidate',
      candidateConfig({ provider_type: 'openai', api_key_secret: '' }),
      ctx({
        deciderEnabled: true,
        providers: [{ enum_value: 'openai', api_key_validation: 'mandatory' }],
      })
    );
    expect(mandatory).toHaveLength(1);

    const optional = registry.getDependencyWarnings(
      'pipe-candidate',
      candidateConfig({ provider_type: 'openai', api_key_secret: '' }),
      ctx({
        deciderEnabled: true,
        providers: [{ enum_value: 'openai', api_key_validation: 'optional' }],
      })
    );
    expect(optional).toEqual([]);

    const none = registry.getDependencyWarnings(
      'pipe-candidate',
      candidateConfig({ provider_type: 'ollama', api_key_secret: '' }),
      ctx({
        deciderEnabled: true,
        providers: [{ enum_value: 'ollama', api_key_validation: 'none' }],
      })
    );
    expect(none).toEqual([]);
  });
});
