import { registry } from '../index';
import { pipeUpstreamDefinition } from '../pipe/definitions';
import type { SurfaceContext } from '../types';

/**
 * The base LLM node's "missing API key" fault is context-aware: whether the
 * chosen provider requires a key is catalogue knowledge, so it lives in
 * `featureDependencies`. Critically, when Decider mode is on (a `pipe-decider`
 * node exists) the base LLM's provider/model/key are deferred to the candidates
 * (Route) or the merger (Mirror), so the LLM node must NOT demand its own key.
 *
 * These tests pin the contract the canvas ring, elements-list badge, and save
 * gate all rely on.
 */

function llmConfig(overrides: { provider?: string; api_key_secret_id?: string }) {
  return {
    provider: overrides.provider ?? 'anthropic',
    model: 'claude-3-5-sonnet',
    endpoint: 'https://api.anthropic.com',
    api_key_secret_id: overrides.api_key_secret_id ?? '',
  };
}

function ctx(opts: {
  deciderPresent?: boolean;
  providers?: Array<{
    enum_value: string;
    api_key_required?: boolean;
    api_key_validation?: string;
  }>;
}): SurfaceContext {
  const decider = opts.deciderPresent
    ? [{ id: 'pipe-decider', type: 'pipe-decider', config: { decider: { enabled: true } } }]
    : [];
  return {
    protocol: 'a2a',
    accessPoint: {},
    target: {},
    allNodes: decider as any,
    llmProviders: opts.providers ?? [{ enum_value: 'anthropic' }],
  };
}

describe('pipe-upstream missing API key dependency', () => {
  it('is registered with a single error-severity feature dependency', () => {
    const def = registry.get('pipe-upstream');
    expect(def).toBeDefined();
    expect(def!.featureDependencies).toHaveLength(1);
    expect(def!.featureDependencies![0].severity).toBe('error');
  });

  it('flags a base LLM whose provider needs a key but has none (no decider)', () => {
    const warnings = registry.getDependencyWarnings(
      'pipe-upstream',
      llmConfig({ api_key_secret_id: '' }),
      ctx({ deciderPresent: false })
    );
    expect(warnings).toHaveLength(1);
    expect(warnings[0].message).toMatch(/api key secret/i);
  });

  it('clears once an API key secret is selected', () => {
    const warnings = registry.getDependencyWarnings(
      'pipe-upstream',
      llmConfig({ api_key_secret_id: 'secret-1' }),
      ctx({ deciderPresent: false })
    );
    expect(warnings).toEqual([]);
  });

  it('does not flag the base LLM when Decider mode is on (deferred to candidates/merger)', () => {
    const warnings = registry.getDependencyWarnings(
      'pipe-upstream',
      llmConfig({ api_key_secret_id: '' }),
      ctx({ deciderPresent: true })
    );
    expect(warnings).toEqual([]);
  });

  it('does not flag a provider that opts out of API keys', () => {
    const warnings = registry.getDependencyWarnings(
      'pipe-upstream',
      llmConfig({ provider: 'ollama', api_key_secret_id: '' }),
      ctx({ deciderPresent: false, providers: [{ enum_value: 'ollama', api_key_required: false }] })
    );
    expect(warnings).toEqual([]);
  });

  it('condition short-circuits to false the moment a decider node appears', () => {
    const dep = pipeUpstreamDefinition.featureDependencies![0];
    const config = llmConfig({ api_key_secret_id: '' });
    expect(dep.condition!(config, ctx({ deciderPresent: false }))).toBe(true);
    expect(dep.condition!(config, ctx({ deciderPresent: true }))).toBe(false);
  });
});
