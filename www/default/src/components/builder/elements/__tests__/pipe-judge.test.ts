import { registry } from '../index';
import { pipeJudgeDefinition } from '../pipe/definitions';
import type { SurfaceContext } from '../types';

function judgeConfig(enabled = true) {
  return {
    judge: {
      enabled,
      mode: 'llm',
      llm: { provider_type: 'openai', model: 'gpt-4o-mini', endpoint_url: '/chat/completions' },
    },
  };
}

function ctx(opts: {
  realtime?: boolean;
  safety?: boolean;
  transcriptJudge?: boolean;
}): SurfaceContext {
  const nodes = opts.realtime
    ? [
        {
          id: 'pipe-audio-stream',
          type: 'pipe-audio-stream',
          config: {
            enabled: true,
            safety: { enabled: opts.safety, judge: opts.transcriptJudge },
          },
        },
      ]
    : [];
  return {
    protocol: 'a2a',
    accessPoint: {},
    target: {},
    allNodes: nodes as any,
    llmProviders: [],
  };
}

describe('pipe-judge realtime voice dependency', () => {
  it('is registered as an error-severity feature dependency', () => {
    const dep = pipeJudgeDefinition.featureDependencies?.[0];
    expect(dep).toBeDefined();
    expect(dep?.severity).toBe('error');
  });

  it('flags Judge whenever realtime voice is enabled', () => {
    const warnings = registry.getDependencyWarnings(
      'pipe-judge',
      judgeConfig(true),
      ctx({ realtime: true, safety: true, transcriptJudge: false })
    );
    expect(warnings).toHaveLength(1);
    expect(warnings[0].severity).toBe('error');
    expect(warnings[0].message).toMatch(/will not block live audio/i);
  });

  it('also flags explicit realtime caller transcript review', () => {
    const warnings = registry.getDependencyWarnings(
      'pipe-judge',
      judgeConfig(true),
      ctx({ realtime: true, safety: true, transcriptJudge: true })
    );
    expect(warnings).toHaveLength(1);
    expect(warnings[0].severity).toBe('error');
    expect(warnings[0].message).toMatch(/before the LLM/i);
  });

  it('does not flag ordinary buffered Judge usage', () => {
    const warnings = registry.getDependencyWarnings('pipe-judge', judgeConfig(true), ctx({}));
    expect(warnings).toEqual([]);
  });

  it('does not flag non-realtime audio input', () => {
    const warnings = registry.getDependencyWarnings(
      'pipe-judge',
      judgeConfig(true),
      ctx({ realtime: false, safety: true, transcriptJudge: true })
    );
    expect(warnings).toEqual([]);
  });

  it('does not flag when the Judge node is disabled', () => {
    const warnings = registry.getDependencyWarnings(
      'pipe-judge',
      judgeConfig(false),
      ctx({ realtime: true, safety: true, transcriptJudge: true })
    );
    expect(warnings).toEqual([]);
  });
});
