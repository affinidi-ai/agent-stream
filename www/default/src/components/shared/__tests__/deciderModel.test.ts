import {
  surfaceModeFromDecider,
  modeToDeciderPatch,
  applyModeToDeciderConfig,
  surfaceModeOption,
  SURFACE_MODE_OPTIONS,
  DECIDER_MODE_OPTIONS,
} from '../deciderModel';

describe('surface execution mode model', () => {
  describe('surfaceModeFromDecider', () => {
    it('maps an absent decider to direct', () => {
      expect(surfaceModeFromDecider(null)).toBe('direct');
      expect(surfaceModeFromDecider(undefined)).toBe('direct');
    });

    it('maps a non-mirror decider to route', () => {
      expect(surfaceModeFromDecider({ strategy: 'route' })).toBe('route');
      expect(surfaceModeFromDecider({})).toBe('route');
    });

    it('maps mirror strategy to merge or collect by mirror.mode', () => {
      expect(surfaceModeFromDecider({ strategy: 'mirror', mirror: { mode: 'collect' } })).toBe(
        'collect'
      );
      expect(surfaceModeFromDecider({ strategy: 'mirror', mirror: { mode: 'merge' } })).toBe(
        'merge'
      );
      // Mirror with no explicit mode defaults to merge.
      expect(surfaceModeFromDecider({ strategy: 'mirror' })).toBe('merge');
    });
  });

  describe('modeToDeciderPatch', () => {
    it('route clears the mirror strategy', () => {
      expect(modeToDeciderPatch({}, 'route')).toEqual({ strategy: 'route' });
    });

    it('collect selects mirror + collect', () => {
      expect(modeToDeciderPatch({}, 'collect')).toEqual({
        strategy: 'mirror',
        mirror: { mode: 'collect' },
      });
    });

    it('merge selects mirror + merge and seeds a merger when absent', () => {
      const patch = modeToDeciderPatch({}, 'merge');
      expect(patch.strategy).toBe('mirror');
      expect(patch.mirror?.mode).toBe('merge');
      expect(patch.mirror?.merger).toBeDefined();
    });

    it('preserves an existing merger and merge prompt when switching modes', () => {
      const existing = {
        mirror: {
          mode: 'collect',
          merger: { provider_type: 'openai', model: 'gpt-4o', endpoint_url: '/x' },
          merge_system_prompt: 'keep me',
        },
      };
      const patch = modeToDeciderPatch(existing, 'merge');
      expect(patch.mirror?.merger).toEqual({
        provider_type: 'openai',
        model: 'gpt-4o',
        endpoint_url: '/x',
      });
      expect(patch.mirror?.merge_system_prompt).toBe('keep me');
      expect(patch.mirror?.mode).toBe('merge');
    });
  });

  describe('applyModeToDeciderConfig', () => {
    it('seeds a fresh enabled decider when none exists', () => {
      const cfg = applyModeToDeciderConfig(null, 'route');
      expect(cfg.enabled).toBe(true);
      expect(cfg.strategy).toBe('route');
      expect(cfg.llm).toBeDefined();
      expect(cfg.system_prompt).toBeDefined();
    });

    it('preserves existing router/candidate-adjacent fields when switching modes', () => {
      const existing = {
        enabled: true,
        strategy: 'route',
        llm: { provider_type: 'anthropic', model: 'x', endpoint_url: '/y' },
        system_prompt: 'route it',
      };
      const cfg = applyModeToDeciderConfig(existing, 'collect');
      expect(cfg.strategy).toBe('mirror');
      expect((cfg.mirror as { mode?: string }).mode).toBe('collect');
      expect(cfg.llm).toEqual({ provider_type: 'anthropic', model: 'x', endpoint_url: '/y' });
      expect(cfg.system_prompt).toBe('route it');
    });
  });

  describe('option lists', () => {
    it('exposes four surface modes with direct first', () => {
      expect(SURFACE_MODE_OPTIONS.map(o => o.value)).toEqual([
        'direct',
        'route',
        'collect',
        'merge',
      ]);
    });

    it('DECIDER_MODE_OPTIONS excludes direct', () => {
      expect(DECIDER_MODE_OPTIONS.some(o => o.value === 'direct')).toBe(false);
      expect(DECIDER_MODE_OPTIONS).toHaveLength(3);
    });

    it('surfaceModeOption falls back to direct for an unknown value', () => {
      // @ts-expect-error deliberately passing an invalid mode
      expect(surfaceModeOption('nonsense').value).toBe('direct');
    });
  });
});
