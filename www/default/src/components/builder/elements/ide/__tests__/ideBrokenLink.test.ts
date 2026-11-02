import { registry } from '../../index';
import type { SurfaceContext, SurfaceContextSurfaceRef } from '../../types';

/**
 * Unit tests for the IDE catalogue broken-link fault.
 *
 * A catalogue member (`ide-member`) references one of the appliance's LLM
 * Surfaces by `pipe_id`. Its `incompleteReason` can only see that a surface was
 * picked, not whether it still exists — so a deleted referenced surface leaves
 * `pipe_id` populated and would silently pass. Existence is host-supplied
 * knowledge threaded onto `SurfaceContext.availableSurfaces` (the generic
 * cross-surface dependency registry), so the broken-link fault lives in
 * `featureDependencies` on both the member and the catalogue.
 *
 * These tests pin the contract the canvas marching-ants ring and the IDE save
 * gate both rely on.
 */

function memberConfig(pipeId: string, mnemonic = '') {
  return {
    pipe_id: pipeId,
    variant_alias: '',
    mnemonic,
    display_name: '',
    group: '',
    order: 0,
    default: false,
    expose: true,
  };
}

function ctx(opts: {
  availableSurfaces?: SurfaceContextSurfaceRef[];
  memberPipeIds?: string[];
  members?: Array<{ pipeId: string; mnemonic?: string }>;
}): SurfaceContext {
  const fromPipeIds = (opts.memberPipeIds ?? []).map((pid, i) => ({
    id: `ide-member-${i}`,
    type: 'ide-member',
    config: memberConfig(pid),
  }));
  const fromExplicit = (opts.members ?? []).map((m, i) => ({
    id: `ide-member-explicit-${i}`,
    type: 'ide-member',
    config: memberConfig(m.pipeId, m.mnemonic ?? ''),
  }));
  const members = [...fromPipeIds, ...fromExplicit];
  return {
    protocol: 'a2a',
    accessPoint: {},
    target: {},
    allNodes: members as any,
    availableSurfaces: opts.availableSurfaces,
  };
}

const SURFACES: SurfaceContextSurfaceRef[] = [
  { id: 'llm-1', type: 'llm-surface', name: 'GPT' },
  { id: 'llm-2', type: 'llm-surface', name: 'Claude' },
];

describe('ide-member broken-link dependency', () => {
  it('is registered with two error-severity feature dependencies', () => {
    // (1) broken-link — the linked LLM Surface must still exist.
    // (2) mnemonic uniqueness — no two members share a resolved model id.
    const def = registry.get('ide-member');
    expect(def).toBeDefined();
    expect(def!.featureDependencies).toHaveLength(2);
    expect(def!.featureDependencies!.every(d => d.severity === 'error')).toBe(true);
  });

  it('flags a member whose linked surface no longer exists', () => {
    const warnings = registry.getDependencyWarnings(
      'ide-member',
      memberConfig('deleted-surface'),
      ctx({ availableSurfaces: SURFACES })
    );
    expect(warnings).toHaveLength(1);
    expect(warnings[0].severity).toBe('error');
    expect(warnings[0].message).toMatch(/no longer exists/i);
  });

  it('passes when the linked surface still exists', () => {
    const warnings = registry.getDependencyWarnings(
      'ide-member',
      memberConfig('llm-1'),
      ctx({ availableSurfaces: SURFACES })
    );
    expect(warnings).toHaveLength(0);
  });

  it('stays inert when no surface has been picked yet', () => {
    const warnings = registry.getDependencyWarnings(
      'ide-member',
      memberConfig(''),
      ctx({ availableSurfaces: SURFACES })
    );
    expect(warnings).toHaveLength(0);
  });

  it('stays inert until the surface registry is supplied (availableSurfaces undefined)', () => {
    const warnings = registry.getDependencyWarnings(
      'ide-member',
      memberConfig('deleted-surface'),
      ctx({ availableSurfaces: undefined })
    );
    expect(warnings).toHaveLength(0);
  });
});

describe('ide-catalog broken-member dependency', () => {
  it('flags the catalogue when any member links to a missing surface', () => {
    const warnings = registry.getDependencyWarnings(
      'ide-catalog',
      {},
      ctx({ availableSurfaces: SURFACES, memberPipeIds: ['llm-1', 'deleted-surface'] })
    );
    // The empty-catalogue rule passes (members exist); only the broken-link
    // rule fires.
    const errors = warnings.filter(w => w.severity === 'error');
    expect(errors).toHaveLength(1);
    expect(errors[0].message).toMatch(/no longer exists/i);
  });

  it('passes when every member links to an existing surface', () => {
    const warnings = registry.getDependencyWarnings(
      'ide-catalog',
      {},
      ctx({ availableSurfaces: SURFACES, memberPipeIds: ['llm-1', 'llm-2'] })
    );
    expect(warnings.filter(w => w.severity === 'error')).toHaveLength(0);
  });

  it('ignores members with no surface picked (their own incompleteReason covers that)', () => {
    const warnings = registry.getDependencyWarnings(
      'ide-catalog',
      {},
      ctx({ availableSurfaces: SURFACES, memberPipeIds: ['llm-1', ''] })
    );
    expect(warnings.filter(w => w.severity === 'error')).toHaveLength(0);
  });

  it('stays inert on the broken-link rule until the registry is supplied', () => {
    const warnings = registry.getDependencyWarnings(
      'ide-catalog',
      {},
      ctx({ availableSurfaces: undefined, memberPipeIds: ['deleted-surface'] })
    );
    // Empty-catalogue rule passes (a member exists); broken-link rule is inert.
    expect(warnings.filter(w => w.severity === 'error')).toHaveLength(0);
  });
});

describe('ide-member mnemonic uniqueness dependency', () => {
  it('passes when a member is unique in the catalogue (self counted once)', () => {
    // Real UI: `ctx.allNodes` contains the node under evaluation, so a unique
    // member appears exactly once — the rule allows `matches <= 1`.
    const warnings = registry.getDependencyWarnings(
      'ide-member',
      memberConfig('llm-1', 'fast'),
      ctx({
        availableSurfaces: SURFACES,
        members: [
          { pipeId: 'llm-1', mnemonic: 'fast' },
          { pipeId: 'llm-2', mnemonic: 'smart' },
        ],
      })
    );
    expect(warnings).toHaveLength(0);
  });

  it('flags a member whose mnemonic collides with a sibling', () => {
    const warnings = registry.getDependencyWarnings(
      'ide-member',
      memberConfig('llm-1', 'fast'),
      ctx({
        availableSurfaces: SURFACES,
        members: [
          { pipeId: 'llm-1', mnemonic: 'fast' },
          { pipeId: 'llm-2', mnemonic: 'fast' },
        ],
      })
    );
    expect(warnings).toHaveLength(1);
    expect(warnings[0].severity).toBe('error');
    expect(warnings[0].message).toMatch(/model id is already in use/i);
  });

  it('resolves the model id via pipe_id[$alias] when no mnemonic is set', () => {
    const warnings = registry.getDependencyWarnings(
      'ide-member',
      memberConfig('llm-1'),
      ctx({
        availableSurfaces: SURFACES,
        // Two members both derive their id from `llm-1` (no mnemonic).
        members: [{ pipeId: 'llm-1' }, { pipeId: 'llm-1' }],
      })
    );
    expect(warnings.map(w => w.message)).toEqual([
      expect.stringMatching(/model id is already in use/i),
    ]);
  });

  it('stays inert while the member has no usable id yet (pipe unset, mnemonic blank)', () => {
    const warnings = registry.getDependencyWarnings(
      'ide-member',
      memberConfig(''),
      ctx({ availableSurfaces: SURFACES, members: [{ pipeId: '' }, { pipeId: '' }] })
    );
    expect(warnings).toHaveLength(0);
  });

  it('is mirrored on the catalogue node so the Catalogue itself flags a collision', () => {
    const warnings = registry.getDependencyWarnings(
      'ide-catalog',
      {},
      ctx({
        availableSurfaces: SURFACES,
        members: [
          { pipeId: 'llm-1', mnemonic: 'fast' },
          { pipeId: 'llm-2', mnemonic: 'fast' },
        ],
      })
    );
    const messages = warnings.filter(w => w.severity === 'error').map(w => w.message);
    expect(messages).toEqual(expect.arrayContaining([expect.stringMatching(/same model id/i)]));
  });
});

describe('ide-member expose mute state', () => {
  it('renders muted when expose is false (hidden from the IDE catalogue)', () => {
    expect(registry.isMuted('ide-member', { pipe_id: 'llm-1', expose: false })).toBe(true);
    expect(registry.getMutedReason('ide-member', { pipe_id: 'llm-1', expose: false })).toMatch(
      /hidden/i
    );
  });

  it('is not muted when expose is true or omitted (default is exposed)', () => {
    expect(registry.isMuted('ide-member', { pipe_id: 'llm-1', expose: true })).toBe(false);
    expect(registry.isMuted('ide-member', { pipe_id: 'llm-1' })).toBe(false);
  });
});
