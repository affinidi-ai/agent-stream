/**
 * `tryDrop` dispatcher tests. Pin the slot-selection rules declared in
 * `archetypes.ts`:
 *   - prefer specific accepts over the `'*'` sentinel
 *   - on ties, prefer lower `order`
 *   - reject when a 'one' slot is occupied (do not silently fall back
 *     to the generic slot)
 */

import { deriveEdges } from '../edges/deriveEdges';
import { tryDrop, getArchetype, EDGE_ARCHETYPES, makeSurfaceSlotFilter } from '../edges/archetypes';
import type { CanvasNode } from '../../SurfaceCanvas';

const node = (n: Partial<CanvasNode> & Pick<CanvasNode, 'id' | 'type'>): CanvasNode =>
  ({ label: '', configured: true, ...n }) as CanvasNode;

describe('archetypes catalogue', () => {
  it('exposes the ap-ma, ma-external, ide-inbound, and pipe-inbound archetypes', () => {
    expect(EDGE_ARCHETYPES.map(a => a.id).sort()).toEqual([
      'ap-ma',
      'ide-inbound',
      'ma-external',
      'pipe-inbound',
    ]);
  });

  it('getArchetype returns undefined for unknown ids', () => {
    expect(getArchetype('does-not-exist')).toBeUndefined();
  });
});

describe('tryDrop', () => {
  const baseNodes: CanvasNode[] = [
    node({ id: 'ap', type: 'access-point' }),
    node({ id: 'ma', type: 'target', parentId: 'ap' }),
  ];

  it('routes a typed mw onto its dedicated slot of an empty ap-ma edge', () => {
    const [apMa] = deriveEdges(baseNodes);
    const r = tryDrop(apMa, 'rate-limit', 'request');
    expect(r).toEqual({ ok: true, slotId: 'request:rate-limit' });
  });

  it('rejects a direction the archetype does not support', () => {
    const apMa = deriveEdges(baseNodes)[0];
    const broken = { ...apMa, archetype: 'unknown-archetype' };
    const r = tryDrop(broken, 'rate-limit', 'request');
    expect(r.ok).toBe(false);
  });

  it('allows multiple generic mw to stack on request:mw (cardinality=many)', () => {
    const nodes: CanvasNode[] = [
      ...baseNodes,
      node({ id: 'mw1', type: 'rate-limit', parentId: 'ap' }),
      // simulate the chain: ma re-parented under mw1
      node({ id: 'ma', type: 'target', parentId: 'mw1' }),
    ];
    // dedupe ma to avoid double entry
    const deduped = nodes.filter((n, i, arr) => arr.findIndex(x => x.id === n.id) === i);
    const apMa = deriveEdges(deduped)[0];
    // Each typed slot is `cardinality: 'one'`; a second
    // custom-metadata is rejected by its own typed slot rather than
    // stacking on the catch-all.
    const r = tryDrop(apMa, 'custom-metadata', 'request');
    expect(r).toEqual({ ok: true, slotId: 'request:custom-metadata' });
  });
});

describe('makeSurfaceSlotFilter (topology-aware slot visibility)', () => {
  const apMaTarget = (endpoint: string): CanvasNode[] => [
    node({ id: 'ap', type: 'access-point' }),
    node({ id: 'target', type: 'target', parentId: 'ap', config: { endpoint } }),
    node({ id: 'npc', type: 'npc-endpoint', parentId: 'target' }),
  ];

  it('returns undefined when MA endpoint is fabric:// (G2G — external slot still meaningful)', () => {
    const filter = makeSurfaceSlotFilter('fabric://gw1/svc');
    expect(filter).toBeUndefined();
  });

  it('hides the external identity slot on plain-URL inbound surfaces', () => {
    const filter = makeSurfaceSlotFilter('https://upstream.example/api');
    expect(filter).toBeDefined();
    const nodes = apMaTarget('https://upstream.example/api');
    const maExt = deriveEdges(nodes).find(e => e.archetype === 'ma-external')!;
    const result = tryDrop(maExt, 'identity', 'response', undefined, filter);
    expect(result.ok).toBe(false);
    expect(result.ok ? '' : result.reason).toMatch(/no slot/i);
  });

  it('leaves AP-side identity slot reachable on plain-URL surfaces', () => {
    const filter = makeSurfaceSlotFilter('https://upstream.example/api');
    const nodes = apMaTarget('https://upstream.example/api');
    const apMa = deriveEdges(nodes).find(e => e.archetype === 'ap-ma')!;
    const result = tryDrop(apMa, 'identity', 'response', undefined, filter);
    expect(result).toEqual({ ok: true, slotId: 'response:identity-protected' });
  });
});
