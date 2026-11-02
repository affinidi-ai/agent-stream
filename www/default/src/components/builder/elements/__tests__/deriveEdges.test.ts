/**
 * Read-only adapter tests for `deriveEdges`. The adapter reconstructs
 * the new edge/slot model from today's encoding without changing
 * behaviour, so these tests pin the inversion of the conventions that
 * the renderer and drop handler currently encode directly:
 *
 *   - AP↔MA: request mw chain via parentId; response mw as direct
 *     children of MA with `direction: 'response'`.
 */

import { deriveEdges } from '../edges/deriveEdges';
import type { CanvasNode } from '../../SurfaceCanvas';

const node = (n: Partial<CanvasNode> & Pick<CanvasNode, 'id' | 'type'>): CanvasNode =>
  ({ label: '', configured: true, ...n }) as CanvasNode;

describe('deriveEdges', () => {
  it('returns empty when neither AP nor MA exist', () => {
    expect(deriveEdges([])).toEqual([]);
  });

  it('emits AP↔MA edge with empty slots when no middleware exists', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ap', type: 'access-point' }),
      node({ id: 'ma', type: 'target', parentId: 'ap' }),
    ];
    const edges = deriveEdges(nodes);
    expect(edges).toHaveLength(1);
    expect(edges[0].id).toBe('ap-ma:ap:ma');
    expect(edges[0].archetype).toBe('ap-ma');
    expect(edges[0].slots.size).toBe(0);
  });

  it('collects request mw chain on AP↔MA', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ap', type: 'access-point' }),
      node({ id: 'mw1', type: 'rate-limit', parentId: 'ap' }),
      node({ id: 'mw2', type: 'custom-metadata', parentId: 'mw1' }),
      node({ id: 'ma', type: 'target', parentId: 'mw2' }),
    ];
    const [edge] = deriveEdges(nodes);
    // Typed slots give each element type its own slot id.
    expect(edge.slots.get('request:rate-limit')).toEqual(['mw1']);
    expect(edge.slots.get('request:custom-metadata')).toEqual(['mw2']);
    expect(edge.slots.get('response:custom-metadata')).toBeUndefined();
  });

  it('collects response mw on AP↔MA as direct children of MA', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ap', type: 'access-point' }),
      node({ id: 'ma', type: 'target', parentId: 'ap' }),
      node({ id: 'rmw', type: 'custom-metadata', parentId: 'ma', direction: 'response' }),
    ];
    const [edge] = deriveEdges(nodes);
    expect(edge.slots.get('response:custom-metadata')).toEqual(['rmw']);
  });

  it('produces a stable edge id derived from archetype + endpoints', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ap', type: 'access-point' }),
      node({ id: 'ma', type: 'target', parentId: 'ap' }),
    ];
    const edges = deriveEdges(nodes);
    expect(new Set(edges.map(e => e.id)).size).toBe(edges.length);
  });

  it('binds inbound identity (child of AP) to AP↔MA request:identity-inbound', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ap', type: 'access-point' }),
      node({ id: 'ma', type: 'target', parentId: 'ap' }),
      node({
        id: 'identity-inbound',
        type: 'identity',
        parentId: 'ap',
        slotId: 'request:identity-inbound',
      }),
    ];
    const [edge] = deriveEdges(nodes);
    expect(edge.slots.get('request:identity-inbound')).toEqual(['identity-inbound']);
  });

  it('binds protected identity (child of MA) to AP↔MA response:identity-protected', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ap', type: 'access-point' }),
      node({ id: 'ma', type: 'target', parentId: 'ap' }),
      node({
        id: 'identity-protected',
        type: 'identity',
        parentId: 'ma',
        direction: 'response',
        slotId: 'response:identity-protected',
      }),
    ];
    const [edge] = deriveEdges(nodes);
    expect(edge.slots.get('response:identity-protected')).toEqual(['identity-protected']);
  });

  it('emits a pipe-inbound edge and buckets the spine into the catch-all', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'pipe-source', type: 'pipe-source' }),
      node({ id: 'pipe-prompt-guard-request', type: 'pipe-prompt-guard', parentId: 'pipe-source' }),
      node({ id: 'pipe-judge', type: 'pipe-judge', parentId: 'pipe-prompt-guard-request' }),
      node({ id: 'pipe-upstream', type: 'pipe-upstream', parentId: 'pipe-judge' }),
    ];
    const edge = deriveEdges(nodes).find(e => e.archetype === 'pipe-inbound')!;
    expect(edge.id).toBe('pipe-inbound:pipe-source:pipe-upstream');
    expect(edge.slots.get('request:mw')).toEqual(['pipe-prompt-guard-request', 'pipe-judge']);
    expect(edge.slots.get('request:pipe-opa-policy')).toBeUndefined();
  });

  it('binds the OPA gate (child of pipe-source) to pipe-inbound request:pipe-opa-policy', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'pipe-source', type: 'pipe-source' }),
      node({ id: 'pipe-upstream', type: 'pipe-upstream', parentId: 'pipe-source' }),
      node({
        id: 'pipe-opa-policy-pipe-source',
        type: 'pipe-opa-policy',
        parentId: 'pipe-source',
        slotId: 'request:pipe-opa-policy',
      }),
    ];
    const edge = deriveEdges(nodes).find(e => e.archetype === 'pipe-inbound')!;
    expect(edge.slots.get('request:pipe-opa-policy')).toEqual(['pipe-opa-policy-pipe-source']);
  });

  it('emits an ide-inbound edge for ide-source → ide-catalog', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ide-source', type: 'ide-source' }),
      node({ id: 'ide-catalog', type: 'ide-catalog', parentId: 'ide-source' }),
    ];
    const edge = deriveEdges(nodes).find(e => e.archetype === 'ide-inbound')!;
    expect(edge).toBeDefined();
    expect(edge.id).toBe('ide-inbound:ide-source:ide-catalog');
  });

  it('binds the IDE OPA gate (child of ide-source) to ide-inbound request:ide-opa-policy', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ide-source', type: 'ide-source' }),
      node({ id: 'ide-catalog', type: 'ide-catalog', parentId: 'ide-source' }),
      node({
        id: 'ide-opa-policy',
        type: 'ide-opa-policy',
        parentId: 'ide-source',
        slotId: 'request:ide-opa-policy',
      }),
    ];
    const edge = deriveEdges(nodes).find(e => e.archetype === 'ide-inbound')!;
    expect(edge.slots.get('request:ide-opa-policy')).toEqual(['ide-opa-policy']);
  });

  it('binds the IDE Rate Limit gate (child of ide-source) to ide-inbound request:ide-rate-limit', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ide-source', type: 'ide-source' }),
      node({ id: 'ide-catalog', type: 'ide-catalog', parentId: 'ide-source' }),
      node({
        id: 'ide-rate-limit',
        type: 'ide-rate-limit',
        parentId: 'ide-source',
        slotId: 'request:ide-rate-limit',
      }),
    ];
    const edge = deriveEdges(nodes).find(e => e.archetype === 'ide-inbound')!;
    expect(edge.slots.get('request:ide-rate-limit')).toEqual(['ide-rate-limit']);
  });

  it('binds the IDE Caller Context (child of ide-source) to ide-inbound request:ide-caller-auth', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ide-source', type: 'ide-source' }),
      node({ id: 'ide-catalog', type: 'ide-catalog', parentId: 'ide-source' }),
      node({
        id: 'ide-caller-auth',
        type: 'ide-caller-auth',
        parentId: 'ide-source',
        slotId: 'request:ide-caller-auth',
      }),
    ];
    const edge = deriveEdges(nodes).find(e => e.archetype === 'ide-inbound')!;
    expect(edge.slots.get('request:ide-caller-auth')).toEqual(['ide-caller-auth']);
  });

  it('binds the Pipe Caller Context (child of pipe-source) to pipe-inbound request:pipe-caller-auth', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'pipe-source', type: 'pipe-source' }),
      node({ id: 'pipe-upstream', type: 'pipe-upstream', parentId: 'pipe-source' }),
      node({
        id: 'pipe-caller-auth',
        type: 'pipe-caller-auth',
        parentId: 'pipe-source',
        slotId: 'request:pipe-caller-auth',
      }),
    ];
    const edge = deriveEdges(nodes).find(e => e.archetype === 'pipe-inbound')!;
    expect(edge.slots.get('request:pipe-caller-auth')).toEqual(['pipe-caller-auth']);
  });
});
