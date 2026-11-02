/**
 * Slot-driven `nodesFromPayload` parity tests.
 *
 * Asserts that the slot-driven hydration of the AP↔MA edge produces a
 * canvas node for every typed slot whose payload path has a non-empty
 * slice, and that the emitted ids match what `useSurfaceBuilder.handleDrop`
 * mints (so save/reload round-trips through the same id).
 */

import { registry } from '../index';
import { getArchetype, ANY_EDGE_MW } from '../edges/archetypes';

const seedSurface = (extra: Record<string, any> = {}) => ({
  name: 'parity',
  status: 'enabled' as const,
  tags: [],
  access_point: { listener_url: 'https://gw/x' },
  target: { endpoint: 'https://upstream/y' },
  ...extra,
});

describe('nodesFromPayload — ap-ma slot-driven hydration', () => {
  const apMa = getArchetype('ap-ma')!;
  const apMaTypedSlots = apMa.slots.filter(
    s => s.payloadPathTemplate && s.accepts !== ANY_EDGE_MW && registry.get(s.accepts[0])
  );

  it('hydrates every typed ap-ma slot from a payload that fills its path', () => {
    // Build a payload with every typed slot path populated by a
    // throw-away truthy slice; assert every one comes back as a node.
    const payload: any = seedSurface();
    for (const slot of apMaTypedSlots) {
      const segs = slot.payloadPathTemplate.split('.');
      let cur = payload;
      for (let i = 0; i < segs.length - 1; i++) {
        cur[segs[i]] = cur[segs[i]] ?? {};
        cur = cur[segs[i]];
      }
      cur[segs[segs.length - 1]] = { _filled: true };
    }
    const nodes = registry.nodesFromPayload(payload);
    for (const slot of apMaTypedSlots) {
      const expectedType = slot.accepts[0];
      const matches = nodes.filter(n => n.type === expectedType);
      expect(matches.length).toBeGreaterThan(0);
    }
  });

  it('response-direction slots emit `${type}-response` ids with direction:"response"', () => {
    const payload = seedSurface({
      target: {
        endpoint: 'https://upstream/y',
        response_custom_metadata: { foo: 'bar' },
      },
    });
    const nodes = registry.nodesFromPayload(payload);
    const cm = nodes.find(n => n.id === 'custom-metadata-response');
    expect(cm).toBeDefined();
    expect(cm!.direction).toBe('response');
  });

  it('skips slots whose payload slice is missing or empty', () => {
    const payload = seedSurface();
    const nodes = registry.nodesFromPayload(payload);
    // No edge mw was filled → no edge mw nodes should appear (only the
    // anchor singletons access-point + target).
    const types = new Set<string>(nodes.map(n => n.type));
    for (const slot of apMaTypedSlots) {
      const t = slot.accepts[0];
      expect(types.has(t)).toBe(false);
    }
  });
});
