import { registry } from '../index';
import * as Cap from '../capabilities';
import type { SurfaceContext } from '../types';

describe('ElementRegistry', () => {
  describe('registration', () => {
    it('registers all 45 element types', () => {
      const types = registry
        .all()
        .map(d => d.type)
        .sort();
      expect(types).toEqual(
        [
          'caller',
          'caller-auth',
          'credential-delegation',
          'custom-metadata',
          'extension-rules',
          'extension-validation',
          'human',
          'ide-caller-auth',
          'ide-catalog',
          'ide-member',
          'ide-member-opa',
          'ide-member-upstream-auth',
          'ide-opa-policy',
          'ide-rate-limit',
          'ide-response',
          'ide-source',
          'local-gateway-hop',
          'networking',
          'npc-actor',
          'npc-agent',
          'npc-database',
          'npc-endpoint',
          'npc-server',
          'npc-service',
          'pipe-caller-auth',
          'pipe-candidate',
          'pipe-decider',
          'pipe-judge',
          'pipe-juror',
          'pipe-jury',
          'pipe-opa-policy',
          'pipe-prompt-guard',
          'pipe-rate-limit',
          'pipe-response',
          'pipe-source',
          'pipe-upstream',
          'pipe-web-fetch',
          'pipe-web-search',
          'pipe-router',
          'pipe-audio-input',
          'pipe-audio-stream',
          'pipe-image-input',
          'pipe-document-input',
          'pipe-drift-harness',
          'pipe-witness-request',
          'pipe-witness-response',
          'rate-limit',
          'remote-channel',
          'remote-gateway',
          'surface',
          'target-variant',
        ].sort()
      );
    });

    it('every definition has matching label, color and icon', () => {
      for (const def of registry.all()) {
        expect(def.label).toBeTruthy();
        expect(def.color).toMatch(/^#[0-9a-f]{3,8}$/i);
        expect(def.icon).toBeTruthy();
        expect(def.defaultRadius).toBeGreaterThan(0);
      }
    });
  });

  describe('isConfigured / getIncompleteReason', () => {
    it('NPC and actor types are always configured', () => {
      expect(registry.isConfigured('human', {})).toBe(true);
      expect(registry.isConfigured('caller', {})).toBe(true);
      expect(registry.isConfigured('npc-agent', {})).toBe(true);
    });
  });

  describe('palette filtering by protocol', () => {
    it('hides extension-rules and extension-validation for marketplace', () => {
      const market = registry.paletteItems('marketplace').map(d => d.type);
      expect(market).not.toContain('extension-rules');
      expect(market).not.toContain('extension-validation');
    });

    it('does not include core auto-created elements (surface, access-point, target)', () => {
      const a2a = registry.paletteItems('a2a').map(d => d.type);
      expect(a2a).not.toContain('surface');
      expect(a2a).not.toContain('access-point');
      expect(a2a).not.toContain('target');
    });
  });

  describe('feature dependencies', () => {
    const baseCtx: SurfaceContext = {
      protocol: 'mcp',
      accessPoint: {},
      target: {},
      allNodes: [],
    };

    it('errors when mirror_percentage out of range', () => {
      const warnings = registry.getDependencyWarnings(
        'networking',
        { mirror_enabled: true, mirror_percentage: 200, mirror_endpoint: 'x' },
        baseCtx
      );
      expect(
        warnings.some(w => w.severity === 'error' && w.message.includes('between 0 and 100'))
      ).toBe(true);
    });
  });

  describe('capability constants', () => {
    it('exports expected pipeline capabilities', () => {
      expect(Cap.PIPELINE_SOURCE).toBe('pipeline-source');
      expect(Cap.PIPELINE_SINK).toBe('pipeline-sink');
      expect(Cap.PIPELINE_EDGE).toBe('pipeline-edge');
    });
  });

  describe('buildSurfaceContext', () => {
    it('extracts accessPoint and target from a node array', () => {
      const { buildSurfaceContext } = require('../surfaceContext');
      const nodes = [
        { id: 'a', type: 'access-point', config: { x: 1 } },
        { id: 't', type: 'target', config: { endpoint: 'http://x' } },
        { id: 'p', type: 'payment', config: {} },
      ];
      const ctx = buildSurfaceContext('mcp', nodes);
      expect(ctx.protocol).toBe('mcp');
      expect(ctx.accessPoint).toEqual({ x: 1 });
      expect(ctx.target).toEqual({ endpoint: 'http://x' });
      expect(ctx.allNodes).toBe(nodes);
    });

    it('falls back to a2a protocol and empty objects on missing input', () => {
      const { buildSurfaceContext } = require('../surfaceContext');
      const ctx = buildSurfaceContext(undefined, undefined);
      expect(ctx.protocol).toBe('a2a');
      expect(ctx.accessPoint).toEqual({});
      expect(ctx.target).toEqual({});
      expect(ctx.allNodes).toEqual([]);
    });
  });

  describe('buildPayload', () => {
    function makeCtx(nodes: any[], overrides: any = {}) {
      return {
        protocol: 'a2a',
        surfaceMeta: {
          name: 'test-surface',
          tags: ['x'],
          status: 'enabled',
          ...overrides.surfaceMeta,
        },
        allNodes: nodes,
        nodesOfType: (type: string) => nodes.filter(n => n.type === type),
        firstNodeOfType: (type: string) => nodes.find(n => n.type === type),
        ...overrides,
      };
    }

    it('always emits surface metadata', () => {
      const out = registry.buildPayload(makeCtx([]));
      expect(out.name).toBe('test-surface');
      expect(out.status).toBe('enabled');
      expect(out.tags).toEqual(['x']);
    });

    it('routes inbound rate-limit to access_point', () => {
      const out = registry.buildPayload(
        makeCtx([
          {
            id: 'rl1',
            type: 'rate-limit',
            parentId: 'access-point',
            config: { requests: '100', window_secs: '60' },
          },
        ])
      );
      expect(out.access_point.rate_limit).toEqual({ requests: 100, window_secs: 60 });
    });

    it('aggregates custom-metadata entries from multiple nodes', () => {
      const out = registry.buildPayload(
        makeCtx([
          { id: 'm1', type: 'custom-metadata', config: { entries: [{ key: 'a', value: '1' }] } },
          {
            id: 'm2',
            type: 'custom-metadata',
            config: { entries: [{ key: 'b', value: '2' }], scope: 'request' },
          },
        ])
      );
      expect(out.target.custom_metadata).toEqual({
        enabled: true,
        payload: { a: '1', b: '2' },
      });
    });

    it('routes extension-validation to access_point only', () => {
      const out = registry.buildPayload(
        makeCtx([
          {
            id: 'e',
            type: 'extension-validation',
            config: { required_extensions: 'foo, bar' },
          },
        ])
      );
      expect(out.access_point.extension_validation).toEqual({
        required_extensions: ['foo', 'bar'],
      });
      expect(out.target?.extension_rules).toBeUndefined();
    });

    it('omits sections for absent elements', () => {
      const out = registry.buildPayload(makeCtx([]));
      expect(out.target?.payment_policy).toBeUndefined();
      expect(out.target?.identity_injection).toBeUndefined();
      expect(out.target?.networking).toBeUndefined();
    });
  });

  describe('deletable', () => {
    it('marks the surface singleton as not deletable', () => {
      expect(registry.get('surface')!.deletable).toBe(false);
    });

    it('leaves all other elements deletable by default', () => {
      const undeletable = registry
        .all()
        .filter(d => d.deletable === false)
        .map(d => d.type)
        .sort();
      // human + caller are auto-injected actors that are also locked
      // (the d3 simulation has hard link dependencies on them).
      // local-gateway-hop + remote-gateway are synthesised view-only
      // nodes with no presence in builder state, so they are also locked.
      // The pipe spine (source, request/response guards, judge, LLM, jury,
      // response) is auto-created and fixed; only the optional pipe
      // decorations (rate-limit, cost-tracking, override-policy) are
      // drag-on / removable.
      expect(undeletable).toEqual(
        [
          'caller',
          'human',
          'ide-catalog',
          'ide-response',
          'ide-source',
          'local-gateway-hop',
          'pipe-decider',
          'pipe-judge',
          'pipe-jury',
          'pipe-prompt-guard',
          'pipe-response',
          'pipe-source',
          'pipe-upstream',
          'pipe-witness-request',
          'pipe-witness-response',
          'remote-channel',
          'remote-gateway',
          'surface',
          'target-variant',
        ].sort()
      );
    });
  });

  describe('configSurface', () => {
    it('defaults to sidebar for normal-sized panels', () => {
      // rate-limit fits in the 320–600px sidebar
      expect(registry.get('rate-limit')!.configSurface).toBeUndefined();
    });
  });

  describe('buildPayload contract (PayloadSlice[] API)', () => {
    function makeCtx(nodes: any[]) {
      return {
        protocol: 'a2a',
        surfaceMeta: { name: 'test', tags: [], status: 'enabled' },
        allNodes: nodes,
        nodesOfType: (type: string) => nodes.filter(n => n.type === type),
        firstNodeOfType: (type: string) => nodes.find(n => n.type === type),
      };
    }

    it('every element with a buildPayload returns slices in the expected shape', () => {
      // For an element that has runtime nodes, calling its buildPayload
      // returns either undefined or an array where every entry has a
      // non-empty string path and a defined value. Sanity check on the
      // contract.
      const probe = (def: any, nodes: any[]) => {
        if (!def.buildPayload) return;
        const slices = def.buildPayload(makeCtx(nodes));
        if (slices === undefined) return;
        expect(Array.isArray(slices)).toBe(true);
        for (const s of slices) {
          expect(typeof s.path).toBe('string');
          expect(s.path.length).toBeGreaterThan(0);
          expect(s.value).toBeDefined();
        }
      };
      probe(registry.get('rate-limit'), [
        {
          id: 'r',
          type: 'rate-limit',
          parentId: 'access-point',
          config: { requests: '1', window_secs: '1' },
        },
      ]);
      probe(registry.get('custom-metadata'), [
        { id: 'm', type: 'custom-metadata', config: { entries: [{ key: 'a', value: '1' }] } },
      ]);
      probe(registry.get('extension-validation'), [
        { id: 'e', type: 'extension-validation', config: { required_extensions: 'foo' } },
      ]);
    });

    it('migrated elements that emit at well-known paths declare them via payloadPath', () => {
      const expected: Record<string, string> = {
        'rate-limit': 'access_point.rate_limit',
        networking: 'target.networking',
        'extension-rules': 'target.extension_rules',
        'custom-metadata': 'target.custom_metadata',
      };
      for (const [type, path] of Object.entries(expected)) {
        const def = registry.get(type as any)!;
        expect(def.payloadPath).toBe(path);
        expect(def.buildPayload).toBeDefined();
      }
    });

    it('deep-merges slices into nested paths without clobbering siblings', () => {
      // custom-metadata (target.custom_metadata) and rate-limit
      // (access_point.rate_limit) write to different nested paths and
      // must coexist without clobbering their parent objects.
      const out = registry.buildPayload(
        makeCtx([
          { id: 'm', type: 'custom-metadata', config: { entries: [{ key: 'a', value: '1' }] } },
          {
            id: 'rl',
            type: 'rate-limit',
            parentId: 'access-point',
            config: { requests: '10', window_secs: '1' },
          },
        ])
      );
      expect(out.target.custom_metadata).toEqual({ enabled: true, payload: { a: '1' } });
      expect(out.access_point.rate_limit).toEqual({ requests: 10, window_secs: 1 });
    });

    it('skips writing when buildPayload returns undefined', () => {
      const out = registry.buildPayload(makeCtx([]));
      expect(out.identity_slots?.protected).toBeUndefined();
      expect(out.target?.payment_policy).toBeUndefined();
      expect(out.access_point?.rate_limit).toBeUndefined();
    });
  });
});
