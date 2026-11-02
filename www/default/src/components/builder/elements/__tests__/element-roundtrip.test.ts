import { registry } from '../index';
import type { PayloadContext } from '../types';

/**
 * Per-element integration test template.
 *
 * For each migrated element we exercise the full lifecycle the wizard
 * relies on:
 *
 *   1. Drop a node onto the canvas with a representative config.
 *   2. Mark `configured` based on `registry.isConfigured`.
 *   3. Run `registry.buildPayload` and check the slice was written at the
 *      expected path with the meaningful fields intact.
 *   4. Run `registry.nodesFromPayload` to recover nodes from the payload
 *      and assert we get back a node of the same type with at least the
 *      meaningful fields matching.
 *
 * The list below is the contract: adding a new element-with-payloadPath
 * should add a row here so the round-trip is guaranteed.
 */

interface Case {
  type: string;
  /**
   * Disambiguator when more than one case targets the same `type`
   * (e.g. an element that can write more than one payload path).
   * Used in `it()` titles only.
   */
  variant?: string;
  /**
   * Optional `slotId` to set on the dropped node. Required for
   * elements that route by slot. Without it the legacy id/parentId
   * fallback runs.
   */
  slotId?: string;
  /**
   * Optional `id` override for the dropped node. Defaults to `c.type`.
   * Set this when the slot's canonical id differs from the type
   * (e.g. identity-inbound).
   */
  nodeId?: string;
  /**
   * Optional `parentId` override on the dropped node. Some elements'
   * routing (rate-limit) inspects this for legacy fallback.
   */
  parentId?: string;
  /**
   * Optional `direction` override on the dropped node. Default is
   * unset (which `buildPayload` treats as 'request').
   */
  direction?: 'request' | 'response';
  /** Config the wizard would store on the canvas node. */
  config: any;
  /** Where the slice is expected to land in the surface payload. */
  payloadPath: string;
  /**
   * Subset of the slice we assert on (deep-equal). Keep this small —
   * each element panel has its own unit tests for shape details.
   */
  expectedSlice: any;
  /**
   * Optional: when the recovered panel config differs from the
   * persisted slice (because the element has a `configFromPayload`
   * adapter), assert against this shape on the round-trip pass instead.
   * Defaults to `expectedSlice`.
   */
  expectedRecoveredConfig?: any;
  /**
   * If the node won't survive the reverse pass (e.g. element is
   * surface-wide and the round-trip strips it), set this. Default true.
   */
  roundtripsToNode?: boolean;
  /**
   * Surface defaults that need to be present for `nodesFromPayload` to
   * see the slice — by default we add a populated access-point + target
   * because every payload has them.
   */
  extraNodes?: any[];
}

const cases: Case[] = [
  {
    type: 'rate-limit',
    config: { requests: '100', window_secs: '60' },
    payloadPath: 'access_point.rate_limit',
    expectedSlice: { requests: 100, window_secs: 60 },
  },
  {
    type: 'custom-metadata',
    config: {
      enabled: true,
      entries: [{ key: 'a', value: '1' }],
    },
    // Default direction is 'request' → lands on the request slice.
    payloadPath: 'target.custom_metadata',
    expectedSlice: { enabled: true, payload: { a: '1' } },
    // After round-trip the panel sees its own form shape (entries[]),
    // not the persisted API shape — `configFromPayload` rebuilds
    // entries from `payload`. Without this, the panel reloads as
    // empty and reports "must have at least one entry".
    expectedRecoveredConfig: {
      entries: [{ key: 'a', value: '1', target: 'header' }],
    },
  },
  {
    type: 'extension-rules',
    config: { default_action: 'allow', rules: [{ name: 'r', action: 'allow' }] },
    // Default direction is 'request' → request slice.
    payloadPath: 'target.extension_rules',
    expectedSlice: {
      default_action: 'allow',
      rules: [{ name: 'r', action: 'allow' }],
    },
  },
  {
    type: 'networking',
    parentId: 'tg',
    config: { timeout_secs: '30' },
    payloadPath: 'target.networking',
    expectedSlice: { timeout: { request_secs: 30 } },
  },
  {
    type: 'extension-validation',
    config: {
      required_extensions: 'ext-a, ext-b',
    },
    payloadPath: 'access_point.extension_validation',
    expectedSlice: {
      required_extensions: ['ext-a', 'ext-b'],
    },
    // configFromPayload converts the array back to a CSV string for
    // the panel's text input.
    expectedRecoveredConfig: {
      required_extensions: 'ext-a, ext-b',
    },
  },
];

function makeCtx(nodes: any[]): PayloadContext {
  return {
    protocol: 'a2a',
    surfaceMeta: { name: 'roundtrip', tags: [], status: 'enabled' },
    allNodes: nodes,
    nodesOfType: type => nodes.filter(n => n.type === type),
    firstNodeOfType: type => nodes.find(n => n.type === type),
  };
}

function readPath(obj: any, path: string): any {
  return path.split('.').reduce((acc, k) => (acc == null ? acc : acc[k]), obj);
}

function deepIncludes(actual: any, expected: any): void {
  if (Array.isArray(expected)) {
    expect(Array.isArray(actual)).toBe(true);
    expect(actual.length).toBeGreaterThanOrEqual(expected.length);
    expected.forEach((e, i) => deepIncludes(actual[i], e));
    return;
  }
  if (expected && typeof expected === 'object') {
    expect(actual).toBeDefined();
    for (const [k, v] of Object.entries(expected)) {
      deepIncludes(actual[k], v);
    }
    return;
  }
  expect(actual).toEqual(expected);
}

describe('Element round-trip (drop → configure → buildPayload → nodesFromPayload)', () => {
  for (const c of cases) {
    const title = c.variant ? `${c.type} (${c.variant})` : c.type;
    // eslint-disable-next-line jest/valid-title
    describe(title, () => {
      const dropNode = () => ({
        id: c.nodeId ?? c.type,
        type: c.type,
        label: '',
        configured: registry.isConfigured(c.type as any, c.config),
        config: c.config,
        ...(c.slotId ? { slotId: c.slotId } : {}),
        ...(c.parentId ? { parentId: c.parentId } : {}),
        ...(c.direction ? { direction: c.direction } : {}),
      });

      it('builds the expected slice at the declared payloadPath', () => {
        const def = registry.get(c.type as any)!;
        expect(def).toBeDefined();
        expect(def.buildPayload).toBeDefined();
        expect(def.payloadPath).toBeTruthy();

        const nodes = [
          {
            id: 'ap',
            type: 'access-point',
            label: 'AP',
            configured: true,
            config: { route: '/api' },
          },
          {
            id: 'tg',
            type: 'target',
            label: 'T',
            configured: true,
            config: { endpoint: 'http://example.com' },
          },
          ...(c.extraNodes ?? []),
          dropNode(),
        ];

        const payload = registry.buildPayload(makeCtx(nodes));
        const slice = readPath(payload, c.payloadPath);
        deepIncludes(slice, c.expectedSlice);
      });

      if (c.roundtripsToNode !== false) {
        it('round-trips: nodesFromPayload(buildPayload(...)) yields a node of the same type', () => {
          const nodes = [
            {
              id: 'ap',
              type: 'access-point',
              label: 'AP',
              configured: true,
              config: { route: '/api' },
            },
            {
              id: 'tg',
              type: 'target',
              label: 'T',
              configured: true,
              config: { endpoint: 'http://example.com' },
            },
            ...(c.extraNodes ?? []),
            dropNode(),
          ];
          const payload = registry.buildPayload(makeCtx(nodes));
          const recovered = registry.nodesFromPayload(payload);
          // When a slotId was specified on the drop, recover the exact
          // node by slotId so multi-variant elements (policy) don't
          // collide on a plain `type` lookup.
          const recoveredOfType = c.slotId
            ? recovered.find(n => n.slotId === c.slotId)
            : recovered.find(n => n.type === c.type);
          expect(recoveredOfType).toBeDefined();
          deepIncludes(recoveredOfType!.config, c.expectedRecoveredConfig ?? c.expectedSlice);
        });
      }
    });
  }

  it('surface contract: every element with a payloadPath has at least one round-trip case', () => {
    // The audit list excludes elements that aren't simple "drop and
    // round-trip" middleware: anchors (access-point, target),
    // per-instance entries (target-variant), and surface-wide elements
    // that participate in different lifecycles (caller-auth). These
    // have their own dedicated tests.
    const exempt = new Set(['access-point', 'target', 'target-variant', 'caller-auth']);
    const expected = registry
      .all()
      .filter(d => d.payloadPath && !exempt.has(d.type))
      .map(d => d.type);
    const covered = new Set(cases.map(c => c.type));
    for (const t of expected) {
      expect(covered.has(t)).toBe(true);
    }
  });
});
