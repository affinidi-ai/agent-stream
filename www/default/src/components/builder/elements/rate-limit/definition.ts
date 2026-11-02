import * as Cap from '../capabilities';
import type { NodeDefinition } from '../types';
import { positiveIntError } from '../validators';
import RateLimitPanel from './RateLimitPanel';

/**
 * Convert the panel's flat config shape into the wire-format
 * RateLimitConfig object. Used by the AP-level `access_point.rate_limit`
 * slice.
 */
export function rateLimitConfigToWire(c: any): Record<string, any> | undefined {
  if (!c?.requests) return undefined;
  return {
    requests: parseInt(c.requests),
    window_secs: parseInt(c.window_secs) || 60,
    ...(c.burst ? { burst: parseInt(c.burst) } : {}),
  };
}

export const rateLimitDefinition: NodeDefinition = {
  type: 'rate-limit',
  label: 'Rate Limit',
  description: 'Per-route or per-caller request rate limiting',
  icon: '\uf625', // fa-gauge-high
  paletteIcon: 'fa-tachometer-alt',
  color: '#fd7e14',
  shape: 'circle',
  defaultRadius: 14,
  resizable: true,
  resizeRange: { min: 16, max: 60 },
  draggable: true,
  containedInSurface: false,
  edgeConstrained: false,
  xWeight: 0.3,
  stage: 'middleware',
  cardinality: 'multi',
  paletteCategory: 'enhancement',
  paletteOrder: 3,
  dropMode: 'edge',
  help: {
    title: 'Rate Limit',
    bodyHtml: `
      <p>Cap how many requests can flow through this Surface in a fixed
      time window. Once the cap is hit the Gateway short-circuits with a
      throttling error — HTTP 429 for HTTP-style protocols, or a
      JSON-RPC error for MCP — and the upstream agent never sees
      the request.</p>
      <p><strong>Where it docks:</strong> request side only. Drop on the
      caller → access-point arrow to limit the inbound surface.</p>
      <p><strong>Settings:</strong></p>
      <ul>
        <li><strong>Request limit</strong> — max number of requests per
        window (e.g. <code>1000</code>)</li>
        <li><strong>Time window (seconds)</strong> — size of the rolling
        bucket (e.g. <code>60</code> = per minute)</li>
        <li><strong>Burst</strong> <em>(optional)</em> — allow short
        spikes above the steady-state rate before throttling kicks in</li>
      </ul>
      <p>The limit is per-Surface; counters reset when the window rolls
      over.</p>
    `,
  },
  // Rate limiting only makes sense on the request side (we don't throttle
  // server\u2192caller responses). Element only docks on request arrows.
  directionality: 'request',
  provides: [Cap.PIPELINE_EDGE, Cap.CONFIGURABLE],
  requires: {
    dropOnEdge: [Cap.RATE_LIMIT_TARGET],
  },
  incompleteReason: c => {
    if (!c.requests) return 'Request limit is required';
    if (!c.window_secs) return 'Time window is required';
    return null;
  },
  validate: c => {
    const errs: Array<{ field?: string; message: string }> = [];
    const r = positiveIntError('requests', c.requests, 'Request limit');
    if (r) errs.push(r);
    const w = positiveIntError('window_secs', c.window_secs, 'Time window');
    if (w) errs.push(w);
    return errs;
  },
  ConfigPanel: RateLimitPanel,
  payloadPath: 'access_point.rate_limit',
  // Pre-fill defaults so a freshly-dropped rate limit "just works".
  defaultConfig: () => ({ requests: '1000', window_secs: '60' }),
  summary: c => (c?.requests ? `${c.requests}/${c.window_secs || 60}s` : null),
  buildPayload: ctx => {
    // Slot identity is the source of truth: the AP→MA `request:rate-limit`
    // slot is `ownedBy: 'source'` so an inbound rate limit always carries
    // that slotId.
    const inbound = ctx.nodesOfType('rate-limit').find(n => {
      return (
        n.slotId === 'request:rate-limit' ||
        (!n.slotId && (!n.parentId || n.parentId === 'access-point'))
      );
    });
    const value = rateLimitConfigToWire(inbound?.config);
    if (!value) return undefined;
    return [
      {
        path: 'access_point.rate_limit',
        value,
      },
    ];
  },
};
