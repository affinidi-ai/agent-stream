/**
 * Read-only `deriveEdges(nodes)` adapter. Reconstructs `DerivedEdge[]`
 * from today's `parentId` + direction conventions without changing any
 * behaviour.
 *
 * Behavioural callers (renderer, drop handler) still use their existing
 * paths. This adapter provides a tested oracle for the derived model
 * while callers migrate over.
 */

import type { CanvasNode } from '../../SurfaceCanvas';
import type { DerivedEdge, SlotId, SlotDirection } from './types';
import { getArchetype, ANY_EDGE_MW } from './archetypes';

/**
 * Resolve the slot id an occupant belongs to within an archetype, by
 * matching the element's `type` against each slot's `accepts`. Falls
 * back to the direction's catch-all `'*'` slot when the archetype
 * declares one. Returns `undefined` when no slot matches AND no
 * catch-all exists, so callers can drop the orphan instead of
 * inventing a phantom slot id.
 */
function slotForOccupant(
  archetypeId: string,
  occupantType: string,
  direction: SlotDirection
): SlotId | undefined {
  const arch = getArchetype(archetypeId);
  if (!arch) return undefined;
  let catchAll: SlotId | undefined;
  for (const s of arch.slots) {
    if (s.direction !== direction) continue;
    if (s.accepts === ANY_EDGE_MW) {
      catchAll = s.id;
      continue;
    }
    if (s.accepts.includes(occupantType as never)) return s.id;
  }
  return catchAll;
}

// Archetypes themselves now live in `./archetypes.ts`. This module is
// the read-only adapter that reconstructs `DerivedEdge[]` from today's
// `parentId` + `direction` conventions.

function isEdgeMiddleware(type: string): boolean {
  // The current renderer treats anything whose dropMode is 'edge' as
  // chain middleware. The adapter uses the same heuristic today: a
  // node is middleware on an edge when it has a parentId, is not an
  // anchor, is not a canvas-only decoration.
  if (
    type === 'access-point' ||
    type === 'target' ||
    type === 'human' ||
    type === 'caller' ||
    type === 'surface'
  ) {
    return false;
  }
  if (type === 'npc-endpoint') return false;
  if (type === 'local-gateway-hop' || type === 'remote-gateway') return false;
  if (type === 'identity') return false;
  return true;
}

interface AdapterContext {
  byId: Map<string, CanvasNode>;
  childrenOf: Map<string, CanvasNode[]>;
}

function buildContext(nodes: CanvasNode[]): AdapterContext {
  const byId = new Map<string, CanvasNode>();
  const childrenOf = new Map<string, CanvasNode[]>();
  for (const n of nodes) {
    byId.set(n.id, n);
  }
  for (const n of nodes) {
    if (!n.parentId) continue;
    const arr = childrenOf.get(n.parentId) ?? [];
    arr.push(n);
    childrenOf.set(n.parentId, arr);
  }
  return { byId, childrenOf };
}

/**
 * Walk the request chain backwards from `targetId` until we reach
 * `expectedSourceId` (or run out). Returns the chain in source→target
 * order, EXCLUDING the endpoints themselves.
 */
function walkRequestChain(
  ctx: AdapterContext,
  expectedSourceId: string,
  targetId: string
): string[] {
  const chain: string[] = [];
  let cur = ctx.byId.get(targetId);
  for (let i = 0; cur && i < 32; i++) {
    const parent = cur.parentId ? ctx.byId.get(cur.parentId) : undefined;
    if (!parent) break;
    if (parent.id === expectedSourceId) return chain;
    if (!isEdgeMiddleware(parent.type)) break;
    chain.unshift(parent.id);
    cur = parent;
  }
  return chain;
}

/** Response middleware sits as direct children of the response source with `direction === 'response'`. */
function collectResponseMw(ctx: AdapterContext, respSourceId: string): string[] {
  const kids = ctx.childrenOf.get(respSourceId) ?? [];
  // Excludes per-endpoint occupants of OTHER archetypes' slots (e.g.
  // `identity` lives on ma-external as a child of MA but must not
  // also be claimed by ap-ma's response chain). `isEdgeMiddleware`
  // is the canonical "is this a chain mw type" predicate.
  return kids.filter(k => k.direction === 'response' && isEdgeMiddleware(k.type)).map(k => k.id);
}

function makeEdge(archetype: string, sourceId: string, targetId: string): DerivedEdge {
  return {
    id: `${archetype}:${sourceId}:${targetId}`,
    archetype,
    endpoints: { source: sourceId, target: targetId },
    slots: new Map<SlotId, string[]>(),
  };
}

function pushSlot(edge: DerivedEdge, slotId: SlotId, occupantId: string): void {
  const list = edge.slots.get(slotId) ?? [];
  list.push(occupantId);
  edge.slots.set(slotId, list);
}

/**
 * Pure derivation. Reads `nodes` and emits one `DerivedEdge` per logical
 * edge in the surface, with each slot populated from today's encoding.
 *
 * No side effects, no I/O, no registry access. Safe to call per render.
 */
export function deriveEdges(nodes: ReadonlyArray<CanvasNode>): DerivedEdge[] {
  const ctx = buildContext(nodes as CanvasNode[]);
  const out: DerivedEdge[] = [];

  const ap = nodes.find(n => n.type === 'access-point' && !n.parentId);
  const ma = nodes.find(n => n.type === 'target');

  // ── AP ↔ MA ────────────────────────────────────────────────────────
  if (ap && ma) {
    const edge = makeEdge('ap-ma', ap.id, ma.id);

    // Request chain: AP → … mw … → MA. Bucket each occupant into its
    // typed slot (one per element type) — the renderer walks slots in
    // declared order and emits a deterministic chain.
    const reqChain = walkRequestChain(ctx, ap.id, ma.id);
    for (const id of reqChain) {
      const node = ctx.byId.get(id);
      const slotId = slotForOccupant('ap-ma', node?.type ?? '', 'request');
      if (slotId) pushSlot(edge, slotId, id);
    }

    // Response mw: children of MA (response source) with direction=response.
    for (const id of collectResponseMw(ctx, ma.id)) {
      const node = ctx.byId.get(id);
      const slotId = slotForOccupant('ap-ma', node?.type ?? '', 'response');
      if (slotId) pushSlot(edge, slotId, id);
    }

    // Per-endpoint identity slots (excluded from chain mw above):
    //   request:identity-inbound   — child of AP (ownedBy: 'source')
    //   response:identity-protected — child of MA (ownedBy: 'target')
    // Without this explicit recovery the dropped node sits in the
    // graph but is never bound to a slot, so the renderer treats it
    // as free-floating instead of locking it onto the AP→MA arrow.
    const apKidsForIdentity = ctx.childrenOf.get(ap.id) ?? [];
    const inboundIdentity = apKidsForIdentity.find(
      c =>
        c.type === 'identity' &&
        (c.id === 'identity-inbound' || c.slotId === 'request:identity-inbound')
    );
    if (inboundIdentity) pushSlot(edge, 'request:identity-inbound', inboundIdentity.id);
    const maKidsForIdentity = ctx.childrenOf.get(ma.id) ?? [];
    const protectedIdentity = maKidsForIdentity.find(
      c =>
        c.type === 'identity' &&
        (c.id === 'identity-protected' ||
          c.slotId === 'response:identity-protected' ||
          // Legacy bare slotId predates external/protected disambiguation;
          // only claim it when the id resolves to identity-protected so
          // identity-external stays on ma-external.
          (c.slotId === 'response:identity' && c.id === 'identity-protected'))
    );
    if (protectedIdentity) pushSlot(edge, 'response:identity-protected', protectedIdentity.id);

    out.push(edge);
  }

  // ── MA ↔ External (one edge per visible target → external arrow) ──
  // The "external" endpoint is one of:
  //   - `npc-endpoint` parented on `target` (direct URL targets)
  //   - the synthesised `local-gateway-hop` parented on `target` (the
  //     first hop of a fabric:// chain — the second hop, `hop → remote-gateway`,
  //     is decorative and is not made droppable for Agent Identity).
  //
  // Identity is the only element that lives on this edge. It uses
  // `ownedBy: 'source'` (per-endpoint slot) so the dropped node is a
  // direct child of `target` with canonical id `identity-target`. The
  // npc/hop's parent stays unchanged.
  if (ma) {
    const externalTypes = new Set<string>(['npc-endpoint', 'local-gateway-hop', 'remote-gateway']);
    // Recover the per-endpoint identity occupant attached to MA. There
    // is at most one (canonical id `identity-target`) — we surface it on
    // every ma-external edge so the user sees the slot occupied no
    // matter which arrow they look at.
    const identityNode = (ctx.childrenOf.get(ma.id) ?? []).find(
      c =>
        c.type === 'identity' &&
        (c.id === 'identity-external' ||
          c.slotId === 'response:identity-external' ||
          // Legacy slotId used before identity slots were disambiguated.
          // Only treat the bare `response:identity` as external when the
          // node id resolves to identity-external — otherwise it belongs
          // to AP→MA's protected slot and stays there.
          (c.slotId === 'response:identity' && c.id === 'identity-external'))
    );
    // ma-external networking is per-endpoint with ownedBy: 'source' on
    // the request direction — i.e. a child of MA.
    const networkingExternalNode = (ctx.childrenOf.get(ma.id) ?? []).find(
      c =>
        c.type === 'networking' &&
        (c.direction ?? 'request') === 'request' &&
        (!c.slotId || c.slotId === 'request:networking')
    );
    // ma-external rate-limit is per-endpoint with ownedBy: 'source'.
    const rateLimitExternalNode = (ctx.childrenOf.get(ma.id) ?? []).find(
      c =>
        c.type === 'rate-limit' &&
        (c.direction ?? 'request') === 'request' &&
        c.slotId === 'request:rate-limit'
    );
    // ma-external credential-delegation is per-endpoint with
    // ownedBy: 'source' on the request direction (child of MA).
    // Without this explicit recovery the dropped node sits in the
    // graph but isn't bound to a slot, so the renderer treats it as
    // free-floating instead of locking it onto the MA→External arrow.
    const credentialDelegationNode = (ctx.childrenOf.get(ma.id) ?? []).find(
      c =>
        c.type === 'credential-delegation' &&
        (c.direction ?? 'request') === 'request' &&
        (!c.slotId || c.slotId === 'request:credential-delegation')
    );
    for (const n of nodes) {
      if (!externalTypes.has(n.type)) continue;
      if (n.parentId !== ma.id) continue;
      const edge = makeEdge('ma-external', ma.id, n.id);
      if (identityNode) pushSlot(edge, 'response:identity-external', identityNode.id);
      if (networkingExternalNode) pushSlot(edge, 'request:networking', networkingExternalNode.id);
      if (rateLimitExternalNode) pushSlot(edge, 'request:rate-limit', rateLimitExternalNode.id);
      if (credentialDelegationNode)
        pushSlot(edge, 'request:credential-delegation', credentialDelegationNode.id);
      out.push(edge);
    }
  }

  // ── Pipe inbound (pipe-source → pipe-upstream) ───────────────────────
  // The pipe builder reuses the generic spine but its inbound gates (OPA
  // policy, rate limit) are per-endpoint slots owned by the source,
  // mirroring the agent surface's inbound identity. The spine's
  // intermediate nodes (prompt guard, judge) are bucketed into the
  // catch-all so a drop on the first inbound segment resolves to this
  // edge; the gate nodes themselves are recovered as direct children of
  // pipe-source.
  const pipeSource = nodes.find(n => n.type === 'pipe-source');
  const pipeUpstream = nodes.find(n => n.type === 'pipe-upstream');
  if (pipeSource && pipeUpstream) {
    const edge = makeEdge('pipe-inbound', pipeSource.id, pipeUpstream.id);
    const reqChain = walkRequestChain(ctx, pipeSource.id, pipeUpstream.id);
    for (const id of reqChain) {
      const node = ctx.byId.get(id);
      const slotId = slotForOccupant('pipe-inbound', node?.type ?? '', 'request');
      if (slotId) pushSlot(edge, slotId, id);
    }
    const pipeCallerAuth = (ctx.childrenOf.get(pipeSource.id) ?? []).find(
      c => c.type === 'pipe-caller-auth'
    );
    if (pipeCallerAuth) pushSlot(edge, 'request:pipe-caller-auth', pipeCallerAuth.id);
    const opa = (ctx.childrenOf.get(pipeSource.id) ?? []).find(c => c.type === 'pipe-opa-policy');
    if (opa) pushSlot(edge, 'request:pipe-opa-policy', opa.id);
    const rateLimit = (ctx.childrenOf.get(pipeSource.id) ?? []).find(
      c => c.type === 'pipe-rate-limit'
    );
    if (rateLimit) pushSlot(edge, 'request:pipe-rate-limit', rateLimit.id);
    out.push(edge);
  }

  // ── IDE inbound (ide-source → ide-catalog) ───────────────────────────
  // The IDE builder reuses the pipe pattern: front-door governance (OPA,
  // rate limit) are per-endpoint slots owned by the source, so the gate
  // nodes are recovered as direct children of ide-source. The AP→Catalogue
  // arrow itself is drawn by the shared spine loop in SurfaceCanvas; the
  // derived edge exists so `findEdgeForHit` can resolve an edge-drop and
  // so the gate glyphs can be projected onto the inbound line.
  const ideSource = nodes.find(n => n.type === 'ide-source');
  const ideCatalog = nodes.find(n => n.type === 'ide-catalog');
  if (ideSource && ideCatalog) {
    const edge = makeEdge('ide-inbound', ideSource.id, ideCatalog.id);
    const reqChain = walkRequestChain(ctx, ideSource.id, ideCatalog.id);
    for (const id of reqChain) {
      const node = ctx.byId.get(id);
      const slotId = slotForOccupant('ide-inbound', node?.type ?? '', 'request');
      if (slotId) pushSlot(edge, slotId, id);
    }
    const ideCallerAuth = (ctx.childrenOf.get(ideSource.id) ?? []).find(
      c => c.type === 'ide-caller-auth'
    );
    if (ideCallerAuth) pushSlot(edge, 'request:ide-caller-auth', ideCallerAuth.id);
    const ideOpa = (ctx.childrenOf.get(ideSource.id) ?? []).find(c => c.type === 'ide-opa-policy');
    if (ideOpa) pushSlot(edge, 'request:ide-opa-policy', ideOpa.id);
    const ideRateLimit = (ctx.childrenOf.get(ideSource.id) ?? []).find(
      c => c.type === 'ide-rate-limit'
    );
    if (ideRateLimit) pushSlot(edge, 'request:ide-rate-limit', ideRateLimit.id);
    out.push(edge);
  }

  return out;
}
