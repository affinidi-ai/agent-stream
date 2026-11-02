import type { CanvasNode } from '../SurfaceCanvas';
import type { SurfaceNodeType } from '../nodeTypes';

/**
 * Stable id prefixes for the synthesised nodes. Synthetic nodes never
 * enter `state.nodes`, so they are not persisted and do not affect
 * `buildPayload`/`buildCanvasBlob`. The prefixes also let downstream
 * code recognise a click target as synthetic.
 */
export const SYNTH_HOP_PREFIX = '__synth_gw_hop__';
export const SYNTH_REMOTE_PREFIX = '__synth_remote_gw__';
export const SYNTH_REMOTE_CHANNEL_PREFIX = '__synth_remote_ch__';

// Parent config fields that back the user-editable names of the
// synthesised nodes. The synth nodes themselves are view-only — the
// name is persisted on the underlying target so it survives
// across renders and reloads.
export const FABRIC_HOP_NAME_FIELD = 'fabric_hop_name';
export const FABRIC_REMOTE_GW_NAME_FIELD = 'fabric_remote_gateway_name';
export const FABRIC_REMOTE_CHANNEL_NAME_FIELD = 'fabric_remote_channel_name';

export function isSyntheticFabricNodeId(id: string | undefined | null): boolean {
  if (!id) return false;
  return (
    id.startsWith(SYNTH_HOP_PREFIX) ||
    id.startsWith(SYNTH_REMOTE_PREFIX) ||
    id.startsWith(SYNTH_REMOTE_CHANNEL_PREFIX)
  );
}

/**
 * Map a synthesised node id back to its underlying parent (the
 * target that owns the `fabric://` endpoint) plus the parent
 * `config` field that stores this synth node's user-editable name.
 * Returns null when the id isn't a recognised synth id.
 */
export function resolveSyntheticNameBinding(
  id: string
): { parentId: string; field: string } | null {
  if (id.startsWith(SYNTH_HOP_PREFIX)) {
    return { parentId: id.substring(SYNTH_HOP_PREFIX.length), field: FABRIC_HOP_NAME_FIELD };
  }
  if (id.startsWith(SYNTH_REMOTE_PREFIX)) {
    return {
      parentId: id.substring(SYNTH_REMOTE_PREFIX.length),
      field: FABRIC_REMOTE_GW_NAME_FIELD,
    };
  }
  if (id.startsWith(SYNTH_REMOTE_CHANNEL_PREFIX)) {
    return {
      parentId: id.substring(SYNTH_REMOTE_CHANNEL_PREFIX.length),
      field: FABRIC_REMOTE_CHANNEL_NAME_FIELD,
    };
  }
  return null;
}

interface FabricRef {
  kind: 'fabric';
  gateway_id: string;
  gateway_channel: string;
}

type EndpointRef = FabricRef;

/**
 * Pull `gateway_id`/`gateway_channel` from a node's config. Falls back
 * to parsing the `fabric://` URL when the explicit fields are missing
 * (older surfaces saved before the panel started persisting them).
 */
function fabricRefForNode(node: CanvasNode): EndpointRef | null {
  const cfg = node.config ?? {};
  const endpoint: string =
    typeof cfg.target_endpoint === 'string'
      ? cfg.target_endpoint
      : typeof cfg.endpoint === 'string'
        ? cfg.endpoint
        : '';
  if (endpoint.startsWith('fabric://')) {
    let gw: string = typeof cfg.gateway_id === 'string' ? cfg.gateway_id : '';
    let ch: string = typeof cfg.gateway_channel === 'string' ? cfg.gateway_channel : '';
    if (!gw || !ch) {
      const path = endpoint.substring('fabric://'.length);
      const parts = path.split('/');
      if (!gw) gw = parts[0] || '';
      if (!ch) ch = parts[1] || '';
    }
    if (!gw || !ch) return null;
    return { kind: 'fabric', gateway_id: gw, gateway_channel: ch };
  }
  return null;
}

/**
 * Returns a node-display list with a synthesised
 * `local-gateway-hop → remote-gateway` chain inserted in place of the
 * existing `npc-endpoint` child for the surface Target whose endpoint
 * is a `fabric://` URL.
 *
 * The transformation is purely view-side: the original `state.nodes`
 * array is untouched, so persistence (`buildCanvasBlob`) and edit
 * gestures continue to operate on the unchanged data model. A user
 * who toggles the Target's destination back to a direct URL gets
 * the original `npc-endpoint` rendering on the next render — no
 * mutation, no migration.
 *
 * When `surfaceSize` is provided, the synthesised `local-gateway-hop`
 * is snapped onto the surface perimeter (south edge for the target)
 * so it visually sits on the surface boundary — the gateway-to-gateway
 * hop represents the point at which traffic leaves this gateway, so it
 * belongs on the surface edge alongside the AP and target. The
 * `remote-gateway` then sits further outward, off-surface, where the
 * original `npc-endpoint` would have rendered.
 */
export function synthesizeFabricCanvasNodes(
  nodes: CanvasNode[],
  surfaceSize?: { w: number; h: number }
): CanvasNode[] {
  if (!Array.isArray(nodes) || nodes.length === 0) return nodes;

  // Index npc-endpoint nodes by the parent they sit on so we can hide
  // exactly the one that the synthesised chain replaces (and reuse its
  // canvas position so the visuals don't jump).
  const npcByParent = new Map<string, CanvasNode>();
  for (const n of nodes) {
    if (n.type === 'npc-endpoint' && n.parentId) {
      npcByParent.set(n.parentId, n);
    }
  }

  // Find every parent that should expand into the synthetic chain.
  const expansions: Array<{ parent: CanvasNode; ref: EndpointRef }> = [];
  for (const n of nodes) {
    if (n.type !== 'target') continue;
    const ref = fabricRefForNode(n);
    if (!ref) continue;
    expansions.push({ parent: n, ref });
  }

  if (expansions.length === 0) return nodes;

  // Hide the npc-endpoints that are being replaced, then append the
  // synthesised chain entries.
  const replacedNpcIds = new Set<string>();
  for (const exp of expansions) {
    const npc = npcByParent.get(exp.parent.id);
    if (npc) replacedNpcIds.add(npc.id);
  }

  const out: CanvasNode[] = [];
  for (const n of nodes) {
    if (replacedNpcIds.has(n.id)) continue;
    out.push(n);
  }

  for (const exp of expansions) {
    const hopId = `${SYNTH_HOP_PREFIX}${exp.parent.id}`;
    const remoteId = `${SYNTH_REMOTE_PREFIX}${exp.parent.id}`;

    // Geometry: anchor the chain to the parent (target) so it
    // stays on the parent's band (target sits on the south surface
    // edge). The original npc-endpoint
    // position — when present — tells us where the chain should
    // *end* (typically just past the surface edge, as placed by
    // auto-layout for the outbound npc); the hop sits midway. When
    // no npc position is available (e.g. user just toggled to
    // fabric://), fall back to a default outward hop along the
    // parent's natural outbound axis (east for target).
    const parentPos = exp.parent.position;
    // Distance the remote gateway sits past the hop, off-surface.
    // Tuned to keep enough room between the GW-hop on the surface
    // border and the external `Remote GW` glyph so the connecting
    // arrow + its label are clearly legible.
    const REMOTE_BEYOND_HOP = 147;
    // Distance the remote-channel external actor hangs below the
    // remote gateway. Vertical (south) by request so the chain reads
    // top-to-bottom: hop → remote GW → remote channel.
    const REMOTE_CHANNEL_DROP = 110;

    let hopPos: { x: number; y: number } | undefined;
    let remotePos: { x: number; y: number } | undefined;
    if (parentPos) {
      // Force the chain onto the parent's band so the arrows render
      // cleanly even if a stale npc position drifted off-axis.
      const bandY = parentPos.y;
      // The Target can sit anywhere inside the surface and any
      // middleware that re-parents it shifts the persisted position
      // around — reading its offset as a direction sends the chain to
      // a random side — so always emit due east.
      const dirX = 1;
      const dirY = 0;
      // Snap the hop onto the surface perimeter along that
      // direction. The hop visualises the boundary at which traffic
      // leaves this gateway — it belongs ON the surface edge
      // alongside the AP and target. Falls back to a fixed outward
      // offset only when surface dimensions are unavailable or the
      // parent already sits on/past the perimeter.
      if (surfaceSize) {
        const halfW = surfaceSize.w / 2;
        const halfH = surfaceSize.h / 2;
        const tCandidates: number[] = [];
        if (Math.abs(dirX) > 0.001) {
          const targetX = dirX > 0 ? halfW : -halfW;
          const t = (targetX - parentPos.x) / dirX;
          if (t > 0.05) tCandidates.push(t);
        }
        if (Math.abs(dirY) > 0.001) {
          const targetY = dirY > 0 ? halfH : -halfH;
          const t = (targetY - parentPos.y) / dirY;
          if (t > 0.05) tCandidates.push(t);
        }
        if (tCandidates.length > 0) {
          const tEdge = Math.min(...tCandidates);
          hopPos = {
            x: parentPos.x + dirX * tEdge,
            y: parentPos.y + dirY * tEdge,
          };
        }
      }
      if (!hopPos) {
        // No surfaceSize — place the hop a fixed step outward.
        const len = Math.hypot(dirX, dirY) || 1;
        const stepX = (dirX / len) * REMOTE_BEYOND_HOP;
        const stepY = (dirY / len) * REMOTE_BEYOND_HOP;
        hopPos = { x: parentPos.x + stepX, y: parentPos.y + stepY };
      }
      // Remote gateway sits one more step past the hop along the
      // same outward direction, off-surface.
      const len = Math.hypot(dirX, dirY) || 1;
      const rStepX = (dirX / len) * REMOTE_BEYOND_HOP;
      const rStepY = (dirY / len) * REMOTE_BEYOND_HOP;
      remotePos = { x: hopPos.x + rStepX, y: hopPos.y + rStepY };
      // Keep the chain locked to the parent's band so arrows render
      // as straight lines.
      hopPos.y = bandY;
      remotePos.y = bandY;
    }

    // Names persisted on the parent — surface them as the synth
    // node's `config.name` so the default Name field in the
    // properties panel reads and writes them transparently. The
    // routing of the write back to the parent's config happens in
    // the click/update layer (see `resolveSyntheticNameBinding`).
    const parentCfg = exp.parent.config ?? {};
    const hopName =
      typeof parentCfg[FABRIC_HOP_NAME_FIELD] === 'string'
        ? (parentCfg[FABRIC_HOP_NAME_FIELD] as string)
        : '';
    const remoteGwName =
      typeof parentCfg[FABRIC_REMOTE_GW_NAME_FIELD] === 'string'
        ? (parentCfg[FABRIC_REMOTE_GW_NAME_FIELD] as string)
        : '';
    const remoteChName =
      typeof parentCfg[FABRIC_REMOTE_CHANNEL_NAME_FIELD] === 'string'
        ? (parentCfg[FABRIC_REMOTE_CHANNEL_NAME_FIELD] as string)
        : '';

    const hop: CanvasNode = {
      id: hopId,
      type: 'local-gateway-hop' as SurfaceNodeType,
      label: hopName || 'GW',
      configured: true,
      parentId: exp.parent.id,
      config: { name: hopName, kind: 'fabric' },
      ...(hopPos ? { position: hopPos } : {}),
      connectionDirection: 'outbound',
    };

    const remoteConfig: Record<string, any> = {
      name: remoteGwName,
      kind: 'fabric',
      gateway_id: exp.ref.gateway_id,
      gateway_channel: exp.ref.gateway_channel,
    };

    const remote: CanvasNode = {
      id: remoteId,
      type: 'remote-gateway' as SurfaceNodeType,
      label: remoteGwName || 'Remote GW',
      configured: true,
      parentId: hopId,
      config: remoteConfig,
      ...(remotePos ? { position: remotePos } : {}),
      connectionDirection: 'outbound',
      description: 'Remote GW + Agent Surface',
    };

    // Remote-channel external actor hangs vertically south of the
    // remote GW. It represents the channel endpoint on the remote
    // gateway that this fabric:// route lands on.
    const remoteChannelId = `${SYNTH_REMOTE_CHANNEL_PREFIX}${exp.parent.id}`;
    const remoteChannelPos = remotePos
      ? { x: remotePos.x, y: remotePos.y + REMOTE_CHANNEL_DROP }
      : undefined;
    const remoteChannelConfig: Record<string, any> = {
      name: remoteChName,
      kind: 'fabric',
      gateway_id: exp.ref.gateway_id,
      gateway_channel: exp.ref.gateway_channel,
    };
    const remoteChannel: CanvasNode = {
      id: remoteChannelId,
      type: 'remote-channel' as SurfaceNodeType,
      label: remoteChName || 'Remote Surface',
      configured: true,
      parentId: remoteId,
      config: remoteChannelConfig,
      ...(remoteChannelPos ? { position: remoteChannelPos } : {}),
      connectionDirection: 'outbound',
      description: 'Agent Surfaces on the remote gateway',
    };

    out.push(hop, remote, remoteChannel);
  }

  return out;
}
