/**
 * Pure auto-layout algorithm for the surface builder.
 *
 * Layout rules:
 *   • AP is always on the WEST edge of the surface.
 *   • MA sits at the centre of the interior bounding box.
 *   • Outbound MA-NPCs hop EAST, aligned with MA's y.
 *   • Middleware sit at evenly distributed t along their pipe with
 *     a canonical lateral offset.
 *   • Every pair of connected anchors enforces a MIN_EDGE_LEN of
 *     edge-to-edge arrow length so no link collapses to a stub.
 *   • Surface width and height are grown to fit the interior with
 *     padding; the layout result is recentred so the geometric mean
 *     of the interior sits on the surface centre.
 */

import type { CanvasNode } from './SurfaceCanvas';
import { registry } from './elements';
import { deriveEdges } from './elements/edges/deriveEdges';
import { getArchetype } from './elements/edges/archetypes';
import type { SlotDirection } from './elements/edges/types';
import {
  JUROR_ROW_GAP_X,
  JUROR_ROW_Y,
  jurorRowOffsetX,
  jurorSlotPosition,
} from '../shared/jurorModel';
import { llmToolSlotPosition, LLM_TOOL_ROW_Y } from './elements/pipe/definitions';
import { WITNESS_RISE } from '../shared/witnessModel';

export interface AutoLayoutResult {
  surfaceSize: { w: number; h: number };
  positions: Array<{ id: string; x: number; y: number }>;
}

const MIN_W = 460;
const MIN_H = 200;
const NPC_HOP = 70; // edge-to-edge gap between surface and external NPC
const MIN_EDGE_LEN = 70; // min edge-to-edge arrow length between connected anchors
const MW_SLOT_W = 60; // horizontal budget per middleware slot along a pipe
const LATERAL = 28; // perpendicular offset of middleware glyph from pipe
// Extra horizontal clearance for east-going MA→outbound-NPC links so the
// arrow tip doesn't land on top of the NPC name label (which renders
// centred below the NPC and extends left of the NPC's circle).
const EAST_NPC_LABEL_CLEARANCE = 40;
const GRID = 10;
const snap = (v: number) => Math.round(v / GRID) * GRID;
const SURFACE_PAD = 30;

function radiusOf(n: CanvasNode, fallback = 24): number {
  return n.radius ?? fallback;
}

/** Stable ordinal of a juror node from its stored `jurorIndex` (0 if absent). */
function jurorOrdinalOf(n: CanvasNode): number {
  const idx = (n.config as { jurorIndex?: unknown } | undefined)?.jurorIndex;
  return typeof idx === 'number' ? idx : 0;
}

/** Stable ordinal of a candidate node from its stored `candidateIndex`. */
function candidateOrdinalOf(n: CanvasNode): number {
  const idx = (n.config as { candidateIndex?: unknown } | undefined)?.candidateIndex;
  return typeof idx === 'number' ? idx : 0;
}

// ── Pipe-scope layout constants ──────────────────────────────────
// A pipe is a fixed left→right chain, so its auto-layout is a direct
// placement (not the surface archetype solver). The whole chain sits
// on the surface centre line, evenly spaced PIPE_SPINE_GAP apart so
// every arrow body has the same length. The surface half-width is
// derived from the chain span plus PIPE_EDGE_PAD so the edge-
// constrained Access Point / Response sit cleanly on the west/east
// perimeter (the per-tick canvas snap in constrainToSurfaceEdge picks
// the nearest edge — the pad is the west/east horizontal distance
// from the AP's chain position, so it must stay below the surface
// half-height to beat the top/bottom edges when the chain is short).
// Kept in step with MAX_EDGE_NODE_RADIUS in SurfaceCanvas so the AP
// visually reads as attached to the boundary rather than floating.
const PIPE_SPINE_GAP = 140;
const PIPE_EDGE_PAD = 40;
const PIPE_DECO_Y = 140;
// LLM-bound tools (Web Search / Web Fetch) rise in a top-biased row above the
// LLM — the mirror of the Decider candidate row below — connected by an
// orthogonal bus. Shared with the drop placement so both agree.
const PIPE_TOOL_ROW_Y = LLM_TOOL_ROW_Y;
const PIPE_HALF_H = 150;
// Decider mode places the candidate row well below the decider, leaves a
// generous margin below the candidates and beside the outermost one, and only
// a small clearance above the spine — the surface then hugs the content
// asymmetrically (the spine no longer sits on the vertical midline).
const PIPE_CANDIDATE_ROW_Y = 300;
const PIPE_CANDIDATE_BOTTOM_PAD = 64;
const PIPE_CANDIDATE_SIDE_PAD = 56;
const PIPE_TOP_PAD = 100;
// Vertical clearance between an off-spine anchor (the LLM tool row above the
// spine, the witness circles + juror row below it) and the surface boundary.
// Tighter than SURFACE_PAD so the surface hugs these anchors.
const PIPE_ANCHOR_PAD = 20;
// Jurors get extra breathing room below the row before the surface boundary.
const PIPE_JUROR_BOTTOM_PAD = PIPE_ANCHOR_PAD + 20;
// An LLM tool's type label ("Web Search" / "Web Fetch") renders above its
// glyph, so reserve the label height on top of the anchor pad — otherwise the
// label butts against the surface's top border.
const PIPE_TOOL_LABEL_PAD = 20;

// ── IDE-scope layout constants ───────────────────────────────────
// An IDE surface is a short chain: Access Point → Catalogue (hero), with the
// front-door governance gates riding that request edge and the member LLM
// Surfaces fanned out below the catalogue (mirroring decider → candidates).
// The catalogue sits at x=0 (visual centre); the edge-constrained source
// snaps to the west perimeter at -halfW.
const IDE_HALF_W = 420;
const IDE_SPINE_GAP = 140;
const IDE_HALF_H = 150;
// Baseline distance from the catalogue (y=0) to the member row when no gate
// chips are docked to any member — tight so the empty catalogue reads as a
// compact fan-out. Each docked chip adds `IDE_CHIP_DROP_STEP` on top of this,
// auto-lengthening the Catalogue → member drop so the chips seat with clear
// breathing room.
const IDE_MEMBER_ROW_Y_BASE = 160;
const IDE_MEMBER_BOTTOM_PAD = 64;
const IDE_MEMBER_SIDE_PAD = 56;
const IDE_TOP_PAD = 80;
/**
 * Extra vertical room reserved on the Catalogue → member drop per docked gate
 * chip, so the incoming vertical arrow is long enough to seat each chip with
 * plenty of breathing room (the chip glyph is ~28 px in diameter and carries a
 * name label pill below it). Kept in lockstep with the drop-fraction pinning
 * in `SurfaceCanvas.tsx` — a bigger drop just spaces the same chip fractions
 * further apart.
 */
const IDE_CHIP_DROP_STEP = 100;

/**
 * The stack slot (0-based) a per-member gate chip occupies on the incoming
 * vertical drop from the bus to the member. Upstream sign-in sits at slot 0
 * (closer to the bus); a Model Policy sits below it (slot 1) when an upstream
 * chip is also present, else at slot 0. Mirrored in the `SurfaceCanvas.tsx`
 * per-tick chip pinning.
 */
function ideMemberChipSlot(chip: CanvasNode, nodes: CanvasNode[]): number {
  if (chip.type === 'ide-member-upstream-auth') return 0;
  const hasUpstream = nodes.some(
    n => n.type === 'ide-member-upstream-auth' && n.parentId === chip.parentId
  );
  return hasUpstream ? 1 : 0;
}

/** Chip count docked to a given member (0..2 in v1). */
function ideMemberChipCount(memberId: string, nodes: CanvasNode[]): number {
  return nodes.filter(
    n =>
      (n.type === 'ide-member-upstream-auth' || n.type === 'ide-member-opa') &&
      n.parentId === memberId
  ).length;
}

/** Stable ordinal of an ide-member node from its stored `order` (0 if absent). */
function ideMemberOrdinalOf(n: CanvasNode): number {
  const idx = (n.config as { order?: unknown } | undefined)?.order;
  return typeof idx === 'number' ? idx : 0;
}

function computeIdeAutoLayout(nodes: CanvasNode[]): AutoLayoutResult {
  const positions: Array<{ id: string; x: number; y: number }> = [];

  const source = nodes.find(n => n.type === 'ide-source');
  const catalog = nodes.find(n => n.type === 'ide-catalog');
  const response = nodes.find(n => n.type === 'ide-response');

  // Front-door gates (OPA / rate limit) ride the Access Point → Catalogue
  // request edge. Each is an edge-drop node; they lay out inline along that
  // segment (like the pipe request gates), evenly spaced.
  const gates = nodes
    .filter(n => registry.get(n.type)?.dropMode === 'edge')
    .sort((a, b) => (a.position?.x ?? 0) - (b.position?.x ?? 0) || a.id.localeCompare(b.id));

  // The Catalogue is the hero at x=0. The edge-constrained Access Point snaps
  // to the west perimeter, so `halfW` must equal its distance from the hero.
  // Each gate splits the source → catalogue segment into one more equal
  // sub-edge, so the surface widens by one gap per gate.
  const halfWForGates = (gates.length + 1) * IDE_SPINE_GAP;
  let halfW = Math.max(IDE_HALF_W, halfWForGates);

  if (catalog) positions.push({ id: catalog.id, x: 0, y: 0 });
  if (source) positions.push({ id: source.id, x: -halfW, y: 0 });
  // The Response is the egress anchor, edge-constrained to the east perimeter
  // (symmetric to the Access Point on the west). The canvas re-snaps its x to
  // the border; y:0 keeps it on the spine and folds into the recentre below.
  if (response) positions.push({ id: response.id, x: halfW, y: 0 });
  gates.forEach((g, i) => {
    const t = (i + 1) / (gates.length + 1);
    positions.push({ id: g.id, x: -halfW + t * halfW, y: 0 });
  });

  // Member LLM Surfaces fan out in a single row beneath the catalogue,
  // mirroring the decider → candidate fan-out.
  const members = nodes
    .filter(n => n.type === 'ide-member')
    .sort((a, b) => ideMemberOrdinalOf(a) - ideMemberOrdinalOf(b) || a.id.localeCompare(b.id));

  let halfH = IDE_HALF_H;
  if (members.length > 0) {
    const memberR = Math.max(...members.map(n => radiusOf(n, 18)));
    const maxStep = Math.ceil((members.length - 1) / 2);
    const room = halfW - IDE_MEMBER_SIDE_PAD - memberR;
    const gap = Math.min(
      JUROR_ROW_GAP_X,
      Math.max(2 * memberR + 8, maxStep > 0 ? room / maxStep : JUROR_ROW_GAP_X)
    );
    let maxAbsX = 0;
    const memberX = new Map<string, number>();
    // Auto-lengthen the Catalogue → member drop when any member carries gate
    // chips, so the incoming vertical arrow has enough room to seat the chips
    // ON the drop (see the per-tick pinning in `SurfaceCanvas.tsx`).
    const maxChips = Math.max(0, ...members.map(m => ideMemberChipCount(m.id, nodes)));
    const memberRowY = IDE_MEMBER_ROW_Y_BASE + maxChips * IDE_CHIP_DROP_STEP;
    members.forEach((n, i) => {
      const x = jurorRowOffsetX(i, gap);
      memberX.set(n.id, x);
      positions.push({ id: n.id, x, y: memberRowY });
      maxAbsX = Math.max(maxAbsX, Math.abs(x) + memberR);
    });

    // Seat per-member gate chips (upstream sign-in / Model Policy) on the
    // incoming vertical drop from the bus to the member, at the member's x.
    // The bus itself is computed per-tick in `SurfaceCanvas.tsx`; here we
    // approximate the drop as [catalogue_bottom, memberTop] and space chips
    // by `(slot+1) / (count+1)` fractions. The live pinning uses the real
    // (dynamic) bus Y, so this is only the initial seed.
    const chips = nodes.filter(
      n => n.type === 'ide-member-upstream-auth' || n.type === 'ide-member-opa'
    );
    for (const chip of chips) {
      const parentId = chip.parentId;
      if (!parentId || !memberX.has(parentId)) continue;
      const count = ideMemberChipCount(parentId, nodes);
      if (count === 0) continue;
      const slot = ideMemberChipSlot(chip, nodes);
      const dropTop = 0; // catalogue centre ≈ 0; the bus sits below this
      const dropBot = memberRowY - memberR;
      const chipY = dropTop + ((slot + 1) / (count + 1)) * (dropBot - dropTop);
      positions.push({ id: chip.id, x: memberX.get(parentId)!, y: chipY });
    }

    halfW = Math.max(halfW, maxAbsX + IDE_MEMBER_SIDE_PAD);

    // Recentre vertically so the surface wraps the content asymmetrically:
    // only `IDE_TOP_PAD` of clearance above the spine, extending down to seat
    // the member row (chips now ride the drop above members, not below them).
    const botExtent = memberRowY + memberR + IDE_MEMBER_BOTTOM_PAD;
    const cy = (botExtent - IDE_TOP_PAD) / 2;
    for (const p of positions) p.y -= cy;
    halfH = (IDE_TOP_PAD + botExtent) / 2;
  }

  return {
    surfaceSize: { w: halfW * 2, h: snap(halfH * 2) },
    positions: positions.map(p => ({ id: p.id, x: snap(p.x), y: snap(p.y) })),
  };
}

function computePipeAutoLayout(nodes: CanvasNode[]): AutoLayoutResult {
  const positions: Array<{ id: string; x: number; y: number }> = [];

  const source = nodes.find(n => n.type === 'pipe-source');
  const response = nodes.find(n => n.type === 'pipe-response');
  const spine = [
    nodes.find(n => n.type === 'pipe-prompt-guard' && n.config?.direction === 'request'),
    nodes.find(n => n.type === 'pipe-judge'),
    nodes.find(n => n.type === 'pipe-upstream'),
    nodes.find(n => n.type === 'pipe-jury'),
    nodes.find(n => n.type === 'pipe-prompt-guard' && n.config?.direction === 'response'),
  ];

  // Request gates (rate limit / OPA) ride the AP → request Prompt Guard
  // segment. Each gate splits that first segment into one more equal
  // sub-edge, so the chain past the first guard shifts east by one
  // PIPE_SPINE_GAP per gate and every arrow body — before and after a
  // gate — keeps the same length while the surface grows to fit.
  const gates = nodes
    .filter(n => registry.get(n.type)?.dropMode === 'edge')
    .sort((a, b) => (a.position?.x ?? 0) - (b.position?.x ?? 0) || a.id.localeCompare(b.id));

  // Ordered chain: AP, request gates, spine, Response — each one
  // PIPE_SPINE_GAP from the previous, recentred on x=0.
  const chain: CanvasNode[] = [];
  if (source) chain.push(source);
  chain.push(...gates);
  for (const n of spine) if (n) chain.push(n);
  if (response) chain.push(response);

  const span = Math.max(0, chain.length - 1) * PIPE_SPINE_GAP;
  const startX = -span / 2;
  chain.forEach((n, i) => positions.push({ id: n.id, x: startX + i * PIPE_SPINE_GAP, y: 0 }));

  // Edge-constrained AP / Response snap to the surface perimeter. Adding
  // PIPE_EDGE_PAD (one edge-node radius) beyond span/2 puts the west/east
  // edge just past the AP's chain position, so constrainToSurfaceEdge — the
  // per-tick nearest-edge snap in SurfaceCanvas — reliably picks west/east
  // over top/bottom (the pad is < PIPE_HALF_H). Without the pad the AP would
  // sit exactly on the perimeter but any halfW floor would leave the AP
  // interior and the tick loop would snap it to the top/bottom edge (the
  // hide-disabled 3-node case, where a 420 floor beat the 140 span/2).
  let halfW = span / 2 + PIPE_EDGE_PAD;

  // Realign edge-constrained source/response to the perimeter directly, so
  // downstream midpoint math (witness tether anchors, caller decorations)
  // sees the final rendered positions rather than their raw chain slots.
  // The per-tick canvas guard would snap them here anyway; doing it up front
  // avoids a first-frame jump and keeps auto-layout's midpoints in step with
  // the tick loop's live-position midpoints.
  const sourcePos = source ? positions.find(p => p.id === source.id) : undefined;
  if (sourcePos) sourcePos.x = -halfW;
  const responsePos = response ? positions.find(p => p.id === response.id) : undefined;
  if (responsePos) responsePos.x = halfW;

  // Expert-witness circles sit below the spine — out of the LLM tool row's way
  // above it — and point up to the request / response edge midpoints. The
  // tether tracks the edge and its arrowhead auto-orients, so below reads the
  // same as above. Placed before the decider's vertical recentre so they shift
  // with the spine at a constant offset; the surface reserves bottom headroom
  // for the drop.
  const witnessRequest = nodes.find(n => n.type === 'pipe-witness-request');
  const witnessResponse = nodes.find(n => n.type === 'pipe-witness-response');
  const witnessR = Math.max(
    witnessRequest ? radiusOf(witnessRequest, 16) : 16,
    witnessResponse ? radiusOf(witnessResponse, 16) : 16
  );
  // LLM-bound tools rise above the LLM in a top row (mirror of the candidates
  // below). Computed before `topPad` so the surface reserves headroom for the
  // row and the orthogonal tool bus.
  const tools = nodes
    .filter(n => registry.get(n.type)?.llmTool)
    // Group by palette category (Inputs before Tools) then palette order so the
    // two groups stay contiguous in the row instead of interleaving when their
    // palette orders collide.
    .sort((a, b) => {
      const ca = registry.get(a.type)?.paletteCategory ?? '';
      const cb = registry.get(b.type)?.paletteCategory ?? '';
      return (
        ca.localeCompare(cb) ||
        (registry.get(a.type)?.paletteOrder ?? 0) - (registry.get(b.type)?.paletteOrder ?? 0) ||
        a.id.localeCompare(b.id)
      );
    });
  const toolR = tools.length ? Math.max(...tools.map(n => radiusOf(n, 18))) : 0;
  const toolTopExtent = tools.length
    ? PIPE_TOOL_ROW_Y + toolR + PIPE_TOOL_LABEL_PAD + PIPE_ANCHOR_PAD
    : 0;
  const topPad = Math.max(PIPE_TOP_PAD, toolTopExtent);
  // Witness anchor along the visible chain. The canonical seam is
  // pgReq→judge / pgResp→response, but any of those nodes may be absent
  // (never configured) or Hide-disabled. Unified fallback: the request
  // witness anchors on the edge whose east endpoint is the first present of
  // {judge, upstream}, and the response witness on the edge whose west
  // endpoint is the last present of {pgResp, upstream} — the other endpoint
  // is always the chain neighbour of that node. So with a Judge present the
  // request witness gets pgReq→judge (unchanged); with the Judge gone it
  // slides one edge east to pgReq→upstream; with the Guard also gone it
  // slides again to source→upstream. Same story symmetrically for response.
  const chainIndex = (id: string): number => chain.findIndex(n => n.id === id);
  const anchorEdge = (
    canonicalId: string,
    fallbackId: string,
    direction: 'east' | 'west'
  ): [string, string] | null => {
    const pivotId = chainIndex(canonicalId) >= 0 ? canonicalId : fallbackId;
    const pivotIdx = chainIndex(pivotId);
    if (pivotIdx < 0) return null;
    if (direction === 'east') {
      // Pivot is the west endpoint; the east endpoint is its chain successor.
      const eastIdx = pivotIdx + 1;
      return eastIdx < chain.length ? [pivotId, chain[eastIdx].id] : null;
    }
    // Pivot is the east endpoint; the west endpoint is its chain predecessor.
    const westIdx = pivotIdx - 1;
    return westIdx >= 0 ? [chain[westIdx].id, pivotId] : null;
  };
  const positionX = (id: string): number => positions.find(p => p.id === id)?.x ?? 0;
  if (witnessRequest) {
    // Request witness: pivot east on judge (canonical) or upstream (fallback).
    const edge = anchorEdge('pipe-judge', 'pipe-upstream', 'west');
    const x = edge ? (positionX(edge[0]) + positionX(edge[1])) / 2 : 0;
    positions.push({ id: witnessRequest.id, x, y: WITNESS_RISE });
  }
  if (witnessResponse) {
    // Response witness: pivot west on pgResp (canonical) or upstream (fallback).
    const edge = anchorEdge('pipe-prompt-guard-response', 'pipe-upstream', 'east');
    const x = edge ? (positionX(edge[0]) + positionX(edge[1])) / 2 : 0;
    positions.push({ id: witnessResponse.id, x, y: WITNESS_RISE });
  }

  // LLM tool row: one evenly-spaced row centred on the LLM (Inputs then Tools)
  // above the hero — the mirror of the Decider candidate row below it.
  if (tools.length > 0) {
    const llmX = positions.find(p => p.id === 'pipe-upstream')?.x ?? 0;
    let maxAbsX = 0;
    tools.forEach((n, i) => {
      const x = llmX + llmToolSlotPosition(i, tools.length).x;
      positions.push({ id: n.id, x, y: -PIPE_TOOL_ROW_Y });
      maxAbsX = Math.max(maxAbsX, Math.abs(x) + toolR);
    });
    halfW = Math.max(halfW, maxAbsX + PIPE_CANDIDATE_SIDE_PAD);
  }

  // Optional decorative-stage nodes dock in a centred row beneath the spine.
  const decorations = nodes.filter(n => registry.get(n.type)?.stage === 'decorative');
  const witnessBotExtent =
    witnessRequest || witnessResponse ? WITNESS_RISE + witnessR + PIPE_ANCHOR_PAD : 0;
  let halfH = Math.max(PIPE_HALF_H, topPad, witnessBotExtent);
  if (decorations.length > 0) {
    const sorted = [...decorations].sort(
      (a, b) => (a.position?.x ?? 0) - (b.position?.x ?? 0) || a.id.localeCompare(b.id)
    );
    const decoSpan = (sorted.length - 1) * PIPE_SPINE_GAP;
    const decoStartX = -decoSpan / 2;
    const decoR = Math.max(...sorted.map(n => radiusOf(n, 22)));
    sorted.forEach((n, i) => {
      positions.push({ id: n.id, x: decoStartX + i * PIPE_SPINE_GAP, y: PIPE_DECO_Y });
    });
    halfH = Math.max(halfH, PIPE_DECO_Y + decoR + SURFACE_PAD);
  }

  // Jurors dock beneath the spine. In `parallel`/`majority` they fan out in a
  // single horizontal row — juror 0 directly under the Jury, the rest right
  // then left — with the centre-to-centre gap clamped so the row stays inside
  // the surface width. In `serial` they stack in a vertical column under the
  // Jury so the layout mirrors the sequential hand-off; the surface grows
  // downward to seat the column.
  const jurors = nodes
    .filter(n => n.type === 'pipe-juror')
    .sort((a, b) => jurorOrdinalOf(a) - jurorOrdinalOf(b) || a.id.localeCompare(b.id));
  if (jurors.length > 0) {
    const juryX = positions.find(p => p.id === 'pipe-jury')?.x ?? 0;
    const juryMode = (nodes.find(n => n.id === 'pipe-jury')?.config as { jury?: { mode?: string } })
      ?.jury?.mode;
    const jurorR = Math.max(...jurors.map(n => radiusOf(n, 16)));
    if (juryMode === 'serial') {
      let maxAbsX = 0;
      let maxY = 0;
      jurors.forEach((n, i) => {
        const { x, y } = jurorSlotPosition('serial', i, juryX, 0);
        positions.push({ id: n.id, x, y });
        maxAbsX = Math.max(maxAbsX, Math.abs(x) + jurorR);
        maxY = Math.max(maxY, y + jurorR);
      });
      halfW = Math.max(halfW, maxAbsX + SURFACE_PAD);
      halfH = Math.max(halfH, maxY + PIPE_JUROR_BOTTOM_PAD);
    } else {
      const maxStep = Math.ceil((jurors.length - 1) / 2);
      // Largest gap that keeps the outermost juror inside the surface (the row
      // is anchored at juryX ≥ 0, so the east side binds first), floored so
      // glyphs never overlap.
      const room = halfW - SURFACE_PAD - jurorR - Math.abs(juryX);
      const gap = Math.min(
        JUROR_ROW_GAP_X,
        Math.max(2 * jurorR + 8, maxStep > 0 ? room / maxStep : JUROR_ROW_GAP_X)
      );
      let maxAbsX = 0;
      jurors.forEach((n, i) => {
        const { x, y } = jurorSlotPosition(juryMode, i, juryX, 0, gap);
        positions.push({ id: n.id, x, y });
        maxAbsX = Math.max(maxAbsX, Math.abs(x) + jurorR);
      });
      halfW = Math.max(halfW, maxAbsX + SURFACE_PAD);
      halfH = Math.max(halfH, JUROR_ROW_Y + jurorR + PIPE_JUROR_BOTTOM_PAD);
    }
  }

  // The Decider (when present) docks directly beneath the LLM hero, with its
  // candidates fanning across one horizontal row beneath it — mirroring the
  // jury → jurors fan-out. The decider's presence on the canvas is "decider
  // mode"; it is only here to lay out when the LLM panel switched it on.
  const decider = nodes.find(n => n.type === 'pipe-decider');
  if (decider) {
    const llmX = positions.find(p => p.id === 'pipe-upstream')?.x ?? 0;
    const deciderR = radiusOf(decider, 20);
    positions.push({ id: decider.id, x: llmX, y: PIPE_DECO_Y });
    let botExtent = Math.max(halfH, PIPE_DECO_Y + deciderR + SURFACE_PAD);

    const candidates = nodes
      .filter(n => n.type === 'pipe-candidate')
      .sort((a, b) => candidateOrdinalOf(a) - candidateOrdinalOf(b) || a.id.localeCompare(b.id));
    if (candidates.length > 0) {
      const candR = Math.max(...candidates.map(n => radiusOf(n, 18)));
      const maxStep = Math.ceil((candidates.length - 1) / 2);
      const room = halfW - PIPE_CANDIDATE_SIDE_PAD - candR - Math.abs(llmX);
      const gap = Math.min(
        JUROR_ROW_GAP_X,
        Math.max(2 * candR + 8, maxStep > 0 ? room / maxStep : JUROR_ROW_GAP_X)
      );
      let maxAbsX = 0;
      candidates.forEach((n, i) => {
        const x = llmX + jurorRowOffsetX(i, gap);
        positions.push({ id: n.id, x, y: PIPE_CANDIDATE_ROW_Y });
        maxAbsX = Math.max(maxAbsX, Math.abs(x) + candR);
      });
      halfW = Math.max(halfW, maxAbsX + PIPE_CANDIDATE_SIDE_PAD);
      botExtent = Math.max(botExtent, PIPE_CANDIDATE_ROW_Y + candR + PIPE_CANDIDATE_BOTTOM_PAD);
    }

    // Recentre vertically so the surface wraps the content asymmetrically:
    // only `topPad` of clearance sits above the spine (room for the LLM tool
    // row) while the box extends down to seat the decider + candidate row.
    const cy = (botExtent - topPad) / 2;
    for (const p of positions) p.y -= cy;
    halfH = (topPad + botExtent) / 2;
  }

  return {
    surfaceSize: { w: halfW * 2, h: snap(halfH * 2) },
    positions: positions.map(p => ({ id: p.id, x: snap(p.x), y: snap(p.y) })),
  };
}

export function computeAutoLayout(nodes: CanvasNode[]): AutoLayoutResult {
  if (nodes.some(n => n.type.startsWith('pipe-'))) {
    return computePipeAutoLayout(nodes);
  }
  if (nodes.some(n => n.type.startsWith('ide-'))) {
    return computeIdeAutoLayout(nodes);
  }

  const byId = new Map(nodes.map(n => [n.id, n] as const));
  const ap = nodes.find(n => n.type === 'access-point');
  const target = nodes.find(n => n.type === 'target');
  const npcs = nodes.filter(n => n.type === 'npc-endpoint' && n.parentId);
  const edges = deriveEdges(nodes);

  const apR = ap ? radiusOf(ap, 36) : 36;
  const maR = target ? radiusOf(target, 28) : 28;

  // ── NPC index ──────────────────────────────────────────────────
  const npcsByAnchor = new Map<string, CanvasNode[]>();
  for (const n of npcs) {
    if (!n.parentId) continue;
    const list = npcsByAnchor.get(n.parentId) ?? [];
    list.push(n);
    npcsByAnchor.set(n.parentId, list);
  }

  // ── Middleware counts per archetype ────────────────────────────
  const apMaEdge = edges.find(e => e.archetype === 'ap-ma');
  let mwOnApMa = 0;
  if (apMaEdge) {
    for (const occList of apMaEdge.slots.values()) mwOnApMa += occList.length;
  }
  let mwOnMaExternalMax = 0;
  for (const e of edges) {
    let n = 0;
    for (const occList of e.slots.values()) n += occList.length;
    if (e.archetype === 'ma-external') mwOnMaExternalMax = Math.max(mwOnMaExternalMax, n);
  }

  // ── Zones around MA (placed at surface centre x=0, y=0) ────────
  // West: AP — middleware — MA. AP sits this far west of MA.
  const westZone = apR + MIN_EDGE_LEN + mwOnApMa * MW_SLOT_W + maR;
  // East: MA — middleware — (outbound NPC if any). Used to size halfW
  // so the outbound NPC sits cleanly past the surface edge.
  const outboundNpcR = (() => {
    if (!target) return 18;
    const list = npcsByAnchor.get(target.id) ?? [];
    return list.length > 0 ? radiusOf(list[0], 18) : 18;
  })();
  const maNpcStack = target ? (npcsByAnchor.get(target.id)?.length ?? 0) : 0;
  // East zone (centre-of-MA → outbound-NPC-centre, when an outbound
  // NPC exists). The NPC then sits NPC_HOP past the surface right edge.
  const eastZone =
    maNpcStack > 0 ? maR + MIN_EDGE_LEN + mwOnMaExternalMax * MW_SLOT_W + outboundNpcR : 0;

  // ── Surface dimensions ─────────────────────────────────────────
  // AP is edge-constrained, meaning the runtime
  // `constrainToSurfaceEdge` will snap it to the nearest surface
  // perimeter edge. So halfW must equal the desired AP→MA distance
  // (so AP at -halfW sits at the intended westZone from MA).
  let halfW = Math.max(MIN_W / 2, westZone, eastZone);
  // NPC stack (outbound, when >1) extends MA's y range — keep room.
  const stackExtent = maNpcStack > 1 ? maR + (maNpcStack - 1) * 50 + SURFACE_PAD : 0;
  // Surface-bound free-floating nodes (e.g. Trust Registry) get laid
  // out in a row along the south interior band; reserve vertical room
  // so they sit inside the surface rectangle rather than colliding
  // with the MA / pipeline above them.
  const containedFree = nodes.filter(
    n => n.type !== 'target' && registry.get(n.type)?.containedInSurface
  );
  const containedR =
    containedFree.length === 0 ? 0 : Math.max(...containedFree.map(n => radiusOf(n, 22)));
  const containedRowExtent =
    containedFree.length > 0 ? maR + MIN_EDGE_LEN + containedR + SURFACE_PAD : 0;
  let halfH = Math.max(MIN_H / 2, maR + SURFACE_PAD, stackExtent, containedRowExtent);

  const positions: Array<{ id: string; x: number; y: number }> = [];

  // ── Anchor positions ───────────────────────────────────────────
  // MA at surface centre. AP on the west perimeter at -halfW.
  const maX = 0;
  const maY = 0;
  if (target) positions.push({ id: target.id, x: maX, y: maY });
  if (ap) positions.push({ id: ap.id, x: -halfW, y: maY });

  // ── Outbound MA NPC: hop east past the surface edge ────────────
  if (target) {
    const outboundList = npcsByAnchor.get(target.id) ?? [];
    if (outboundList.length > 0) {
      const r = radiusOf(outboundList[0], 18);
      // Add EAST_NPC_LABEL_CLEARANCE so the arrow tip lands well
      // clear of the NPC's name label (centred below the NPC and
      // typically extending past its left edge).
      const baseX = halfW + NPC_HOP + EAST_NPC_LABEL_CLEARANCE + r;
      for (let i = 0; i < outboundList.length; i++) {
        const offsetY = (i - (outboundList.length - 1) / 2) * 50;
        positions.push({ id: outboundList[i].id, x: baseX, y: maY + offsetY });
      }
    }
  }

  // ── Surface-bound free-floating nodes (e.g. Trust Registry) ────
  // Lay them out in a single row along the south interior band,
  // left-to-right, evenly spread across the surface width. Anchored
  // INSIDE the surface (y = halfH - r - PAD) so the surface-resize
  // clamp never has to push them around after the fact.
  if (containedFree.length > 0) {
    // Stable order so the same set always lands in the same slots.
    const sorted = [...containedFree].sort(
      (a, b) => (a.position?.x ?? 0) - (b.position?.x ?? 0) || a.id.localeCompare(b.id)
    );
    const rowY = halfH - containedR - SURFACE_PAD;
    const innerW = halfW * 2 - 2 * (containedR + SURFACE_PAD);
    const step = sorted.length > 1 ? innerW / (sorted.length - 1) : 0;
    const startX = -halfW + containedR + SURFACE_PAD;
    for (let i = 0; i < sorted.length; i++) {
      const x = sorted.length === 1 ? 0 : startX + i * step;
      positions.push({ id: sorted[i].id, x, y: rowY });
    }
  }

  // ── Middleware: evenly spaced along their pipe ─────────────────
  const newPosOf = (id: string): { x: number; y: number } | undefined => {
    const written = positions.find(p => p.id === id);
    if (written) return { x: written.x, y: written.y };
    const cn = byId.get(id);
    return cn?.position;
  };
  for (const edge of edges) {
    const arch = getArchetype(edge.archetype);
    if (!arch) continue;
    for (const dir of arch.directions as readonly SlotDirection[]) {
      const slots = arch.slots.filter(s => s.direction === dir).sort((a, b) => a.order - b.order);
      const occupants: string[] = [];
      for (const s of slots) {
        const list = edge.slots.get(s.id) ?? [];
        for (const id of list) occupants.push(id);
      }
      if (occupants.length === 0) continue;
      const srcId = dir === 'request' ? edge.endpoints.source : edge.endpoints.target;
      const tgtId = dir === 'request' ? edge.endpoints.target : edge.endpoints.source;
      const sp = newPosOf(srcId);
      const tgtP = newPosOf(tgtId);
      if (!sp || !tgtP) continue;
      const ldx = tgtP.x - sp.x;
      const ldy = tgtP.y - sp.y;
      const llen = Math.sqrt(ldx * ldx + ldy * ldy) || 1;
      const ux = ldx / llen;
      const uy = ldy / llen;
      const nx = -uy;
      const ny = ux;
      const occCount = occupants.length;
      for (let i = 0; i < occCount; i++) {
        const t = (i + 1) / (occCount + 1);
        const bx = sp.x + ux * llen * t;
        const by = sp.y + uy * llen * t;
        const x = bx + nx * LATERAL;
        const y = by + ny * LATERAL;
        positions.push({ id: occupants[i], x, y });
      }
    }
  }

  return {
    surfaceSize: { w: snap(halfW * 2), h: snap(halfH * 2) },
    positions: positions.map(p => ({ id: p.id, x: snap(p.x), y: snap(p.y) })),
  };
}
