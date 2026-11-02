import type { SurfaceNodeType } from '../nodeTypes';
import type {
  BuilderScope,
  NodeDefinition,
  PayloadContext,
  PayloadSlice,
  Protocol,
  SurfaceContext,
} from './types';
import { getArchetype, ANY_EDGE_MW } from './edges/archetypes';

export interface DependencyWarning {
  severity: 'error' | 'warning';
  message: string;
}

class ElementRegistry {
  private definitions = new Map<SurfaceNodeType, NodeDefinition>();

  register(def: NodeDefinition): void {
    if (this.definitions.has(def.type)) {
      // Allow re-registration in HMR; warn in dev only.
      if (process.env.NODE_ENV !== 'production') {
        // eslint-disable-next-line no-console
        console.warn(`[ElementRegistry] Re-registering element type "${def.type}"`);
      }
    }
    this.definitions.set(def.type, def);
  }

  get(type: SurfaceNodeType | string): NodeDefinition | undefined {
    return this.definitions.get(type as SurfaceNodeType);
  }

  has(type: SurfaceNodeType | string): boolean {
    return this.definitions.has(type as SurfaceNodeType);
  }

  all(): NodeDefinition[] {
    return Array.from(this.definitions.values());
  }

  /** Protocol bound to this element, if any. */
  getProtocolForType(type: SurfaceNodeType | string | undefined | null): Protocol | undefined {
    if (!type) return undefined;
    return this.get(type)?.getProtocol?.();
  }

  /**
   * Elements available in the palette for a given protocol and scope.
   * Excludes core elements (auto-created), protocol-locked items that don't
   * match the current protocol, and (when `scope` is provided) elements
   * whose declared scope is neither the requested scope nor 'shared'.
   *
   * An element with no explicit `scope` defaults to 'surface' — the vast
   * majority of registered elements are surface-only, so this keeps them out
   * of the Pipe palette without each definition having to opt out. Genuinely
   * cross-cutting elements must declare `scope: 'shared'` explicitly.
   *
   * Omitting the `scope` argument returns every matching element regardless
   * of scope — the back-compat path for callers that haven't been threaded
   * yet.
   */
  paletteItems(protocol: Protocol, scope?: BuilderScope): NodeDefinition[] {
    return this.all()
      .filter(d => !d.hiddenFromPalette)
      .filter(d => !d.protocols || d.protocols.includes(protocol))
      .filter(d => {
        if (!scope) return true;
        const declared = d.scope ?? 'surface';
        return declared === scope || declared === 'shared';
      })
      .sort((a, b) => {
        if (a.paletteCategory !== b.paletteCategory) {
          return a.paletteCategory.localeCompare(b.paletteCategory);
        }
        return a.paletteOrder - b.paletteOrder;
      });
  }

  /** Group palette items by category. */
  paletteByCategory(
    protocol: Protocol,
    scope?: BuilderScope
  ): Partial<Record<import('./types').PaletteCategory, NodeDefinition[]>> {
    const out: Partial<Record<import('./types').PaletteCategory, NodeDefinition[]>> = {};
    for (const def of this.paletteItems(protocol, scope)) {
      const list = out[def.paletteCategory] ?? [];
      list.push(def);
      out[def.paletteCategory] = list;
    }
    return out;
  }

  /**
   * Can an element of `elementType` be dropped on the edge between
   * a node of `sourceType` and a node of `targetType`?
   *
   * Returns true when every capability in `element.requires.dropOnEdge`
   * is provided by either the source or the target node.
   */
  canDropOnEdge(
    elementType: SurfaceNodeType | string,
    sourceType: SurfaceNodeType | string,
    targetType: SurfaceNodeType | string
  ): boolean {
    const element = this.get(elementType);
    const source = this.get(sourceType);
    const target = this.get(targetType);
    if (!element || !source || !target) return false;

    const required = element.requires.dropOnEdge;
    if (!required || required.length === 0) return false;

    const available = new Set([...source.provides, ...target.provides]);
    return required.every(cap => available.has(cap));
  }

  /**
   * Can this element be dropped directly on a specific node
   * (as a node-modifier rather than as an edge node)?
   */
  canDropOnNode(
    elementType: SurfaceNodeType | string,
    nodeType: SurfaceNodeType | string
  ): boolean {
    const element = this.get(elementType);
    const node = this.get(nodeType);
    if (!element || !node) return false;

    const required = element.requires.dropOnNode;
    if (!required || required.length === 0) return false;

    return required.every(cap => node.provides.includes(cap));
  }

  /**
   * Is the node configured? Derived from both `incompleteReason` (required
   * fields present) AND `validate` (present fields are well-formed). A
   * node with an invalid URL is reported the same as a missing one so the
   * canvas mirrors the sidebar's fault state.
   */
  isConfigured(type: SurfaceNodeType | string, config: any): boolean {
    if (this.getIncompleteReason(type, config) !== null) return false;
    return this.getValidationErrors(type, config).length === 0;
  }

  /**
   * Returns a reason the node is intentionally disabled (switched off), or
   * null when it is active. Drives the greyed-out canvas treatment for
   * opt-in middleware (judge / jury / prompt guard) without marking the node
   * as a fault. Delegates to the element's optional `mutedReason`.
   */
  getMutedReason(type: SurfaceNodeType | string, config: any): string | null {
    const def = this.get(type);
    if (!def?.mutedReason) return null;
    return def.mutedReason(config ?? {});
  }

  /** Whether the node is intentionally disabled (greyed, not a fault). */
  isMuted(type: SurfaceNodeType | string, config: any): boolean {
    return this.getMutedReason(type, config) !== null;
  }

  /**
   * Returns a human-readable reason why a node is incomplete, or null if it
   * is fully configured. Delegates to the element's `incompleteReason` (a
   * mandatory contract member); returns null for unknown types.
   */
  getIncompleteReason(type: SurfaceNodeType | string, config: any): string | null {
    const def = this.get(type);
    if (!def) return null;
    return def.incompleteReason(config ?? {});
  }

  /**
   * Run the element's format validators (regex / range / etc.). Returns
   * an empty array when the element has none. Validation errors are
   * separate from `incompleteReason` and from cross-element dependency
   * warnings — they catch malformed values in already-filled fields.
   */
  getValidationErrors(
    type: SurfaceNodeType | string,
    config: any
  ): Array<{ field?: string; message: string }> {
    const def = this.get(type);
    if (!def?.validate) return [];
    try {
      return def.validate(config ?? {}) ?? [];
    } catch {
      return [];
    }
  }

  /**
   * Single fault reason suitable for canvas chrome (ring tooltip + label
   * text under the node). Prefers `incompleteReason` (missing required
   * fields) and falls back to the first validation error so a malformed
   * URL surfaces on the canvas the same way the sidebar shows it.
   */
  getFaultReason(type: SurfaceNodeType | string, config: any): string | null {
    const incomplete = this.getIncompleteReason(type, config);
    if (incomplete) return incomplete;
    const errs = this.getValidationErrors(type, config);
    return errs.length > 0 ? errs[0].message : null;
  }

  /** Evaluate feature dependencies for a node in the surface context. */
  getDependencyWarnings(
    type: SurfaceNodeType | string,
    config: any,
    context: SurfaceContext
  ): DependencyWarning[] {
    const def = this.get(type);
    if (!def?.featureDependencies) return [];
    const cfg = config ?? {};
    return def.featureDependencies
      .filter(dep => {
        try {
          return dep.condition(cfg, context);
        } catch {
          return false;
        }
      })
      .filter(dep => {
        try {
          return !dep.check(cfg, context);
        } catch {
          return true;
        }
      })
      .map(dep => ({ severity: dep.severity, message: dep.message }));
  }

  /**
   * Build the full surface payload from registered elements.
   *
   * Single-pass execution: every element's `buildPayload(ctx)` is invoked
   * and the returned slices are deep-merged into the payload at their
   * declared path. Slices are sorted by path depth ascending (parents
   * before children) and then by `paletteOrder` so deterministic ordering
   * is preserved across renders.
   *
   * Slice merging never replaces existing leaf objects wholesale — it
   * deep-merges so siblings written by other elements coexist (e.g.
   * `target.endpoint` from `target` and `target.custom_metadata` from
   * `custom-metadata`).
   */
  buildPayload(ctx: PayloadContext): any {
    const payload: any = {
      ...(ctx.surfaceMeta.surface_id ? { surface_id: ctx.surfaceMeta.surface_id } : {}),
      name: ctx.surfaceMeta.name,
      ...(ctx.surfaceMeta.description ? { description: ctx.surfaceMeta.description } : {}),
      status: ctx.surfaceMeta.status ?? 'enabled',
      tags: ctx.surfaceMeta.tags,
    };

    interface Pending {
      def: NodeDefinition;
      slice: PayloadSlice;
    }
    const pending: Pending[] = [];
    for (const def of this.all()) {
      if (!def.buildPayload) continue;
      let slices: PayloadSlice[] | undefined;
      try {
        slices = def.buildPayload(ctx);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error(`[ElementRegistry] buildPayload failed for ${def.type}:`, err);
        continue;
      }
      if (!slices || slices.length === 0) continue;
      for (const slice of slices) {
        if (!slice || typeof slice.path !== 'string' || slice.path.length === 0) continue;
        if (slice.value === undefined || slice.value === null) continue;
        pending.push({ def, slice });
      }
    }

    pending.sort((a, b) => {
      const ad = a.slice.path.split('.').length;
      const bd = b.slice.path.split('.').length;
      if (ad !== bd) return ad - bd;
      return a.def.paletteOrder - b.def.paletteOrder;
    });

    for (const { slice } of pending) {
      deepMergePath(payload, slice.path, slice.value);
    }

    return payload;
  }

  /**
   * Reverse of {@link buildPayload}: reconstruct a list of canvas nodes from
   * a saved surface payload. Used by the detail page to render the canvas in
   * read-only / re-edit mode without forcing each element to ship a bespoke
   * deserializer.
   *
   * Reconstruction rules:
   * - Always emit `access-point` and `target` nodes, with `target` parented
   *   to the access-point so the primary chain renders.
   * - For every registered element with a `payloadPath`, look up the slice in
   *   the payload. When present (and non-empty for objects), emit a node with
   *   the slice as its config. Parenting is inferred from the path prefix
   *   (`target.*` → child of target, `access_point.*` → child of access-point,
   *   surface-wide elements → no parent).
   *
   * Element-specific slice → config conventions (e.g. transforming a
   * persisted shape back to wizard form fields) are out of scope here; the
   * panels read whatever shape they receive and degrade gracefully.
   */
  nodesFromPayload(payload: any): Array<{
    id: string;
    type: SurfaceNodeType;
    label: string;
    configured: boolean;
    config: any;
    parentId?: string;
    position?: { x: number; y: number };
    radius?: number;
    direction?: 'request' | 'response';
    slotId?: string;
  }> {
    type N = {
      id: string;
      type: SurfaceNodeType;
      label: string;
      configured: boolean;
      config: any;
      parentId?: string;
      position?: { x: number; y: number };
      radius?: number;
      direction?: 'request' | 'response';
      slotId?: string;
    };
    const nodes: N[] = [];

    // IDs are deterministic everywhere: singletons use their bare type
    // name (`access-point`, `target`, …). The canvas blob layered on
    // top uses the same scheme, so a node and its layout always merge
    // into a single record.
    const apConfig = payload?.access_point ?? {};
    const targetConfig = payload?.target ?? {};

    const apDef = this.get('access-point');
    const apPanelConfig = apDef?.configFromPayload
      ? apDef.configFromPayload(apConfig, payload)
      : apConfig;

    nodes.push({
      id: 'access-point',
      type: 'access-point',
      label: apDef?.label ?? 'Access Point',
      configured: this.isConfigured('access-point', apPanelConfig),
      config: apPanelConfig,
    });

    const targetDef = this.get('target');
    const targetPanelConfig = targetDef?.configFromPayload
      ? targetDef.configFromPayload(targetConfig, payload)
      : targetConfig;

    nodes.push({
      id: 'target',
      type: 'target',
      label: targetDef?.label ?? 'Target',
      configured: this.isConfigured('target', targetPanelConfig),
      config: targetPanelConfig,
    });

    /**
     * Materialise a node from a single slice path. Returns null when the
     * slice is missing or empty. Direction defaults to 'request'; pass
     * 'response' for the response-direction slice.
     */
    const emitFromSlice = (
      def: NodeDefinition,
      path: string,
      direction: 'request' | 'response',
      idSuffix?: string
    ): N | null => {
      const slice = readPath(payload, path);
      if (slice === undefined || slice === null) return null;
      if (typeof slice === 'object' && !Array.isArray(slice) && Object.keys(slice).length === 0) {
        return null;
      }
      if (Array.isArray(slice) && slice.length === 0) return null;
      if (
        typeof slice === 'object' &&
        !Array.isArray(slice) &&
        slice.enabled === false &&
        Object.keys(slice).every(k => k === 'enabled' || slice[k] === false || slice[k] == null)
      ) {
        return null;
      }

      const parentId = def.surfaceWide
        ? undefined
        : path.startsWith('target.')
          ? 'target'
          : path.startsWith('access_point.')
            ? 'access-point'
            : undefined;

      const panelConfig = def.configFromPayload ? def.configFromPayload(slice, payload) : slice;
      // Append id suffixes so multiple slices for the same element type
      // don't collide. Default request slice keeps the bare type name.
      const id = idSuffix ? `${def.type}-${idSuffix}` : def.type;
      // Middleware nodes (and other multi-instance elements) don't get
      // an auto-generated user-facing label — leaving label empty here
      // means the canvas renders no caption beneath the icon unless the
      // user explicitly sets one. Only the singleton anchor nodes
      // (target, access-point, surface) above auto-name themselves.
      return {
        id,
        type: def.type as SurfaceNodeType,
        label: '',
        configured: this.isConfigured(def.type, panelConfig),
        config: panelConfig,
        parentId,
        ...(direction === 'response' ? { direction: 'response' as const } : {}),
      };
    };

    // Non-edge-drop elements (mode: 'node' / 'canvas' / surface-wide)
    // still consult their own `payloadPath`/`responsePayloadPath`
    // declarations: they're anchored to nodes (credential-binding,
    // trust-registry) or live free on the surface (identity,
    // mcp-tools). The slot model only governs
    // edge-drop routing today; node-anchored hydration is unchanged.
    for (const def of this.all()) {
      if (def.type === 'access-point' || def.type === 'target') continue;
      if (def.dropMode === 'edge') continue; // handled by slot walk above
      if (!def.payloadPath) continue;
      const reqNode = emitFromSlice(def, def.payloadPath, 'request');
      if (reqNode) nodes.push(reqNode);
      if (def.responsePayloadPath) {
        const respNode = emitFromSlice(def, def.responsePayloadPath, 'response', 'response');
        if (respNode) nodes.push(respNode);
      }
    }
    const apMaArchetype = getArchetype('ap-ma');
    const maExternalArchetype = getArchetype('ma-external');
    // Map archetype id → owner node ids. Per-endpoint slots resolve
    // their `parentId`/`{owner}` against this lookup so each
    // archetype's source/target endpoints point to the correct
    // singleton anchor (ap-ma: access-point↔target,
    // ma-external: target↔external — only `source` is meaningful for
    // hydration since the external endpoint is not a persisted node).
    const archetypeOwners: Record<string, { source: string; target: string }> = {
      'ap-ma': { source: 'access-point', target: 'target' },
      'ma-external': { source: 'target', target: 'target' },
    };
    // Tracks payload paths already hydrated by an earlier archetype
    // so paths exposed on multiple archetypes (UX-aliased drop zones)
    // don't emit duplicate nodes. The archetype iteration order below
    // (ap-ma → ma-external) determines which slot wins.
    const consumedPayloadPaths = new Set<string>();
    for (const archetype of [apMaArchetype, maExternalArchetype]) {
      if (!archetype) continue;
      const owners = archetypeOwners[archetype.id];
      for (const slot of archetype.slots) {
        if (!slot.payloadPathTemplate) continue; // catch-all: no path
        if (slot.accepts === ANY_EDGE_MW) continue;
        // Some archetypes alias the same payload path on more than one
        // edge (e.g. `access_point.rate_limit` is exposed both on
        // ap↔ma and on ma↔external as a UX convenience for drag-drop).
        // Only the first archetype that owns the path should hydrate
        // it — otherwise we emit duplicate nodes (the second one
        // appears in the canvas as an orphan element pointing at the
        // wrong endpoint).
        if (consumedPayloadPaths.has(slot.payloadPathTemplate)) continue;
        const elementType = slot.accepts[0] as SurfaceNodeType;
        const def = this.get(elementType);
        if (!def) continue;
        const path = slot.payloadPathTemplate; // archetype slots never use {owner}
        const slice = readPath(payload, path);
        if (slice === undefined || slice === null) continue;
        if (typeof slice === 'object' && !Array.isArray(slice) && Object.keys(slice).length === 0) {
          continue;
        }
        if (Array.isArray(slice) && slice.length === 0) continue;
        if (
          typeof slice === 'object' &&
          !Array.isArray(slice) &&
          slice.enabled === false &&
          Object.keys(slice).every(k => k === 'enabled' || slice[k] === false || slice[k] == null)
        ) {
          continue;
        }

        consumedPayloadPaths.add(path);
        const panelConfig = def.configFromPayload ? def.configFromPayload(slice, payload) : slice;
        // Id format mirrors `useSurfaceBuilder.handleDrop`:
        //  - per-endpoint slot → `${type}-${owner}` (with `-response`
        //    suffix on response direction)
        //  - non-endpoint slot → bare type for request, `${type}-response`
        //    for response.
        let id: string;
        if (slot.ownedBy) {
          const owner = slot.ownedBy === 'source' ? owners.source : owners.target;
          id =
            slot.direction === 'response'
              ? `${elementType}-${owner}-response`
              : `${elementType}-${owner}`;
        } else {
          id = slot.direction === 'response' ? `${elementType}-response` : elementType;
        }
        // Identity slots share the same `type='identity'` across three
        // distinct edges; derive a stable id from the payload path so
        // protected (AP→MA response) and external (MA→External response)
        // don't collide on `identity-target-response`.
        if (elementType === 'identity') {
          if (path === 'identity_slots.inbound') id = 'identity-inbound';
          else if (path === 'identity_slots.protected') id = 'identity-protected';
          else if (path === 'identity_slots.external') id = 'identity-external';
        }

        const parentId = slot.ownedBy
          ? slot.ownedBy === 'source'
            ? owners.source
            : owners.target
          : path.startsWith('access_point.')
            ? 'access-point'
            : path.startsWith('target.')
              ? 'target'
              : undefined;

        nodes.push({
          id,
          type: elementType,
          label: '',
          configured: this.isConfigured(elementType, panelConfig),
          config: panelConfig,
          parentId,
          slotId: slot.id,
          ...(slot.direction === 'response' ? { direction: 'response' as const } : {}),
        });
      }
    }

    // Variants — always emit a surface-wide `target-variant` node,
    // even when the surface has no variants yet. The dedicated
    // top-left widget is the only entry point to the editor; the node
    // is hidden from the canvas (filtered in SurfaceBuilder) but its
    // config still carries `variants[]` and `default_variant_id` for
    // round-trip persistence. Prefer the north-star top-level
    // `variants` shape (`AgentSurface.variants`); fall back to the
    // legacy `target.variants` for surfaces saved before the migration.
    const useTopLevel = Array.isArray(payload?.variants) && payload.variants.length > 0;
    const variants: any[] = useTopLevel
      ? payload.variants
      : Array.isArray(payload?.target?.variants)
        ? payload.target.variants
        : [];
    const defaultVariantId = useTopLevel
      ? payload?.default_variant_id
      : payload?.target?.default_variant_id;
    const variantList = variants.map((v, idx) => {
      const id = v?.id || `target-variant-${idx + 1}`;
      // Identity-only shape for the panel. Legacy override fields
      // (endpoint, policy_definition_id, mpp_*, agent_card_*,
      // extensions, …) are no longer surfaced here — they live on
      // `surface.variants[].overrides` and are produced by the
      // (forthcoming) per-element `VariantEditingContext`.
      return {
        id,
        alias: typeof v?.alias === 'string' ? v.alias : '',
        name: typeof v?.name === 'string' ? v.name : '',
        enabled: v?.enabled !== false,
        ...(typeof v?.description === 'string' && v.description
          ? { description: v.description }
          : {}),
      };
    });
    nodes.push({
      id: 'target-variant',
      type: 'target-variant',
      label: 'Variants',
      configured: variantList.length === 0 || variantList.every(v => !!v.alias && !!v.name),
      config: {
        variants: variantList,
        ...(typeof defaultVariantId === 'string' ? { default_variant_id: defaultVariantId } : {}),
      },
    });

    const blob = readCanvasBlob(payload?.canvas);
    if (blob) {
      const byId = new Map(nodes.map(n => [n.id, n] as const));
      const claimedIds = new Set<string>();
      for (const bn of blob.nodes) {
        let target = byId.get(bn.id);
        if (target) claimedIds.add(target.id);
        if (!target && bn.type) {
          // Adopt an unclaimed synthesized node of the same type when
          // the blob's id derives from a different archetype slot for
          // the same payload path. Example: `target.networking` is
          // exposed both on ap-ma (id `networking`) and on ma-external
          // with `ownedBy: 'source'` (id `networking-target`).
          // Hydration emits the ap-ma variant first; if the user
          // actually dropped on ma-external the blob carries
          // `networking-target`. Without adoption we'd render both.
          const candidates = nodes.filter(
            n =>
              n.type === bn.type &&
              !claimedIds.has(n.id) &&
              !byId.has(bn.id) &&
              !blob.nodes.some(b => b.id === n.id)
          );
          if (candidates.length === 1) {
            const adoptee = candidates[0];
            byId.delete(adoptee.id);
            adoptee.id = bn.id;
            byId.set(bn.id, adoptee);
            target = adoptee;
            claimedIds.add(bn.id);
          }
        }
        if (!target) {
          if (!bn.type) continue;
          // Compute `configured` from the blob's config rather than
          // hard-coding `true`. Otherwise an element that the user
          // dropped but never finished configuring (no payload slice
          // emitted because required fields were missing) reloads as
          // "configured" on the canvas while every other surface (the
          // panel banner, the elements list) computes the opposite from
          // `incompleteReason`. The canvas badge then disagrees with
          // the panel — exactly the "shows invalid on canvas, ok in
          // panel" symptom users report.
          const blobCfg = bn.config ?? {};
          target = {
            id: bn.id,
            type: bn.type as SurfaceNodeType,
            label: bn.label || bn.id,
            configured: this.isConfigured(bn.type as SurfaceNodeType, blobCfg),
            config: blobCfg,
            parentId: bn.parentId ?? undefined,
            ...(bn.slotId ? { slotId: bn.slotId } : {}),
          };
          nodes.push(target);
          byId.set(bn.id, target);
        }
        // Restore slotId from the blob if the slot-walker didn't set it
        // (e.g. the runtime payload slice was missing or the node was
        // canvas-only).
        if (target && !target.slotId && bn.slotId) {
          target.slotId = bn.slotId;
        }
        const blobConfig = bn.config;
        if (target && blobConfig && typeof blobConfig === 'object') {
          // Backend-truth fields (set by `nodesFromPayload`) win on key
          // collision; canvas-blob fields fill in UI-only keys (e.g.
          // `endpoint_type`, `route_prefix`, `route_suffix`,
          // `gateway_id`, `auth_type`) so the panel doesn't "reset"
          // after save. Without this, every save round-trip strips
          // those fields and the panel re-derives them on next mount.
          target.config = { ...blobConfig, ...(target.config ?? {}) };
          // Recompute `configured` after the merge — UI-only fields
          // pulled from the blob can flip validity (e.g. an element
          // whose `incompleteReason` looks at a field that isn't part
          // of the persisted payload slice).
          target.configured = this.isConfigured(target.type, target.config);
        }
        const overlay = readLayoutOverlay(bn);
        if (overlay.position) target.position = overlay.position;
        if (overlay.radius !== undefined) target.radius = overlay.radius;
        // The canvas blob is authoritative for layout-time parenting:
        // it captures middleware insertions (e.g. a node re-parented from
        // the access-point onto the managed agent or onto a freshly
        // dropped middleware node). Always honour an explicit overlay
        // parentId so reloads don't snap edges back to defaults.
        if (overlay.parentId !== undefined) {
          target.parentId = overlay.parentId || undefined;
        }
      }
    }

    return nodes;
  }
}

/**
 * Layout-only fields persisted alongside each node in the canvas blob.
 * Kept separate from the runtime config so the wizard can reason about
 * "where does this go on screen" independently of "what does this do".
 */
interface LayoutOverlay {
  position?: { x: number; y: number };
  radius?: number;
  /**
   * `string` → set this parent on the target node.
   * `null`   → explicitly clear the parent (the runtime had no
   *            parentId and the registry default should be ignored).
   * `undefined` → no opinion; keep whatever default `nodesFromPayload`
   *            already picked.
   */
  parentId?: string | null;
}

function readLayoutOverlay(bn: CanvasBlob['nodes'][number]): LayoutOverlay {
  const out: LayoutOverlay = {};
  if (bn.position && typeof bn.position.x === 'number' && typeof bn.position.y === 'number') {
    out.position = { x: bn.position.x, y: bn.position.y };
  }
  if (typeof bn.radius === 'number') out.radius = bn.radius;
  if (bn.parentId !== undefined) out.parentId = bn.parentId;
  return out;
}

/**
 * Shape persisted under `payload.canvas` — opaque to the backend, owned by
 * the management dashboard. Bumping `version` is the migration hook.
 */
export interface CanvasBlob {
  version: number;
  /** Persisted surface rectangle dimensions so resizes round-trip. */
  surface?: { width: number; height: number };
  /**
   * Persisted d3 zoom transform (pan + scale) so the canvas resumes
   * the same view on reload. Identity (`{x:0,y:0,k:1}`) is omitted at
   * write time. Cleared by the recentre button.
   */
  view?: { x: number; y: number; k: number };
  /**
   * Per-canvas view preferences. `hide_disabled` drives the toolbar
   * eye toggle that hides muted (opt-in / disabled) elements from
   * both the render and the auto-layout so a surface with unused
   * middleware presents cleanly. Omitted from the blob when every
   * flag is at its default (`false`).
   */
  settings?: { hide_disabled?: boolean };
  nodes: Array<{
    id: string;
    type?: string;
    label?: string;
    /**
     * `null` means "no parent" (explicit). `undefined` means the field
     * was not persisted. `string` is a normal parent id.
     */
    parentId?: string | null;
    position?: { x: number; y: number };
    radius?: number;
    /** Only persisted for canvas-only node types (NPCs, human, caller). */
    config?: any;
    /**
     * Slot identity (e.g. `'request:custom-metadata'`). Persisted so a
     * round-trip preserves which payload path this node owns even when
     * the runtime payload alone is ambiguous (e.g. an element whose
     * request and response sides map to different payload paths).
     */
    slotId?: string;
  }>;
}

const CANVAS_BLOB_VERSION = 1;

/**
 * Build the `canvas` blob from the live wizard nodes. Always emits layout
 * hints; emits config only for canvas-only node types so we don't duplicate
 * data that already lives in the runtime payload.
 */
export function buildCanvasBlob(
  nodes: Array<{
    id: string;
    type: string;
    label?: string;
    parentId?: string;
    position?: { x: number; y: number };
    radius?: number;
    config?: any;
    slotId?: string;
  }>,
  meta?: {
    surfaceSize?: { width: number; height: number };
    view?: { x: number; y: number; k: number } | null;
    settings?: { hide_disabled?: boolean } | null;
  }
): CanvasBlob {
  const view = meta?.view;
  const viewIsIdentity = !view || (view.x === 0 && view.y === 0 && view.k === 1);
  const hideDisabled = !!meta?.settings?.hide_disabled;
  return {
    version: CANVAS_BLOB_VERSION,
    ...(meta?.surfaceSize ? { surface: meta.surfaceSize } : {}),
    ...(view && !viewIsIdentity ? { view: { x: view.x, y: view.y, k: view.k } } : {}),
    ...(hideDisabled ? { settings: { hide_disabled: true } } : {}),
    nodes: nodes.map(n => {
      const def = registry.get(n.type);
      const canvasOnly = !!def?.canvasOnly;
      const persistPosition = !!n.position;
      // `parentId` is persisted explicitly: a runtime value of
      // `undefined` means "no parent" and must round-trip to "no
      // parent" rather than fall back to whichever default
      // `nodesFromPayload` would otherwise pick (e.g. TPs default to
      // `access-point`). Serialise as `null` so JSON keeps the key.
      const parentId = n.parentId == null ? null : n.parentId;
      // Persist config for canvas-only nodes (the only place those
      // configs live) AND for configurable runtime nodes whose panels
      // depend on UI-only fields not present in the backend payload
      // (TPs and APs especially — endpoint_type, route_prefix,
      // route_suffix, gateway_id, auth_type, etc.). Without this the
      // panel "resets" after save because reconstruction sees only
      // backend-known keys.
      const persistConfig = canvasOnly || !!def?.ConfigPanel;
      return {
        id: n.id,
        type: n.type,
        label: n.label,
        parentId,
        ...(persistPosition ? { position: { x: n.position!.x, y: n.position!.y } } : {}),
        ...(typeof n.radius === 'number' ? { radius: n.radius } : {}),
        ...(persistConfig ? { config: n.config ?? {} } : {}),
        ...(n.slotId ? { slotId: n.slotId } : {}),
      };
    }),
  };
}

function readCanvasBlob(raw: any): CanvasBlob | null {
  if (!raw || typeof raw !== 'object' || !Array.isArray(raw.nodes)) return null;
  return raw as CanvasBlob;
}

/** Read the persisted surface rectangle from `payload.canvas.surface`, if any. */
export function readCanvasSurfaceSize(payload: any): { width: number; height: number } | null {
  const blob = readCanvasBlob(payload?.canvas);
  const s = blob?.surface;
  if (!s || typeof s.width !== 'number' || typeof s.height !== 'number') return null;
  return { width: s.width, height: s.height };
}

/** Read the persisted zoom/pan transform from `payload.canvas.view`, if any. */
export function readCanvasView(payload: any): { x: number; y: number; k: number } | null {
  const blob = readCanvasBlob(payload?.canvas);
  const v = blob?.view;
  if (!v || typeof v.x !== 'number' || typeof v.y !== 'number' || typeof v.k !== 'number') {
    return null;
  }
  return { x: v.x, y: v.y, k: v.k };
}

/**
 * Read the persisted per-canvas view preferences from `payload.canvas.settings`.
 * Returns null when no settings block is present so callers can fall back to
 * defaults (currently `{ hide_disabled: false }`).
 */
export function readCanvasSettings(payload: any): { hide_disabled: boolean } | null {
  const blob = readCanvasBlob(payload?.canvas);
  const s = blob?.settings;
  if (!s || typeof s !== 'object') return null;
  return { hide_disabled: !!s.hide_disabled };
}

function readPath(obj: any, path: string): any {
  if (!obj || !path) return undefined;
  return path.split('.').reduce((cur, key) => (cur == null ? cur : cur[key]), obj);
}

/**
 * True when a payload slice is "absent" for hydration purposes: missing,
 * null, an empty object, an empty array, or an explicitly-disabled toggle
 * object (`{ enabled: false, ... }` with no other meaningful fields).
 *
 * Shared by every scope's `nodesFrom*Payload` hydrator.
 */
export function isEmptySlice(slice: any): boolean {
  if (slice === undefined || slice === null) return true;
  if (Array.isArray(slice)) return slice.length === 0;
  if (typeof slice === 'object') {
    const keys = Object.keys(slice);
    if (keys.length === 0) return true;
    if (
      slice.enabled === false &&
      keys.every(k => k === 'enabled' || slice[k] === false || slice[k] == null)
    ) {
      return true;
    }
  }
  return false;
}

/** Read a dot-notation `path` from `obj`. Exposed for scope-specific hydrators. */
export function readPayloadPath(obj: any, path: string): any {
  return readPath(obj, path);
}

/**
 * Deep-merge `value` into `obj` at the dot-notation `path`.
 * - Intermediate objects are created on demand.
 * - Plain objects are merged shallowly at the leaf (existing keys preserved
 *   when `value` doesn't override them).
 * - Arrays and primitives replace any existing value at the leaf.
 */
function deepMergePath(obj: any, path: string, value: any): void {
  if (value === undefined || value === null) return;
  const parts = path.split('.').filter(p => p.length > 0);
  if (parts.length === 0) return;
  let cur = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    const key = parts[i];
    const nextKey = parts[i + 1];
    const nextIsNumeric = /^\d+$/.test(nextKey);
    // Decide what container to materialise at `key` if it's missing.
    // - If the next key is numeric, the container should be an array.
    // - Otherwise, an object.
    if (Array.isArray(cur)) {
      const idx = /^\d+$/.test(key) ? parseInt(key, 10) : NaN;
      if (Number.isNaN(idx)) return; // can't merge into a non-numeric key on an array
      if (cur[idx] === undefined || cur[idx] === null) {
        cur[idx] = nextIsNumeric ? [] : {};
      }
      cur = cur[idx];
    } else {
      if (cur[key] === undefined || cur[key] === null) {
        cur[key] = nextIsNumeric ? [] : {};
      } else if (nextIsNumeric && !Array.isArray(cur[key])) {
        // Need an array but found something else — leave it alone to avoid data loss.
        return;
      } else if (!nextIsNumeric && Array.isArray(cur[key])) {
        // Need an object but found an array — bail out for the same reason.
        return;
      }
      cur = cur[key];
    }
  }
  const leaf = parts[parts.length - 1];
  if (Array.isArray(cur)) {
    const idx = /^\d+$/.test(leaf) ? parseInt(leaf, 10) : NaN;
    if (Number.isNaN(idx)) return;
    const existing = cur[idx];
    if (
      existing &&
      typeof existing === 'object' &&
      !Array.isArray(existing) &&
      typeof value === 'object' &&
      !Array.isArray(value)
    ) {
      cur[idx] = { ...existing, ...value };
    } else {
      cur[idx] = value;
    }
    return;
  }
  const existing = cur[leaf];
  if (
    existing &&
    typeof existing === 'object' &&
    !Array.isArray(existing) &&
    typeof value === 'object' &&
    !Array.isArray(value)
  ) {
    cur[leaf] = { ...existing, ...value };
  } else {
    cur[leaf] = value;
  }
}

export const registry = new ElementRegistry();
