import { ComponentType } from 'react';
import type { CanvasNode } from '../SurfaceCanvas';
import type { SurfaceNodeType } from '../nodeTypes';

/**
 * Node-type identifier for any builder scope. All node types — surface and
 * pipe alike — are members of the single closed {@link SurfaceNodeType} union,
 * so the registry and canvas share one exhaustive vocabulary.
 */
export type NodeType = SurfaceNodeType;

/** Visual shape on the canvas. */
export type NodeShape = 'circle' | 'rect' | 'diamond';

/**
 * Protocol identifiers matching backend SurfaceProtocol values.
 */
export type Protocol = 'a2a' | 'mcp' | 'didcomm' | 'marketplace';

/** Where this element lives in the request pipeline. */
export type PipelineStage =
  | 'ingress' // access-point
  | 'middleware' // policy, payment, identity, rate-limit, etc.
  | 'target' // target
  | 'egress' // pipe-response
  | 'decorative'; // NPCs, actors

/** Multiplicity per surface. */
export type Cardinality = 'singleton' | 'multi';

/**
 * Direction of a pipeline middleware on the canvas.
 * - 'request'  — sits on the request arrow (caller → agent flow)
 * - 'response' — sits on the response arrow (agent → caller flow)
 *
 * Surface-wide / bidirectional elements (signing, identity, trust-registry
 * verification, etc.) do NOT carry a direction.
 */
export type EdgeDirection = 'request' | 'response';

/**
 * How an element relates to the request/response arrows.
 *
 * - 'request'       — droppable only on a request arrow (e.g. inbound rate-limit,
 *                     access-point inbound policy, request-side schema).
 * - 'response'      — droppable only on a response arrow (e.g. response-policy,
 *                     response extension rules).
 * - 'either'        — single instance per slot per direction; the user picks
 *                     direction by dropping on the matching arrow. Replaces the
 *                     legacy in-panel inbound/outbound toggles
 *                     (custom-metadata, extension-rules, schema, policy injection,
 *                     trust-registry injection).
 * - 'bidirectional' — single instance, conceptually applies to both directions
 *                     at once (e.g. signing, networking). Drops on a node, not
 *                     an arrow; no `direction` field is set.
 *
 * Defaults to 'bidirectional' when omitted (the safe choice for non-pipeline
 * elements).
 */
export type Directionality = 'request' | 'response' | 'either' | 'bidirectional';

/** Palette grouping. */
export type PaletteCategory =
  | 'connections'
  | 'policy'
  | 'enhancement'
  | 'inputs'
  | 'tools'
  | 'npc'
  | 'actor';

/**
 * Which top-level builder consumer an element belongs to. The same registry
 * hosts elements for multiple consumers (Surfaces, Pipes, future builders);
 * scope filters the palette without affecting capability-keyed drop rules or
 * `registry.get(type)` lookups.
 *
 * - 'surface': only appears in the Surface builder palette.
 * - 'pipe':    only appears in the Pipe builder palette.
 * - 'shared': appears in every scope. Use for middleware that is genuinely
 *   cross-cutting (e.g. trust-registry, custom-metadata) once it has been
 *   ported to support both. Must be set explicitly.
 *
 * Omitting `scope` defaults to 'surface' — the common case, since most
 * elements are surface-only and should never leak into the Pipe palette.
 */
export type BuilderScope = 'surface' | 'pipe' | 'ide' | 'shared';

/**
 * UX drop semantic.
 * - 'canvas': dropping creates a new top-level node connected to the surface
 *             (e.g. access-point, target, NPCs).
 * - 'edge':   dropping inserts a visible intermediate node on a pipeline edge
 *             (e.g. policy, payment, networking).
 * - 'node':   dropping configures an existing node without adding a new visual
 *             node (e.g. identity, trust-registry attached to AP/Target).
 */
export type DropMode = 'canvas' | 'edge' | 'node';

export interface ResizeRange {
  min: number;
  max: number;
}

/** Where the element can be dropped. */
export interface CompatibilitySpec {
  /** Capabilities that must be jointly provided by source+target of an edge. */
  dropOnEdge?: string[];
  /** Capabilities that the target node must provide. */
  dropOnNode?: string[];
  /** Capabilities outbound links can connect to. */
  connectTo?: string[];
  /** Capabilities inbound links can come from. */
  connectFrom?: string[];
}

/**
 * Minimal LLM-provider shape a dependency check needs to decide whether a
 * node is missing a required API key. Kept structural (not the full catalog
 * type) so `SurfaceContext` stays decoupled from the pipe panel types.
 */
export interface SurfaceContextLlmProvider {
  enum_value: string;
  /** Absent or `true` ⇒ a key is required; only `false` opts out. */
  api_key_required?: boolean;
  /**
   * Three-state key policy (`mandatory` | `optional` | `none`). Authoritative
   * over `api_key_required` when present. See `utils/apiKeyValidation.ts`.
   */
  api_key_validation?: string;
}

/**
 * A surface that nodes on the canvas may depend on (reference by id) —
 * e.g. an IDE catalogue member linking to one of the appliance's LLM
 * Surfaces. Deliberately generic (id/type/name only) so any surface type
 * can register cross-surface dependency targets without the context
 * learning about a specific surface family.
 */
export interface SurfaceContextSurfaceRef {
  id: string;
  /** Coarse family tag, e.g. `'llm-surface'`. */
  type: string;
  name?: string;
}

/** Full surface state passed to dependency checks. */
export interface SurfaceContext {
  protocol: Protocol;
  accessPoint: any;
  target: any;
  allNodes: CanvasNode[];
  /**
   * LLM provider catalogue, when the host builder is pipe-scoped. Lets
   * pipe nodes (e.g. a juror) decide whether their selected provider needs
   * an API-key secret — knowledge the static node definition can't carry.
   * Empty/absent in surface-scoped builders.
   */
  llmProviders?: SurfaceContextLlmProvider[];
  /**
   * Surfaces this builder's nodes may reference by id, when the host page
   * supplies them (e.g. the IDE editor threads the live LLM-Surface list).
   * `undefined` means the host didn't supply a registry, so cross-surface
   * existence checks stay inert; an array (possibly empty) means the list
   * is authoritative and a referenced id absent from it is a broken link.
   */
  availableSurfaces?: SurfaceContextSurfaceRef[];
}

/**
 * Context passed to {@link NodeDefinition.buildPayload}.
 * Each element reads from this to find its own nodes and returns a list of
 * payload slices that the registry deep-merges into the final payload.
 */
export interface PayloadContext {
  protocol: string;
  surfaceMeta: {
    /** Optional pre-assigned UUID; the registry writes it as `surface_id`. */
    surface_id?: string;
    name: string;
    description?: string;
    tags: string[];
    status?: string;
  };
  allNodes: CanvasNode[];
  /** All nodes whose `type` matches the requested type. */
  nodesOfType: (type: NodeType) => CanvasNode[];
  /** First node of the requested type, or undefined. */
  firstNodeOfType: (type: NodeType) => CanvasNode | undefined;
}

/**
 * One fragment of the surface payload.
 *
 * - `path` is dot-notation, e.g. `"target.policy"` or `"access_point"`.
 *   Empty path is invalid; use the top-level slice's parent key instead.
 * - `value` is deep-merged at that path. Plain objects merge shallowly at
 *   the leaf (existing keys preserved if `value` doesn't override). Arrays
 *   and primitives replace any existing leaf value.
 * - Returning `undefined`/`null` for `value` (or skipping the slice
 *   entirely) writes nothing.
 */
export interface PayloadSlice {
  path: string;
  value: any;
}

/**
 * Display row for the Elements list-view tab. Each element decides which
 * configured values matter most at a glance — e.g. an Access Point shows
 * its listener, a Target shows its endpoint, a Policy node
 * shows its rule count.
 *
 * `name` and `description` default to the canvas label and the element's
 * static description if omitted. `fields` is an ordered, variable-length
 * list of label/value pairs rendered as additional columns/badges; values
 * are kept short (one line, ~40 chars) for table density.
 */
export interface ListViewInfo {
  name?: string;
  description?: string;
  /**
   * Arbitrary additional cells rendered after Description, in order.
   * Each element supplies its own meaning per column position; the table
   * does not label these columns because semantics differ across element
   * types.
   */
  extras?: import('react').ReactNode[];
}

export interface FeatureDependency {
  /** Human-readable rule identifier. */
  description: string;
  /** Predicate: when does this rule apply? */
  condition: (config: any, ctx: SurfaceContext) => boolean;
  /** Predicate: is the requirement satisfied? Return true to PASS. */
  check: (config: any, ctx: SurfaceContext) => boolean;
  /** Severity if check returns false while condition holds. */
  severity: 'error' | 'warning';
  /** Message shown to the user. */
  message: string;
}

export interface ConfigPanelProps {
  /** The node being configured. */
  node: CanvasNode;
  /** Current config values. */
  config: any;
  /**
   * Update a single config field.
   *
   * NOTE: Sequential calls within the same render WILL clobber each other
   * because each call reads from the original `node.config` snapshot.
   * For multi-field updates, always use `updateFields` instead.
   */
  updateField: (field: string, value: any) => void;
  /** Update multiple config fields atomically (single onUpdate call). */
  updateFields: (fields: Record<string, any>) => void;
  /** Surface protocol (used for protocol-aware fields). Optional only for elements that don't depend on it. */
  protocol?: Protocol;
  /** All canvas nodes (used by NPC/identity panels for dropdowns). */
  allNodes?: CanvasNode[];
  /**
   * Request that the wizard opens this element's `FullscreenPanel` in a new
   * builder tab. Available only for elements that declare a
   * `FullscreenPanel`. No-op otherwise.
   */
  openFullscreenEditor?: () => void;
  /**
   * Open the surface-level "Configure Surface Features" full-page editor (the
   * synthetic `__surface__` node's `FullscreenPanel`). Unlike
   * `openFullscreenEditor` (which targets the panel's own node), this always
   * targets the surface, so a non-surface panel (e.g. the Access Point) can
   * offer the same "Configure Surface Features" button the surface panel has.
   */
  openSurfaceConfig?: () => void;
  /**
   * Close the current fullscreen editor tab and return to the canvas.
   * Only set when the panel is rendered inside the fullscreen tab.
   */
  closeFullscreenEditor?: () => void;
  /**
   * Replace the top history snapshot with the current state in-place.
   * Use this from a panel's mount-time seeding effect so that the
   * auto-seeded defaults coalesce with the post-drop snapshot — undo
   * from after-seed will then revert the drop in a single step,
   * instead of leaving a "node exists, config empty" entry that causes
   * the seeding effect to re-run with a fresh random path.
   */
  replaceCommit?: () => void;
  /**
   * Validation errors keyed by `field` (matching the `field` returned by
   * `NodeDefinition.validate`). Panels can render `errorByField[name]`
   * inline beneath the matching input. Errors without a `field` are not
   * surfaced here — the parent banner shows them.
   */
  errorByField?: Record<string, string>;
  /**
   * Append a sibling node to the canvas. Lets a panel create related
   * nodes it owns the lifecycle of (e.g. the Jury panel adding a juror
   * node). The caller mints the node's id / parentId / config / position.
   */
  addNode?: (node: CanvasNode) => void;
  /** Remove any node by id (e.g. the Jury panel deleting a juror node). */
  removeNode?: (nodeId: string) => void;
  /**
   * Replace another node's config by id (e.g. the Jury panel toggling a
   * juror's `enabled` flag). For the panel's own node, use `updateField`.
   */
  updateNodeConfig?: (nodeId: string, config: any) => void;
  /**
   * Run a full canvas auto-layout (reflow every node + resize the surface to
   * fit), exactly as the "Auto layout" toolbar button does. The Jury panel
   * calls this after switching the execution mode so the surface boundary
   * grows/shrinks to fit the new juror arrangement instead of clamping it.
   */
  autoLayout?: () => void;
  /**
   * Select another node by id, exactly as clicking it on the canvas would —
   * opening its properties panel. Lets a panel jump to a related node it
   * lists (e.g. the Jury panel jumping to a juror row).
   */
  selectNode?: (nodeId: string) => void;
}

/**
 * Where the config UI is rendered.
 * - `sidebar` (default): inline in the right-hand 280–600px properties panel.
 * - `fullscreen`: opened as a fullscreen overlay covering the surface builder
 *   canvas + palette + sidebar area. Use for complex editors that don't fit
 *   in the sidebar (e.g. identity and extension rules).
 */
export type ConfigSurface = 'sidebar' | 'fullscreen';

export interface NodeDefinition {
  // Identity
  type: NodeType;
  label: string;
  description: string;

  // Visual
  icon: string;
  /** FontAwesome class name (without `fa-` prefix not needed; full e.g. "fa-shield-alt") for palette/sidebar UI. Falls back to `icon` glyph if absent. */
  paletteIcon?: string;
  color: string;
  shape: NodeShape;
  defaultRadius: number;
  resizable: boolean;
  resizeRange?: ResizeRange;

  // Canvas behavior
  draggable: boolean;
  containedInSurface: boolean;
  edgeConstrained: boolean;
  xWeight: number;

  // Pipeline
  stage: PipelineStage;
  cardinality: Cardinality;
  paletteCategory: PaletteCategory;
  paletteOrder: number;
  /**
   * Which builder scope(s) this element belongs to. Omit (= 'surface') for
   * elements that only appear in the Surface builder. See {@link BuilderScope}.
   */
  scope?: BuilderScope;
  /** UX drop semantic — what happens when this element is dropped. */
  dropMode: DropMode;
  /**
   * Whether this element binds to a request arrow, a response arrow, either
   * (user picks via drop position), or operates bidirectionally without a
   * direction. Defaults to 'bidirectional'. See {@link Directionality}.
   */
  directionality?: Directionality;
  /**
   * When true, this element applies to the surface as a whole (not part of the
   * request pipeline). Drops are auto-positioned in a grid outside the surface
   * rect (bottom-left first, then right, then up) instead of using the cursor
   * drop point.
   */
  surfaceWide?: boolean;
  /**
   * When true, this element is a tool bound to the LLM node: it can only be
   * dropped onto the LLM's top landing area (mirroring the Decider candidates
   * below), becomes a child of the LLM (`parentId: 'pipe-upstream'`), and is
   * laid out in the top-biased tool row. See `llmToolSlotPosition`.
   */
  llmTool?: boolean;
  /** Hidden from palette (auto-created by surface, e.g. access-point, target, surface). */
  hiddenFromPalette?: boolean;

  /**
   * Optional in-palette help. When present, clicking (not dragging) the
   * palette item opens a balloon to the right of the item showing this
   * content. `bodyHtml` is rendered with `dangerouslySetInnerHTML` — content
   * is hardcoded in the registry, so we trust it.
   */
  help?: { title?: string; bodyHtml: string };

  // Capabilities
  provides: string[];
  requires: CompatibilitySpec;

  // Protocol constraints
  /** When set, element only available for these protocols. Undefined = all protocols. */
  protocols?: Protocol[];

  /**
   * Returns the protocol this element binds to. Used for elements whose
   * type itself encodes the protocol. Optional; undefined means "no
   * protocol affinity".
   */
  getProtocol?: () => Protocol;

  // Config validation
  /**
   * Returns null when the node is fully configured, else a human-readable
   * reason it is not. This is the single source of truth for completeness;
   * `registry.isConfigured` is derived from this.
   *
   * For decorative elements (NPCs, actors, surface) return `null`
   * unconditionally.
   */
  incompleteReason: (config: any) => string | null;

  /**
   * Returns a reason the node is intentionally switched OFF (disabled), or
   * null when it is active. A muted node is rendered greyed-out on the canvas
   * but is NOT a fault: it draws no error ring and its `incompleteReason`
   * should return null while disabled. Validation only applies once the node
   * is enabled. Optional; undefined means "never muted".
   */
  mutedReason?: (config: any) => string | null;

  /**
   * Format / value validators run on the current config. Distinct from
   * `incompleteReason` (which gates "configured = true" on required-field
   * presence): a validator fires once a field has been filled with bad
   * content (malformed URL, negative number, etc.).
   *
   * Each error may attach to a specific `field` so the panel can render
   * it inline beneath the matching input. Errors block save.
   */
  validate?: (config: any) => Array<{ field?: string; message: string }>;
  ConfigPanel?: ComponentType<ConfigPanelProps>;

  /**
   * Optional editor opened in a separate "editor" builder tab when a sidebar
   * panel calls `openFullscreenEditor()`. Lets a small sidebar form delegate
   * a heavy sub-editor (e.g. payload-field list, JSON editor) to the
   * full-area surface without forcing the whole config into fullscreen.
   */
  FullscreenPanel?: ComponentType<ConfigPanelProps>;

  /**
   * Where the ConfigPanel is rendered.
   * - `sidebar` (default): inline in the properties panel.
   * - `fullscreen`: opened as a full-area overlay covering the surface
   *   builder, triggered by a button in the sidebar. Use for panels too
   *   large for the 600px sidebar maximum.
   */
  configSurface?: ConfigSurface;

  /**
   * Whether the user can delete this node from the canvas. Defaults to true.
   * Set false for singletons that are auto-created with the surface
   * (`access-point`, `target`, `surface`).
   */
  deletable?: boolean;

  /**
   * Initial config object stamped onto a freshly-dropped node. Defaults to
   * `{}`. Override when an element needs a sensible starting state (e.g.
   * `target` ships with a placeholder endpoint, `identity` ships with an
   * empty JSON-schema scaffold).
   */
  defaultConfig?: () => any;

  /**
   * When true, this node lives ONLY on the canvas — its config is persisted
   * in the canvas blob, not the runtime payload. Used for decorative nodes
   * (NPCs, human, caller). Defaults to false.
   */
  canvasOnly?: boolean;

  /**
   * Optional renderer used by the wizard's review step to summarise this
   * element. Receives the merged config; should return a short ReactNode
   * (badges, codes, plain text). Returning `null` hides the row entirely.
   * Elements that don't implement this fall back to "Configured" / "—".
   */
  summary?: (config: any) => import('react').ReactNode;

  /**
   * Optional list-view metadata for the Elements tab. Lets each element
   * surface the data points that actually matter for it (an AP shows its
   * listener, a Target shows its endpoint, a policy shows the rule
   * count). When omitted, the list view falls back to the canvas label,
   * static description, and `summary()` output.
   */
  getListViewInfo?: (config: any) => ListViewInfo;

  // Dependency rules
  featureDependencies?: FeatureDependency[];

  /**
   * Dot-notation path used by the default reverse mapper
   * (`registry.nodesFromPayload`) when reconstructing a node from a saved
   * payload. When set and the path resolves to a non-empty slice, the
   * registry emits one node with that slice as its config.
   *
   * Single-slice elements only. Multi-slice elements (policy,
   * extension-validation) and elements with custom round-trip
   * (access-point, target) are handled by registry-level
   * special cases and do not need this hint.
   *
   * Has NO effect on the forward direction — that is owned by `buildPayload`
   * exclusively.
   */
  payloadPath?: string;

  /**
   * For `directionality: 'either'` elements: the dot-notation path of the
   * RESPONSE-direction slice (the request slice lives at `payloadPath`).
   * Registry's reverse mapper emits a second node from this slice with
   * `direction: 'response'` and an `-response` id suffix when present and
   * non-empty.
   *
   * Example: custom-metadata declares
   *   payloadPath:         'target.custom_metadata'
   *   responsePayloadPath: 'target.response_custom_metadata'
   */
  responsePayloadPath?: string;

  /**
   * Optional inverse of `buildPayload`: convert the saved wire-shape slice
   * back into the flat shape the panel reads/writes. When omitted, the
   * registry passes the slice through verbatim — which is fine for
   * elements whose panel and wire shapes are already identical, but
   * causes round-trip bugs for elements like access-point that fan a
   * flat field out to a nested object on save (`caller_context` →
   * `{ mode: ... }`).
   *
   * The full payload is provided as a second argument for elements that
   * need to read fields outside their own slice (e.g. the managed agent
   * absorbs `access_point.didwebvh_identity` into its DID Management
   * section). Most elements should ignore it.
   */
  configFromPayload?: (slice: any, payload?: any) => any;

  /**
   * Returns the payload slices this element contributes. Called once per
   * surface (not once per node — implementations look up their own nodes via
   * `ctx.nodesOfType(this.type)` when they support multiple instances).
   *
   * Return `undefined` (or an empty array) to skip writing anything. Each
   * slice is deep-merged into the final payload at its declared path; see
   * {@link PayloadSlice}.
   *
   * Multi-path elements — those that emit onto more than one payload
   * path (e.g. distinct request- and response-side slices) — return
   * multiple slices in a single call.
   */
  buildPayload?: (ctx: PayloadContext) => PayloadSlice[] | undefined;
}
