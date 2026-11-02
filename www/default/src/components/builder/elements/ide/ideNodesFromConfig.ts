import type { CanvasNode } from '../../SurfaceCanvas';
import type { SourceAuthConfig } from '../../../../types';
import { flattenSourceAuth, readSourceAuthFromNode } from '../caller-auth/sourceAuthMapping';
import type { IdeRoutingConfig } from './idePanelData';

/**
 * Surface rectangle the IDE canvas seeds. Half-width 420 places the
 * edge-constrained Access Point on the west border (matching
 * `computeIdeAutoLayout`), with the Catalogue as the hero on the centre line
 * and the member surfaces fanned out below it.
 */
export const IDE_SURFACE_SIZE = { w: 840, h: 300 };

/**
 * Loose shape of a saved IDE surface — the subset of `PipeConfig`
 * (`src/pipes/config.rs`, `PipeType::IDECatalog`) the canvas needs to hydrate
 * its anchors. Kept structural (not imported from a page) so this stays
 * page-agnostic, mirroring `PipeConfigLike` in `nodesFromPipe.ts`.
 */
export interface IdeMemberLike {
  pipe_id?: string;
  variant_alias?: string | null;
  mnemonic?: string | null;
  display_name?: string | null;
  group?: string | null;
  order?: number;
  default?: boolean;
  expose?: boolean;
  metadata?: Record<string, unknown> | null;
  /**
   * Stable, opaque canvas node id minted once by the editor and persisted with
   * the member (`IdeCatalogMember::node_id`). Used as the member's canvas node
   * id so its position and docked gate chips stay bound to *this* member across
   * catalogue reorders (which re-sort the persisted array). Absent on legacy
   * configs — the editor falls back to a positional id and mints one on save.
   */
  node_id?: string | null;
  /**
   * Per-member upstream sign-in via an OAuth Identifier profile reference. The
   * way to give a member a distinct upstream token — the surface synthesizes
   * and publishes the slot automatically. Mirrors
   * `IdeCatalogMember::upstream_oauth_identifier_id`.
   */
  upstream_oauth_identifier_id?: string | null;
  /**
   * Optional per-member Model Policy — the id of an IDE-type policy definition
   * evaluated on this specific model when it is dispatched. Mirrors
   * `IdeCatalogMember::opa_policy_id`.
   */
  opa_policy_id?: string | null;
}

/**
 * Central client sign-in (SSO) identifiers published to IDE clients via the
 * surface bootstrap document. All fields are public OAuth identifiers, never
 * secrets. Mirrors `IdeClientAuth` in `src/pipes/catalog.rs`.
 */
export interface IdeClientAuthLike {
  provider?: string;
  tenant_id?: string;
  client_id?: string;
  scopes?: string[];
  /**
   * Optional reference to an OAuth Identifier profile (public sign-in
   * identifiers managed once in Credentials). When set, the profile supplies
   * the tenant/client/scopes at publish time and the inline fields are a
   * fallback. Mirrors `IdeClientAuth.oauth_identifier_id` in `catalog.rs`.
   */
  oauth_identifier_id?: string | null;
}

export interface IdeConfigLike {
  id?: string;
  name?: string;
  description?: string;
  listen_address?: string;
  route?: string;
  rate_limit?: {
    enabled?: boolean;
    requests_per_minute?: number;
    tokens_per_minute?: number;
  } | null;
  opa_policy?: {
    enabled?: boolean;
    policy_definition_id?: string;
    log_decisions?: boolean;
  } | null;
  /**
   * Source authentication config — populated by the `ide-caller-auth`
   * canvas element. When present, the backend validates every inbound
   * caller and exposes the identity to the front-door OPA gate as
   * `input.source_auth.*`.
   */
  source_auth?: SourceAuthConfig | null;
  pipe_type?: {
    type?: string;
    config?: {
      members?: IdeMemberLike[];
      client_auth?: IdeClientAuthLike | null;
    };
    [k: string]: unknown;
  };
  canvas?: unknown;
  [k: string]: unknown;
}

/**
 * Split a saved full `route` into the routing `prefix` + `custom_path` the
 * Access Point panel edits, using the routing catalogue. Mirrors the pipe
 * decompose in `usePipeForm.ts`: find the first path prefix the route starts
 * with (`prefix + '/'`), then the remainder is the custom path.
 */
function decomposeRoute(
  route: string | undefined,
  routing: IdeRoutingConfig | undefined
): { prefix: string; custom_path: string } {
  if (!route || !routing?.pathPrefixes) return { prefix: '', custom_path: '' };
  for (const p of routing.pathPrefixes) {
    if (route.startsWith(p.prefix + '/')) {
      return { prefix: p.prefix, custom_path: route.substring(p.prefix.length + 1) };
    }
  }
  return { prefix: '', custom_path: '' };
}

/**
 * Seed the IDE canvas from a saved surface config. The Access Point and
 * Catalogue are the two auto-created spine anchors; each `config.members[]`
 * entry becomes an `ide-member` node; and the front-door governance nodes
 * (`ide-opa-policy`, `ide-rate-limit`) are seeded from the backend config so an
 * API-created surface still shows its governance on the canvas — the saved
 * `canvas` blob only restores positions on top. Member node ids follow the
 * builder's `${type}-N` (1-based) convention (`mintNodeId`) so a seeded member
 * and a palette-dropped one share one id namespace.
 */
export function nodesFromIde(
  config: IdeConfigLike | null,
  routing?: IdeRoutingConfig
): CanvasNode[] {
  const { prefix, custom_path } = decomposeRoute(config?.route, routing);

  const clientAuth = config?.pipe_type?.config?.client_auth ?? undefined;

  const source: CanvasNode = {
    id: 'ide-source',
    type: 'ide-source',
    label: 'Access Point',
    configured: !!(config?.listen_address && prefix && custom_path),
    config: {
      listen_address: config?.listen_address ?? '',
      prefix,
      custom_path,
      client_auth_provider: clientAuth?.provider ?? 'entra',
      client_auth_tenant_id: clientAuth?.tenant_id ?? '',
      client_auth_client_id: clientAuth?.client_id ?? '',
      client_auth_scopes: Array.isArray(clientAuth?.scopes) ? clientAuth!.scopes! : [],
      client_auth_oauth_identifier_id: clientAuth?.oauth_identifier_id ?? '',
    },
  };

  const catalog: CanvasNode = {
    id: 'ide-catalog',
    type: 'ide-catalog',
    label: 'Catalogue',
    configured: true,
    position: { x: 0, y: 0 },
    parentId: 'ide-source',
  };

  const responseCfg =
    config?.canvas &&
    typeof config.canvas === 'object' &&
    Array.isArray((config.canvas as { nodes?: unknown }).nodes)
      ? ((config.canvas as { nodes: Array<Record<string, any>> }).nodes.find(
          n => n?.id === 'ide-response'
        )?.config as { visualize_response_to_caller?: boolean } | undefined)
      : undefined;

  const response: CanvasNode = {
    id: 'ide-response',
    type: 'ide-response',
    label: 'Response',
    configured: true,
    parentId: 'ide-catalog',
    config: {
      visualize_response_to_caller: responseCfg?.visualize_response_to_caller !== false,
    },
  };

  const members: IdeMemberLike[] = Array.isArray(config?.pipe_type?.config?.members)
    ? config!.pipe_type!.config!.members!
    : [];

  // Each config member becomes an `ide-member` node; its optional per-member
  // upstream sign-in / Model Policy become opt-in gate *chips* docked to that
  // member (seeded only when the member actually carries the value, so the
  // default surface has no chips). Chip ids are derived from the member id so
  // `readIdeMembers` reads them back deterministically.
  const memberNodes: CanvasNode[] = [];
  const gateChips: CanvasNode[] = [];
  members.forEach((m, i) => {
    // Prefer the member's persisted stable node id; fall back to a positional
    // id for legacy configs authored before `node_id` existed (matches the
    // legacy canvas blob so saved positions survive the first load). The editor
    // persists a stable id on the next save via `readIdeMembers`.
    const memberId =
      typeof m.node_id === 'string' && m.node_id.trim().length > 0
        ? m.node_id.trim()
        : `ide-member-${i + 1}`;
    // A user-provided display name reads out as the below-node name label,
    // which also drives suppression of the redundant top "LLM Surface" type
    // label (see SurfaceCanvas.tsx). Fall back to the generic type label so
    // an unnamed member still shows something below the glyph.
    const memberDisplayName = typeof m.display_name === 'string' ? m.display_name.trim() : '';
    memberNodes.push({
      id: memberId,
      type: 'ide-member',
      label: memberDisplayName || 'LLM Surface',
      configured: !!m.pipe_id,
      parentId: 'ide-catalog',
      config: {
        pipe_id: m.pipe_id ?? '',
        variant_alias: m.variant_alias ?? '',
        mnemonic: m.mnemonic ?? '',
        display_name: m.display_name ?? '',
        group: m.group ?? '',
        order: typeof m.order === 'number' ? m.order : 0,
        default: m.default === true,
        expose: m.expose !== false,
        max_input_tokens:
          typeof m.metadata?.max_input_tokens === 'number'
            ? m.metadata.max_input_tokens
            : undefined,
        max_output_tokens:
          typeof m.metadata?.max_output_tokens === 'number'
            ? m.metadata.max_output_tokens
            : undefined,
        metadata: m.metadata ?? undefined,
      },
    });
    const upstream =
      typeof m.upstream_oauth_identifier_id === 'string'
        ? m.upstream_oauth_identifier_id.trim()
        : '';
    if (upstream) {
      gateChips.push({
        id: `ide-member-upstream-auth-${memberId}`,
        type: 'ide-member-upstream-auth',
        label: 'Upstream Sign-in',
        configured: true,
        parentId: memberId,
        config: { upstream_oauth_identifier_id: upstream },
      });
    }
    const opa = typeof m.opa_policy_id === 'string' ? m.opa_policy_id.trim() : '';
    if (opa) {
      gateChips.push({
        id: `ide-member-opa-${memberId}`,
        type: 'ide-member-opa',
        label: 'Model Policy',
        configured: true,
        parentId: memberId,
        config: { policy_definition_id: opa },
      });
    }
  });

  const spine: CanvasNode[] = [source, catalog, response, ...memberNodes, ...gateChips];

  // Governance seeds are gated on the blob's node types: if the persisted
  // canvas already carries an OPA / rate-limit node (e.g. a user dropped it on
  // the source→catalogue edge, so its canonical id is
  // `ide-opa-policy-ide-source` — not the fixed `ide-opa-policy` we seed) the
  // config-derived seed would land as a *second* node under the fixed id and
  // `applyCanvasOverlay` would then restore the blob node too, doubling it.
  // Mirror the pipe editor's `reconcilePipeCanvasGuards` defensive gate.
  const blobTypes = collectBlobTypes(config?.canvas);

  if (config?.opa_policy && !blobTypes.has('ide-opa-policy')) {
    spine.push({
      id: 'ide-opa-policy',
      type: 'ide-opa-policy',
      label: 'OPA Policy',
      configured: config.opa_policy.enabled === false || !!config.opa_policy.policy_definition_id,
      parentId: 'ide-source',
      config: {
        enabled: config.opa_policy.enabled !== false,
        policy_definition_id: config.opa_policy.policy_definition_id ?? '',
        log_decisions: config.opa_policy.log_decisions === true,
      },
    });
  }

  if (config?.rate_limit && !blobTypes.has('ide-rate-limit')) {
    spine.push({
      id: 'ide-rate-limit',
      type: 'ide-rate-limit',
      label: 'Rate Limit',
      configured: true,
      parentId: 'ide-source',
      config: {
        enabled: config.rate_limit.enabled !== false,
        requests_per_minute:
          typeof config.rate_limit.requests_per_minute === 'number'
            ? config.rate_limit.requests_per_minute
            : 60,
        tokens_per_minute:
          typeof config.rate_limit.tokens_per_minute === 'number'
            ? config.rate_limit.tokens_per_minute
            : 100000,
      },
    });
  }

  if (config?.source_auth && !blobTypes.has('ide-caller-auth')) {
    const cfg = flattenSourceAuth(config.source_auth);
    if (cfg) {
      spine.push({
        id: 'ide-caller-auth',
        type: 'ide-caller-auth',
        label: 'Caller Context',
        configured: true,
        parentId: 'ide-source',
        config: cfg,
      });
    }
  }

  return applyCanvasOverlay(spine, config?.canvas);
}

/**
 * Set of node `type` values present in a persisted canvas blob. Used to
 * suppress the config-derived spine seed for governance elements a user has
 * already dropped on the canvas (which land under composite ids like
 * `ide-opa-policy-ide-source`) so reopening the surface does not double them.
 */
function collectBlobTypes(canvas: unknown): Set<string> {
  const types = new Set<string>();
  if (!canvas || typeof canvas !== 'object') return types;
  const nodes = (canvas as { nodes?: unknown }).nodes;
  if (!Array.isArray(nodes)) return types;
  for (const n of nodes) {
    if (n && typeof n === 'object' && typeof (n as { type?: unknown }).type === 'string') {
      types.add((n as { type: string }).type);
    }
  }
  return types;
}

/**
 * Layer the persisted `canvas` blob over the config-derived spine so a saved
 * layout round-trips on reload — mirroring `applyCanvasOverlay` in
 * `nodesFromPipe.ts`. Matching nodes get their saved position / radius /
 * parentId and UI-only config keys (backend truth wins). Unmatched blob nodes
 * (drag-on governance) are restored as standalone nodes, except `ide-member`
 * nodes, which are derived solely from `config.members` and must never be
 * resurrected from a stale blob.
 */
function applyCanvasOverlay(nodes: CanvasNode[], canvas: unknown): CanvasNode[] {
  const blobNodes =
    canvas && typeof canvas === 'object' && Array.isArray((canvas as { nodes?: unknown }).nodes)
      ? ((canvas as { nodes: unknown[] }).nodes as Array<Record<string, any>>)
      : null;
  if (!blobNodes) return nodes;

  const byId = new Map(nodes.map(n => [n.id, n] as const));
  for (const bn of blobNodes) {
    if (!bn || typeof bn !== 'object' || typeof bn.id !== 'string') continue;
    const target = byId.get(bn.id);
    if (target) {
      if (bn.position && typeof bn.position.x === 'number' && typeof bn.position.y === 'number') {
        target.position = { x: bn.position.x, y: bn.position.y };
      }
      if (typeof bn.radius === 'number') target.radius = bn.radius;
      if (bn.parentId !== undefined) target.parentId = bn.parentId ?? undefined;
      if (bn.config && typeof bn.config === 'object') {
        target.config = { ...bn.config, ...(target.config ?? {}) };
      }
      continue;
    }
    if (typeof bn.type !== 'string') continue;
    // Member nodes and their per-member gate chips are derived solely from
    // `config.members`; never resurrect one from the saved blob (a removed
    // member — or a gate whose member is gone — would otherwise reappear).
    if (
      bn.type === 'ide-member' ||
      bn.type === 'ide-member-upstream-auth' ||
      bn.type === 'ide-member-opa'
    )
      continue;
    const restored: CanvasNode = {
      id: bn.id,
      type: bn.type as CanvasNode['type'],
      label: typeof bn.label === 'string' ? bn.label : bn.id,
      configured: true,
      config: bn.config && typeof bn.config === 'object' ? bn.config : {},
      ...(bn.parentId ? { parentId: bn.parentId as string } : {}),
      ...(bn.position && typeof bn.position.x === 'number' && typeof bn.position.y === 'number'
        ? { position: { x: bn.position.x, y: bn.position.y } }
        : {}),
      ...(typeof bn.radius === 'number' ? { radius: bn.radius } : {}),
    };
    nodes.push(restored);
    byId.set(restored.id, restored);
  }
  return nodes;
}

/** One IDE catalogue member read back off the canvas on save. */
export interface IdeMemberChange {
  pipe_id: string;
  variant_alias: string | null;
  mnemonic: string | null;
  display_name: string | null;
  group: string | null;
  order: number;
  default: boolean;
  expose: boolean;
  metadata: Record<string, unknown> | null;
  upstream_oauth_identifier_id: string | null;
  opa_policy_id: string | null;
  /**
   * The member's canvas node id, persisted as `IdeCatalogMember::node_id` so
   * the same member re-seeds under the same id on the next load — the stable
   * binding that keeps per-member canvas state (position, gate chips) attached
   * to this member across catalogue reorders.
   */
  node_id: string;
}

const str = (v: unknown) => (typeof v === 'string' ? v : '');
const num = (v: unknown, fallback: number) => (typeof v === 'number' ? v : fallback);

/**
 * Normalise a single OAuth scope entry. Users often paste a JSON-style list
 * (e.g. copied from the `sandbox_auth` block of `llm.json`) into a
 * newline-per-scope textarea, leaving each line wrapped in quotes and/or with a
 * trailing comma — `"https://graph.microsoft.com/Sites.Read.All",`. A scope
 * string with those literal characters is not a valid Entra scope, so the token
 * ends up minted for the wrong audience. Strip surrounding whitespace, a
 * leading/trailing comma, and wrapping single/double quotes so the saved scope
 * is the bare URI/URN the identity provider expects.
 */
const sanitizeScope = (raw: unknown): string => {
  let s = String(raw).trim();
  // Drop a trailing or leading comma left over from a pasted JSON array.
  s = s.replace(/^,+/, '').replace(/,+$/, '').trim();
  // Drop one layer of wrapping single or double quotes.
  if (
    s.length >= 2 &&
    ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'")))
  ) {
    s = s.slice(1, -1).trim();
  }
  return s;
};

/**
 * Rebuild a member's `metadata` object on save. Starts from any preserved
 * metadata (so description / capabilities / sunset authored via the API survive
 * a UI save) and overlays the context-window fields edited on the member panel.
 * Returns null when the object would be empty so it collapses to the backend's
 * `skip_serializing_if` shape.
 */
function readMemberMetadata(config: Record<string, unknown>): Record<string, unknown> | null {
  const preserved =
    config.metadata && typeof config.metadata === 'object'
      ? { ...(config.metadata as Record<string, unknown>) }
      : {};
  const maxIn = config.max_input_tokens;
  const maxOut = config.max_output_tokens;
  if (typeof maxIn === 'number' && maxIn > 0) preserved.max_input_tokens = maxIn;
  else delete preserved.max_input_tokens;
  if (typeof maxOut === 'number' && maxOut > 0) preserved.max_output_tokens = maxOut;
  else delete preserved.max_output_tokens;
  return Object.keys(preserved).length > 0 ? preserved : null;
}

/**
 * Read every `ide-member` node off the canvas into the backend
 * `pipe_type.config.members` array. Members with no chosen surface (`pipe_id`
 * blank) are dropped. Ordered by each member's `order` then its node id so the
 * saved list is stable. Empty optional fields collapse to `null` to match the
 * backend `skip_serializing_if` shape.
 */
export function readIdeMembers(nodes: CanvasNode[]): IdeMemberChange[] {
  const sorted = nodes
    .filter(n => n.type === 'ide-member')
    .map(n => {
      const c = (n.config ?? {}) as Record<string, unknown>;
      return { node: n, config: c };
    })
    .filter(({ config }) => str(config.pipe_id).trim().length > 0)
    .sort(
      (a, b) =>
        num(a.config.order, 0) - num(b.config.order, 0) || a.node.id.localeCompare(b.node.id)
    );
  // `default` is derived from the roster order: the first exposed row is the
  // catalogue's default model (falling back to the first row when every entry
  // is hidden). The per-member "Default model" switch was removed — reorder on
  // the Catalogue panel to change which model is pre-selected in the IDE.
  const defaultIndex = (() => {
    const firstExposed = sorted.findIndex(({ config }) => config.expose !== false);
    return firstExposed >= 0 ? firstExposed : 0;
  })();
  return sorted.map(({ node, config }, index) => {
    const alias = str(config.variant_alias).trim();
    const mnemonic = str(config.mnemonic).trim();
    const displayName = str(config.display_name).trim();
    const group = str(config.group).trim();
    // Per-member gate chips (opt-in) are docked to this member — read the
    // upstream sign-in / Model Policy back off them. Fall back to any legacy
    // value still on the member's own config (older configs / Config-tab
    // edits authored the ref directly on the member).
    const upstreamChip = nodes.find(
      c => c.type === 'ide-member-upstream-auth' && c.parentId === node.id
    );
    const opaChip = nodes.find(c => c.type === 'ide-member-opa' && c.parentId === node.id);
    const upstreamProfileId = (
      str(upstreamChip?.config?.upstream_oauth_identifier_id) ||
      str(config.upstream_oauth_identifier_id)
    ).trim();
    const opaPolicyId = (
      str(opaChip?.config?.policy_definition_id) || str(config.opa_policy_id)
    ).trim();
    return {
      pipe_id: str(config.pipe_id).trim(),
      variant_alias: alias.length > 0 ? alias : null,
      mnemonic: mnemonic.length > 0 ? mnemonic : null,
      display_name: displayName.length > 0 ? displayName : null,
      group: group.length > 0 ? group : null,
      order: num(config.order, 0),
      default: index === defaultIndex,
      expose: config.expose !== false,
      metadata: readMemberMetadata(config),
      upstream_oauth_identifier_id: upstreamProfileId.length > 0 ? upstreamProfileId : null,
      opa_policy_id: opaPolicyId.length > 0 ? opaPolicyId : null,
      node_id: node.id,
    };
  });
}

/** Access-point route parts read back off the canvas on save. */
export interface IdeSourceChange {
  listen_address: string;
  prefix: string;
  custom_path: string;
}

export function readIdeSource(nodes: CanvasNode[]): IdeSourceChange {
  const source = nodes.find(n => n.id === 'ide-source');
  return {
    listen_address: str(source?.config?.listen_address),
    prefix: str(source?.config?.prefix),
    custom_path: str(source?.config?.custom_path),
  };
}

/**
 * Central client sign-in read back off the canvas on save. `present` is false
 * when no identifier is set (the surface then publishes no bootstrap and IDE
 * clients fall back to their own manual settings). When present, `provider`
 * defaults to `entra`.
 */
export interface IdeClientAuthChange {
  present: boolean;
  provider: string;
  tenant_id: string;
  client_id: string;
  scopes: string[];
  /** Referenced OAuth Identifier profile id, or empty for inline/manual auth. */
  oauth_identifier_id: string;
}

export function readIdeClientAuth(nodes: CanvasNode[]): IdeClientAuthChange {
  const source = nodes.find(n => n.id === 'ide-source');
  const c = (source?.config ?? {}) as Record<string, unknown>;
  const provider = str(c.client_auth_provider).trim() || 'entra';
  const tenant = str(c.client_auth_tenant_id).trim();
  const client = str(c.client_auth_client_id).trim();
  const oauthId = str(c.client_auth_oauth_identifier_id).trim();
  const scopes = Array.isArray(c.client_auth_scopes)
    ? c.client_auth_scopes.map(sanitizeScope).filter(s => s.length > 0)
    : [];
  // A profile reference alone is enough to publish a bootstrap (the profile
  // supplies tenant/client/scopes), so it counts as "present".
  const present = oauthId.length > 0 || tenant.length > 0 || client.length > 0 || scopes.length > 0;
  return {
    present,
    provider,
    tenant_id: tenant,
    client_id: client,
    scopes,
    oauth_identifier_id: oauthId,
  };
}

/** Front-door OPA gate read back off the canvas on save (`null` when absent). */
export interface IdeOpaPolicyChange {
  present: boolean;
  enabled: boolean;
  policy_definition_id: string;
  log_decisions: boolean;
}

export function readIdeOpaPolicy(nodes: CanvasNode[]): IdeOpaPolicyChange {
  const op = nodes.find(n => n.type === 'ide-opa-policy');
  return {
    present: !!op,
    enabled: op?.config?.enabled !== false,
    policy_definition_id: str(op?.config?.policy_definition_id),
    log_decisions: op?.config?.log_decisions === true,
  };
}

/** Front-door rate limit read back off the canvas on save (`null` when absent). */
export interface IdeRateLimitChange {
  present: boolean;
  enabled: boolean;
  requests_per_minute: number;
  tokens_per_minute: number;
}

export function readIdeRateLimit(nodes: CanvasNode[]): IdeRateLimitChange {
  const rl = nodes.find(n => n.type === 'ide-rate-limit');
  return {
    present: !!rl,
    enabled: rl?.config?.enabled !== false,
    requests_per_minute: num(rl?.config?.requests_per_minute, 60),
    tokens_per_minute: num(rl?.config?.tokens_per_minute, 100000),
  };
}

/**
 * Front-door caller-context extraction read back off the canvas on save.
 * Returns `null` when no `ide-caller-auth` node is present or its config is
 * incomplete (e.g. JWT bearer with no strategy selected) — the surface then
 * saves without `source_auth` and stays open. When present, the returned
 * `SourceAuthConfig` is the wire shape the backend accepts on `PipeConfig`.
 * Mirrors the `caller-auth/definition.ts::buildPayload` method switch but
 * without the `access_point.caller_authentication.methods[0]` wrapper.
 */
export function readIdeSourceAuth(
  nodes: CanvasNode[],
  surfaceId?: string
): SourceAuthConfig | null {
  return readSourceAuthFromNode(
    nodes.find(n => n.type === 'ide-caller-auth'),
    surfaceId
  );
}

/**
 * Compose the Access Point's `prefix` + `custom_path` back into the single
 * full `route` string the backend stores. Mirrors the pipe compose: strip a
 * leading slash off the custom path, then join `prefix/custom_path`.
 */
export function composeIdeRoute(prefix: string, customPath: string): string {
  const normalized = customPath.startsWith('/') ? customPath.substring(1) : customPath;
  return prefix ? `${prefix}/${normalized}` : '';
}
