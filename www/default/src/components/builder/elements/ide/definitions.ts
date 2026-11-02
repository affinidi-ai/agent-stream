import * as Cap from '../capabilities';
import type { NodeDefinition } from '../types';
import CallerAuthPanel from '../caller-auth/CallerAuthPanel';
import CallerAuthFullscreen from '../caller-auth/CallerAuthFullscreen';
import { callerAuthIncompleteReason } from '../caller-auth/sourceAuthMapping';
import {
  IdeCatalogPanel,
  IdeMemberOpaPanel,
  IdeMemberPanel,
  IdeMemberUpstreamAuthPanel,
  IdeOpaPolicyPanel,
  IdeRateLimitPanel,
  IdeResponsePanel,
  IdeSourcePanel,
} from './panels';

/**
 * IDE builder nodes. An IDE surface aggregates other LLM Surfaces into a
 * governed, per-caller model-discovery menu that IDEs consume over an
 * OpenAI-compatible `/v1/models` + `/v1/chat/completions` front door.
 *
 * Topology mirrors the pipe builder:
 *
 *   Access Point → Catalogue (hero)
 *
 * with the front-door governance (OPA, rate limit) dragged onto the request
 * edge and the member surfaces (`LLM Surface` elements) fanned out below the
 * catalogue. The Access Point (west) is the edge-constrained listener; the
 * Catalogue is the hero. Both are auto-created (`hiddenFromPalette`) and
 * non-deletable. Member surfaces are added and picked from the Catalogue
 * panel's roster (mirroring the decider → candidate metaphor) rather than
 * dragged from the palette, so they too are `hiddenFromPalette` (but still
 * deletable). Only the governance nodes are dragged from the palette.
 *
 * Only OPA and Rate Limit are offered on the front door because those are the
 * controls the IDE surface actually enforces before dispatch; circuit breaker
 * and retry belong to (and re-run on) the member surface after dispatch.
 *
 * All are `scope: 'ide'` so they never appear in the Surface or Pipe palette.
 */

/**
 * Resolves a catalogue member's client-facing model id — the trimmed mnemonic
 * when set, else the derived `{pipe_id}[$alias]` — matching the backend's
 * `IdeCatalogMember::model_id()`. Used by the mnemonic-uniqueness
 * featureDependency and available for other UI callers that need the same
 * derivation.
 */
export function resolveIdeMemberModelId(config: unknown): string {
  const cfg = (config ?? {}) as Record<string, unknown>;
  const mnemonic = typeof cfg.mnemonic === 'string' ? cfg.mnemonic.trim() : '';
  if (mnemonic) return mnemonic;
  const pipeId = typeof cfg.pipe_id === 'string' ? cfg.pipe_id.trim() : '';
  if (!pipeId) return '';
  const alias = typeof cfg.variant_alias === 'string' ? cfg.variant_alias.trim() : '';
  return alias ? `${pipeId}$${alias}` : pipeId;
}

export const ideSourceDefinition: NodeDefinition = {
  type: 'ide-source',
  label: 'Access Point',
  description: 'The listener that fronts this IDE catalogue — where IDEs connect',
  icon: '\uf2f6', // fa-sign-in-alt
  paletteIcon: 'fa-sign-in-alt',
  color: '#6f42c1',
  shape: 'circle',
  defaultRadius: 24,
  resizable: false,
  draggable: true,
  containedInSurface: false,
  edgeConstrained: true,
  xWeight: 0.06,
  stage: 'ingress',
  cardinality: 'singleton',
  paletteCategory: 'connections',
  paletteOrder: 1,
  scope: 'ide',
  dropMode: 'canvas',
  hiddenFromPalette: true,
  deletable: false,
  provides: [Cap.PIPELINE_SOURCE, Cap.IDE_SOURCE, Cap.MIDDLEWARE_SLOT, Cap.CONFIGURABLE],
  requires: {},
  incompleteReason: c => {
    if (!c?.listen_address) return 'Select a listen address';
    if (!c?.prefix) return 'Select a path prefix';
    const path = typeof c?.custom_path === 'string' ? c.custom_path.replace(/^\/+/, '').trim() : '';
    if (!path) return 'Enter a custom path';
    return null;
  },
  validate: c => {
    const raw = typeof c?.custom_path === 'string' ? c.custom_path.replace(/^\/+/, '').trim() : '';
    if (raw && !/^[A-Za-z0-9][A-Za-z0-9\-_/]*$/.test(raw)) {
      return [
        {
          field: 'custom_path',
          message: 'Path may only contain letters, numbers, dashes, underscores and slashes',
        },
      ];
    }
    // Client sign-in is optional, but once any identifier is entered the Entra
    // provider needs all three (tenant, client, at least one scope) — an
    // incomplete bootstrap would be rejected by the backend, so block save here.
    const tenant =
      typeof c?.client_auth_tenant_id === 'string' ? c.client_auth_tenant_id.trim() : '';
    const client =
      typeof c?.client_auth_client_id === 'string' ? c.client_auth_client_id.trim() : '';
    const scopes = Array.isArray(c?.client_auth_scopes)
      ? (c.client_auth_scopes as unknown[]).map(s => String(s).trim()).filter(s => s.length > 0)
      : [];
    if (tenant || client || scopes.length > 0) {
      if (!tenant) {
        return [
          {
            field: 'client_auth_tenant_id',
            message: 'Enter the sign-in tenant ID (or clear the Client sign-in fields)',
          },
        ];
      }
      if (!client) {
        return [
          {
            field: 'client_auth_client_id',
            message: 'Enter the sign-in client ID (or clear the Client sign-in fields)',
          },
        ];
      }
      if (scopes.length === 0) {
        return [
          {
            field: 'client_auth_scopes',
            message: 'Enter at least one sign-in scope (or clear the Client sign-in fields)',
          },
        ];
      }
    }
    return [];
  },
  ConfigPanel: IdeSourcePanel,
};

export const ideCatalogDefinition: NodeDefinition = {
  type: 'ide-catalog',
  label: 'Catalogue',
  description: 'Publishes the aggregated model list to IDEs and dispatches chat requests',
  icon: '\uf022', // fa-list-alt
  paletteIcon: 'fa-list-alt',
  color: '#28a745',
  shape: 'rect',
  defaultRadius: 28,
  resizable: false,
  draggable: true,
  containedInSurface: true,
  edgeConstrained: false,
  xWeight: 0.5,
  stage: 'target',
  cardinality: 'singleton',
  paletteCategory: 'connections',
  paletteOrder: 2,
  scope: 'ide',
  dropMode: 'canvas',
  hiddenFromPalette: true,
  deletable: false,
  provides: [Cap.PIPELINE_SINK, Cap.IDE_CATALOG, Cap.MIDDLEWARE_SLOT, Cap.CONFIGURABLE],
  requires: {},
  incompleteReason: () => null,
  featureDependencies: [
    {
      description: 'A catalogue needs at least one LLM Surface member',
      condition: () => true,
      check: (_config, ctx) => ctx.allNodes.some(n => n.type === 'ide-member'),
      severity: 'error',
      message: 'Add at least one LLM Surface to the catalogue.',
    },
    {
      description: 'Every catalogue member must link to an LLM Surface that still exists',
      // Only evaluate once the host supplies the live LLM-Surface registry;
      // `undefined` means "not loaded / not applicable", so we stay inert.
      condition: (_config, ctx) => Array.isArray(ctx.availableSurfaces),
      check: (_config, ctx) => {
        const surfaces = ctx.availableSurfaces ?? [];
        return ctx.allNodes
          .filter(n => n.type === 'ide-member')
          .every(m => {
            const pipeId = (m.config as { pipe_id?: unknown })?.pipe_id;
            // A member with no surface picked is caught by its own
            // incompleteReason; only a picked-but-missing link is broken here.
            if (typeof pipeId !== 'string' || pipeId.trim() === '') return true;
            return surfaces.some(s => s.id === pipeId);
          });
      },
      severity: 'error',
      message: 'A catalogue member links to an LLM Surface that no longer exists.',
    },
    {
      description: 'Every catalogue member must have a unique model id (mnemonic)',
      condition: () => true,
      check: (_config, ctx) => {
        const seen = new Set<string>();
        for (const n of ctx.allNodes) {
          if (n.type !== 'ide-member') continue;
          const id = resolveIdeMemberModelId(n.config);
          if (!id) continue;
          if (seen.has(id)) return false;
          seen.add(id);
        }
        return true;
      },
      severity: 'error',
      message:
        'Two or more catalogue members share the same model id — set a unique mnemonic on each.',
    },
  ],
  ConfigPanel: IdeCatalogPanel,
};

export const ideResponseDefinition: NodeDefinition = {
  type: 'ide-response',
  label: 'Response',
  description: 'The model list / chat reply returned to the IDE after the catalogue runs',
  icon: '\uf3e5', // fa-reply
  paletteIcon: 'fa-reply',
  color: '#6f42c1',
  shape: 'circle',
  defaultRadius: 24,
  resizable: false,
  draggable: true,
  containedInSurface: false,
  edgeConstrained: true,
  xWeight: 0.94,
  stage: 'egress',
  cardinality: 'singleton',
  paletteCategory: 'connections',
  paletteOrder: 4,
  scope: 'ide',
  dropMode: 'canvas',
  hiddenFromPalette: true,
  deletable: false,
  provides: [Cap.IDE_RESPONSE],
  requires: {},
  incompleteReason: () => null,
  ConfigPanel: IdeResponsePanel,
};

export const ideMemberDefinition: NodeDefinition = {
  type: 'ide-member',
  label: 'LLM Surface',
  description: 'One of your configured LLM Surfaces, exposed as a model in this catalogue',
  icon: '\uf5dc', // fa-brain
  paletteIcon: 'fa-brain',
  color: '#20c997',
  shape: 'rect',
  defaultRadius: 18,
  resizable: false,
  draggable: true,
  containedInSurface: true,
  edgeConstrained: false,
  xWeight: 0.5,
  stage: 'target',
  cardinality: 'multi',
  paletteCategory: 'connections',
  paletteOrder: 3,
  scope: 'ide',
  dropMode: 'canvas',
  hiddenFromPalette: true,
  deletable: true,
  defaultConfig: () => ({
    pipe_id: '',
    variant_alias: '',
    mnemonic: '',
    display_name: '',
    group: '',
    order: 0,
    default: false,
    expose: true,
  }),
  help: {
    title: 'LLM Surface',
    bodyHtml: `
      <p>Expose one of your configured <strong>LLM Surfaces</strong> through
      this IDE catalogue. Members are added and picked from the
      <strong>Catalogue</strong> panel — click the Catalogue to choose a surface
      and give it a mnemonic. Each member appears as a model in the OpenAI-
      compatible <code>/v1/models</code> list that IDEs read; selecting it in
      the IDE dispatches the chat request to that surface, which re-runs its
      own governance under the caller's identity.</p>
      <ul>
        <li><strong>Mnemonic</strong> — the model id the IDE sends back to
        pick this surface (must be unique within the catalogue)</li>
        <li><strong>Variant</strong> — optionally pin a specific variant</li>
        <li><strong>Display name</strong> — how it appears in the IDE picker</li>
        <li><strong>Expose</strong> — turn off to hide without deleting</li>
      </ul>
      <p class="mb-0 text-muted small">The catalogue's default model is
      auto-derived from the first row on the Catalogue panel — reorder with
      the ↑ / ↓ buttons to change which model is pre-selected.</p>
    `,
  },
  provides: [Cap.IDE_MEMBER, Cap.CONFIGURABLE],
  requires: {},
  incompleteReason: c => (c?.pipe_id ? null : 'Select an LLM Surface'),
  // Hidden members (expose === false) publish nothing to the IDE, so render
  // them the same grey/muted way disabled Judges and Jurors are drawn — a
  // clear visual cue that the model is on the canvas but dark. Membership in
  // the catalogue is still evaluated (broken-link + uniqueness rules still
  // fire) so a hidden row with a bad config still highlights.
  mutedReason: config => (config?.expose === false ? 'Hidden from callers' : null),
  featureDependencies: [
    {
      description: 'The linked LLM Surface must still exist',
      // Only evaluate once the host supplies the live LLM-Surface registry
      // (`availableSurfaces`) and a surface has actually been picked.
      condition: (c, ctx) =>
        Array.isArray(ctx.availableSurfaces) &&
        typeof c?.pipe_id === 'string' &&
        c.pipe_id.trim() !== '',
      check: (c, ctx) => (ctx.availableSurfaces ?? []).some(s => s.id === c.pipe_id),
      severity: 'error',
      message: 'The linked LLM Surface no longer exists — pick another.',
    },
    {
      description: 'Model id (mnemonic or derived from surface) must be unique in this catalogue',
      // Only evaluate once this member has a usable id — a blank row is caught
      // separately by `incompleteReason`, and we don't want two half-added
      // rows to false-positive against each other.
      condition: c => resolveIdeMemberModelId(c).length > 0,
      check: (c, ctx) => {
        const myId = resolveIdeMemberModelId(c);
        const dupes = ctx.allNodes
          .filter(n => n.type === 'ide-member')
          .map(n => resolveIdeMemberModelId(n.config))
          .filter(id => id === myId);
        return dupes.length <= 1;
      },
      severity: 'error',
      message:
        'This model id is already in use by another catalogue member — set a unique mnemonic.',
    },
  ],
  ConfigPanel: IdeMemberPanel,
  summary: c => {
    if (!c?.pipe_id) return null;
    if (c?.expose === false) return 'hidden';
    const mnemonic = typeof c?.mnemonic === 'string' ? c.mnemonic.trim() : '';
    return (
      c?.display_name ||
      mnemonic ||
      (c?.variant_alias ? `${c.pipe_id}$${c.variant_alias}` : c.pipe_id)
    );
  },
};

/**
 * Per-member upstream sign-in (identity pass-through). An opt-in chip docked to
 * a catalogue member that gives *that model* its own upstream token — a distinct
 * OAuth Identifier profile whose token is forwarded to the model's upstream
 * provider (e.g. a Microsoft 365 Copilot Graph token) instead of the caller's
 * front-door token. Minted from the member panel's "Add gate" disclosure, never
 * dragged from the palette, so it is `hiddenFromPalette`; deletable. Round-trips
 * to the member's `upstream_oauth_identifier_id`.
 */
export const ideMemberUpstreamAuthDefinition: NodeDefinition = {
  type: 'ide-member-upstream-auth',
  label: 'Upstream Sign-in',
  description: 'Forward a distinct upstream token for this model (identity pass-through)',
  icon: '\uf084', // fa-key
  paletteIcon: 'fa-key',
  color: '#6610f2',
  // Diamond so the per-member gate chips read distinctly from the standard
  // round anchors that sit above the Catalogue → member bus.
  shape: 'diamond',
  defaultRadius: 14,
  resizable: false,
  draggable: true,
  containedInSurface: true,
  edgeConstrained: false,
  xWeight: 0.5,
  stage: 'middleware',
  cardinality: 'multi',
  paletteCategory: 'policy',
  paletteOrder: 5,
  scope: 'ide',
  dropMode: 'canvas',
  hiddenFromPalette: true,
  deletable: true,
  defaultConfig: () => ({ upstream_oauth_identifier_id: '' }),
  help: {
    title: 'Upstream Sign-in',
    bodyHtml: `
      <p>Give this model its own <strong>upstream token</strong>. When set, the
      IDE client forwards a token acquired from the referenced
      <strong>OAuth Identifier</strong> to the model's upstream provider (sent
      in <code>X-Agent-Stream-Upstream-Authorization</code>) instead of the
      caller's front-door token.</p>
      <p>Only takes effect when the selected LLM Surface enables
      <em>forward caller's token</em> — e.g. a Microsoft&nbsp;365 Copilot
      surface that needs a Graph-audience token distinct from the sign-in
      token.</p>
    `,
  },
  provides: [Cap.CONFIGURABLE],
  requires: {},
  incompleteReason: c =>
    typeof c?.upstream_oauth_identifier_id === 'string' &&
    c.upstream_oauth_identifier_id.trim() !== ''
      ? null
      : 'Select an OAuth Identifier',
  ConfigPanel: IdeMemberUpstreamAuthPanel,
  summary: c =>
    typeof c?.upstream_oauth_identifier_id === 'string' && c.upstream_oauth_identifier_id.trim()
      ? 'upstream token'
      : 'no profile',
};

/**
 * Per-member Model Policy. An opt-in chip docked to a catalogue member that runs
 * an IDE-scoped OPA (Rego) gate on *that specific model* after the front-door
 * gates pass and the member is resolved, under the caller's front-door identity.
 * Lets a catalogue expose a model to only a subset of callers (e.g. a premium
 * model gated to one Entra group) without touching the member LLM Surface's own
 * policy. Minted from the member panel's "Add gate" disclosure; deletable.
 * Round-trips to the member's `opa_policy_id`.
 */
export const ideMemberOpaDefinition: NodeDefinition = {
  type: 'ide-member-opa',
  label: 'Model Policy',
  description: 'Per-model OPA (Rego) gate evaluated when this model is dispatched',
  icon: '\uf3ed', // fa-shield-halved
  paletteIcon: 'fa-shield-alt',
  color: '#e74a3b',
  // Diamond so the per-member gate chips read distinctly from the standard
  // round anchors that sit above the Catalogue → member bus.
  shape: 'diamond',
  defaultRadius: 14,
  resizable: false,
  draggable: true,
  containedInSurface: true,
  edgeConstrained: false,
  xWeight: 0.5,
  stage: 'middleware',
  cardinality: 'multi',
  paletteCategory: 'policy',
  paletteOrder: 6,
  scope: 'ide',
  dropMode: 'canvas',
  hiddenFromPalette: true,
  deletable: true,
  defaultConfig: () => ({ policy_definition_id: '' }),
  help: {
    title: 'Model Policy',
    bodyHtml: `
      <p>Gate this <em>specific model</em> with its own OPA (Rego) policy,
      evaluated after the front-door gates pass and the member is resolved —
      under the caller's front-door identity. A <code>false</code> result
      denies the dispatch with HTTP 403.</p>
      <p>Use it to expose a model to only a subset of callers (e.g. a premium
      model gated to one Entra group) without touching the member LLM Surface's
      own policy. Fail-closed: a selected policy is required. Define IDE-scoped
      policies under Settings → Policies.</p>
    `,
  },
  provides: [Cap.CONFIGURABLE],
  requires: {},
  incompleteReason: c =>
    typeof c?.policy_definition_id === 'string' && c.policy_definition_id.trim() !== ''
      ? null
      : 'Policy definition must be selected',
  ConfigPanel: IdeMemberOpaPanel,
  summary: c =>
    typeof c?.policy_definition_id === 'string' && c.policy_definition_id.trim()
      ? String(c.policy_definition_id).substring(0, 16)
      : 'no policy',
};

export const ideOpaPolicyDefinition: NodeDefinition = {
  type: 'ide-opa-policy',
  label: 'OPA Policy',
  description: 'OPA (Rego) gate evaluated on every inbound request to this IDE front door',
  icon: '\uf3ed', // fa-shield-halved
  paletteIcon: 'fa-shield-alt',
  color: '#e74a3b',
  shape: 'circle',
  defaultRadius: 18,
  resizable: false,
  draggable: true,
  containedInSurface: true,
  edgeConstrained: false,
  xWeight: 0.22,
  stage: 'middleware',
  cardinality: 'singleton',
  paletteCategory: 'policy',
  paletteOrder: 1,
  scope: 'ide',
  dropMode: 'edge',
  directionality: 'request',
  hiddenFromPalette: false,
  deletable: true,
  defaultConfig: () => ({ enabled: true, policy_definition_id: '', log_decisions: false }),
  help: {
    title: 'OPA Policy',
    bodyHtml: `
      <p>Evaluate an OPA (Rego) policy on every inbound request to this IDE
      front door, before any member surface is dispatched. A
      <code>false</code> result denies the call with HTTP 403.</p>
      <p>Fail-closed: enabling the gate without selecting a policy denies
      everything. Define pipe-scoped policies under Settings → Policies.</p>
    `,
  },
  provides: [Cap.PIPELINE_EDGE, Cap.CONFIGURABLE],
  requires: {
    dropOnEdge: [Cap.IDE_SOURCE],
  },
  incompleteReason: config =>
    config?.enabled !== false && !config?.policy_definition_id
      ? 'Policy definition must be selected'
      : null,
  ConfigPanel: IdeOpaPolicyPanel,
  summary: c =>
    c?.enabled === false
      ? 'disabled'
      : c?.policy_definition_id
        ? String(c.policy_definition_id).substring(0, 16)
        : 'no policy',
};

export const ideRateLimitDefinition: NodeDefinition = {
  type: 'ide-rate-limit',
  label: 'Rate Limit',
  description: 'Request and token rate caps applied to this IDE front door',
  icon: '\uf625', // fa-gauge-high
  paletteIcon: 'fa-tachometer-alt',
  color: '#fd7e14',
  shape: 'circle',
  defaultRadius: 18,
  resizable: false,
  draggable: true,
  containedInSurface: true,
  edgeConstrained: false,
  xWeight: 0.22,
  stage: 'middleware',
  cardinality: 'singleton',
  paletteCategory: 'enhancement',
  paletteOrder: 2,
  scope: 'ide',
  dropMode: 'edge',
  directionality: 'request',
  hiddenFromPalette: false,
  deletable: true,
  defaultConfig: () => ({
    enabled: true,
    requests_per_minute: 60,
    tokens_per_minute: 100000,
  }),
  help: {
    title: 'Rate Limit',
    bodyHtml: `
      <p>Cap how many requests and tokens this IDE front door accepts in a
      rolling one-minute window. Once a cap is hit the gateway
      short-circuits with an HTTP 429 before any member surface runs.</p>
      <ul>
        <li><strong>Requests per minute</strong> — max calls per minute</li>
        <li><strong>Tokens per minute</strong> — max tokens per minute</li>
      </ul>
    `,
  },
  provides: [Cap.PIPELINE_EDGE, Cap.CONFIGURABLE],
  requires: {
    dropOnEdge: [Cap.IDE_SOURCE],
  },
  incompleteReason: () => null,
  ConfigPanel: IdeRateLimitPanel,
  summary: c =>
    c?.enabled === false
      ? 'disabled'
      : c?.requests_per_minute
        ? `${c.requests_per_minute}/min`
        : null,
};

/**
 * Front-door Caller Context extraction for the IDE surface. Configures the
 * surface's `source_auth` — validating the inbound caller and exposing the
 * verified identity (JWT claims, API-key subject, mTLS principal) to the OPA
 * gate as `input.source_auth.*`. Mirrors the AgentSurface `caller-auth`
 * element (same panel components, same wire methods) but writes to the IDE
 * surface's own top-level `source_auth` config instead of
 * `access_point.caller_authentication`. Without this element the surface is
 * open and OPA sees no caller identity — so a policy that reads
 * `input.source_auth.claims.tid` etc. cannot evaluate.
 */
export const ideCallerAuthDefinition: NodeDefinition = {
  type: 'ide-caller-auth',
  label: 'Caller Context',
  description: 'Validates the inbound caller (JWT, API key, mTLS) and exposes the identity to OPA',
  icon: '\uf084', // fa-key
  paletteIcon: 'fa-key',
  color: '#1cc88a',
  shape: 'circle',
  defaultRadius: 18,
  resizable: false,
  draggable: true,
  containedInSurface: true,
  edgeConstrained: false,
  xWeight: 0.15,
  stage: 'middleware',
  cardinality: 'singleton',
  paletteCategory: 'policy',
  paletteOrder: 0,
  scope: 'ide',
  dropMode: 'edge',
  directionality: 'request',
  hiddenFromPalette: false,
  deletable: true,
  defaultConfig: () => ({
    method_type: 'jwt_bearer',
    extraction_source: 'http_header',
    extraction_field: 'Authorization',
    jwt_token_header: 'Authorization',
    jwt_token_scheme: 'Bearer',
  }),
  help: {
    title: 'Caller Context',
    bodyHtml: `
      <p>Validates the inbound caller before dispatch and exposes the
      verified identity to the OPA gate as <code>input.source_auth.*</code>.
      Without this element the surface is open — anonymous callers reach
      the catalogue and any policy that reads a claim (e.g. Entra
      tenant / group) has nothing to evaluate.</p>
      <p>Mirrors the equivalent element on an Agent Surface — same
      methods, same wire shape — but wired to the IDE surface's own
      <code>source_auth</code> config.</p>
      <ul>
        <li><strong>JWT bearer</strong> — verify a signed token against
        a configured JWT verification strategy; publishes the full
        validated claim set to OPA under
        <code>input.source_auth.claims.*</code>.</li>
        <li><strong>API key</strong> — validate against a stored secret;
        publishes the key name to <code>input.source_auth.subject</code>.</li>
        <li><strong>API key provider</strong> — delegate to the API-key
        provider addressed by this surface's id.</li>
        <li><strong>mTLS</strong> — trust the TLS-terminated client
        certificate; publishes the bound principal to OPA.</li>
      </ul>
    `,
  },
  provides: [Cap.PIPELINE_EDGE, Cap.CONFIGURABLE],
  requires: {
    dropOnEdge: [Cap.IDE_SOURCE],
  },
  incompleteReason: callerAuthIncompleteReason,
  ConfigPanel: CallerAuthPanel,
  FullscreenPanel: CallerAuthFullscreen,
  summary: c => (c?.method_type ? String(c.method_type).replace(/_/g, ' ') : null),
};

export const ideAnchorDefinitions: NodeDefinition[] = [
  ideSourceDefinition,
  ideCatalogDefinition,
  ideResponseDefinition,
  ideMemberDefinition,
  ideMemberUpstreamAuthDefinition,
  ideMemberOpaDefinition,
  ideCallerAuthDefinition,
  ideOpaPolicyDefinition,
  ideRateLimitDefinition,
];
