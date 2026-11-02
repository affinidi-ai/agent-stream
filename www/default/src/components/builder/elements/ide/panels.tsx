import React from 'react';
import type { CanvasNode } from '../../SurfaceCanvas';
import type { ConfigPanelProps } from '../types';
import { RouteListenerBanner } from '../_shared/RouteListenerSection';
import { useIdePanelData } from './idePanelData';

const toInt = (v: string): number => {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : 0;
};

/**
 * Mint an opaque, collision-resistant suffix for a new member's stable canvas
 * node id. Prefers `crypto.randomUUID`, falling back to a random+timestamp
 * string in environments (older test runners) that lack it.
 */
const stableNodeSuffix = (): string => {
  const c = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto;
  if (c && typeof c.randomUUID === 'function') return c.randomUUID();
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
};

/** Parse a positive integer, collapsing blank / non-positive input to undefined. */
const toPositiveIntOrUndef = (v: string): number | undefined => {
  const t = v.trim();
  if (t === '') return undefined;
  const n = parseInt(t, 10);
  return Number.isFinite(n) && n > 0 ? n : undefined;
};

/**
 * Sidebar panel for the ide-source anchor — the caller's entry point into the
 * IDE front door. Edits the listener address and route (path prefix + custom
 * path). IDEs discover models at `{route}/v1/models` and dispatch at
 * `{route}/v1/chat/completions`. Mirrors the pipe-source panel.
 */
export const IdeSourcePanel: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  updateFields,
}) => {
  const { routing, oauthIdentifiers } = useIdePanelData();
  const oauthIdentifierId =
    typeof config?.client_auth_oauth_identifier_id === 'string'
      ? config.client_auth_oauth_identifier_id
      : '';
  const listenAddress = typeof config?.listen_address === 'string' ? config.listen_address : '';
  const prefix = typeof config?.prefix === 'string' ? config.prefix : '';
  const customPath = typeof config?.custom_path === 'string' ? config.custom_path : '';
  const normalizedCustom = customPath.startsWith('/') ? customPath.slice(1) : customPath;
  const fullRoute =
    listenAddress && prefix
      ? `${listenAddress}${prefix}${normalizedCustom ? `/${normalizedCustom}` : ''}`
      : '';

  if (routing.availableListenAddresses.length === 0 && routing.pathPrefixes.length === 0) {
    return (
      <div className="surface-config-panel">
        <p className="text-muted small mb-0">
          Represents the IDE reaching this catalogue. Routing options are still loading; the
          listener and path are edited here once available. Callers authenticate once at this front
          door.
        </p>
      </div>
    );
  }

  return (
    <div className="surface-config-panel">
      <RouteListenerBanner
        label="IDE Route"
        url={fullRoute}
        placeholder="(select listen address and prefix)"
      />
      <div className="mb-3">
        <label className="form-label">Listen address</label>
        <select
          className="form-select"
          value={listenAddress}
          onChange={e => updateField('listen_address', e.target.value)}
        >
          <option value="">Select listen address…</option>
          {routing.availableListenAddresses.map(addr => (
            <option key={addr} value={addr}>
              {addr}
            </option>
          ))}
        </select>
      </div>
      <div className="mb-3">
        <label className="form-label">Path prefix</label>
        <select
          className="form-select"
          value={prefix}
          onChange={e => updateField('prefix', e.target.value)}
        >
          <option value="">Select prefix…</option>
          {routing.pathPrefixes.map(p => (
            <option key={p.id} value={p.prefix}>
              {p.name}
            </option>
          ))}
        </select>
      </div>
      <div className="mb-0">
        <label className="form-label">Custom path</label>
        <input
          type="text"
          className="form-control"
          value={normalizedCustom}
          onChange={e => updateField('custom_path', e.target.value)}
          placeholder="e.g. team-models"
        />
      </div>
      <hr className="my-3" />
      <div className="mb-2">
        <label className="form-label mb-1">Publish OAuth Metadata to Caller</label>
        <p className="text-muted small mb-2">
          OAuth configuration metadata details published to clients. Facilitates centralised
          configuration management. See{' '}
          <a href="/credentials?tab=oauth-identifiers" target="_blank" rel="noopener noreferrer">
            <strong>credentials manager</strong>
          </a>
          .
        </p>
      </div>
      <div className="mb-3">
        {oauthIdentifiers.length > 0 ? (
          <select
            className="form-select"
            value={oauthIdentifierId}
            onChange={e => {
              const next = e.target.value;
              if (next === '') {
                // "Do not publish" — clear the profile ref AND any legacy
                // inline identifiers that may have been hydrated from a
                // previously-saved surface, so `readIdeClientAuth` returns
                // `present=false` and the saved payload carries no
                // `client_auth` block (nothing published at
                // `.well-known/agent-stream`, sandbox shows no bootstrap).
                updateFields({
                  client_auth_oauth_identifier_id: '',
                  client_auth_tenant_id: '',
                  client_auth_client_id: '',
                  client_auth_scopes: [],
                });
              } else {
                updateField('client_auth_oauth_identifier_id', next);
              }
            }}
            data-testid="ide-client-auth-profile"
          >
            <option value="">Not published - client manually configured</option>
            {oauthIdentifiers.map(o => (
              <option key={o.id} value={o.id}>
                {o.name} ({o.provider})
              </option>
            ))}
          </select>
        ) : (
          <div className="form-text text-warning">
            No OAuth Identifiers defined. See{' '}
            <a href="/credentials?tab=oauth-identifiers" target="_blank" rel="noopener noreferrer">
              <strong>credentials manager</strong>
            </a>
          </div>
        )}
      </div>
    </div>
  );
};

/**
 * Read the catalogue's member nodes (`ide-member`) sorted by their stored
 * `order` then node id, so the roster the panel renders and the array the
 * canvas persists stay in the order the user sees. Mirrors
 * `readCandidateNodes` in the pipe decider panel.
 */
function readIdeMemberNodes(allNodes: CanvasNode[] | undefined): CanvasNode[] {
  return (allNodes ?? [])
    .filter(n => n.type === 'ide-member')
    .sort((a, b) => {
      const ao = typeof a.config?.order === 'number' ? a.config.order : 0;
      const bo = typeof b.config?.order === 'number' ? b.config.order : 0;
      return ao - bo || a.id.localeCompare(b.id);
    });
}

/**
 * Sidebar panel for the ide-catalog hero — the roster that owns the catalogue's
 * member surfaces, mirroring the pipe decider's candidate roster. Each member is
 * one of your configured LLM Surfaces mapped to a unique mnemonic; that mnemonic
 * is the model id the IDE client sends back to pick this surface. "Add LLM
 * Surface" mints a member node; each row picks a surface and edits its mnemonic
 * inline, and opens the member's own panel for advanced options.
 */
export const IdeCatalogPanel: React.FC<ConfigPanelProps> = ({
  allNodes,
  addNode,
  removeNode,
  updateNodeConfig,
  selectNode,
  autoLayout,
}) => {
  const { memberPipes } = useIdePanelData();
  const memberNodes = readIdeMemberNodes(allNodes);
  const exposed = memberNodes.filter(
    n => (n.config as { expose?: boolean })?.expose !== false
  ).length;

  const addMember = () => {
    if (!addNode) return;
    // Mint a stable, opaque node id (not positional) so this member's canvas
    // position and docked gate chips stay bound to *it* across catalogue
    // reorders — the id is persisted as `IdeCatalogMember.node_id` and re-used
    // on the next load. A UUID can never collide with the legacy positional
    // `ide-member-N` fallback used for pre-`node_id` configs.
    const node: CanvasNode = {
      id: `ide-member-${stableNodeSuffix()}`,
      type: 'ide-member',
      label: 'LLM Surface',
      configured: false,
      parentId: 'ide-catalog',
      config: {
        pipe_id: '',
        variant_alias: '',
        mnemonic: '',
        display_name: '',
        group: '',
        order: memberNodes.length,
        default: false,
        expose: true,
      },
    };
    addNode(node);
    autoLayout?.();
  };

  const patchMember = (node: CanvasNode, updates: Record<string, unknown>) => {
    if (!updateNodeConfig) return;
    updateNodeConfig(node.id, { ...(node.config ?? {}), ...updates });
  };

  /**
   * Swap the row at `index` with its neighbour at `index + delta` and re-stamp
   * every member's `order` to its new position (0..n-1). This is the source of
   * truth for a member's rank in the published `/v1/models` list — top of the
   * roster maps to the lowest `order`, which the backend sorts first, so top
   * of this list = top of the IDE model picker.
   */
  const moveMember = (index: number, delta: number) => {
    const next = index + delta;
    if (next < 0 || next >= memberNodes.length) return;
    const reordered = [...memberNodes];
    [reordered[index], reordered[next]] = [reordered[next], reordered[index]];
    reordered.forEach((n, i) => {
      const current = typeof n.config?.order === 'number' ? n.config.order : -1;
      if (current !== i) {
        updateNodeConfig?.(n.id, { ...(n.config ?? {}), order: i });
      }
    });
  };

  const removeMember = (nodeId: string) => {
    removeNode?.(nodeId);
    autoLayout?.();
  };

  return (
    <div className="surface-config-panel">
      <div className="alert alert-info py-2 mb-3" style={{ fontSize: '11px' }}>
        <i className="fas fa-info-circle me-1" /> The catalogue publishes an OpenAI-compatible model
        model list to IDEs such as VSCode, IntelliJ, Cursor.
      </div>

      <div className="d-flex justify-content-between align-items-center mb-1">
        <label className="form-label small text-muted mb-0">
          LLM Surfaces ({exposed}/{memberNodes.length} published)
        </label>
        <button
          type="button"
          className="btn btn-outline-primary btn-sm py-0 px-2"
          onClick={addMember}
          disabled={!addNode}
          data-testid="ide-catalog-add-member"
        >
          <i className="fas fa-plus me-1" />
          Publish LLM Surface
        </button>
      </div>

      {memberNodes.length === 0 ? (
        <p className="text-muted small mb-0">
          No member surfaces yet. Add at least one LLM Surface for this catalogue to publish.
        </p>
      ) : (
        <ul className="list-group mb-0">
          {memberNodes.map((node, idx) => {
            const c = (node.config ?? {}) as Record<string, unknown>;
            const pipeId = typeof c.pipe_id === 'string' ? c.pipe_id : '';
            const mnemonic = typeof c.mnemonic === 'string' ? c.mnemonic : '';
            const variantAlias = typeof c.variant_alias === 'string' ? c.variant_alias : '';
            const derivedId = variantAlias ? `${pipeId}$${variantAlias}` : pipeId;
            const hidden = c.expose === false;
            return (
              <li key={node.id} className="list-group-item py-2">
                <div className="d-flex justify-content-between align-items-center mb-1">
                  <span className="small text-muted">
                    Model {idx + 1}
                    {hidden && <span className="badge text-bg-secondary ms-1">hidden</span>}
                  </span>
                  <div className="d-flex gap-1">
                    <button
                      type="button"
                      className="btn btn-outline-secondary btn-sm py-0 px-2"
                      onClick={() => moveMember(idx, -1)}
                      disabled={!updateNodeConfig || idx === 0}
                      title="Move up (higher in the IDE picker)"
                      aria-label="Move up"
                      data-testid="ide-catalog-member-up"
                    >
                      <i className="fas fa-arrow-up" />
                    </button>
                    <button
                      type="button"
                      className="btn btn-outline-secondary btn-sm py-0 px-2"
                      onClick={() => moveMember(idx, 1)}
                      disabled={!updateNodeConfig || idx === memberNodes.length - 1}
                      title="Move down (lower in the IDE picker)"
                      aria-label="Move down"
                      data-testid="ide-catalog-member-down"
                    >
                      <i className="fas fa-arrow-down" />
                    </button>
                    {selectNode && (
                      <button
                        type="button"
                        className="btn btn-outline-secondary btn-sm py-0 px-2"
                        onClick={() => selectNode(node.id)}
                        title="Configure this surface (variant, display name, gates…)"
                      >
                        <i className="fas fa-sliders" />
                      </button>
                    )}
                    <button
                      type="button"
                      className="btn btn-outline-danger btn-sm py-0 px-2"
                      onClick={() => removeMember(node.id)}
                      disabled={!removeNode}
                      title="Remove surface"
                      aria-label="Remove surface"
                    >
                      <i className="fas fa-trash" />
                    </button>
                  </div>
                </div>
                {memberPipes.length === 0 ? (
                  <div className="alert alert-warning py-1 px-2 mb-1" style={{ fontSize: '11px' }}>
                    <i className="fas fa-exclamation-triangle me-1" />
                    No LLM Surfaces available yet. Create one under LLM first.
                  </div>
                ) : (
                  <select
                    className="form-select form-select-sm mb-1"
                    value={pipeId}
                    data-testid="ide-catalog-member-pipe"
                    onChange={e =>
                      patchMember(node, { pipe_id: e.target.value, variant_alias: '' })
                    }
                  >
                    <option value="">-- Select an LLM Surface --</option>
                    {memberPipes.map(p => (
                      <option key={p.id} value={p.id}>
                        {p.name}
                        {p.model ? ` (${p.model})` : ''}
                      </option>
                    ))}
                  </select>
                )}
                <input
                  type="text"
                  className="form-control form-control-sm"
                  value={mnemonic}
                  data-testid="ide-catalog-member-mnemonic"
                  onChange={e => patchMember(node, { mnemonic: e.target.value })}
                  placeholder={derivedId ? `Mnemonic (default: ${derivedId})` : 'Model identifier'}
                />
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
};

/**
 * Sidebar panel for the ide-response anchor — the model list / chat reply the
 * catalogue returns to the IDE. Mirrors the pipe-response panel: a single
 * toggle controlling the dotted arc the canvas draws back to the caller.
 */
export const IdeResponsePanel: React.FC<ConfigPanelProps> = ({ config, updateField }) => {
  const visualize = config?.visualize_response_to_caller !== false;
  return (
    <div className="surface-config-panel">
      <div className="alert alert-info py-2 mb-3" style={{ fontSize: '11px' }}>
        <i className="fas fa-info-circle me-1" /> The response is what the catalogue returns to the
        IDE — the aggregated model list at <code>/v1/models</code>, or the dispatched chat reply.
        The toggle below controls the dotted arc the canvas draws from the response back to the
        caller.
      </div>
      <div className="form-check form-switch mb-3">
        <input
          className="form-check-input"
          type="checkbox"
          role="switch"
          id="ide-response-visualize"
          checked={visualize}
          onChange={e => updateField('visualize_response_to_caller', e.target.checked)}
        />
        <label className="form-check-label" htmlFor="ide-response-visualize">
          Visualise response to caller
        </label>
      </div>
    </div>
  );
};

/**
 * Sidebar panel for an ide-member node — the STAR of the IDE builder. Picks a
 * real, already-configured LLM Surface (and optionally one of its variants)
 * from the live catalogue, then tunes how it appears in the published model
 * list (display name, default, exposure). Ordering is edited on the Catalogue
 * panel (up/down buttons) rather than here.
 */
export const IdeMemberPanel: React.FC<ConfigPanelProps> = ({
  node,
  config,
  updateField,
  updateFields,
  allNodes,
  addNode,
  removeNode,
  selectNode,
  autoLayout,
}) => {
  const { memberPipes } = useIdePanelData();
  const pipeId = typeof config?.pipe_id === 'string' ? config.pipe_id : '';
  const variantAlias = typeof config?.variant_alias === 'string' ? config.variant_alias : '';
  const selectedPipe = memberPipes.find(p => p.id === pipeId) || null;
  const derivedId = pipeId ? (variantAlias ? `${pipeId}$${variantAlias}` : pipeId) : '';

  // Opt-in per-model gate chips docked to this member. Their ids are derived
  // from the member id so the round-trip in `ideNodesFromConfig` can seed and
  // read them back deterministically (`{chipType}-{memberId}`).
  const memberId = node.id;
  const upstreamChipId = `ide-member-upstream-auth-${memberId}`;
  const opaChipId = `ide-member-opa-${memberId}`;
  const upstreamChip = (allNodes ?? []).find(n => n.id === upstreamChipId);
  const opaChip = (allNodes ?? []).find(n => n.id === opaChipId);

  const addUpstreamChip = () => {
    if (!addNode || upstreamChip) return;
    addNode({
      id: upstreamChipId,
      type: 'ide-member-upstream-auth',
      label: 'Upstream Sign-in',
      configured: false,
      parentId: memberId,
      config: { upstream_oauth_identifier_id: '' },
    });
    autoLayout?.();
  };

  const addOpaChip = () => {
    if (!addNode || opaChip) return;
    addNode({
      id: opaChipId,
      type: 'ide-member-opa',
      label: 'Model Policy',
      configured: false,
      parentId: memberId,
      config: { policy_definition_id: '' },
    });
    autoLayout?.();
  };

  const removeChip = (id: string) => {
    removeNode?.(id);
    autoLayout?.();
  };

  const toggleUpstreamChip = (enabled: boolean) => {
    if (enabled) {
      if (!upstreamChip) addUpstreamChip();
    } else if (upstreamChip) {
      removeChip(upstreamChipId);
    }
  };

  const toggleOpaChip = (enabled: boolean) => {
    if (enabled) {
      if (!opaChip) addOpaChip();
    } else if (opaChip) {
      removeChip(opaChipId);
    }
  };

  const onSelectPipe = (nextId: string) => {
    // Changing the surface drops any variant that no longer applies.
    if (updateFields) {
      updateFields({ pipe_id: nextId, variant_alias: '' });
    } else {
      updateField('pipe_id', nextId);
      updateField('variant_alias', '');
    }
  };

  return (
    <div className="surface-config-panel">
      <div className="mb-3">
        <label className="form-label">LLM Surface</label>
        {memberPipes.length === 0 ? (
          <div className="alert alert-warning py-2 mb-0" style={{ fontSize: '11px' }}>
            <i className="fas fa-exclamation-triangle me-1" />
            No LLM Surfaces available yet.{' '}
            <a href="/llm/new" target="_blank" rel="noopener noreferrer">
              Create a new LLM Surface
            </a>
          </div>
        ) : (
          <select
            className="form-select"
            value={pipeId}
            data-testid="ide-member-pipe"
            onChange={e => onSelectPipe(e.target.value)}
          >
            <option value="">-- Select a surface --</option>
            {memberPipes.map(p => (
              <option key={p.id} value={p.id}>
                {p.name}
                {p.model ? ` (${p.model})` : ''}
              </option>
            ))}
          </select>
        )}
      </div>

      {selectedPipe && selectedPipe.variants.length > 0 && (
        <div className="mb-3">
          <label className="form-label">Target Variant</label>
          <select
            className="form-select"
            value={variantAlias}
            data-testid="ide-member-variant"
            onChange={e => updateField('variant_alias', e.target.value)}
          >
            <option value="">Base surface</option>
            {selectedPipe.variants.map(v => (
              <option key={v.alias} value={v.alias}>
                {v.name} (${v.alias})
              </option>
            ))}
          </select>
        </div>
      )}

      <div className="mb-3">
        <label className="form-label">Display name in client IDE</label>
        <input
          type="text"
          className="form-control"
          value={typeof config?.display_name === 'string' ? config.display_name : ''}
          onChange={e => updateField('display_name', e.target.value)}
          placeholder={selectedPipe ? selectedPipe.name : 'Shown to the IDE (optional)'}
        />
      </div>

      <div className="mb-3">
        <label className="form-label">Mnemonic (model id)</label>
        <input
          type="text"
          className="form-control"
          value={typeof config?.mnemonic === 'string' ? config.mnemonic : ''}
          data-testid="ide-member-mnemonic"
          onChange={e => updateField('mnemonic', e.target.value)}
          placeholder={derivedId ? `Default: ${derivedId}` : 'e.g. fast-coder'}
        />
        <small className="form-text text-muted">
          The model id the IDE sends to select this surface. Must be unique across the catalogue.
        </small>
      </div>

      <hr className="my-3" />
      <label className="form-label">Caller Context & Policy Enforcement (optional)</label>
      <p className="text-muted small mb-2"></p>
      <div className="form-check form-switch mb-2">
        <input
          className="form-check-input"
          type="checkbox"
          role="switch"
          id={`ide-member-upstream-toggle-${memberId}`}
          checked={!!upstreamChip}
          onChange={e => toggleUpstreamChip(e.target.checked)}
          disabled={!addNode || !removeNode}
          data-testid="ide-member-toggle-upstream"
        />

        <label className="form-check-label" htmlFor={`ide-member-upstream-toggle-${memberId}`}>
          Upstream sign-in
        </label>
      </div>
      <div className="form-check form-switch mb-0">
        <input
          className="form-check-input"
          type="checkbox"
          role="switch"
          id={`ide-member-opa-toggle-${memberId}`}
          checked={!!opaChip}
          onChange={e => toggleOpaChip(e.target.checked)}
          disabled={!addNode || !removeNode}
          data-testid="ide-member-toggle-opa"
        />
        <label className="form-check-label" htmlFor={`ide-member-opa-toggle-${memberId}`}>
          Enforce an OPA Policy for this LLM surface model route
        </label>
      </div>

      <hr className="my-3" />
      <div className="mb-3">
        <label className="form-label">Context window (advertised to the IDE)</label>
        <div className="row g-2">
          <div className="col">
            <input
              type="number"
              min={1}
              className="form-control form-control-sm"
              value={typeof config?.max_input_tokens === 'number' ? config.max_input_tokens : ''}
              onChange={e => updateField('max_input_tokens', toPositiveIntOrUndef(e.target.value))}
              placeholder="Max input tokens"
              aria-label="Max input tokens"
            />
          </div>
          <div className="col">
            <input
              type="number"
              min={1}
              className="form-control form-control-sm"
              value={typeof config?.max_output_tokens === 'number' ? config.max_output_tokens : ''}
              onChange={e => updateField('max_output_tokens', toPositiveIntOrUndef(e.target.value))}
              placeholder="Max output tokens"
              aria-label="Max output tokens"
            />
          </div>
        </div>
        <small className="form-text text-muted">
          Sets the model's context size shown in the IDE picker. Leave blank to use the client's
          defaults.
        </small>
      </div>

      <div className="form-check form-switch mb-0">
        <input
          className="form-check-input"
          type="checkbox"
          role="switch"
          id="ide-member-expose"
          checked={config?.expose !== false}
          onChange={e => updateField('expose', e.target.checked)}
        />
        <label className="form-check-label" htmlFor="ide-member-expose">
          Enabled (published to the IDE model list)
        </label>
      </div>
    </div>
  );
};

/**
 * Front-door rate limit for the IDE surface. Caps requests/tokens per rolling
 * minute at the catalogue's own listener, before any member surface runs.
 */
export const IdeRateLimitPanel: React.FC<ConfigPanelProps> = ({ config, updateField }) => (
  <div className="surface-config-panel">
    <p className="text-muted small">
      Cap how many requests and tokens this IDE front door accepts per rolling minute. Delete this
      node to remove rate limiting.
    </p>
    <div className="mb-3">
      <label className="form-label">Requests per minute</label>
      <input
        type="number"
        min={0}
        className="form-control"
        value={config?.requests_per_minute ?? 0}
        onChange={e => updateField('requests_per_minute', toInt(e.target.value))}
        placeholder="60"
      />
    </div>
    <div className="mb-0">
      <label className="form-label">Tokens per minute</label>
      <input
        type="number"
        min={0}
        className="form-control"
        value={config?.tokens_per_minute ?? 0}
        onChange={e => updateField('tokens_per_minute', toInt(e.target.value))}
        placeholder="100000"
      />
    </div>
  </div>
);

/**
 * Front-door OPA (Rego) gate for the IDE surface, evaluated against each
 * inbound request before dispatch. Mirrors the pipe OPA panel; the node's
 * presence IS the enabled state.
 */
export const IdeOpaPolicyPanel: React.FC<ConfigPanelProps> = ({ config, updateField }) => {
  // Load-once via IdePanelData — the editor fetches the IDE-scoped policy
  // list at open time and threads it through context, so opening this panel
  // (or any other Model Policy chip) never refires the request or flashes an
  // empty-state warning between clicks.
  const { policies } = useIdePanelData();

  const selected = policies.find(p => p.id === config?.policy_definition_id) || null;

  return (
    <div className="surface-config-panel">
      <div className="alert alert-info py-2 mt-2 mb-0" style={{ fontSize: '11px' }}>
        <i className="fas fa-info-circle me-1" /> Evaluate an OPA (Rego) policy on every inbound
        request to this IDE front door. A <code>false</code> result denies the call (403).
        Fail-closed: a selected policy is required.
      </div>

      <div className="mb-0">
        <label className="form-label">Policy Definition</label>
        {policies.length === 0 ? (
          <div className="alert alert-warning py-2 mb-0" style={{ fontSize: '11px' }}>
            <i className="fas fa-exclamation-triangle me-1" />
            No IDE policies are defined yet. Create one in the Policies manager.
          </div>
        ) : (
          <select
            className="form-control"
            value={config?.policy_definition_id || ''}
            onChange={e => updateField('policy_definition_id', e.target.value || '')}
          >
            <option value="">-- Select a policy --</option>
            {policies.map(p => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        )}
        {selected?.description && (
          <p className="text-muted small mt-2 mb-0">{selected.description}</p>
        )}
      </div>
      <div className="form-check form-switch mt-3 mb-0">
        <input
          className="form-check-input"
          type="checkbox"
          id="ide-opa-log-decisions"
          checked={config?.log_decisions === true}
          onChange={e => updateField('log_decisions', e.target.checked)}
        />
        <label className="form-check-label" htmlFor="ide-opa-log-decisions">
          Log OPA decisions
        </label>
      </div>
      <div className="alert alert-info py-2 mt-2 mb-0" style={{ fontSize: '11px' }}>
        <i className="fas fa-info-circle me-1" /> When on, every OPA evaluation logs the full input
        JSON handed to Rego and the resulting allow/deny to the appliance log — useful when
        authoring or debugging a policy. Leave off in production.
      </div>
    </div>
  );
};

/**
 * Sidebar panel for a per-member Upstream Sign-in chip
 * (`ide-member-upstream-auth`). Picks the OAuth Identifier profile whose token
 * this model forwards to its upstream provider (identity pass-through), in place
 * of the caller's front-door token. Round-trips to the member's
 * `upstream_oauth_identifier_id`.
 */
export const IdeMemberUpstreamAuthPanel: React.FC<ConfigPanelProps> = ({ config, updateField }) => {
  const { oauthIdentifiers } = useIdePanelData();
  const profileId =
    typeof config?.upstream_oauth_identifier_id === 'string'
      ? config.upstream_oauth_identifier_id
      : '';
  return (
    <div className="surface-config-panel">
      <p className="text-muted small">
        Forward a distinct upstream token for this model instead of the caller's front-door token
        (sent in <code>X-Agent-Stream-Upstream-Authorization</code>). Only takes effect when the
        selected LLM Surface enables <em>forward caller's token</em>. Delete this node to forward
        the front-door token.
      </p>
      <div className="mb-0">
        <label className="form-label">OAuth Identifier</label>
        {oauthIdentifiers.length === 0 ? (
          <div className="alert alert-warning py-2 mb-0" style={{ fontSize: '11px' }}>
            <i className="fas fa-exclamation-triangle me-1" />
            No OAuth Identifiers yet. Create one under{' '}
            <strong>Credentials → OAuth Identifiers</strong>.
          </div>
        ) : (
          <select
            className="form-select"
            value={profileId}
            data-testid="ide-member-upstream-profile"
            onChange={e => updateField('upstream_oauth_identifier_id', e.target.value)}
          >
            <option value="">-- Select an OAuth Identifier --</option>
            {oauthIdentifiers.map(o => (
              <option key={o.id} value={o.id}>
                {o.name} ({o.provider})
              </option>
            ))}
          </select>
        )}
      </div>
    </div>
  );
};

/**
 * Sidebar panel for a per-member Model Policy chip (`ide-member-opa`). Selects
 * an IDE-scoped policy definition (`package ide.policy`) evaluated when this
 * specific model is dispatched, under the caller's front-door identity. Mirrors
 * the front-door IdeOpaPolicyPanel but writes the member's `opa_policy_id`.
 */
export const IdeMemberOpaPanel: React.FC<ConfigPanelProps> = ({ config, updateField }) => {
  // Load-once via IdePanelData — see IdeOpaPolicyPanel above.
  const { policies } = useIdePanelData();

  const selected = policies.find(p => p.id === config?.policy_definition_id) || null;

  return (
    <div className="surface-config-panel">
      <div className="alert alert-info py-2 mt-2 mb-0" style={{ fontSize: '11px' }}>
        <i className="fas fa-info-circle me-1" /> Gate this specific model with an OPA (Rego) policy
        evaluated when it is dispatched, under the caller's front-door identity. A{' '}
        <code>false</code> result denies the call (403). Fail-closed: a selected policy is required.
      </div>
      <br />
      <div className="mb-0">
        <label className="form-label">Policy Definition</label>
        {policies.length === 0 ? (
          <div className="alert alert-warning py-2 mb-0" style={{ fontSize: '11px' }}>
            <i className="fas fa-exclamation-triangle me-1" />
            No IDE policies are defined yet. Create one in the Policies manager.
          </div>
        ) : (
          <select
            className="form-control"
            value={config?.policy_definition_id || ''}
            data-testid="ide-member-opa-policy"
            onChange={e => updateField('policy_definition_id', e.target.value || '')}
          >
            <option value="">-- Select a policy --</option>
            {policies.map(p => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        )}
        {selected?.description && (
          <p className="text-muted small mt-2 mb-0">{selected.description}</p>
        )}
      </div>
    </div>
  );
};
