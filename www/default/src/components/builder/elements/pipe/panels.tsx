import React from 'react';
import { apiClient } from '../../../../api';
import type { CanvasNode } from '../../SurfaceCanvas';
import type { ConfigPanelProps } from '../types';
import { JurorConfig, makeDefaultJuror, jurorSlotPosition } from '../../../shared/jurorModel';
import {
  DeciderCandidate,
  DeciderConfig,
  SurfaceExecutionMode,
  SURFACE_MODE_OPTIONS,
  MAX_MIRROR_CANDIDATES,
  surfaceModeFromDecider,
  surfaceModeOption,
  applyModeToDeciderConfig,
  freshDeciderConfig,
  candidateSlotPosition,
  makeDefaultCandidate,
} from '../../../shared/deciderModel';
import {
  WitnessConfig,
  WitnessProvider,
  WITNESS_PROVIDERS,
  makeDefaultWitness,
} from '../../../shared/witnessModel';
import { RouteListenerBanner } from '../_shared/RouteListenerSection';
import { usePipePanelData } from './pipePanelData';
import SecretSelector from '../../../shared/SecretSelector';
import { firstEnabledModelValue, selectableModels } from '../../../../utils/modelVisibility';
import { apiKeyDisabled } from '../../../../utils/apiKeyValidation';

/**
 * Inline usage-limit controls shared by the LLM, Judge, Jury, and Access Point
 * panels. A single switch ("enforce a limit") toggles a monthly cost / token
 * ceiling for that node's scope; the caps surface only while enforcement is on.
 * The values live as `usage_limit_*` config on the node and are assembled into
 * the backend `usage_limits` array by `readUsageLimits` (one entry per node).
 * Once a running monthly total reaches a cap the gateway short-circuits further
 * calls for that scope with HTTP 429 until the month rolls over.
 */
const usageLimitToNum = (v: string): number | null => {
  if (v.trim() === '') return null;
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? n : null;
};

const PipeUsageLimitControls: React.FC<{
  config: any;
  updateField: (field: string, value: any) => void;
  label: string;
  idPrefix: string;
}> = ({ config, updateField, label, idPrefix }) => {
  const enabled = config?.usage_limit_enabled === true;
  return (
    <div className="mb-0">
      <div className="form-check form-switch">
        <input
          className="form-check-input"
          type="checkbox"
          role="switch"
          id={`${idPrefix}-usage-limit-enabled`}
          data-testid={`${idPrefix}-usage-limit-enabled`}
          checked={enabled}
          onChange={e => updateField('usage_limit_enabled', e.target.checked)}
        />
        <label className="form-check-label" htmlFor={`${idPrefix}-usage-limit-enabled`}>
          {label}
        </label>
      </div>
      {enabled && (
        <div className="mt-2">
          <div className="mb-3">
            <label className="form-label">Monthly budget (USD)</label>
            <input
              type="number"
              min={0}
              step="0.01"
              className="form-control"
              data-testid={`${idPrefix}-usage-limit-budget`}
              value={config?.usage_limit_monthly_budget_usd ?? ''}
              onChange={e =>
                updateField('usage_limit_monthly_budget_usd', usageLimitToNum(e.target.value))
              }
              placeholder="No budget cap"
            />
          </div>
          <div className="mb-0">
            <label className="form-label">Monthly token cap</label>
            <input
              type="number"
              min={0}
              step="1"
              className="form-control"
              data-testid={`${idPrefix}-usage-limit-tokens`}
              value={config?.usage_limit_monthly_token_cap ?? ''}
              onChange={e =>
                updateField('usage_limit_monthly_token_cap', usageLimitToNum(e.target.value))
              }
              placeholder="No token cap"
            />
          </div>
        </div>
      )}
    </div>
  );
};

/**
 * Sidebar panel for the pipe-source anchor — the caller's entry point. Edits
 * the listener address and route (path prefix + custom path), the routing
 * fields that decide where the pipe is reachable. When the routing catalogue
 * is unavailable (via {@link usePipePanelData}) it shows a read-only note so
 * the node never blocks. Source authentication attaches as its own element.
 */
export const PipeSourcePanel: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  openSurfaceConfig,
}) => {
  const { routing } = usePipePanelData();
  const listenAddress = typeof config?.listen_address === 'string' ? config.listen_address : '';
  const prefix = typeof config?.prefix === 'string' ? config.prefix : '';
  const customPath = typeof config?.custom_path === 'string' ? config.custom_path : '';
  const normalizedCustom = customPath.startsWith('/') ? customPath.slice(1) : customPath;
  const fullRoute =
    listenAddress && prefix
      ? `${listenAddress}${prefix}${normalizedCustom ? `/${normalizedCustom}` : ''}`
      : '';

  const configureSurfaceButton = openSurfaceConfig && (
    <button
      type="button"
      className="btn btn-outline-primary btn-sm w-100 mt-3"
      data-testid="ap-configure-surface"
      onClick={() => openSurfaceConfig()}
    >
      <i className="fas fa-pen-to-square me-1" /> Configure Surface Features
    </button>
  );

  if (routing.availableListenAddresses.length === 0 && routing.pathPrefixes.length === 0) {
    return (
      <div className="surface-config-panel">
        <p className="text-muted small mb-0">
          Represents the caller entering this pipe. Routing options are still loading; the listener
          and path are edited here once available. Authentication and rate limits attach as their
          own elements.
        </p>
        {configureSurfaceButton}
      </div>
    );
  }

  return (
    <div className="surface-config-panel">
      <RouteListenerBanner
        label="Pipe Route"
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
          placeholder="e.g. my-gpt-4"
        />
      </div>
      {configureSurfaceButton}
    </div>
  );
};

// ── Surface execution mode (LLM Direct / decide / compare / consolidate) ──
// One top-level choice unifying the decider on/off state, routing strategy, and
// mirror aggregation. Applied by mutating the canvas: `direct` removes the
// decider (+ candidates); the others create it (seeding a first candidate) or,
// when it already exists, patch its strategy/mirror in place.
interface SurfaceModeOps {
  allNodes?: CanvasNode[];
  addNode?: (node: CanvasNode) => void;
  removeNode?: (nodeId: string) => void;
  updateNodeConfig?: (nodeId: string, config: any) => void;
  autoLayout?: () => void;
}

function applySurfaceMode(mode: SurfaceExecutionMode, ops: SurfaceModeOps): void {
  const nodes = ops.allNodes ?? [];
  const deciderNode = nodes.find(n => n.type === 'pipe-decider');

  if (mode === 'direct') {
    if (!deciderNode || !ops.removeNode) return;
    nodes
      .filter(n => n.type === 'pipe-decider' || n.type === 'pipe-candidate')
      .forEach(n => ops.removeNode!(n.id));
    ops.autoLayout?.();
    return;
  }

  if (deciderNode) {
    ops.updateNodeConfig?.('pipe-decider', {
      ...(deciderNode.config ?? {}),
      decider: applyModeToDeciderConfig(
        (deciderNode.config?.decider ?? null) as Record<string, unknown> | null,
        mode
      ),
    });
    return;
  }

  if (!ops.addNode) return;
  const llmX = nodes.find(n => n.type === 'pipe-upstream')?.position?.x ?? 0;
  const deciderY = 140;
  ops.addNode({
    id: 'pipe-decider',
    type: 'pipe-decider',
    label: 'Decider',
    configured: false,
    position: { x: llmX, y: deciderY },
    parentId: 'pipe-upstream',
    config: {
      decider: applyModeToDeciderConfig(freshDeciderConfig(), mode),
    },
  });
  const candidate = makeDefaultCandidate(0);
  ops.addNode({
    id: 'pipe-candidate-0',
    type: 'pipe-candidate',
    label: candidate.name,
    configured: false,
    position: candidateSlotPosition(0, llmX, deciderY),
    parentId: 'pipe-decider',
    config: { candidate, candidateIndex: 0 },
  });
  ops.autoLayout?.();
}

/** Shared "surface mode" dropdown. `options` defaults to all four modes. */
const SurfaceModeSelect: React.FC<{
  mode: SurfaceExecutionMode;
  onChange: (mode: SurfaceExecutionMode) => void;
  idPrefix: string;
  options?: typeof SURFACE_MODE_OPTIONS;
  disabled?: boolean;
}> = ({ mode, onChange, idPrefix, options = SURFACE_MODE_OPTIONS, disabled }) => (
  <div className="mb-3">
    <label className="form-label small text-muted mb-1" htmlFor={`${idPrefix}-surface-mode`}>
      Mode
    </label>
    <select
      id={`${idPrefix}-surface-mode`}
      data-testid={`${idPrefix}-surface-mode`}
      className="form-select form-select-sm"
      value={mode}
      disabled={disabled}
      onChange={e => onChange(e.target.value as SurfaceExecutionMode)}
    >
      {options.map(o => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  </div>
);

/**
 * Sidebar panel for the pipe-upstream anchor — the external LLM service the
 * pipe forwards to. When the provider catalogue is available (via
 * {@link usePipePanelData}) it offers provider / endpoint / model / API-key
 * pickers with a cascade; otherwise it falls back to a raw endpoint field so
 * custom (non-catalogue) upstreams stay editable.
 */
export const PipeUpstreamPanel: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  updateFields,
  openFullscreenEditor,
  allNodes,
  addNode,
  removeNode,
  updateNodeConfig,
  autoLayout,
  selectNode,
}) => {
  const { llmProviders, secrets } = usePipePanelData();
  const providerValue = typeof config?.provider === 'string' ? config.provider : '';
  const modelValue = typeof config?.model === 'string' ? config.model : '';
  const endpointValue = typeof config?.endpoint === 'string' ? config.endpoint : '';
  const secretValue = typeof config?.api_key_secret_id === 'string' ? config.api_key_secret_id : '';

  // The surface "mode" dropdown unifies the decider on/off state, routing
  // strategy, and mirror aggregation into one choice. Its value is derived from
  // whether a `pipe-decider` node exists plus its strategy/mirror config;
  // changing it mints/removes/patches the decider (see `applySurfaceMode`).
  const deciderNode = (allNodes ?? []).find(n => n.type === 'pipe-decider');
  const surfaceMode = surfaceModeFromDecider(
    (deciderNode?.config?.decider ?? null) as {
      strategy?: string;
      mirror?: { mode?: string };
    } | null
  );
  const canSetMode = !!addNode && !!removeNode;

  const handleModeChange = (mode: SurfaceExecutionMode) => {
    applySurfaceMode(mode, { allNodes, addNode, removeNode, updateNodeConfig, autoLayout });
    // Picking any non-direct mode from the LLM panel jumps to the decider node
    // so the same sidebar appears to update into the decider configuration.
    if (mode !== 'direct') selectNode?.('pipe-decider');
  };

  const modeSelect = (
    <SurfaceModeSelect
      mode={surfaceMode}
      onChange={handleModeChange}
      idPrefix="pipe-upstream"
      disabled={!canSetMode}
    />
  );

  if (surfaceMode !== 'direct') {
    return (
      <div className="surface-config-panel">
        <div className="alert alert-info py-2 mb-3" style={{ fontSize: '11px' }}>
          <i className="fas fa-info-circle me-1" /> {surfaceModeOption(surfaceMode).description} The
          upstream model is configured on the Decider node.
        </div>
        {modeSelect}
        {selectNode && (
          <button
            type="button"
            className="btn btn-outline-secondary btn-sm w-100 mb-3"
            onClick={() => selectNode('pipe-decider')}
          >
            <i className="fas fa-code-branch me-1" /> Open decider…
          </button>
        )}
        <PipeUsageLimitControls
          config={config}
          updateField={updateField}
          label="Enforce a usage limit"
          idPrefix="pipe-upstream"
        />
      </div>
    );
  }

  if (llmProviders.length === 0) {
    return (
      <div className="surface-config-panel">
        <div className="alert alert-info py-2 mb-3" style={{ fontSize: '11px' }}>
          <i className="fas fa-info-circle me-1" /> The upstream LLM this surface proxies to. Set
          the endpoint this surface forwards requests to.
        </div>
        {modeSelect}
        <div className="mb-0">
          <label className="form-label">Upstream endpoint</label>
          <input
            type="text"
            className="form-control"
            value={endpointValue}
            onChange={e => updateField('endpoint', e.target.value)}
            placeholder="https://api.example.com"
          />
        </div>
        {openFullscreenEditor && (
          <button
            type="button"
            className="btn btn-outline-primary btn-sm w-100 mt-3"
            onClick={openFullscreenEditor}
          >
            <i className="fas fa-sliders-h me-1" /> Configure LLM…
          </button>
        )}
      </div>
    );
  }

  const selectedProvider = llmProviders.find(p => p.enum_value === providerValue) ?? null;
  const apiKeyLabel = selectedProvider?.api_key_label || 'API key secret';
  // When the provider takes no key (`api_key_validation: "none"`) the secret
  // picker is greyed out — mirroring the full-page LLM config editor.
  const secretDisabled = apiKeyDisabled(selectedProvider);

  const onProviderChange = (next: string) => {
    const prov = llmProviders.find(p => p.enum_value === next) ?? null;
    const defaultEndpoint =
      prov?.endpoints.find(ep => (ep as { is_default?: boolean }).is_default)?.path ||
      prov?.endpoints[0]?.path ||
      '';
    const firstModel = firstEnabledModelValue(prov?.models ?? []);
    // Auto-select the API-key secret when exactly one is applicable for the
    // chosen provider, so a single-secret setup needs no manual pick.
    let autoSecret = '';
    if (prov && !apiKeyDisabled(prov)) {
      const filterPattern = (prov.filter_tag ?? '').trim();
      let matcher: RegExp | null = null;
      if (filterPattern) {
        try {
          matcher = new RegExp(filterPattern, 'i');
        } catch {
          matcher = null;
        }
      }
      const applicable = matcher
        ? secrets.filter(s => (s.tags ?? []).some(tag => matcher!.test(tag)))
        : secrets;
      if (applicable.length === 1) autoSecret = applicable[0].id;
    }
    updateFields({
      provider: next,
      endpoint: defaultEndpoint,
      model: firstModel,
      api_key_secret_id: autoSecret,
    });
  };

  const selectedModel = selectedProvider?.models.find(m => m.value === modelValue) ?? null;
  const inputPrice = selectedModel?.cost_per_1k_input;
  const outputPrice = selectedModel?.cost_per_1k_output;
  const hasPricing =
    typeof inputPrice === 'number' &&
    typeof outputPrice === 'number' &&
    (inputPrice > 0 || outputPrice > 0);

  return (
    <div className="surface-config-panel">
      <div className="alert alert-info py-2 mb-3" style={{ fontSize: '11px' }}>
        <i className="fas fa-info-circle me-1" /> In LLM Direct mode, the input is passed directly
        to the selected LLM.
      </div>
      {modeSelect}
      <div className="mb-3">
        <label className="form-label">Provider</label>
        <select
          className="form-select"
          value={providerValue}
          onChange={e => onProviderChange(e.target.value)}
        >
          <option value="">Select a provider…</option>
          {llmProviders.map(p => (
            <option key={p.enum_value} value={p.enum_value}>
              {p.name}
            </option>
          ))}
        </select>
      </div>

      {selectedProvider && selectedProvider.endpoints.length > 0 && (
        <div className="mb-3">
          <label className="form-label">Endpoint</label>
          <select
            className="form-select"
            value={endpointValue}
            onChange={e => updateField('endpoint', e.target.value)}
          >
            {selectedProvider.endpoints.map(ep => (
              <option key={ep.path} value={ep.path}>
                {ep.name}
              </option>
            ))}
          </select>
        </div>
      )}

      {selectedProvider && selectedProvider.models.length > 0 && (
        <div className="mb-3">
          <label className="form-label">Model</label>
          <select
            className="form-select"
            value={modelValue}
            onChange={e => updateField('model', e.target.value)}
          >
            <option value="">Select a model…</option>
            {selectableModels(selectedProvider.models, modelValue).map(m => (
              <option key={m.value} value={m.value}>
                {m.name}
              </option>
            ))}
          </select>
        </div>
      )}

      {selectedProvider && (
        <div className="mb-3">
          <SecretSelector
            secrets={secrets}
            selectedSecretId={secretValue}
            onChange={secretId => updateField('api_key_secret_id', secretId)}
            label={apiKeyLabel}
            filterRegex={selectedProvider.filter_tag ?? ''}
            disabled={secretDisabled}
            emptyLabel="No secret"
            helpText=""
            testId="pipe-upstream-secret"
          />
        </div>
      )}

      {selectedModel && (
        <div className="mb-3">
          <div
            className="py-2 px-3 mb-0 rounded"
            style={{
              fontSize: '11px',
              backgroundColor: 'transparent',
              border: '1px solid var(--accent-blue)',
            }}
            data-testid="pipe-upstream-cost-detail"
          >
            {hasPricing ? (
              <>
                <div className="fw-semibold mb-1">
                  <i className="fas fa-coins me-1" /> Catalog pricing —{' '}
                  {selectedModel?.name || modelValue}
                </div>
                <div>${inputPrice!.toFixed(4)} / 1K input tokens</div>
                <div>${outputPrice!.toFixed(4)} / 1K output tokens</div>
              </>
            ) : (
              <span className="text-muted">
                <i className="fas fa-info-circle me-1" /> No catalog pricing for this model — spend
                counts as $0 until pricing is added to the model catalog.
              </span>
            )}
          </div>
        </div>
      )}

      <div className="mb-3">
        <PipeUsageLimitControls
          config={config}
          updateField={updateField}
          label="Enforce a usage limit"
          idPrefix="pipe-upstream"
        />
      </div>

      {openFullscreenEditor && (
        <button
          type="button"
          className="btn btn-outline-primary btn-sm w-100"
          onClick={openFullscreenEditor}
        >
          <i className="fas fa-sliders-h me-1" /> Configure LLM…
        </button>
      )}
    </div>
  );
};

/**
 * Sidebar panel for the pipe-rate-limit node — the pipe's request/token rate
 * caps. The node's presence on the canvas IS the enabled state; remove the
 * node (delete) to disable rate limiting. There is no enabled toggle.
 */
export const PipeRateLimitPanel: React.FC<ConfigPanelProps> = ({ config, updateField }) => {
  const toInt = (v: string) => {
    const n = parseInt(v, 10);
    return Number.isFinite(n) ? n : 0;
  };
  return (
    <div className="surface-config-panel">
      <p className="text-muted small">
        Cap how many requests and tokens this pipe accepts per rolling minute. Delete this node to
        remove rate limiting.
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
};

/**
 * Sidebar panel for the pipe-opa-policy node — an OPA (Rego) gate evaluated
 * against each inbound request to this pipe. The node's presence on the
 * canvas IS the enabled state; remove the node (delete) to disable the gate.
 * The picker selects a `pipe`-scoped policy definition (its id is what
 * persists). Mirrors the surface policy element but scoped to a single pipe.
 */
export const PipeOpaPolicyPanel: React.FC<ConfigPanelProps> = ({ config, updateField }) => {
  const [policies, setPolicies] = React.useState<
    Array<{ id: string; name: string; description: string; policy: string }>
  >([]);

  React.useEffect(() => {
    apiClient
      .fetch('/api/v1/policy-definitions?policy_type=llm')
      .then(r => (r.ok ? r.json() : []))
      .then((data: any[]) => setPolicies(data || []))
      .catch(() => {});
  }, []);

  const selected = policies.find(p => p.id === config?.policy_definition_id) || null;

  return (
    <div className="surface-config-panel">
      <p className="text-muted small">
        Evaluate an OPA (Rego) policy on every inbound request to this pipe. A <code>false</code>{' '}
        result denies the call (403). Fail-closed: a selected policy is required, otherwise
        everything is denied.
      </p>
      <br />
      <div className="mb-0">
        <label className="form-label">Policy Definition</label>
        {policies.length === 0 ? (
          <div className="alert alert-warning py-2 mb-0" style={{ fontSize: '11px' }}>
            <i className="fas fa-exclamation-triangle me-1" />
            No LLM Surface policies are defined yet. Create one in the Policies manager.
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
          id="pipe-opa-log-decisions"
          checked={config?.log_decisions === true}
          onChange={e => updateField('log_decisions', e.target.checked)}
        />
        <label className="form-check-label" htmlFor="pipe-opa-log-decisions">
          Log OPA decisions
        </label>
        <p className="text-muted small mt-1 mb-0">
          When on, every OPA evaluation logs the full input JSON handed to Rego and the resulting
          allow/deny to the appliance log — useful when authoring or debugging a policy. Leave off
          in production.
        </p>
      </div>
    </div>
  );
};

/** Compact one-line summary of a tool's domain policy for the sidebar. */
const domainSummary = (config: any): string => {
  const policy = config?.domain_policy === 'block_all' ? 'block_all' : 'allow_all';
  const n = Array.isArray(config?.domain_exceptions) ? config.domain_exceptions.length : 0;
  if (policy === 'allow_all') {
    return n === 0 ? 'Allow all domains' : `Allow all except ${n} domain${n === 1 ? '' : 's'}`;
  }
  return n === 0 ? 'Block all domains' : `Block all except ${n} domain${n === 1 ? '' : 's'}`;
};

const toPositiveInt = (v: string, fallback: number): number => {
  const n = parseInt(v, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
};

/**
 * Sidebar panel for the pipe-web-search node — a governed server tool that lets
 * the model search the web through a selectable engine (Tavily, Brave, Google).
 * The node's presence on the canvas enables the tool; its config is assembled
 * into the surface's `server_tools.web_search` on save. The engine API key is
 * chosen from the shared secret store via {@link SecretSelector}.
 */
export const PipeWebSearchPanel: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  openFullscreenEditor,
}) => {
  const { secrets } = usePipePanelData();
  const engine = typeof config?.engine === 'string' ? config.engine : 'tavily';
  const secretValue = typeof config?.engine_secret_id === 'string' ? config.engine_secret_id : '';
  const enabled = config?.enabled !== false;
  return (
    <div className="surface-config-panel">
      <p className="text-muted small">
        Let the model search the web through a governed engine. Every query runs under this
        surface&apos;s policy, domain rules, budget and governance recording. Delete this node to
        remove web search.
      </p>
      <div className="form-check form-switch mb-3">
        <input
          className="form-check-input"
          type="checkbox"
          role="switch"
          id="web-search-enabled"
          checked={enabled}
          onChange={e => updateField('enabled', e.target.checked)}
        />
        <label className="form-check-label" htmlFor="web-search-enabled">
          Enabled
        </label>
      </div>
      <div className="mb-3">
        <label className="form-label">Search engine</label>
        <select
          className="form-select form-control"
          value={engine}
          onChange={e => updateField('engine', e.target.value)}
          data-testid="web-search-engine"
        >
          <option value="tavily">Tavily</option>
          <option value="brave">Brave Search</option>
          <option value="google">Google Programmable Search</option>
        </select>
      </div>
      <SecretSelector
        secrets={secrets}
        selectedSecretId={secretValue}
        onChange={id => updateField('engine_secret_id', id)}
        label="Engine API key"
        required
        filterRegex={engine}
        autoSelectSingleMatch
        helpText="API key secret for the selected search engine"
        testId="web-search-secret"
      />
      {engine === 'google' && (
        <div className="mb-3">
          <label className="form-label">Google Programmable Search id (cx)</label>
          <input
            type="text"
            className="form-control"
            value={typeof config?.google_cse_id === 'string' ? config.google_cse_id : ''}
            onChange={e => updateField('google_cse_id', e.target.value)}
            placeholder="0123456789abcdef"
          />
        </div>
      )}
      <div className="mb-3">
        <label className="form-label">Max results</label>
        <input
          type="number"
          min={1}
          max={20}
          className="form-control"
          value={config?.max_results ?? 5}
          onChange={e => updateField('max_results', toPositiveInt(e.target.value, 5))}
        />
      </div>
      <div className="mb-3">
        <label className="form-label">Max tool iterations</label>
        <input
          type="number"
          min={1}
          max={10}
          className="form-control"
          value={config?.max_iterations ?? 3}
          onChange={e => updateField('max_iterations', toPositiveInt(e.target.value, 3))}
        />
        <p className="text-muted small mt-1 mb-0">
          How many model⇄tool round-trips are allowed before the model must answer.
        </p>
      </div>
      <div className="mb-0">
        <label className="form-label d-block">Domain policy</label>
        <p className="text-muted small mb-2">{domainSummary(config)}</p>
        <button
          type="button"
          className="btn btn-outline-primary btn-sm w-100"
          onClick={openFullscreenEditor}
          disabled={!openFullscreenEditor}
        >
          <i className="fas fa-sliders me-1" />
          Configure domains…
        </button>
      </div>
    </div>
  );
};

/**
 * Sidebar panel for the pipe-web-fetch node — a governed server tool that lets
 * the model fetch and read a web page by URL. Self-contained (no API key); each
 * fetch is SSRF-guarded (private / loopback / cloud-metadata targets are
 * blocked) and subject to this surface's domain rules. The node's config is
 * assembled into `server_tools.web_fetch` on save.
 */
export const PipeWebFetchPanel: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  openFullscreenEditor,
}) => {
  const enabled = config?.enabled !== false;
  const kb = Math.max(1, Math.round((config?.max_content_bytes ?? 60000) / 1000));
  return (
    <div className="surface-config-panel">
      <p className="text-muted small">
        Let the model fetch and read a web page by URL. Requests are SSRF-guarded (private, loopback
        and cloud-metadata targets are blocked) and need no API key. Delete this node to remove web
        fetch.
      </p>
      <div className="form-check form-switch mb-3">
        <input
          className="form-check-input"
          type="checkbox"
          role="switch"
          id="web-fetch-enabled"
          checked={enabled}
          onChange={e => updateField('enabled', e.target.checked)}
        />
        <label className="form-check-label" htmlFor="web-fetch-enabled">
          Enabled
        </label>
      </div>
      <div className="mb-3">
        <label className="form-label">Max content size (KB)</label>
        <input
          type="number"
          min={1}
          className="form-control"
          value={kb}
          onChange={e => updateField('max_content_bytes', toPositiveInt(e.target.value, 60) * 1000)}
        />
        <p className="text-muted small mt-1 mb-0">
          Fetched pages are reduced to readable text and truncated to this size.
        </p>
      </div>
      <div className="mb-0">
        <label className="form-label d-block">Domain policy</label>
        <p className="text-muted small mb-2">{domainSummary(config)}</p>
        <button
          type="button"
          className="btn btn-outline-primary btn-sm w-100"
          onClick={openFullscreenEditor}
          disabled={!openFullscreenEditor}
        >
          <i className="fas fa-sliders me-1" />
          Configure domains…
        </button>
      </div>
    </div>
  );
};

/**
 * Sidebar panel for the pipe-prompt-guard node — a status summary plus a
 * button that opens the full-area guard editor. The request/response guard
 * tables are too large for the narrow sidebar, so they live in
 * {@link PipePromptGuardFullscreenPanel}.
 */
export const PipePromptGuardPanel: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  openFullscreenEditor,
}) => {
  const enabled = config?.enabled === true;
  const direction = config?.direction === 'response' ? 'response' : 'request';
  const regexCount = Array.isArray(config?.[direction]) ? config[direction].length : 0;
  const aiCount =
    direction === 'request' && Array.isArray(config?.llm_pii) ? config.llm_pii.length : 0;
  const count = regexCount + aiCount;
  const side = direction === 'request' ? 'request' : 'response';
  return (
    <div className="surface-config-panel">
      <div className="alert alert-info py-2 mb-3" style={{ fontSize: '11px' }}>
        <i className="fas fa-info-circle me-1" /> Prompt guards screen {side} content with regex
        patterns or an AI model, blocking or masking matches (e.g. PII) before they reach the model
        or the caller.
      </div>
      <div className="form-check form-switch mb-3">
        <input
          className="form-check-input"
          type="checkbox"
          role="switch"
          id="pipe-prompt-guard-enabled"
          checked={enabled}
          onChange={e => updateField('enabled', e.target.checked)}
        />
        <label className="form-check-label" htmlFor="pipe-prompt-guard-enabled">
          Enabled
        </label>
      </div>
      <p className="mb-2">
        {count === 0 ? (
          <span className="text-muted">No {side} prompt guards configured.</span>
        ) : (
          <span>
            <strong>{count}</strong> {side} prompt guard{count === 1 ? '' : 's'}.
          </span>
        )}
      </p>
      <button
        type="button"
        className="btn btn-outline-primary btn-sm w-100"
        onClick={openFullscreenEditor}
        disabled={!openFullscreenEditor || !enabled}
        title={enabled ? undefined : 'Enable this guard to configure it'}
      >
        <i className="fas fa-pen-to-square me-1"></i>Edit {side} guards…
      </button>
    </div>
  );
};

/**
 * Sidebar panel for the pipe-judge node — a status summary plus a button that
 * opens the full-area judge editor. The provider/strictness/rules controls are
 * too large for the narrow sidebar, so they live in
 * {@link PipeJudgeFullscreenPanel}.
 */
export const PipeJudgePanel: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  openFullscreenEditor,
}) => {
  const judge = config?.judge && typeof config.judge === 'object' ? config.judge : null;
  const present = !!judge;
  const enabled = judge?.enabled === true;
  const mode = typeof judge?.mode === 'string' ? judge.mode : '';
  return (
    <div className="surface-config-panel">
      <div className="alert alert-info py-2 mb-3" style={{ fontSize: '11px' }}>
        <i className="fas fa-info-circle me-1" /> A judge runs a single model to review each
        response before it is returned, scoring or vetoing answers that fail your criteria.
      </div>
      <div className="form-check form-switch mb-3">
        <input
          className="form-check-input"
          type="checkbox"
          role="switch"
          id="pipe-judge-enabled"
          checked={enabled}
          onChange={e => updateField('judge', { ...(judge ?? {}), enabled: e.target.checked })}
        />
        <label className="form-check-label" htmlFor="pipe-judge-enabled">
          Enabled
        </label>
      </div>
      <p className="mb-2">
        {!present ? (
          <span className="text-muted">No judge configured.</span>
        ) : mode ? (
          <span className="badge text-bg-info">{mode}</span>
        ) : null}
      </p>
      <button
        type="button"
        className="btn btn-outline-primary btn-sm w-100"
        onClick={openFullscreenEditor}
        disabled={!openFullscreenEditor || !enabled}
        title={enabled ? undefined : 'Enable the judge to configure it'}
      >
        <i className="fas fa-pen-to-square me-1"></i>Edit judge…
      </button>
      <hr />
      <PipeUsageLimitControls
        config={config}
        updateField={updateField}
        label="Enforce a usage limit"
        idPrefix="pipe-judge"
      />
    </div>
  );
};

/**
 * Read the juror nodes (first-class pipe-juror siblings of the jury) out of
 * the canvas, ordered by their stored `jurorIndex`. The jury node owns only
 * jury-level settings; the jurors live as their own nodes so each is clickable
 * and individually configurable.
 */
function readJurorNodes(allNodes: CanvasNode[] | undefined): CanvasNode[] {
  return (allNodes ?? [])
    .filter(n => n.type === 'pipe-juror')
    .sort((a, b) => {
      const ai = typeof a.config?.jurorIndex === 'number' ? a.config.jurorIndex : 0;
      const bi = typeof b.config?.jurorIndex === 'number' ? b.config.jurorIndex : 0;
      return ai - bi;
    });
}

type UpdateNodeConfig = (nodeId: string, config: any) => void;

/**
 * Switch every juror on. Used when the jury is enabled so the user doesn't have
 * to re-enable each juror by hand — an enabled jury with no enabled jurors
 * can't render a verdict.
 */
function enableAllJurors(jurorNodes: CanvasNode[], updateNodeConfig?: UpdateNodeConfig): void {
  if (!updateNodeConfig) return;
  jurorNodes.forEach(node => {
    const j = (node.config?.juror ?? {}) as JurorConfig;
    if (j.enabled === false) {
      updateNodeConfig(node.id, { ...node.config, juror: { ...j, enabled: true } });
    }
  });
}

/**
 * Keep the jury consistent after a juror's enabled flag changes: if no juror is
 * left enabled the jury can never reach a verdict, so switch the jury off too.
 * `changed` overrides the just-toggled juror because the `allNodes` snapshot
 * still holds its pre-toggle config.
 */
function disableJuryIfNoJurorsEnabled(
  allNodes: CanvasNode[] | undefined,
  updateNodeConfig: UpdateNodeConfig | undefined,
  changed: { id: string; enabled: boolean }
): void {
  if (!updateNodeConfig) return;
  const anyEnabled = readJurorNodes(allNodes).some(node => {
    if (node.id === changed.id) return changed.enabled;
    return ((node.config?.juror ?? {}) as JurorConfig).enabled !== false;
  });
  if (anyEnabled) return;
  const juryNode = (allNodes ?? []).find(n => n.type === 'pipe-jury');
  const juryCfg = juryNode?.config?.jury;
  if (juryNode && juryCfg && typeof juryCfg === 'object' && juryCfg.enabled === true) {
    updateNodeConfig(juryNode.id, { ...juryNode.config, jury: { ...juryCfg, enabled: false } });
  }
}

/**
 * Sidebar panel for the pipe-jury node. Owns the jury-level settings the user
 * touches most — enable, execution mode, and the roster of jurors. Each juror
 * is a first-class sibling node: this panel lists them with a per-row
 * enable/disable toggle and remove button, and an "Add juror" action that
 * mints a new juror node beneath the jury. Selecting a juror node opens its
 * own panel; the deeper jury-level verdict/redrive settings live in
 * {@link PipeJuryFullscreenPanel}.
 */
export const PipeJuryPanel: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  openFullscreenEditor,
  allNodes,
  addNode,
  removeNode,
  updateNodeConfig,
  autoLayout,
  selectNode,
}) => {
  const jury = config?.jury && typeof config.jury === 'object' ? config.jury : null;
  const enabled = jury?.enabled === true;
  const mode = typeof jury?.mode === 'string' ? jury.mode : 'parallel';
  const jurorNodes = readJurorNodes(allNodes);
  const maxRetries = typeof jury?.max_retries === 'number' ? jury.max_retries : 0;
  const rejectionStatus =
    typeof jury?.rejection?.status_code === 'number' ? jury.rejection.status_code : 403;

  // Anchor a newly added juror to the Jury's live position so "Add juror"
  // lands relative to wherever the Jury currently sits, not the original seed
  // coordinate.
  const juryNode = (allNodes ?? []).find(n => n.type === 'pipe-jury');
  const juryX = juryNode?.position?.x ?? 140;
  const juryY = juryNode?.position?.y ?? 0;

  // Switching the execution mode also changes the juror layout: parallel and
  // majority fan the jurors across a row (concurrent deliberation), serial
  // stacks them in a column (sequential hand-off). Run a full auto-layout so
  // the jurors re-seat into the new mode's slots AND the surface boundary
  // resizes to fit them — re-seating alone would leave the boundary fixed and
  // clamp jurors that no longer fit (a serial column is taller, a parallel row
  // wider). `updateField` and `autoLayout` queue in the same tick, so the
  // layout (computed from pending state) already sees the new mode.
  const setMode = (next: 'parallel' | 'serial' | 'majority') => {
    updateField('jury', { ...(jury ?? {}), mode: next, enabled });
    autoLayout?.();
  };

  const addJuror = () => {
    if (!addNode) return;
    const maxIndex = jurorNodes.reduce((max, n) => {
      const i = typeof n.config?.jurorIndex === 'number' ? n.config.jurorIndex : -1;
      return i > max ? i : max;
    }, -1);
    const nextIndex = maxIndex + 1;
    const juror = makeDefaultJuror(nextIndex);
    const node: CanvasNode = {
      id: `pipe-juror-${nextIndex}`,
      type: 'pipe-juror',
      label: juror.name,
      configured: false,
      position: jurorSlotPosition(mode, jurorNodes.length, juryX, juryY),
      parentId: 'pipe-jury',
      config: { juror, jurorIndex: nextIndex },
    };
    addNode(node);
  };

  const toggleJuror = (node: CanvasNode) => {
    if (!updateNodeConfig) return;
    const j = (node.config?.juror ?? {}) as JurorConfig;
    const nextEnabled = j.enabled === false;
    updateNodeConfig(node.id, {
      ...node.config,
      juror: { ...j, enabled: nextEnabled },
    });
    if (!nextEnabled) {
      disableJuryIfNoJurorsEnabled(allNodes, updateNodeConfig, { id: node.id, enabled: false });
    }
  };

  // Re-order a juror by swapping its `jurorIndex` with the adjacent juror's.
  // `jurorNodes` is already sorted by `jurorIndex`, so the neighbour is found
  // by list position. The swap drives both the canvas "Juror N" captions and
  // the persisted `jury.jurors` order (readJury sorts by `jurorIndex`), which
  // is the serial-mode execution order.
  const moveJuror = (node: CanvasNode, direction: -1 | 1) => {
    if (!updateNodeConfig) return;
    const idx = jurorNodes.findIndex(n => n.id === node.id);
    const swapWith = jurorNodes[idx + direction];
    if (!swapWith) return;
    const aIndex = typeof node.config?.jurorIndex === 'number' ? node.config.jurorIndex : idx;
    const bIndex =
      typeof swapWith.config?.jurorIndex === 'number'
        ? swapWith.config.jurorIndex
        : idx + direction;
    updateNodeConfig(node.id, { ...node.config, jurorIndex: bIndex });
    updateNodeConfig(swapWith.id, { ...swapWith.config, jurorIndex: aIndex });
  };

  return (
    <div className="surface-config-panel">
      <div className="alert alert-info py-2 mb-3" style={{ fontSize: '11px' }}>
        <i className="fas fa-info-circle me-1" /> A jury runs multiple jurors to review each
        response and combines their verdicts. Use parallel for speed or serial for staged review.
      </div>
      <div className="form-check form-switch mb-3">
        <input
          className="form-check-input"
          type="checkbox"
          role="switch"
          id="pipe-jury-enabled"
          checked={enabled}
          onChange={e => {
            const nextEnabled = e.target.checked;
            updateField('jury', {
              mode: 'parallel',
              ...(jury ?? {}),
              enabled: nextEnabled,
            });
            if (nextEnabled && !enabled) {
              enableAllJurors(jurorNodes, updateNodeConfig);
            }
          }}
        />
        <label className="form-check-label" htmlFor="pipe-jury-enabled">
          Enabled
        </label>
      </div>

      {enabled && (
        <>
          <div className="mb-3">
            <label className="form-label small text-muted mb-1">Execution mode</label>
            <select
              className="form-select form-select-sm"
              value={mode}
              onChange={e => setMode(e.target.value as 'parallel' | 'serial' | 'majority')}
            >
              <option value="parallel">Parallel — all must approve</option>
              <option value="serial">Serial — staged, stops on first reject</option>
              <option value="majority">Majority — &gt; 50% must approve</option>
            </select>
          </div>

          <div className="d-flex justify-content-between align-items-center mb-1">
            <label className="form-label small text-muted mb-0">Jurors ({jurorNodes.length})</label>
            <button
              type="button"
              className="btn btn-outline-primary btn-sm py-0 px-2"
              onClick={addJuror}
              disabled={!addNode}
            >
              <i className="fas fa-plus me-1" />
              Add juror
            </button>
          </div>

          <div className="alert alert-info py-2 mb-2" style={{ fontSize: '11px' }}>
            <i className="fas fa-info-circle me-1" /> Jurors run in this order, top to bottom. In{' '}
            <strong>serial</strong> mode they execute one after another and the jury stops at the
            first reject, so the order matters. Use the arrows to re-order them.
          </div>

          {jurorNodes.length === 0 ? (
            <p className="text-muted small mb-3">
              No jurors yet. Add at least one for the jury to render a verdict.
            </p>
          ) : (
            <ul className="list-group mb-3">
              {jurorNodes.map((node, idx) => {
                const j = (node.config?.juror ?? {}) as JurorConfig;
                const jurorEnabled = j.enabled !== false;
                const provider = j.llm?.provider_type || '';
                const model = j.llm?.model || '';
                const switchId = `pipe-juror-toggle-${node.id}`;
                return (
                  <li
                    key={node.id}
                    className="list-group-item d-flex justify-content-between align-items-center py-2"
                  >
                    <div className="d-flex align-items-center me-2" style={{ minWidth: 0 }}>
                      <div className="d-flex flex-column me-2">
                        <button
                          type="button"
                          className="btn btn-link btn-sm p-0 lh-1 text-muted"
                          onClick={() => moveJuror(node, -1)}
                          disabled={!updateNodeConfig || idx === 0}
                          title="Move earlier"
                          aria-label="Move juror earlier"
                        >
                          <i className="fas fa-chevron-up" />
                        </button>
                        <button
                          type="button"
                          className="btn btn-link btn-sm p-0 lh-1 text-muted"
                          onClick={() => moveJuror(node, 1)}
                          disabled={!updateNodeConfig || idx === jurorNodes.length - 1}
                          title="Move later"
                          aria-label="Move juror later"
                        >
                          <i className="fas fa-chevron-down" />
                        </button>
                      </div>
                      <div
                        style={{ minWidth: 0, cursor: selectNode ? 'pointer' : undefined }}
                        role={selectNode ? 'button' : undefined}
                        tabIndex={selectNode ? 0 : undefined}
                        onClick={selectNode ? () => selectNode(node.id) : undefined}
                        onKeyDown={
                          selectNode
                            ? e => {
                                if (e.key === 'Enter' || e.key === ' ') {
                                  e.preventDefault();
                                  selectNode(node.id);
                                }
                              }
                            : undefined
                        }
                        title={selectNode ? 'Open juror' : undefined}
                      >
                        <div
                          className="text-truncate"
                          style={{ fontSize: '13px', opacity: jurorEnabled ? 1 : 0.5 }}
                        >
                          <span className="text-muted me-1">Juror {idx + 1}:</span>
                          {j.name || node.label}
                        </div>
                        <div className="text-muted text-truncate" style={{ fontSize: '11px' }}>
                          {provider || model
                            ? `${provider}${provider && model ? ' · ' : ''}${model}`
                            : 'Not configured'}
                        </div>
                      </div>
                    </div>
                    <div className="d-flex align-items-center flex-shrink-0">
                      <div className="form-check form-switch mb-0 me-2">
                        <input
                          className="form-check-input"
                          type="checkbox"
                          role="switch"
                          id={switchId}
                          checked={jurorEnabled}
                          onChange={() => toggleJuror(node)}
                          title={jurorEnabled ? 'Disable juror' : 'Enable juror'}
                          aria-label={jurorEnabled ? 'Disable juror' : 'Enable juror'}
                        />
                      </div>
                      <button
                        type="button"
                        className="btn btn-outline-danger btn-sm py-0 px-2"
                        onClick={() => removeNode?.(node.id)}
                        disabled={!removeNode}
                        title="Remove juror"
                        aria-label="Remove juror"
                      >
                        <i className="fas fa-trash" />
                      </button>
                    </div>
                  </li>
                );
              })}
            </ul>
          )}

          <div className="mb-2">
            <label className="form-label small text-muted mb-1">Verdict handling</label>
            <div className="border rounded bg-light px-2 py-2">
              <div className="d-flex justify-content-between align-items-center mb-1">
                <span className="small text-muted">On negative verdict</span>
                <span className="small fw-semibold">
                  {maxRetries > 0 ? `Redrive ${maxRetries}×` : 'Return immediately'}
                </span>
              </div>
              <div className="d-flex justify-content-between align-items-center">
                <span className="small text-muted">Final response</span>
                <span className="badge text-bg-secondary">HTTP {rejectionStatus}</span>
              </div>
            </div>
          </div>

          <button
            type="button"
            className="btn btn-outline-secondary btn-sm w-100"
            onClick={openFullscreenEditor}
            disabled={!openFullscreenEditor}
          >
            <i className="fas fa-sliders me-1"></i>Verdict &amp; redrive settings…
          </button>
        </>
      )}
    </div>
  );
};

/**
 * Sidebar panel for a pipe-juror node — identity (name) and the per-juror
 * enable/disable toggle, plus a summary of the chosen model and a button that
 * opens the full-area juror editor for the complex LLM / strictness / decision
 * config. The juror's name and enabled flag live in `config.juror`; the
 * remaining fields are edited in {@link PipeJurorFullscreenPanel}.
 */
export const PipeJurorPanel: React.FC<ConfigPanelProps> = ({
  node,
  config,
  updateField,
  openFullscreenEditor,
  allNodes,
  updateNodeConfig,
}) => {
  const juror = (config?.juror ?? {}) as JurorConfig;
  const enabled = juror.enabled !== false;
  const provider = juror.llm?.provider_type || '';
  const model = juror.llm?.model || '';
  const configured = !!(provider && model && juror.llm?.endpoint_url);

  const patchJuror = (updates: Partial<JurorConfig>) => {
    updateField('juror', { ...juror, ...updates });
  };

  return (
    <div className="surface-config-panel">
      <div className="alert alert-info py-2 mb-3" style={{ fontSize: '11px' }}>
        <i className="fas fa-info-circle me-1" /> A juror is one independent LLM reviewer in the
        jury. <strong>Set it up:</strong> give it a name, toggle it on, then open{' '}
        <strong>Configure juror…</strong> to choose its model and how strictly it votes. Disabled
        jurors are skipped, and turning off the last one disables the jury.
      </div>
      <div className="config-section">
        <label className="form-label small text-muted mb-1">Name</label>
        <input
          type="text"
          className="form-control form-control-sm"
          value={juror.name || ''}
          onChange={e => patchJuror({ name: e.target.value })}
          placeholder="Juror name…"
        />
      </div>

      <div className="form-check form-switch my-3">
        <input
          className="form-check-input"
          type="checkbox"
          role="switch"
          id="pipe-juror-enabled"
          checked={enabled}
          onChange={e => {
            const nextEnabled = e.target.checked;
            patchJuror({ enabled: nextEnabled });
            if (!nextEnabled) {
              disableJuryIfNoJurorsEnabled(allNodes, updateNodeConfig, {
                id: node.id,
                enabled: false,
              });
            }
          }}
        />
        <label className="form-check-label" htmlFor="pipe-juror-enabled">
          Enabled
        </label>
      </div>

      <p className="mb-2">
        {configured ? (
          <span>
            <span className="badge text-bg-info me-1">{provider}</span>
            <span className="badge text-bg-secondary">{model}</span>
          </span>
        ) : (
          <span className="text-warning small">
            <i className="fas fa-triangle-exclamation me-1" />
            Not configured
          </span>
        )}
      </p>

      <button
        type="button"
        className="btn btn-outline-primary btn-sm w-100"
        onClick={openFullscreenEditor}
        disabled={!openFullscreenEditor}
      >
        <i className="fas fa-pen-to-square me-1"></i>Configure juror…
      </button>
      <hr />
      <PipeUsageLimitControls
        config={config}
        updateField={updateField}
        label="Enforce a usage limit"
        idPrefix={node.id}
      />
    </div>
  );
};

/**
 * Read the decider's candidate nodes (`pipe-candidate`) sorted by their stored
 * index, so the roster the panel renders and the array `readDecider` rebuilds
 * stay in the same order the user sees.
 */
function readCandidateNodes(allNodes: CanvasNode[] | undefined): CanvasNode[] {
  return (allNodes ?? [])
    .filter(n => n.type === 'pipe-candidate')
    .sort((a, b) => {
      const ai = typeof a.config?.candidateIndex === 'number' ? a.config.candidateIndex : 0;
      const bi = typeof b.config?.candidateIndex === 'number' ? b.config.candidateIndex : 0;
      return ai - bi;
    });
}

/**
 * Sidebar panel for the pipe-decider node. Owns the decider-level settings —
 * enable, the candidate roster, and the default (fallback) candidate — and an
 * "Add candidate" action that mints a candidate node beneath the decider. Each
 * candidate is a first-class sibling node; selecting one opens its own panel.
 * The router LLM and routing prompt live in {@link PipeDeciderFullscreenPanel}.
 */
export const PipeDeciderPanel: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  openFullscreenEditor,
  allNodes,
  addNode,
  removeNode,
  updateNodeConfig,
  autoLayout,
  selectNode,
}) => {
  const decider = config?.decider && typeof config.decider === 'object' ? config.decider : null;
  const candidateNodes = readCandidateNodes(allNodes);
  const defaultId =
    typeof decider?.default_candidate_id === 'string' ? decider.default_candidate_id : '';
  const surfaceMode = surfaceModeFromDecider(decider);
  // Route only ever calls one candidate, so the fan-out cap applies to mirror.
  const atMirrorCandidateCap =
    surfaceMode !== 'route' && candidateNodes.length >= MAX_MIRROR_CANDIDATES;

  const deciderNode = (allNodes ?? []).find(n => n.type === 'pipe-decider');
  const deciderX = deciderNode?.position?.x ?? 0;
  const deciderY = deciderNode?.position?.y ?? 0;

  const patchDecider = (updates: Partial<DeciderConfig>) => {
    updateField('decider', { ...(decider ?? {}), ...updates });
  };

  const handleModeChange = (mode: SurfaceExecutionMode) => {
    applySurfaceMode(mode, { allNodes, addNode, removeNode, updateNodeConfig, autoLayout });
    // Switching to Direct removes the decider — jump to the LLM node so the
    // sidebar returns to the direct LLM configuration.
    if (mode === 'direct') selectNode?.('pipe-upstream');
  };

  const addCandidate = () => {
    if (!addNode) return;
    const maxIndex = candidateNodes.reduce((max, n) => {
      const i = typeof n.config?.candidateIndex === 'number' ? n.config.candidateIndex : -1;
      return i > max ? i : max;
    }, -1);
    const nextIndex = maxIndex + 1;
    const candidate = makeDefaultCandidate(nextIndex);
    const node: CanvasNode = {
      id: `pipe-candidate-${nextIndex}`,
      type: 'pipe-candidate',
      label: candidate.name,
      configured: false,
      position: candidateSlotPosition(candidateNodes.length, deciderX, deciderY),
      parentId: 'pipe-decider',
      config: { candidate, candidateIndex: nextIndex },
    };
    addNode(node);
  };

  return (
    <div className="surface-config-panel">
      <SurfaceModeSelect
        mode={surfaceMode}
        onChange={handleModeChange}
        idPrefix="pipe-decider"
        disabled={!addNode || !removeNode}
      />
      <div className="alert alert-info py-2 mb-3" style={{ fontSize: '11px' }}>
        <i className="fas fa-info-circle me-1" /> {surfaceModeOption(surfaceMode).description}
      </div>

      <div className="d-flex justify-content-between align-items-center mb-1">
        <label className="form-label small text-muted mb-0">
          Candidates ({candidateNodes.length})
        </label>
        <button
          type="button"
          className="btn btn-outline-primary btn-sm py-0 px-2"
          onClick={addCandidate}
          disabled={!addNode || atMirrorCandidateCap}
          title={
            atMirrorCandidateCap
              ? `Mirror allows at most ${MAX_MIRROR_CANDIDATES} candidates`
              : undefined
          }
        >
          <i className="fas fa-plus me-1" />
          Add candidate
        </button>
      </div>

      {candidateNodes.length === 0 ? (
        <p className="text-muted small mb-3">
          No candidates yet. Add at least one for the decider to route to.
        </p>
      ) : (
        <ul className="list-group mb-3">
          {candidateNodes.map((node, idx) => {
            const c = (node.config?.candidate ?? {}) as DeciderCandidate;
            const provider = c.llm?.provider_type || '';
            const model = c.llm?.model || '';
            return (
              <li
                key={node.id}
                className="list-group-item d-flex justify-content-between align-items-center py-2"
              >
                <div
                  className="me-2"
                  style={{ minWidth: 0, cursor: selectNode ? 'pointer' : undefined }}
                  role={selectNode ? 'button' : undefined}
                  tabIndex={selectNode ? 0 : undefined}
                  onClick={selectNode ? () => selectNode(node.id) : undefined}
                  onKeyDown={
                    selectNode
                      ? e => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault();
                            selectNode(node.id);
                          }
                        }
                      : undefined
                  }
                  title={selectNode ? 'Open candidate' : undefined}
                >
                  <div className="text-truncate" style={{ fontSize: '13px' }}>
                    <span className="text-muted me-1">Candidate {idx + 1}:</span>
                    {c.name || node.label}
                    {c.id && <span className="badge text-bg-light ms-1">{c.id}</span>}
                  </div>
                  <div className="text-muted text-truncate" style={{ fontSize: '11px' }}>
                    {provider || model
                      ? `${provider}${provider && model ? ' · ' : ''}${model}`
                      : 'Not configured'}
                  </div>
                </div>
                <button
                  type="button"
                  className="btn btn-outline-danger btn-sm py-0 px-2 flex-shrink-0"
                  onClick={() => removeNode?.(node.id)}
                  disabled={!removeNode}
                  title="Remove candidate"
                  aria-label="Remove candidate"
                >
                  <i className="fas fa-trash" />
                </button>
              </li>
            );
          })}
        </ul>
      )}

      {surfaceMode === 'route' && (
        <div className="mb-3">
          <label className="form-label small text-muted mb-1">Default candidate (fallback)</label>
          <select
            className="form-select form-select-sm"
            value={defaultId}
            onChange={e => patchDecider({ default_candidate_id: e.target.value || null })}
            data-testid="pipe-decider-default-candidate"
          >
            <option value="">First candidate</option>
            {candidateNodes.map(node => {
              const c = (node.config?.candidate ?? {}) as DeciderCandidate;
              if (!c.id) return null;
              return (
                <option key={node.id} value={c.id}>
                  {c.name || c.id} ({c.id})
                </option>
              );
            })}
          </select>
          <small className="form-text text-muted">
            Used when the router's choice is unknown or empty.
          </small>
        </div>
      )}

      <button
        type="button"
        className="btn btn-outline-secondary btn-sm w-100"
        onClick={openFullscreenEditor}
        disabled={!openFullscreenEditor}
      >
        <i className="fas fa-sliders me-1"></i>Configure Decider
      </button>
    </div>
  );
};

/**
 * Sidebar panel for a pipe-candidate node — its routing identity (name) and a
 * summary of the chosen model, plus a button that opens the full-area editor
 * for the id/description and LLM config. The candidate's fields live in
 * `config.candidate`; the deeper config is edited in
 * {@link PipeCandidateFullscreenPanel}.
 */
export const PipeCandidatePanel: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  openFullscreenEditor,
}) => {
  const candidate = (config?.candidate ?? {}) as DeciderCandidate;
  const provider = candidate.llm?.provider_type || '';
  const model = candidate.llm?.model || '';
  const configured = !!(provider && model && candidate.llm?.endpoint_url);

  const patchCandidate = (updates: Partial<DeciderCandidate>) => {
    updateField('candidate', { ...candidate, ...updates });
  };

  return (
    <div className="surface-config-panel">
      <div className="alert alert-info py-2 mb-3" style={{ fontSize: '11px' }}>
        <i className="fas fa-info-circle me-1" /> A candidate is one upstream the decider may route
        to. <strong>Set it up:</strong> give it a name, then open{' '}
        <strong>Configure candidate…</strong> to set its id, description and model.
      </div>
      <div className="config-section">
        <label className="form-label small text-muted mb-1">Name</label>
        <input
          type="text"
          className="form-control form-control-sm"
          value={candidate.name || ''}
          onChange={e => patchCandidate({ name: e.target.value })}
          placeholder="Candidate name…"
        />
      </div>

      {candidate.id && (
        <p className="text-muted small mt-2 mb-2">
          id: <span className="badge text-bg-light">{candidate.id}</span>
        </p>
      )}

      <p className="mb-2 mt-2">
        {configured ? (
          <span>
            <span className="badge text-bg-info me-1">{provider}</span>
            <span className="badge text-bg-secondary">{model}</span>
          </span>
        ) : (
          <span className="text-warning small">
            <i className="fas fa-triangle-exclamation me-1" />
            Not configured
          </span>
        )}
      </p>

      <button
        type="button"
        className="btn btn-outline-primary btn-sm w-100"
        onClick={openFullscreenEditor}
        disabled={!openFullscreenEditor}
      >
        <i className="fas fa-pen-to-square me-1"></i>Configure candidate…
      </button>
    </div>
  );
};

/**
 * Sidebar panel for an Expert Witness seam node (`pipe-witness-request` /
 * `pipe-witness-response`). Owns the list of witnesses for its seam
 * (`config.witnesses`) — an external safety classifier roster consulted
 * alongside the local regex guards. Add / remove / rename here; the per-witness
 * provider, endpoint, key, timeout and fail-open settings are edited in
 * {@link PipeWitnessFullscreenPanel}.
 */
export const PipeWitnessPanel: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  openFullscreenEditor,
}) => {
  const seam: 'request' | 'response' = config?.direction === 'response' ? 'response' : 'request';
  const witnesses: WitnessConfig[] = Array.isArray(config?.witnesses) ? config.witnesses : [];

  const providerLabel = (p: WitnessProvider): string =>
    WITNESS_PROVIDERS.find(o => o.value === p)?.label ?? p;

  const addWitness = () => {
    updateField('witnesses', [...witnesses, makeDefaultWitness(seam, witnesses.length)]);
  };
  const removeWitness = (index: number) => {
    updateField(
      'witnesses',
      witnesses.filter((_, i) => i !== index)
    );
  };
  const renameWitness = (index: number, name: string) => {
    const next = witnesses.slice();
    next[index] = { ...next[index], name };
    updateField('witnesses', next);
  };

  return (
    <div className="surface-config-panel">
      <div className="alert alert-info py-2 mb-3" style={{ fontSize: '11px' }}>
        <i className="fas fa-info-circle me-1" /> An expert witness is an external, purpose-trained
        safety classifier consulted on the {seam} alongside the local regex guards. A flagged
        verdict blocks the call. Add one per provider — the same provider on the other seam is a
        separate witness on the other circle.
      </div>

      <div className="d-flex justify-content-between align-items-center mb-1">
        <label className="form-label small text-muted mb-0">Witnesses ({witnesses.length})</label>
        <button
          type="button"
          className="btn btn-outline-primary btn-sm py-0 px-2"
          onClick={addWitness}
          data-testid={`pipe-witness-${seam}-add`}
        >
          <i className="fas fa-plus me-1" />
          Add witness
        </button>
      </div>

      {witnesses.length === 0 ? (
        <p className="text-muted small mb-3">
          No witnesses yet. Add one to screen the {seam} with an external classifier.
        </p>
      ) : (
        <ul className="list-group mb-3" data-testid={`pipe-witness-${seam}-list`}>
          {witnesses.map((w, idx) => {
            const configured = !!(w.provider && w.endpoint_url);
            return (
              <li key={w.id || idx} className="list-group-item py-2">
                <div className="d-flex justify-content-between align-items-start">
                  <div className="me-2 flex-grow-1" style={{ minWidth: 0 }}>
                    <input
                      type="text"
                      className="form-control form-control-sm mb-1"
                      value={w.name || ''}
                      onChange={e => renameWitness(idx, e.target.value)}
                      placeholder={`Witness ${idx + 1}`}
                      data-testid={`pipe-witness-${seam}-name-${idx}`}
                    />
                    <div className="text-muted text-truncate" style={{ fontSize: '11px' }}>
                      {configured ? (
                        <>
                          <span className="badge text-bg-info me-1">
                            {providerLabel(w.provider)}
                          </span>
                          <span className="text-truncate">{w.endpoint_url}</span>
                        </>
                      ) : (
                        <span className="text-warning">
                          <i className="fas fa-triangle-exclamation me-1" />
                          Not configured
                        </span>
                      )}
                    </div>
                  </div>
                  <button
                    type="button"
                    className="btn btn-outline-danger btn-sm py-0 px-2 flex-shrink-0"
                    onClick={() => removeWitness(idx)}
                    title="Remove witness"
                    aria-label="Remove witness"
                    data-testid={`pipe-witness-${seam}-remove-${idx}`}
                  >
                    <i className="fas fa-trash" />
                  </button>
                </div>
              </li>
            );
          })}
        </ul>
      )}

      <button
        type="button"
        className="btn btn-outline-secondary btn-sm w-100"
        onClick={openFullscreenEditor}
        disabled={!openFullscreenEditor}
        data-testid={`pipe-witness-${seam}-configure`}
      >
        <i className="fas fa-sliders me-1"></i>Configure witnesses…
      </button>
    </div>
  );
};

/**
 * Sidebar panel for the pipe-response node — the reply returned to the caller.
 * Owns the "visualise response to caller" toggle, which controls whether the
 * canvas draws the dotted correlation arc looping the response back out to the
 * caller glyph. Defaults to on (the flag is absent until the user turns it
 * off), so existing pipes keep the arc.
 */
export const PipeResponsePanel: React.FC<ConfigPanelProps> = ({ config, updateField }) => {
  const visualize = config?.visualize_response_to_caller !== false;
  return (
    <div className="surface-config-panel">
      <div className="alert alert-info py-2 mb-3" style={{ fontSize: '11px' }}>
        <i className="fas fa-info-circle me-1" /> The response is what the pipe returns to the
        caller once every stage has run. The toggle below controls the dotted arc the canvas draws
        from the response back to the caller.
      </div>
      <div className="form-check form-switch mb-3">
        <input
          className="form-check-input"
          type="checkbox"
          role="switch"
          id="pipe-response-visualize"
          checked={visualize}
          onChange={e => updateField('visualize_response_to_caller', e.target.checked)}
        />
        <label className="form-check-label" htmlFor="pipe-response-visualize">
          Visualise response to caller
        </label>
      </div>
    </div>
  );
};
