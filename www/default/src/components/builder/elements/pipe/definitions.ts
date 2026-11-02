import * as Cap from '../capabilities';
import CallerAuthFullscreen from '../caller-auth/CallerAuthFullscreen';
import CallerAuthPanel from '../caller-auth/CallerAuthPanel';
import { callerAuthIncompleteReason } from '../caller-auth/sourceAuthMapping';
import { pipeDriftHarnessDefinition } from '../drift-harness/definition';
import type { NodeDefinition } from '../types';
import AudioStreamFullscreenPanel from './AudioStreamFullscreenPanel';
import RouterFullscreenPanel from './RouterFullscreenPanel';
import RouterPanel from './RouterPanel';
import PipeCandidateFullscreenPanel from './PipeCandidateFullscreenPanel';
import PipeDeciderFullscreenPanel from './PipeDeciderFullscreenPanel';
import PipeJudgeFullscreenPanel from './PipeJudgeFullscreenPanel';
import PipeJuryFullscreenPanel from './PipeJuryFullscreenPanel';
import PipeJurorFullscreenPanel from './PipeJurorFullscreenPanel';
import PipePromptGuardFullscreenPanel from './PipePromptGuardFullscreenPanel';
import PipeServerToolDomainsFullscreen from './PipeServerToolDomainsFullscreen';
import PipeUpstreamFullscreenPanel from './PipeUpstreamFullscreenPanel';
import PipeWitnessFullscreenPanel from './PipeWitnessFullscreenPanel';
import {
  PipeCandidatePanel,
  PipeDeciderPanel,
  PipeJudgePanel,
  PipeJuryPanel,
  PipeJurorPanel,
  PipeOpaPolicyPanel,
  PipePromptGuardPanel,
  PipeRateLimitPanel,
  PipeResponsePanel,
  PipeSourcePanel,
  PipeUpstreamPanel,
  PipeWebFetchPanel,
  PipeWebSearchPanel,
  PipeWitnessPanel,
} from './panels';
import {
  PipeAudioInputPanel,
  PipeAudioStreamPanel,
  PipeDocumentInputPanel,
  PipeImageInputPanel,
} from './InputModalityPanels';
import { DEFAULT_INPUT_MODALITIES } from './pipePanelData';
import { apiKeyValidation } from '../../../../utils/apiKeyValidation';

/**
 * Pipe builder nodes laid out left-to-right to mirror the agent-surface
 * topology and the legacy pipe flow visualisation:
 *
 *   Access Point → Prompt Guard (request) → Judge → LLM → Jury →
 *   Prompt Guard (response) → Response
 *
 * The Access Point (left border) and Response (right border) are edge-
 * constrained endpoints. The LLM is the hero — a rect node centred inside the
 * surface, mirroring the Managed Agent. Prompt Guard appears twice (request
 * and response side) around the LLM. Rate Limit and OPA Policy are
 * edge-drop guards that attach to the Access Point → Prompt Guard edge.
 *
 * All are `scope: 'pipe'` so they never appear in the Surface palette. The
 * spine nodes are `hiddenFromPalette` (auto-created) and non-deletable; the
 * draggable guards are added from the palette and deletable.
 */

export const pipeSourceDefinition: NodeDefinition = {
  type: 'pipe-source',
  label: 'Access Point',
  description: 'The listener that fronts this pipe — where callers reach it',
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
  scope: 'pipe',
  dropMode: 'canvas',
  hiddenFromPalette: true,
  deletable: false,
  provides: [Cap.PIPELINE_SOURCE, Cap.PIPE_SOURCE, Cap.MIDDLEWARE_SLOT, Cap.CONFIGURABLE],
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
    return [];
  },
  ConfigPanel: PipeSourcePanel,
};

export const pipeUpstreamDefinition: NodeDefinition = {
  type: 'pipe-upstream',
  label: 'LLM',
  description: 'The LLM this pipe proxies to — the heart of the pipe',
  icon: '\uf5dc', // fa-brain
  paletteIcon: 'fa-brain',
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
  scope: 'pipe',
  dropMode: 'canvas',
  hiddenFromPalette: true,
  deletable: false,
  provides: [Cap.PIPELINE_SINK, Cap.PIPE_UPSTREAM, Cap.MIDDLEWARE_SLOT, Cap.CONFIGURABLE],
  requires: {},
  incompleteReason: c =>
    c?.provider || c?.endpoint || c?.model ? null : 'Select a provider or set an endpoint',
  // Whether a key is required is catalogue knowledge the static
  // `incompleteReason` can't see, so the missing-key fault is a context-aware
  // dependency. Only a provider whose `api_key_validation` resolves to
  // `mandatory` fails the gate; `optional`/`none` providers never do.
  featureDependencies: [
    {
      description: 'An LLM provider that mandates an API key must have one selected',
      condition: (config, ctx) => {
        // Decider mode defers the base LLM's provider/model/key to the
        // candidates (Route) or the merger (Mirror), so the LLM node itself
        // needs no key — the candidate/merger nodes carry their own.
        if (ctx.allNodes?.some(n => n.type === 'pipe-decider')) return false;
        const providerType = config?.provider;
        if (!providerType) return false;
        const provider = ctx.llmProviders?.find(p => p.enum_value === providerType);
        return !!provider && apiKeyValidation(provider) === 'mandatory';
      },
      check: config => !!config?.api_key_secret_id,
      severity: 'error',
      message: 'Select an API key secret for this LLM.',
    },
  ],
  ConfigPanel: PipeUpstreamPanel,
  FullscreenPanel: PipeUpstreamFullscreenPanel,
  summary: c => (c?.model ? c.model : c?.endpoint ? c.endpoint : null),
};

export const pipeResponseDefinition: NodeDefinition = {
  type: 'pipe-response',
  label: 'Response',
  description: 'The reply returned to the caller after the pipe runs',
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
  paletteOrder: 3,
  scope: 'pipe',
  dropMode: 'canvas',
  hiddenFromPalette: true,
  deletable: false,
  provides: [Cap.PIPE_RESPONSE],
  requires: {},
  incompleteReason: () => null,
  ConfigPanel: PipeResponsePanel,
};

/**
 * Front-door Caller Context extraction for the LLM Surface. Configures the
 * surface's `source_auth` — validating the inbound caller and exposing the
 * verified identity (JWT claims, API-key subject, mTLS principal) to the OPA
 * gate as `input.source_auth.*`. Mirrors the IDE Surface `ide-caller-auth`
 * element (same panel components, same wire methods) but writes to the LLM
 * Surface's own top-level `source_auth` config. Without this element the
 * surface is open and OPA sees no caller identity — so a policy that reads
 * `input.source_auth.claims.tid` etc. cannot evaluate.
 */
export const pipeCallerAuthDefinition: NodeDefinition = {
  type: 'pipe-caller-auth',
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
  scope: 'pipe',
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
      the upstream LLM and any policy that reads a claim (e.g. Entra
      tenant / group) has nothing to evaluate.</p>
      <p>Mirrors the equivalent element on an IDE Surface — same
      methods, same wire shape — but wired to the LLM Surface's own
      top-level <code>source_auth</code> config.</p>
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
    dropOnEdge: [Cap.PIPE_SOURCE],
  },
  incompleteReason: callerAuthIncompleteReason,
  ConfigPanel: CallerAuthPanel,
  FullscreenPanel: CallerAuthFullscreen,
  summary: c => (c?.method_type ? String(c.method_type).replace(/_/g, ' ') : null),
};

export const pipeRateLimitDefinition: NodeDefinition = {
  type: 'pipe-rate-limit',
  label: 'Rate Limit',
  description: 'Request and token rate caps applied to this pipe',
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
  paletteOrder: 1,
  scope: 'pipe',
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
      <p>Cap how many requests and tokens this LLM surface accepts in a
      rolling one-minute window. Once a cap is hit the gateway
      short-circuits with an HTTP 429 and the upstream model never sees the
      request.</p>
      <p><strong>Settings:</strong></p>
      <ul>
        <li><strong>Requests per minute</strong> — max calls per minute</li>
        <li><strong>Tokens per minute</strong> — max tokens per minute</li>
      </ul>
      <p>Toggle <em>Enabled</em> off to keep the caps configured without
      enforcing them.</p>
    `,
  },
  provides: [Cap.PIPELINE_EDGE, Cap.CONFIGURABLE],
  requires: {
    dropOnEdge: [Cap.PIPE_SOURCE],
  },
  incompleteReason: () => null,
  ConfigPanel: PipeRateLimitPanel,
  summary: c =>
    c?.enabled === false
      ? 'disabled'
      : c?.requests_per_minute
        ? `${c.requests_per_minute}/min`
        : null,
};

export const pipeOpaPolicyDefinition: NodeDefinition = {
  type: 'pipe-opa-policy',
  label: 'OPA Policy',
  description: 'OPA (Rego) gate evaluated on every inbound request to this pipe',
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
  paletteOrder: 4,
  scope: 'pipe',
  dropMode: 'edge',
  directionality: 'request',
  hiddenFromPalette: false,
  deletable: true,
  defaultConfig: () => ({ enabled: true, policy_definition_id: '', log_decisions: false }),
  help: {
    title: 'OPA Policy',
    bodyHtml: `
      <p>Evaluate an OPA (Rego) policy on every inbound request to this
      surface. A <code>false</code> result denies the call with HTTP 403.</p>
      <p>Fail-closed: enabling the gate without selecting a policy denies
      everything. Define pipe-scoped policies under Settings → Policies.</p>
    `,
  },
  provides: [Cap.PIPELINE_EDGE, Cap.CONFIGURABLE],
  requires: {
    dropOnEdge: [Cap.PIPE_SOURCE],
  },
  incompleteReason: config =>
    config?.enabled !== false && !config?.policy_definition_id
      ? 'Policy definition must be selected'
      : null,
  ConfigPanel: PipeOpaPolicyPanel,
  summary: c =>
    c?.enabled === false
      ? 'disabled'
      : c?.policy_definition_id
        ? String(c.policy_definition_id).substring(0, 16)
        : 'no policy',
};

export const pipePromptGuardDefinition: NodeDefinition = {
  type: 'pipe-prompt-guard',
  label: 'Prompt Guard',
  description: 'Regex content rules screening requests and responses',
  icon: '\uf3ed', // fa-shield-halved
  paletteIcon: 'fa-shield-alt',
  color: '#fd7e14',
  shape: 'circle',
  defaultRadius: 20,
  resizable: false,
  draggable: true,
  containedInSurface: true,
  edgeConstrained: false,
  xWeight: 0.22,
  stage: 'middleware',
  cardinality: 'multi',
  paletteCategory: 'enhancement',
  paletteOrder: 4,
  scope: 'pipe',
  dropMode: 'canvas',
  hiddenFromPalette: true,
  deletable: false,
  defaultConfig: () => ({ enabled: false, request: [], response: [] }),
  provides: [Cap.MIDDLEWARE_SLOT, Cap.CONFIGURABLE],
  requires: {},
  mutedReason: config => (config?.enabled === true ? null : 'Not enabled'),
  incompleteReason: config => {
    if (config?.enabled !== true) return null;
    const dir = config?.direction === 'response' ? 'response' : 'request';
    const regexGuards = Array.isArray(config?.[dir]) ? config[dir] : [];
    // AI detectors are request-side only.
    const aiDetectors = dir === 'request' && Array.isArray(config?.llm_pii) ? config.llm_pii : [];
    if (regexGuards.length === 0 && aiDetectors.length === 0) {
      return 'Add at least one Prompt Guard (regex or AI)';
    }
    const emptyRegex = regexGuards.some(
      (g: any) => !Array.isArray(g?.regex?.rules) || g.regex.rules.length === 0
    );
    if (emptyRegex) return 'Add at least one pattern to each regex Prompt Guard';
    const incompleteAi = aiDetectors.some((d: any) => {
      if (d?.enabled === false) return false;
      const hasEndpoint =
        !!(d?.endpoint_url || '').toString().trim() || !!(d?.provider_type || '').toString().trim();
      const hasModel = !!(d?.model || '').toString().trim();
      return !hasEndpoint || !hasModel;
    });
    if (incompleteAi) return 'Select a provider and model for each AI Prompt Guard';
    return null;
  },
  ConfigPanel: PipePromptGuardPanel,
  FullscreenPanel: PipePromptGuardFullscreenPanel,
  summary: c => {
    const dir = c?.direction;
    const reqCount =
      (Array.isArray(c?.request) ? c.request.length : 0) +
      (Array.isArray(c?.llm_pii) ? c.llm_pii.length : 0);
    const resCount = Array.isArray(c?.response) ? c.response.length : 0;
    if (dir === 'request') {
      return reqCount > 0 ? `${reqCount} guard${reqCount === 1 ? '' : 's'}` : null;
    }
    if (dir === 'response') {
      return resCount > 0 ? `${resCount} guard${resCount === 1 ? '' : 's'}` : null;
    }
    const total = reqCount + resCount;
    return total > 0 ? `${total} guard${total === 1 ? '' : 's'}` : null;
  },
};

export const pipeJudgeDefinition: NodeDefinition = {
  type: 'pipe-judge',
  label: 'Judge',
  description: 'Single-model response review',
  icon: '\uf0e3', // fa-gavel
  paletteIcon: 'fa-gavel',
  color: '#dc3545',
  shape: 'circle',
  defaultRadius: 20,
  resizable: false,
  draggable: true,
  containedInSurface: true,
  edgeConstrained: false,
  xWeight: 0.37,
  stage: 'middleware',
  cardinality: 'singleton',
  paletteCategory: 'enhancement',
  paletteOrder: 5,
  scope: 'pipe',
  dropMode: 'canvas',
  hiddenFromPalette: true,
  deletable: false,
  defaultConfig: () => ({ judge: { enabled: false } }),
  provides: [Cap.MIDDLEWARE_SLOT, Cap.CONFIGURABLE],
  requires: {},
  mutedReason: config => (config?.judge?.enabled === true ? null : 'Not enabled'),
  incompleteReason: config => {
    const judge = config?.judge;
    if (judge?.enabled !== true) return null;
    if (!judge.mode) return 'Choose a judge mode';
    if (judge.mode === 'llm') return judge.llm?.model ? null : 'Select a judge model';
    return null;
  },
  featureDependencies: [
    {
      description: 'The standard Judge does not run as a pre-LLM guard on realtime voice',
      condition: (config, ctx) => {
        if (config?.judge?.enabled !== true) return false;
        const audioStream = ctx.allNodes.find(n => n.type === 'pipe-audio-stream');
        return (audioStream?.config as any)?.enabled === true;
      },
      check: () => false,
      severity: 'error',
      message:
        'Realtime voice streams caller audio to the model before the standard Judge can run, so this Judge will not block live audio before the LLM. Disable Judge for realtime voice, rely on Jury for model replies, or use a pre-transcription/moderation flow.',
    },
  ],
  ConfigPanel: PipeJudgePanel,
  FullscreenPanel: PipeJudgeFullscreenPanel,
  summary: c => {
    const judge = c?.judge && typeof c.judge === 'object' ? c.judge : null;
    if (!judge) return null;
    return judge.enabled ? judge.mode || 'enabled' : 'disabled';
  },
};

export const pipeJuryDefinition: NodeDefinition = {
  type: 'pipe-jury',
  label: 'Jury',
  description: 'Multi-juror response review',
  icon: '\uf500', // fa-users
  paletteIcon: 'fa-users',
  color: '#2e59d9',
  shape: 'circle',
  defaultRadius: 20,
  resizable: false,
  draggable: true,
  containedInSurface: true,
  edgeConstrained: false,
  xWeight: 0.63,
  stage: 'middleware',
  cardinality: 'singleton',
  paletteCategory: 'enhancement',
  paletteOrder: 6,
  scope: 'pipe',
  dropMode: 'canvas',
  hiddenFromPalette: true,
  deletable: false,
  defaultConfig: () => ({ jury: { enabled: false } }),
  provides: [Cap.MIDDLEWARE_SLOT, Cap.CONFIGURABLE],
  requires: {},
  mutedReason: config => (config?.jury?.enabled === true ? null : 'Not enabled'),
  // The jury node owns only jury-level settings; jurors are first-class
  // sibling nodes. Jury-level config is always complete once enabled, so the
  // "needs at least one juror" requirement is a cross-node feature dependency
  // (it inspects `ctx.allNodes`), and each juror's own completeness is checked
  // by the pipe-juror definition.
  incompleteReason: () => null,
  featureDependencies: [
    {
      description: 'An enabled jury needs at least one juror',
      condition: config => config?.jury?.enabled === true,
      check: (_config, ctx) => ctx.allNodes.some(n => n.type === 'pipe-juror'),
      severity: 'error',
      message: 'Add at least one juror for the jury to render a verdict.',
    },
  ],
  ConfigPanel: PipeJuryPanel,
  FullscreenPanel: PipeJuryFullscreenPanel,
  summary: c => {
    const jury = c?.jury && typeof c.jury === 'object' ? c.jury : null;
    if (!jury) return null;
    return jury.enabled ? jury.mode || 'enabled' : 'disabled';
  },
};

export const pipeJurorDefinition: NodeDefinition = {
  type: 'pipe-juror',
  label: 'Juror',
  description: 'A single LLM that reviews each response for the jury',
  icon: '\uf508', // fa-user-tie
  paletteIcon: 'fa-user-tie',
  color: '#2e59d9',
  shape: 'circle',
  defaultRadius: 16,
  resizable: false,
  draggable: true,
  containedInSurface: true,
  edgeConstrained: false,
  xWeight: 0.63,
  stage: 'middleware',
  cardinality: 'multi',
  paletteCategory: 'enhancement',
  paletteOrder: 7,
  scope: 'pipe',
  dropMode: 'canvas',
  hiddenFromPalette: true,
  deletable: true,
  provides: [Cap.MIDDLEWARE_SLOT, Cap.CONFIGURABLE],
  requires: {},
  mutedReason: config => (config?.juror?.enabled === false ? 'Disabled' : null),
  incompleteReason: config => {
    const juror = config?.juror;
    if (!juror || typeof juror !== 'object') return 'Configure this juror';
    if (juror.enabled === false) return null;
    const llm = juror.llm ?? {};
    if (!llm.provider_type || !llm.model || !llm.endpoint_url) {
      return 'Select a provider, model and endpoint';
    }
    return null;
  },
  // Whether the selected provider needs an API key is catalogue knowledge the
  // static `incompleteReason` can't see, so the missing-key fault is a
  // context-aware dependency instead. It mirrors the save gate in
  // `EditPipePage.getBlockingReason`: an enabled juror under an enabled jury
  // whose provider requires a key (absent/`true`) but has none selected is in
  // error. The canvas already suppresses rings on jurors muted by a disabled
  // jury, but the condition re-checks the jury so the sidebar warning and the
  // save-gate stay consistent too.
  featureDependencies: [
    {
      description: 'A juror whose provider requires an API key must have one selected',
      condition: (config, ctx) => {
        const juror = config?.juror;
        if (!juror || typeof juror !== 'object' || juror.enabled === false) return false;
        const jury = ctx.allNodes.find(n => n.type === 'pipe-jury');
        if (jury && (jury.config as any)?.jury?.enabled !== true) return false;
        const providerType = juror.llm?.provider_type;
        if (!providerType) return false;
        const provider = ctx.llmProviders?.find(p => p.enum_value === providerType);
        return !!provider && apiKeyValidation(provider) === 'mandatory';
      },
      check: config => !!config?.juror?.llm?.api_key_secret,
      severity: 'error',
      message: 'Select an API key secret for this juror.',
    },
  ],
  ConfigPanel: PipeJurorPanel,
  FullscreenPanel: PipeJurorFullscreenPanel,
  summary: c => {
    const juror = c?.juror && typeof c.juror === 'object' ? c.juror : null;
    if (!juror) return null;
    if (juror.enabled === false) return 'disabled';
    return juror.llm?.model || juror.llm?.provider_type || null;
  },
};

/**
 * The decider LLM whose provider/model/API key actually runs for the current
 * strategy: the router in Route, the merger in Mirror + Merge, and none in
 * Mirror + Collect (every candidate answers, so no extra model is configured).
 */
function activeDeciderLlm(decider: any): any {
  if (!decider) return null;
  if (decider.strategy === 'mirror') {
    return decider.mirror?.mode === 'collect' ? null : (decider.mirror?.merger ?? null);
  }
  return decider.llm ?? null;
}

export const pipeDeciderDefinition: NodeDefinition = {
  type: 'pipe-decider',
  label: 'Decider',
  description: 'Routes each request to one of several candidate LLMs',
  icon: '\uf126', // fa-code-branch
  paletteIcon: 'fa-code-branch',
  color: '#20c997',
  shape: 'circle',
  defaultRadius: 20,
  resizable: false,
  draggable: true,
  containedInSurface: true,
  edgeConstrained: false,
  xWeight: 0.5,
  stage: 'target',
  cardinality: 'singleton',
  paletteCategory: 'enhancement',
  paletteOrder: 8,
  scope: 'pipe',
  dropMode: 'canvas',
  hiddenFromPalette: true,
  deletable: false,
  defaultConfig: () => ({ decider: { enabled: true } }),
  provides: [Cap.MIDDLEWARE_SLOT, Cap.CONFIGURABLE],
  requires: {},
  mutedReason: config => (config?.decider?.enabled === true ? null : 'Not enabled'),
  incompleteReason: config => {
    const decider = config?.decider;
    if (decider?.enabled !== true) return null;
    // Mirror ignores the router LLM: Merge needs a merger, Collect needs no model.
    if (decider.strategy === 'mirror') {
      if (decider.mirror?.mode !== 'collect') {
        const merger = decider.mirror?.merger;
        if (!merger?.provider_type || !merger?.model || !merger?.endpoint_url) {
          return 'Select a merger provider, model and endpoint';
        }
      }
      return null;
    }
    if (!decider.llm?.provider_type || !decider.llm?.model || !decider.llm?.endpoint_url) {
      return 'Select a router provider, model and endpoint';
    }
    return null;
  },
  featureDependencies: [
    {
      description: 'An enabled decider needs at least one candidate',
      condition: config => config?.decider?.enabled === true,
      check: (_config, ctx) => ctx.allNodes.some(n => n.type === 'pipe-candidate'),
      severity: 'error',
      message: 'Add at least one candidate for the decider to route to.',
    },
    {
      description: "An enabled decider's active provider that mandates an API key must have one",
      condition: (config, ctx) => {
        if (config?.decider?.enabled !== true) return false;
        const providerType = activeDeciderLlm(config?.decider)?.provider_type;
        if (!providerType) return false;
        const provider = ctx.llmProviders?.find(p => p.enum_value === providerType);
        return !!provider && apiKeyValidation(provider) === 'mandatory';
      },
      // No active model (Mirror + Collect) → nothing to key.
      check: config => {
        const active = activeDeciderLlm(config?.decider);
        return !active || !!active.api_key_secret;
      },
      severity: 'error',
      message: 'Select an API key secret for the decider model.',
    },
  ],
  ConfigPanel: PipeDeciderPanel,
  FullscreenPanel: PipeDeciderFullscreenPanel,
  summary: c => {
    const decider = c?.decider && typeof c.decider === 'object' ? c.decider : null;
    if (!decider) return null;
    if (decider.enabled !== true) return 'disabled';
    if (decider.strategy === 'mirror') {
      return decider.mirror?.mode === 'collect' ? 'mirror · collect' : 'mirror · merge';
    }
    return decider.llm?.model || 'enabled';
  },
};

export const pipeCandidateDefinition: NodeDefinition = {
  type: 'pipe-candidate',
  label: 'Candidate',
  description: 'A routable upstream LLM the decider may select',
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
  paletteCategory: 'enhancement',
  paletteOrder: 9,
  scope: 'pipe',
  dropMode: 'canvas',
  hiddenFromPalette: true,
  deletable: true,
  provides: [Cap.MIDDLEWARE_SLOT, Cap.CONFIGURABLE],
  requires: {},
  incompleteReason: config => {
    const candidate = config?.candidate;
    if (!candidate || typeof candidate !== 'object') return 'Configure this candidate';
    if (!candidate.id) return 'Give this candidate an id';
    const llm = candidate.llm ?? {};
    if (!llm.provider_type || !llm.model || !llm.endpoint_url) {
      return 'Select a provider, model and endpoint';
    }
    return null;
  },
  featureDependencies: [
    {
      description: 'A candidate whose provider requires an API key must have one selected',
      condition: (config, ctx) => {
        const candidate = config?.candidate;
        if (!candidate || typeof candidate !== 'object') return false;
        const decider = ctx.allNodes.find(n => n.type === 'pipe-decider');
        if (decider && (decider.config as any)?.decider?.enabled !== true) return false;
        const providerType = candidate.llm?.provider_type;
        if (!providerType) return false;
        const provider = ctx.llmProviders?.find(p => p.enum_value === providerType);
        return !!provider && apiKeyValidation(provider) === 'mandatory';
      },
      check: config => !!config?.candidate?.llm?.api_key_secret,
      severity: 'error',
      message: 'Select an API key secret for this candidate.',
    },
  ],
  ConfigPanel: PipeCandidatePanel,
  FullscreenPanel: PipeCandidateFullscreenPanel,
  summary: c => {
    const candidate = c?.candidate && typeof c.candidate === 'object' ? c.candidate : null;
    if (!candidate) return null;
    return candidate.llm?.model || candidate.llm?.provider_type || candidate.name || null;
  },
};

/**
 * The two Expert Witness seam nodes — external safety classifiers consulted
 * alongside the local regex guards. Rendered as circles that point down to the
 * request (PromptGuard → Judge) and response (PromptGuard → Response) edges.
 * Each owns a list of witnesses for its seam (`config.witnesses`); the request
 * node serializes `check_request`, the response node `check_response`. Always
 * present (greyed when empty), like the prompt-guard seams.
 */
function witnessDefinition(seam: 'request' | 'response'): NodeDefinition {
  const type = seam === 'request' ? 'pipe-witness-request' : 'pipe-witness-response';
  return {
    type,
    label: 'Expert Witness',
    description:
      seam === 'request'
        ? 'External safety classifiers screening the request before the LLM'
        : 'External safety classifiers screening the response before the client',
    icon: '\uf505', // fa-user-shield
    paletteIcon: 'fa-user-shield',
    color: '#e83e8c',
    shape: 'circle',
    defaultRadius: 16,
    resizable: false,
    draggable: true,
    containedInSurface: true,
    edgeConstrained: false,
    xWeight: seam === 'request' ? 0.3 : 0.7,
    stage: 'middleware',
    cardinality: 'singleton',
    paletteCategory: 'enhancement',
    paletteOrder: seam === 'request' ? 10 : 11,
    scope: 'pipe',
    dropMode: 'canvas',
    hiddenFromPalette: true,
    deletable: false,
    defaultConfig: () => ({ direction: seam, witnesses: [] }),
    provides: [Cap.MIDDLEWARE_SLOT, Cap.CONFIGURABLE],
    requires: {},
    mutedReason: config =>
      Array.isArray(config?.witnesses) && config.witnesses.length > 0 ? null : 'No witnesses',
    incompleteReason: config => {
      const ws = Array.isArray(config?.witnesses) ? config.witnesses : [];
      if (ws.length === 0) return null;
      const bad = ws.some((w: any) => w?.enabled !== false && (!w?.provider || !w?.endpoint_url));
      return bad ? 'Set a provider and endpoint for each witness' : null;
    },
    ConfigPanel: PipeWitnessPanel,
    FullscreenPanel: PipeWitnessFullscreenPanel,
    summary: c => {
      const ws = Array.isArray(c?.witnesses) ? c.witnesses : [];
      return ws.length > 0 ? `${ws.length} witness${ws.length === 1 ? '' : 'es'}` : null;
    },
  };
}

export const pipeWitnessRequestDefinition: NodeDefinition = witnessDefinition('request');
export const pipeWitnessResponseDefinition: NodeDefinition = witnessDefinition('response');

/**
 * Governed server tool: web search. Dropping this node enables the model to
 * search the web through a selectable engine (Tavily / Brave / Google) that
 * the gateway executes on the surface's behalf under OPA, per-surface domain
 * rules, budget and governance recording. Its config is assembled into
 * `server_tools.web_search` on save (see `serverToolsFromCanvas`).
 */
export const pipeWebSearchDefinition: NodeDefinition = {
  type: 'pipe-web-search',
  label: 'Web Search',
  description: 'Let the model search the web through a governed engine (Tavily, Brave, Google)',
  icon: '\uf002', // fa-magnifying-glass
  paletteIcon: 'fa-search',
  color: '#17a2b8',
  shape: 'circle',
  defaultRadius: 18,
  resizable: false,
  draggable: true,
  containedInSurface: true,
  edgeConstrained: false,
  xWeight: 0.36,
  stage: 'middleware',
  cardinality: 'singleton',
  paletteCategory: 'tools',
  paletteOrder: 0,
  scope: 'pipe',
  dropMode: 'canvas',
  llmTool: true,
  hiddenFromPalette: false,
  deletable: true,
  defaultConfig: () => ({
    enabled: true,
    engine: 'tavily',
    engine_secret_id: '',
    max_results: 5,
    max_iterations: 3,
    google_cse_id: '',
    domain_policy: 'allow_all',
    domain_exceptions: [],
  }),
  help: {
    title: 'Web Search',
    bodyHtml: `
      <p>Give the model a <strong>Agent Stream-executed</strong> web search tool.
      When the model asks to search, the gateway runs the query against the
      configured engine, feeds the results back, and lets the model answer
      with citations — all within the request.</p>
      <p>Pick an <strong>engine</strong> (Tavily, Brave, or Google
      Programmable Search) and select the <strong>API key</strong> secret it
      uses. Every call is subject to this surface's OPA policy, the domain
      allow/deny rules below, the surface budget, and governance recording.</p>
    `,
  },
  provides: [Cap.CONFIGURABLE],
  requires: {},
  mutedReason: c => (c?.enabled === false ? 'Disabled' : null),
  incompleteReason: c => {
    if (c?.enabled === false) return null;
    if (!c?.engine) return 'Select a search engine';
    if (!c?.engine_secret_id) return 'Select the engine API key';
    if (c.engine === 'google' && !c?.google_cse_id)
      return 'Enter the Google Programmable Search id';
    return null;
  },
  ConfigPanel: PipeWebSearchPanel,
  FullscreenPanel: PipeServerToolDomainsFullscreen,
  summary: c =>
    c?.enabled === false ? 'disabled' : typeof c?.engine === 'string' ? c.engine : null,
};

/**
 * Governed server tool: web fetch. Dropping this node enables the model to
 * fetch and read a web page by URL. Self-contained (no API key); each fetch is
 * SSRF-guarded and subject to this surface's domain rules. Its config is
 * assembled into `server_tools.web_fetch` on save.
 */
export const pipeWebFetchDefinition: NodeDefinition = {
  type: 'pipe-web-fetch',
  label: 'Web Fetch',
  description: 'Let the model fetch and read a web page by URL (SSRF-guarded, no key needed)',
  icon: '\uf0ac', // fa-globe
  paletteIcon: 'fa-globe',
  color: '#20c997',
  shape: 'circle',
  defaultRadius: 18,
  resizable: false,
  draggable: true,
  containedInSurface: true,
  edgeConstrained: false,
  xWeight: 0.44,
  stage: 'middleware',
  cardinality: 'singleton',
  paletteCategory: 'tools',
  paletteOrder: 1,
  scope: 'pipe',
  dropMode: 'canvas',
  llmTool: true,
  hiddenFromPalette: false,
  deletable: true,
  defaultConfig: () => ({
    enabled: true,
    max_content_bytes: 60000,
    domain_policy: 'allow_all',
    domain_exceptions: [],
  }),
  help: {
    title: 'Web Fetch',
    bodyHtml: `
      <p>Give the model an <strong>Agent Stream-executed</strong> web fetch tool.
      When the model asks to read a URL, the gateway fetches it, reduces the
      page to readable text, and feeds it back — within the request.</p>
      <p>No API key is needed. Each fetch is <strong>SSRF-guarded</strong>
      (private, loopback and cloud-metadata targets are blocked) and subject
      to this surface's domain allow/deny rules, budget and governance
      recording.</p>
    `,
  },
  provides: [Cap.CONFIGURABLE],
  requires: {},
  mutedReason: c => (c?.enabled === false ? 'Disabled' : null),
  incompleteReason: () => null,
  ConfigPanel: PipeWebFetchPanel,
  FullscreenPanel: PipeServerToolDomainsFullscreen,
  summary: c =>
    c?.enabled === false
      ? 'disabled'
      : `${Math.max(1, Math.round((c?.max_content_bytes ?? 60000) / 1000))}KB`,
};

/**
 * Vertical distance the LLM tool row sits above the LLM node centre. Mirrors
 * the Decider candidate row below the LLM, keeping tools (top) and routing
 * candidates (bottom) balanced around the model. Shared by the drop placement
 * and Auto Layout so a freshly dropped tool lands at its final spot. Set high
 * enough that the LLM→tool bus trunk can rise a full `WITNESS_RISE` (104px)
 * above the LLM while the bus still sits below the tool drops — that clearance
 * keeps the horizontal bus above the jury→LLM redrive arc, which bows up over
 * the spine into this region.
 */
export const LLM_TOOL_ROW_Y = 200;

/** Horizontal centre-to-centre gap between LLM tools in the top row. */
export const LLM_TOOL_ROW_SPACING = 90;

/**
 * Position of the ordinal-th LLM tool in the top row above the LLM,
 * surface-relative (the LLM sits at the surface centre). When `count` is given
 * (Auto Layout and the drop re-slot, which know the full set) the tools lay out
 * as one evenly-spaced row centred on the LLM. Without it — a single conditional
 * synthesis that can't know the total (canvas reconcile) — they fan out in
 * symmetric pairs so each keeps a stable slot as more are added.
 */
export function llmToolSlotPosition(ordinal: number, count = 0): { x: number; y: number } {
  if (count > 0) {
    return { x: (ordinal - (count - 1) / 2) * LLM_TOOL_ROW_SPACING, y: -LLM_TOOL_ROW_Y };
  }
  const pair = Math.floor(ordinal / 2);
  const dir = ordinal % 2 === 0 ? -1 : 1;
  return { x: dir * (60 + pair * 90), y: -LLM_TOOL_ROW_Y };
}

/**
 * Shared node-definition scaffold for the three Inputs-palette modality nodes.
 * Each is an LLM-bound, opt-in gate: dropping it onto the LLM enables that
 * inbound modality on the surface; its config maps to `audio_input` /
 * `image_input` / `document_ingestion` on save. Mirrors the governed
 * server-tool nodes (LLM-bound, canvas-as-source-of-truth).
 */
function inputModalityDefinition(
  type: NodeDefinition['type'],
  label: string,
  description: string,
  icon: string,
  paletteIcon: string,
  color: string,
  paletteOrder: number,
  xWeight: number,
  defaultConfig: () => Record<string, unknown>,
  ConfigPanel: NodeDefinition['ConfigPanel'],
  incompleteReason: NodeDefinition['incompleteReason'],
  summary: NodeDefinition['summary'],
  helpBodyHtml: string,
  FullscreenPanel?: NodeDefinition['FullscreenPanel']
): NodeDefinition {
  return {
    type,
    label,
    description,
    icon,
    paletteIcon,
    color,
    shape: 'circle',
    defaultRadius: 18,
    resizable: false,
    draggable: true,
    containedInSurface: true,
    edgeConstrained: false,
    xWeight,
    stage: 'middleware',
    cardinality: 'singleton',
    paletteCategory: 'inputs',
    paletteOrder,
    scope: 'pipe',
    dropMode: 'canvas',
    llmTool: true,
    hiddenFromPalette: false,
    deletable: true,
    defaultConfig,
    help: { title: label, bodyHtml: helpBodyHtml },
    provides: [Cap.CONFIGURABLE],
    requires: {},
    mutedReason: c => (c?.enabled === false ? 'Disabled' : null),
    incompleteReason,
    ConfigPanel,
    FullscreenPanel,
    summary,
  };
}

/**
 * Front-door **Router** for the LLM Surface. Attribute-based routing to a
 * variant by request header, top-level body field, or attachment type
 * (modality — including the realtime WebSocket transport). Edge-bound on the
 * inbound edge (dropped between the Access Point and the first governance node),
 * so it renders first — mirroring the backend, where routing resolves the
 * variant before auth, policy, and guards. The rules are the surface's base-pipe
 * `routing_rules`, edited in the full-page editor via the surface meta; the node
 * carries only the enable flag, and deleting it stops enforcement.
 */
export const pipeRouterDefinition: NodeDefinition = {
  type: 'pipe-router',
  label: 'Router',
  description:
    'Route a request to a variant by header, body field, or attachment type (deterministic)',
  icon: '\uf4d7', // fa-route
  paletteIcon: 'fa-route',
  color: '#0dcaf0',
  shape: 'circle',
  defaultRadius: 18,
  resizable: false,
  draggable: true,
  containedInSurface: true,
  edgeConstrained: false,
  xWeight: 0.08,
  stage: 'middleware',
  cardinality: 'singleton',
  paletteCategory: 'inputs',
  paletteOrder: 4,
  scope: 'pipe',
  dropMode: 'edge',
  directionality: 'request',
  hiddenFromPalette: false,
  deletable: true,
  defaultConfig: () => ({ enabled: true }),
  help: {
    title: 'Router',
    bodyHtml:
      '<p>Deterministic, LLM-free request routing. Ordered rules match a request <strong>header</strong>, a top-level <strong>body field</strong>, or an <strong>attachment type</strong> (image / audio / document / realtime voice) and route the request to a <strong>variant</strong> configured with a capable model and its own guards.</p><p>Runs first at the front door — before auth, policy, and guards — so a variant may change the model, modality gates, and even the Judge/Jury. An explicit <code>$alias</code> always wins; anything unmatched (including plain text) goes to the base surface. Configure the rules in the full-page editor.</p>',
  },
  provides: [Cap.PIPELINE_EDGE, Cap.CONFIGURABLE],
  requires: {
    dropOnEdge: [Cap.PIPE_SOURCE],
  },
  mutedReason: c => (c?.enabled === false ? 'Disabled' : null),
  incompleteReason: () => null,
  ConfigPanel: RouterPanel,
  FullscreenPanel: RouterFullscreenPanel,
  summary: c => (c?.enabled === false ? 'disabled' : 'routing'),
};

export const pipeAudioInputDefinition: NodeDefinition = inputModalityDefinition(
  'pipe-audio-input',
  'Audio File',
  'Accept an attached audio file (input_audio: wav/mp3) for an audio-capable model',
  '\uf1c7', // fa-file-audio
  'fa-file-audio',
  '#6f42c1',
  0,
  0.22,
  () => ({
    enabled: true,
    allowed_formats: [...DEFAULT_INPUT_MODALITIES.audio.formats],
    max_bytes: 25 * 1024 * 1024,
  }),
  PipeAudioInputPanel,
  c => {
    if (c?.enabled === false) return null;
    return Array.isArray(c?.allowed_formats) && c.allowed_formats.length > 0
      ? null
      : 'Select at least one audio format';
  },
  c =>
    c?.enabled === false
      ? 'disabled'
      : `${Array.isArray(c?.allowed_formats) ? c.allowed_formats.length : 0} format(s)`,
  '<p>Accept an attached <strong>audio file</strong> (an <code>input_audio</code> chat part, wav/mp3) so an audio-capable model can hear it. Choose the accepted formats and a size cap.</p><p>The target model must support audio input — audio sent to a text-only model is rejected. Delete this element to reject audio files.</p><p>For live, bidirectional voice over a WebSocket, use the separate <strong>Audio Stream</strong> element instead.</p>'
);

export const pipeAudioStreamDefinition: NodeDefinition = inputModalityDefinition(
  'pipe-audio-stream',
  'Audio Stream',
  'Realtime voice streaming over /v1/realtime for a realtime-capable model',
  '\uf519', // fa-tower-broadcast
  'fa-tower-broadcast',
  '#6610f2',
  1,
  0.26,
  () => ({
    enabled: true,
    max_session_secs: 600,
  }),
  PipeAudioStreamPanel,
  () => null,
  c => (c?.enabled === false ? 'disabled' : 'realtime'),
  '<p>Accept a <strong>realtime voice</strong> session (Mode C) — the governed <code>/v1/realtime</code> WebSocket relay that streams live audio to the model both ways, segmented into per-turn governance records.</p><p>Needs a realtime-capable model (an OpenAI realtime model or a Gemini Live model). Configure the session length, per-turn voice safety, and the pre-recorded audio-stream clips in the full editor. Delete this element to refuse realtime sessions.</p>',
  AudioStreamFullscreenPanel
);

export const pipeImageInputDefinition: NodeDefinition = inputModalityDefinition(
  'pipe-image-input',
  'Image File',
  'Accept inline images (image_url) for a vision-capable model',
  '\uf1c5', // fa-file-image
  'fa-file-image',
  '#d63384',
  2,
  0.28,
  () => ({
    enabled: true,
    allowed_formats: [...DEFAULT_INPUT_MODALITIES.image.formats],
    max_bytes: 20 * 1024 * 1024,
  }),
  PipeImageInputPanel,
  c => {
    if (c?.enabled === false) return null;
    return Array.isArray(c?.allowed_formats) && c.allowed_formats.length > 0
      ? null
      : 'Select at least one image format';
  },
  c =>
    c?.enabled === false
      ? 'disabled'
      : `${Array.isArray(c?.allowed_formats) ? c.allowed_formats.length : 0} format(s)`,
  '<p>Accept inline <strong>images</strong> (an <code>image_url</code> part) for a vision-capable model. Inline data images are checked against the accepted formats and the size cap; remote image URLs are forwarded.</p><p>Delete this element to reject images.</p>'
);

export const pipeDocumentInputDefinition: NodeDefinition = inputModalityDefinition(
  'pipe-document-input',
  'Document File',
  'Accept and extract attached documents (file parts: text/markdown/csv/json/docx)',
  '\uf56f', // fa-file-import
  'fa-file-import',
  '#fd7e14',
  3,
  0.32,
  () => ({
    enabled: true,
    allowed_types: [...DEFAULT_INPUT_MODALITIES.document.extractable],
    mode: 'auto',
    max_file_bytes: 5 * 1024 * 1024,
    max_extracted_chars: 100000,
  }),
  PipeDocumentInputPanel,
  c => {
    if (c?.enabled === false) return null;
    return Array.isArray(c?.allowed_types) && c.allowed_types.length > 0
      ? null
      : 'Select at least one document type';
  },
  c => (c?.enabled === false ? 'disabled' : typeof c?.mode === 'string' ? c.mode : null),
  '<p>Accept an attached <strong>document</strong> (a <code>file</code> part) and, per the mode, extract it to prompt text so any model can read it — the text then flows through PII masking and guardrails.</p><p>Choose the accepted types (text/markdown/csv/json/docx; PDF is forwarded, not yet parsed). Delete this element to reject documents.</p>'
);

export const pipeAnchorDefinitions: NodeDefinition[] = [
  pipeSourceDefinition,
  pipeUpstreamDefinition,
  pipeResponseDefinition,
  pipeCallerAuthDefinition,
  pipeRateLimitDefinition,
  pipeOpaPolicyDefinition,
  pipePromptGuardDefinition,
  pipeJudgeDefinition,
  pipeJuryDefinition,
  pipeJurorDefinition,
  pipeDeciderDefinition,
  pipeCandidateDefinition,
  pipeWitnessRequestDefinition,
  pipeWitnessResponseDefinition,
  pipeWebSearchDefinition,
  pipeWebFetchDefinition,
  pipeRouterDefinition,
  pipeAudioInputDefinition,
  pipeAudioStreamDefinition,
  pipeImageInputDefinition,
  pipeDocumentInputDefinition,
  pipeDriftHarnessDefinition,
];
