import type { CanvasNode } from '../../SurfaceCanvas';
import type { SourceAuthConfig } from '../../../../types';
import { registry } from '../registry';
import { jurorSlotPosition } from '../../../shared/jurorModel';
import { candidateSlotPosition } from '../../../shared/deciderModel';
import { partitionWitnesses, WITNESS_RISE, type WitnessConfig } from '../../../shared/witnessModel';

/**
 * Surface rectangle the pipe canvas seeds. Half-width 420 places the
 * edge-constrained Access Point / Response on the left / right borders
 * (matching `computeAutoLayout`'s pipe branch) at the max edge-node
 * radius; the whole spine sits on the surface centre line.
 */
export const PIPE_SURFACE_SIZE = { w: 840, h: 300 };

/**
 * Loose shape of a saved pipe, matching the subset of `PipeConfig`
 * (`src/pipes/config.rs`) the canvas needs to hydrate its anchors. Kept
 * structural (not imported from a page) so this stays page-agnostic.
 */
export interface PipeConfigLike {
  id?: string;
  name?: string;
  description?: string;
  enabled?: boolean;
  listen_address?: string;
  route?: string;
  route_prefix?: string;
  /**
   * True once the editor has attempted to resolve `route` into `route_prefix`
   * against the routing catalogue — regardless of whether a match was found.
   * Distinguishes "not parsed yet" (empty `route_prefix`, still loading)
   * from "parsed, no matching prefix" (also empty `route_prefix`, but
   * resolved) so a reseed-gate waiting on the parse doesn't block forever
   * when a saved route no longer matches any known prefix.
   */
  route_prefix_resolved?: boolean;
  custom_path?: string;
  provider?: string;
  model?: string;
  api_key_secret_id?: string;
  rate_limit?: {
    enabled?: boolean;
    requests_per_minute?: number;
    tokens_per_minute?: number;
  };
  cost_tracking?: {
    enabled?: boolean;
    input_price_per_1k?: number;
    output_price_per_1k?: number;
  };
  override_policy?: Record<string, string>;
  opa_policy?: {
    enabled?: boolean;
    policy_definition_id?: string;
  } | null;
  prompt_guard?: {
    enabled?: boolean;
    request?: unknown[];
    response?: unknown[];
    llm_pii?: unknown[];
  } | null;
  expert_witnesses?: unknown[];
  judge?: {
    enabled?: boolean;
    mode?: string;
  } | null;
  jury?: {
    enabled?: boolean;
    mode?: string;
    jurors?: unknown[];
    max_retries?: number;
  } | null;
  decider?: {
    enabled?: boolean;
    llm?: unknown;
    system_prompt?: string;
    candidates?: unknown[];
    default_candidate_id?: string | null;
    disable_thinking?: boolean;
  } | null;
  usage_limits?: Array<{
    id?: string;
    enabled?: boolean;
    scope?: string;
    stage?: string | null;
    juror_index?: number | null;
    monthly_budget_usd?: number | null;
    monthly_token_cap?: number | null;
  }>;
  failover?: unknown;
  load_balancing?: unknown;
  /**
   * Inbound caller authentication (`source_auth`). Round-trips through the
   * `pipe-caller-auth` edge-bound anchor on the LLM Surface canvas. Absent
   * when no caller-context element is configured.
   */
  source_auth?: SourceAuthConfig | null;
  pipe_type?: {
    type?: string;
    endpoint?: string;
    server_endpoint?: string;
    server_name?: string;
    provider?: { endpoint?: string; base_url?: string; [k: string]: any };
    [k: string]: any;
  };
  [k: string]: any;
}

/** Pull the most meaningful upstream endpoint out of a pipe_type blob. */
function upstreamEndpoint(pipeType: PipeConfigLike['pipe_type']): string {
  if (!pipeType) return '';
  return (
    pipeType.endpoint ||
    pipeType.server_endpoint ||
    pipeType.server_name ||
    pipeType.provider?.endpoint ||
    pipeType.provider?.base_url ||
    ''
  );
}

/**
 * Project the backend `usage_limits` array onto a single stage / juror node.
 * The limit set is edited inline on the LLM, Judge, and per-Juror panels (one
 * switch each), and cumulatively on the surface property sidebar, rather than
 * via standalone nodes, so each node owns the `usage_limit_*` slice for its own
 * scope. Matches by scope + stage (+ juror index for jury limits), ignoring the
 * stored `id` (the canvas mints deterministic ids on the way out).
 */
function usageLimitConfig(
  pipe: PipeConfigLike | null,
  scope: 'cumulative' | 'stage',
  stage: 'llm' | 'judge' | 'jury' | null,
  jurorIndex?: number
): Record<string, unknown> {
  const list = Array.isArray(pipe?.usage_limits) ? pipe!.usage_limits! : [];
  const match = list.find(l => {
    const s = l?.scope === 'cumulative' ? 'cumulative' : 'stage';
    if (s !== scope) return false;
    if (scope === 'cumulative') return true;
    const st = l?.stage === 'judge' || l?.stage === 'jury' ? l.stage : 'llm';
    if (st !== stage) return false;
    if (stage === 'jury' && jurorIndex !== undefined) {
      return l?.juror_index === jurorIndex;
    }
    return true;
  });
  return {
    usage_limit_enabled: !!match && match.enabled !== false,
    usage_limit_monthly_budget_usd:
      typeof match?.monthly_budget_usd === 'number' ? match.monthly_budget_usd : null,
    usage_limit_monthly_token_cap:
      typeof match?.monthly_token_cap === 'number' ? match.monthly_token_cap : null,
  };
}

/**
 * Reconstruct the live canvas nodes for a pipe, laid out left-to-right to
 * mirror the agent-surface topology and the legacy flow visualisation:
 *
 *   Access Point → Prompt Guard (request) → Judge → LLM → Jury →
 *   Prompt Guard (response) → Response
 *
 * The spine is always emitted (greyed when a stage is unconfigured). The
 * Access Point and Response are edge-constrained endpoints (snapped to the
 * left/right surface border). The interior nodes are pinned in a straight
 * horizontal line via explicit `position` offsets from the surface centre.
 * The LLM (`pipe-upstream`) is the hero — the rect node at centre. Prompt
 * Guard appears twice, sharing one `prompt_guard` config split by `direction`.
 * Only the spine is seeded; the Rate Limit and OPA Policy decorations are
 * overlaid from the saved canvas blob. The page mapping layer reconciles that
 * blob against the pipe's backend `rate_limit` / `opa_policy` first, so an
 * enabled guard configured outside the canvas still renders (see
 * `reconcilePipeCanvasGuards`).
 */
export function nodesFromPipe(pipe: PipeConfigLike | null): CanvasNode[] {
  const endpoint = upstreamEndpoint(pipe?.pipe_type);
  const requestGuards = Array.isArray(pipe?.prompt_guard?.request)
    ? structuredClone(pipe!.prompt_guard!.request)
    : [];
  const responseGuards = Array.isArray(pipe?.prompt_guard?.response)
    ? structuredClone(pipe!.prompt_guard!.response)
    : [];
  // AI detectors (`llm_pii`) live on the request node only.
  const llmPiiDetectors = Array.isArray(pipe?.prompt_guard?.llm_pii)
    ? structuredClone(pipe!.prompt_guard!.llm_pii)
    : [];
  // Prompt guarding defaults to off for a blank pipe (greyed). An explicit
  // flag wins; legacy configs (guards present, no flag) stay enabled to match
  // the backend's `default_true`.
  const guardEnabled =
    pipe?.prompt_guard?.enabled !== undefined
      ? pipe.prompt_guard.enabled === true
      : requestGuards.length > 0 || responseGuards.length > 0;

  // The backend stores a single `prompt_guard.enabled` master flag, but the
  // canvas exposes the request and response guards as independently-togglable
  // nodes. Per-direction enable state is preserved in the saved canvas blob;
  // recover it here so disabling one direction does not resurrect or toggle the
  // other on reload. When the master flag is off both directions are off.
  //
  // With no blob to consult, a direction defaults on only if it actually has
  // rules. It used to default on unconditionally, which broke every pipe
  // configured by an API client rather than this canvas: a config with
  // request-side rules and no `response` array (and so no canvas blob) rendered
  // the response guard as *enabled and empty*, then failed its own
  // `incompleteReason` — "Add at least one Prompt Guard (regex or AI)" — so the
  // pipe could not be saved again without deleting a guard nobody asked for.
  // Deriving from the rules keeps legacy single-flag configs working, because a
  // direction with rules still defaults on.
  const blobGuardEnabled = (nodeId: string): boolean | undefined => {
    const blobNodes = (pipe as { canvas?: { nodes?: Array<Record<string, any>> } } | null)?.canvas
      ?.nodes;
    if (!Array.isArray(blobNodes)) return undefined;
    const match = blobNodes.find(n => n && n.id === nodeId);
    const enabled = match?.config?.enabled;
    return typeof enabled === 'boolean' ? enabled : undefined;
  };
  const requestGuardEnabled =
    guardEnabled &&
    (blobGuardEnabled('pipe-prompt-guard-request') ??
      (requestGuards.length > 0 || llmPiiDetectors.length > 0));
  const responseGuardEnabled =
    guardEnabled && (blobGuardEnabled('pipe-prompt-guard-response') ?? responseGuards.length > 0);

  const source: CanvasNode = {
    id: 'pipe-source',
    type: 'pipe-source',
    label: 'Access Point',
    configured: !!(pipe?.listen_address && pipe?.route_prefix && pipe?.custom_path),
    config: {
      listen_address: pipe?.listen_address ?? '',
      prefix: pipe?.route_prefix ?? '',
      custom_path: pipe?.custom_path ?? '',
    },
  };

  const promptGuardRequestConfig = {
    direction: 'request',
    enabled: requestGuardEnabled,
    request: structuredClone(requestGuards),
    response: structuredClone(responseGuards),
    llm_pii: structuredClone(llmPiiDetectors),
  };
  const promptGuardRequest: CanvasNode = {
    id: 'pipe-prompt-guard-request',
    type: 'pipe-prompt-guard',
    label: 'Prompt Guard',
    configured: registry.isConfigured('pipe-prompt-guard', promptGuardRequestConfig),
    position: { x: -280, y: 0 },
    parentId: 'pipe-source',
    config: promptGuardRequestConfig,
  };

  const judge: CanvasNode = {
    id: 'pipe-judge',
    type: 'pipe-judge',
    label: 'Judge',
    configured: registry.isConfigured('pipe-judge', { judge: pipe?.judge ?? null }),
    position: { x: -140, y: 0 },
    parentId: 'pipe-prompt-guard-request',
    config: {
      judge: pipe?.judge ?? null,
      prompt_guard: pipe?.prompt_guard ?? null,
      jury: pipe?.jury ?? null,
      ...usageLimitConfig(pipe, 'stage', 'judge'),
    },
  };

  const llm: CanvasNode = {
    id: 'pipe-upstream',
    type: 'pipe-upstream',
    label: 'LLM',
    configured: !!(pipe?.provider || endpoint || pipe?.model),
    position: { x: 0, y: 0 },
    parentId: 'pipe-judge',
    config: {
      endpoint,
      provider: pipe?.provider ?? '',
      model: pipe?.model ?? '',
      api_key_secret_id: pipe?.api_key_secret_id ?? '',
      cost_tracking_enabled: pipe?.cost_tracking?.enabled === true,
      model_parameters:
        pipe?.model_parameters && typeof pipe.model_parameters === 'object'
          ? structuredClone(pipe.model_parameters)
          : {},
      override_policy:
        pipe?.override_policy && typeof pipe.override_policy === 'object'
          ? structuredClone(pipe.override_policy)
          : {},
      failover: pipe?.failover ? structuredClone(pipe.failover) : null,
      load_balancing: pipe?.load_balancing ? structuredClone(pipe.load_balancing) : null,
      ...usageLimitConfig(pipe, 'stage', 'llm'),
    },
  };

  // Jurors are first-class sibling nodes (see below), so the jury node owns
  // only jury-level settings. Strip the jurors array from its config slice;
  // `readJury` reassembles it from the juror nodes on the way back out.
  const juryLevel: Record<string, unknown> | null = pipe?.jury
    ? (() => {
        const { jurors: _jurors, ...rest } = pipe.jury as Record<string, unknown>;
        return rest;
      })()
    : null;

  const jury: CanvasNode = {
    id: 'pipe-jury',
    type: 'pipe-jury',
    label: 'Jury',
    configured: registry.isConfigured('pipe-jury', { jury: juryLevel }),
    position: { x: 140, y: 0 },
    parentId: 'pipe-upstream',
    config: {
      jury: juryLevel,
      max_retries: pipe?.jury?.max_retries ?? 0,
      prompt_guard: pipe?.prompt_guard ?? null,
      judge: pipe?.judge ?? null,
    },
  };

  // One node per juror, seeded beneath the jury. `parallel`/`majority` fan the
  // jurors across a horizontal row (juror 0 directly under the Jury, the rest
  // fanning out) so a fresh jury never overflows the surface vertically;
  // `serial` stacks them in a vertical column so the seed already mirrors the
  // sequential hand-off. Each node owns its juror config (incl. the per-juror
  // `enabled` flag); the jury node never holds the jurors array. Node ids are
  // positional so a saved canvas blob can restore each juror's dragged position.
  const juryMode = typeof pipe?.jury?.mode === 'string' ? pipe.jury.mode : 'parallel';
  const jurorNodes: CanvasNode[] = Array.isArray(pipe?.jury?.jurors)
    ? (pipe!.jury!.jurors as unknown[]).map((juror, i) => {
        const jr = (juror && typeof juror === 'object' ? juror : {}) as Record<string, unknown>;
        const name = typeof jr.name === 'string' && jr.name ? jr.name : `Juror ${i + 1}`;
        const pos = jurorSlotPosition(juryMode, i, 140, 0);
        return {
          id: `pipe-juror-${i}`,
          type: 'pipe-juror',
          label: name,
          configured: registry.isConfigured('pipe-juror', { juror: jr, jurorIndex: i }),
          position: pos,
          parentId: 'pipe-jury',
          config: { juror: jr, jurorIndex: i, ...usageLimitConfig(pipe, 'stage', 'jury', i) },
        };
      })
    : [];

  // The decider node and its candidates are only seeded when the LLM is in
  // "decider mode" (`decider.enabled === true`). The decider switch lives on the
  // LLM panel, so a disabled decider leaves the canvas as a plain single-LLM
  // pipe with no decider/candidate glyphs.
  const deciderEnabled = pipe?.decider?.enabled === true;

  // The decider node owns only decider-level settings (router LLM + prompt +
  // fallback); the candidate roster is held by sibling candidate nodes, so
  // strip the candidates array from its config slice (`readDecider` rebuilds it
  // from the candidate nodes on the way back out). Seeded below the LLM hero so
  // it reads as an alternate routing path rather than another middleware stage.
  const deciderLevel: Record<string, unknown> | null = pipe?.decider
    ? (() => {
        const { candidates: _candidates, ...rest } = pipe.decider as Record<string, unknown>;
        return rest;
      })()
    : null;

  const decider: CanvasNode = {
    id: 'pipe-decider',
    type: 'pipe-decider',
    label: 'Decider',
    configured: registry.isConfigured('pipe-decider', { decider: deciderLevel }),
    position: { x: 0, y: 140 },
    parentId: 'pipe-upstream',
    config: { decider: deciderLevel },
  };

  // One node per candidate, fanned across a horizontal row beneath the decider.
  // Each node owns its candidate config; the decider node never holds the
  // candidates array. Node ids are positional so a saved canvas blob can
  // restore each candidate's dragged position.
  const candidateNodes: CanvasNode[] = Array.isArray(pipe?.decider?.candidates)
    ? (pipe!.decider!.candidates as unknown[]).map((candidate, i) => {
        const c = (candidate && typeof candidate === 'object' ? candidate : {}) as Record<
          string,
          unknown
        >;
        const name = typeof c.name === 'string' && c.name ? c.name : `Candidate ${i + 1}`;
        const pos = candidateSlotPosition(i, 0, 140);
        return {
          id: `pipe-candidate-${i}`,
          type: 'pipe-candidate',
          label: name,
          configured: registry.isConfigured('pipe-candidate', { candidate: c, candidateIndex: i }),
          position: pos,
          parentId: 'pipe-decider',
          config: { candidate: c, candidateIndex: i },
        };
      })
    : [];

  const promptGuardResponseConfig = {
    direction: 'response',
    enabled: responseGuardEnabled,
    request: structuredClone(requestGuards),
    response: structuredClone(responseGuards),
  };
  const promptGuardResponse: CanvasNode = {
    id: 'pipe-prompt-guard-response',
    type: 'pipe-prompt-guard',
    label: 'Prompt Guard',
    configured: registry.isConfigured('pipe-prompt-guard', promptGuardResponseConfig),
    position: { x: 280, y: 0 },
    parentId: 'pipe-jury',
    config: promptGuardResponseConfig,
  };

  const response: CanvasNode = {
    id: 'pipe-response',
    type: 'pipe-response',
    label: 'Response',
    configured: true,
    parentId: 'pipe-prompt-guard-response',
  };

  // Expert-witness seam circles — external safety classifiers consulted
  // alongside the regex guards. Each owns the witness list for its seam; the
  // request circle points down to the request edge, the response circle to the
  // response edge. They carry no `parentId` (no spine link); SurfaceCanvas
  // draws a dedicated tether from each circle down to the spine. Always seeded
  // (greyed when empty), like the prompt-guard seams.
  const { request: requestWitnesses, response: responseWitnesses } = partitionWitnesses(
    pipe?.expert_witnesses
  );
  const witnessConfigured = (list: WitnessConfig[]): boolean =>
    list.every(w => w.enabled === false || (!!w.provider && !!w.endpoint_url));
  const witnessRequest: CanvasNode = {
    id: 'pipe-witness-request',
    type: 'pipe-witness-request',
    label: 'Expert Witness',
    configured: witnessConfigured(requestWitnesses),
    position: { x: -210, y: WITNESS_RISE },
    config: { direction: 'request', witnesses: requestWitnesses },
  };
  const witnessResponse: CanvasNode = {
    id: 'pipe-witness-response',
    type: 'pipe-witness-response',
    label: 'Expert Witness',
    configured: witnessConfigured(responseWitnesses),
    position: { x: 350, y: WITNESS_RISE },
    config: { direction: 'response', witnesses: responseWitnesses },
  };

  const spine = [
    source,
    promptGuardRequest,
    judge,
    llm,
    jury,
    ...jurorNodes,
    ...(deciderEnabled ? [decider, ...candidateNodes] : []),
    promptGuardResponse,
    response,
    witnessRequest,
    witnessResponse,
  ];
  return applyCanvasOverlay(spine, pipe?.canvas);
}

/**
 * Layer the persisted `canvas` blob over the registry-derived spine so a
 * user's saved layout round-trips on reload — mirroring the agent surface's
 * overlay in `registry.ts`. For matching spine nodes it applies layout hints
 * (position / radius / parentId) and fills UI-only config keys (backend-truth
 * wins). Blob nodes with no spine match (drag-on decorations like the Rate
 * Limit and OPA Policy guards) are restored as standalone nodes.
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
    // Juror nodes are derived solely from `jury.jurors`; never resurrect one
    // from the saved blob (a removed juror would otherwise reappear). The blob
    // only contributes saved positions to jurors that still exist (handled by
    // the matching-node branch above).
    if (bn.type === 'pipe-juror') continue;
    // The decider node is derived solely from `decider.enabled`; never
    // resurrect one from the saved blob (leaving decider mode would otherwise
    // bring it back). A surviving decider's saved position is restored by the
    // matching-node branch above.
    if (bn.type === 'pipe-decider') continue;
    // Candidate nodes are derived solely from `decider.candidates`; never
    // resurrect one from the saved blob (a removed candidate would otherwise
    // reappear). Saved positions for surviving candidates are restored by the
    // matching-node branch above.
    if (bn.type === 'pipe-candidate') continue;
    // Usage limits are no longer standalone nodes — they live as `usage_limit_*`
    // config on the LLM / Judge / Jury / Access Point nodes. Drop any legacy
    // `pipe-usage-limit` node a saved blob still carries so it never resurfaces.
    if (bn.type === 'pipe-usage-limit') continue;
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
