import type { CanvasNode } from '../../components/builder/SurfaceCanvas';
import type {
  PipeSourceChange,
  PipeUpstreamChange,
  PipeRateLimitChange,
  PipeOpaPolicyChange,
  PipePromptGuardChange,
  PipeJudgeChange,
  PipeJuryChange,
  PipeDeciderChange,
  PipeExpertWitnessesChange,
  PipeUsageLimitEntry,
  PipeUsageLimitsChange,
} from '../../components/builder/PipeBuilderPanel';
import {
  stampSeam,
  type WitnessConfig,
  type WitnessSeam,
} from '../../components/shared/witnessModel';

const str = (v: unknown) => (typeof v === 'string' ? v : '');
const num = (v: unknown, fallback: number) => (typeof v === 'number' ? v : fallback);

export function readSource(nodes: CanvasNode[]): PipeSourceChange {
  const source = nodes.find(n => n.id === 'pipe-source');
  return {
    listen_address: str(source?.config?.listen_address),
    prefix: str(source?.config?.prefix),
    custom_path: str(source?.config?.custom_path),
  };
}

export function readUpstream(nodes: CanvasNode[]): PipeUpstreamChange {
  const upstream = nodes.find(n => n.id === 'pipe-upstream');
  const modelParameters =
    upstream?.config?.model_parameters && typeof upstream.config.model_parameters === 'object'
      ? (upstream.config.model_parameters as Record<string, unknown>)
      : {};
  const overridePolicy =
    upstream?.config?.override_policy && typeof upstream.config.override_policy === 'object'
      ? (upstream.config.override_policy as Record<string, string>)
      : {};
  return {
    endpoint: str(upstream?.config?.endpoint),
    provider: str(upstream?.config?.provider),
    model: str(upstream?.config?.model),
    api_key_secret_id: str(upstream?.config?.api_key_secret_id),
    model_parameters: modelParameters,
    override_policy: overridePolicy,
    cost_tracking_enabled: upstream?.config?.cost_tracking_enabled === true,
    failover: upstream?.config?.failover ?? null,
    load_balancing: upstream?.config?.load_balancing ?? null,
  };
}

export function readRateLimit(nodes: CanvasNode[]): PipeRateLimitChange {
  const rl = nodes.find(n => n.type === 'pipe-rate-limit');
  return {
    present: !!rl,
    enabled: rl?.config?.enabled !== false,
    requests_per_minute: num(rl?.config?.requests_per_minute, 60),
    tokens_per_minute: num(rl?.config?.tokens_per_minute, 100000),
  };
}

export function readOpaPolicy(nodes: CanvasNode[]): PipeOpaPolicyChange {
  const op = nodes.find(n => n.type === 'pipe-opa-policy');
  return {
    present: !!op,
    enabled: op?.config?.enabled !== false,
    policy_definition_id: str(op?.config?.policy_definition_id),
    log_decisions: op?.config?.log_decisions === true,
  };
}

export function readUsageLimits(nodes: CanvasNode[]): PipeUsageLimitsChange {
  const limits: PipeUsageLimitEntry[] = [];
  const read = (
    id: string,
    nodeId: string,
    scope: 'cumulative' | 'stage',
    stage: 'llm' | 'judge' | 'jury' | null,
    jurorIndex?: number
  ) => {
    const node = nodes.find(n => n.id === nodeId);
    const c = (node?.config ?? {}) as Record<string, unknown>;
    if (c.usage_limit_enabled !== true) return;
    const entry: PipeUsageLimitEntry = {
      id,
      enabled: true,
      scope,
      stage,
      monthly_budget_usd:
        typeof c.usage_limit_monthly_budget_usd === 'number'
          ? c.usage_limit_monthly_budget_usd
          : null,
      monthly_token_cap:
        typeof c.usage_limit_monthly_token_cap === 'number'
          ? c.usage_limit_monthly_token_cap
          : null,
    };
    if (jurorIndex !== undefined) entry.juror_index = jurorIndex;
    limits.push(entry);
  };
  read('usage-limit-llm', 'pipe-upstream', 'stage', 'llm');
  read('usage-limit-judge', 'pipe-judge', 'stage', 'judge');
  for (const node of nodes) {
    if (node.type !== 'pipe-juror') continue;
    const i = (node.config as Record<string, unknown>)?.jurorIndex;
    if (typeof i !== 'number') continue;
    read(`usage-limit-juror-${i}`, node.id, 'stage', 'jury', i);
  }
  return { limits };
}

export function readPromptGuard(nodes: CanvasNode[]): PipePromptGuardChange {
  const req = nodes.find(n => n.type === 'pipe-prompt-guard' && n.config?.direction === 'request');
  const res = nodes.find(n => n.type === 'pipe-prompt-guard' && n.config?.direction === 'response');
  // A direction contributes its rules only when its node is present and not
  // toggled off — otherwise a response guard switched off in the UI would still
  // be compiled into `prompt_guard.response` (running it, and forcing buffering).
  const reqOn = !!req && req.config?.enabled !== false;
  const resOn = !!res && res.config?.enabled !== false;
  const request = reqOn && Array.isArray(req?.config?.request) ? req!.config.request : [];
  const response = resOn && Array.isArray(res?.config?.response) ? res!.config.response : [];
  // AI detectors (`llm_pii`) live on the request node only.
  const llmPii = reqOn && Array.isArray(req?.config?.llm_pii) ? req!.config.llm_pii : [];
  const enabled = reqOn || resOn;
  return {
    present: enabled || request.length > 0 || response.length > 0 || llmPii.length > 0,
    enabled,
    request,
    response,
    llm_pii: llmPii,
  };
}

/**
 * Reassemble the backend `expert_witnesses` list from the two witness seam
 * nodes. Each node owns the witnesses for its seam (`config.witnesses`); the
 * request node's entries are stamped `check_request`, the response node's
 * `check_response`, then concatenated. Mirrors how `readPromptGuard`
 * reassembles from its two direction nodes.
 */
export function readExpertWitnesses(nodes: CanvasNode[]): PipeExpertWitnessesChange {
  const readSeam = (type: CanvasNode['type'], seam: WitnessSeam): WitnessConfig[] => {
    const node = nodes.find(n => n.type === type);
    const list = Array.isArray(node?.config?.witnesses)
      ? (node!.config!.witnesses as WitnessConfig[])
      : [];
    return stampSeam(list, seam);
  };
  const witnesses = [
    ...readSeam('pipe-witness-request', 'request'),
    ...readSeam('pipe-witness-response', 'response'),
  ];
  return { present: witnesses.length > 0, witnesses };
}

export function readJudge(nodes: CanvasNode[]): PipeJudgeChange {
  const j = nodes.find(n => n.id === 'pipe-judge');
  const judge = j?.config?.judge;
  return {
    present: !!j,
    judge: judge && typeof judge === 'object' ? (judge as Record<string, unknown>) : null,
  };
}

export function readJury(nodes: CanvasNode[]): PipeJuryChange {
  const j = nodes.find(n => n.id === 'pipe-jury');
  if (!j) return { present: false, jury: null };
  const base =
    j.config?.jury && typeof j.config.jury === 'object'
      ? (j.config.jury as Record<string, unknown>)
      : {};
  // Jurors are first-class sibling nodes; reassemble the array from them
  // (sorted by their stored index) so the jury node only owns jury-level
  // settings. Mirrors how readPromptGuard reassembles from its two nodes.
  const jurors = nodes
    .filter(n => n.type === 'pipe-juror')
    .map(n => {
      const cfg = (n.config ?? {}) as { juror?: unknown; jurorIndex?: unknown };
      const juror =
        cfg.juror && typeof cfg.juror === 'object' ? (cfg.juror as Record<string, unknown>) : null;
      const index = typeof cfg.jurorIndex === 'number' ? cfg.jurorIndex : 0;
      return { index, juror };
    })
    .filter((e): e is { index: number; juror: Record<string, unknown> } => e.juror !== null)
    .sort((a, b) => a.index - b.index)
    .map(e => e.juror);
  return {
    present: true,
    jury: { ...base, jurors },
  };
}

export function readDecider(nodes: CanvasNode[]): PipeDeciderChange {
  const d = nodes.find(n => n.id === 'pipe-decider');
  if (!d) return { present: false, decider: null };
  const base =
    d.config?.decider && typeof d.config.decider === 'object'
      ? (d.config.decider as Record<string, unknown>)
      : {};
  // Candidates are first-class sibling nodes; reassemble the array from them
  // (sorted by their stored index) so the decider node only owns decider-level
  // settings. Mirrors how readJury reassembles its jurors.
  const candidates = nodes
    .filter(n => n.type === 'pipe-candidate')
    .map(n => {
      const cfg = (n.config ?? {}) as { candidate?: unknown; candidateIndex?: unknown };
      const candidate =
        cfg.candidate && typeof cfg.candidate === 'object'
          ? (cfg.candidate as Record<string, unknown>)
          : null;
      const index = typeof cfg.candidateIndex === 'number' ? cfg.candidateIndex : 0;
      return { index, candidate };
    })
    .filter((e): e is { index: number; candidate: Record<string, unknown> } => e.candidate !== null)
    .sort((a, b) => a.index - b.index)
    .map(e => e.candidate);
  return {
    present: true,
    decider: { ...base, candidates },
  };
}
