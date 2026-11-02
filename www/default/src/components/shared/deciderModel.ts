import { jurorSlotPosition } from './jurorModel';

/**
 * Decider domain model — mirrors the backend `DeciderConfig` /
 * `DeciderCandidate` in `src/pipes/judge_jury/config.rs`. The Decider is a
 * content-based router: a small "router" LLM inspects each request and picks
 * one of the candidate upstreams, whose provider then serves that request.
 */
export interface DeciderLlm {
  provider_type: string;
  model: string;
  endpoint_url: string;
  api_key_secret?: string;
  parameters?: Record<string, any>;
  timeout_secs?: number;
  capabilities?: Record<string, any>;
  api_schema?: string;
}

export interface DeciderCandidate {
  id: string;
  name: string;
  description?: string;
  llm: DeciderLlm;
}

/** How the Decider dispatches a request across its candidates. */
export type DeciderStrategy = 'route' | 'mirror';

/** How Mirror strategy aggregates the fanned-out candidate answers. */
export type MirrorMode = 'merge' | 'collect';

/**
 * Mirror-strategy settings. Only consulted when `strategy === 'mirror'`.
 * `merge` synthesizes all answers into one via the `merger` LLM (then Jury/guards
 * run as normal); `collect` returns every candidate answer for a human to choose.
 */
export interface MirrorConfig {
  mode: MirrorMode;
  /** Independently-configured LLM that synthesizes the answers (Merge mode). */
  merger?: DeciderLlm;
  /** System prompt steering the merge; the answers are appended automatically. */
  merge_system_prompt?: string;
  disable_thinking?: boolean;
}

export interface DeciderConfig {
  enabled: boolean;
  /** Dispatch strategy: route to one candidate (default) or mirror to all. */
  strategy?: DeciderStrategy;
  /** Router LLM — required in Route strategy, unused (and absent) in Mirror. */
  llm?: DeciderLlm;
  system_prompt: string;
  candidates: DeciderCandidate[];
  default_candidate_id?: string | null;
  /** Mirror aggregation settings; consulted only when `strategy === 'mirror'`. */
  mirror?: MirrorConfig;
  disable_thinking?: boolean;
}

/** Default synthesis instructions used when `merge_system_prompt` is empty. */
export const DEFAULT_MERGE_PROMPT =
  'You are given several candidate answers to the user request, each produced by a different model. ' +
  'Synthesize a single best answer that combines the strongest, most accurate parts of each and discards ' +
  'any errors or weaker content. Do not mention that multiple answers exist — reply only with the merged answer.';

/** Default routing instructions appended with the candidate menu at runtime. */
export const DEFAULT_DECIDER_PROMPT =
  'You are a routing classifier. Read the user request and choose the single best ' +
  'candidate upstream to handle it. Reply with JSON {"candidate":"<id>"} naming exactly ' +
  'one candidate id from the list. Pick the cheapest candidate that can handle the ' +
  'request well; escalate to a more capable candidate only when the request clearly needs it.';

/** A fresh router LLM target seeded empty (provider chosen in the panel). */
export function makeDefaultDeciderLlm(): DeciderLlm {
  return { provider_type: '', model: '', endpoint_url: '' };
}

/** A fresh candidate seeded with a stable id for the given index. */
export function makeDefaultCandidate(index: number): DeciderCandidate {
  return {
    id: `candidate-${index + 1}`,
    name: `Candidate ${index + 1}`,
    description: '',
    llm: makeDefaultDeciderLlm(),
  };
}

/** A fresh Mirror config seeded in Merge mode with an empty merger target. */
export function makeDefaultMirrorConfig(): MirrorConfig {
  return {
    mode: 'merge',
    merger: makeDefaultDeciderLlm(),
    merge_system_prompt: '',
  };
}

/**
 * The single top-level "how does this surface pick/aggregate its LLM(s)" choice
 * a user makes. It unifies the decider on/off state, the routing strategy, and
 * the mirror aggregation mode into one flat list:
 *
 * - `direct`  — no decider; proxy straight to the base LLM.
 * - `route`   — decider, Route strategy (router picks one candidate).
 * - `collect` — decider, Mirror strategy, Collect mode (return every answer).
 * - `merge`   — decider, Mirror strategy, Merge mode (consolidate to one answer).
 */
export type SurfaceExecutionMode = 'direct' | 'route' | 'collect' | 'merge';

export interface SurfaceModeOption {
  value: SurfaceExecutionMode;
  label: string;
  /** One-line explainer shown in the mode info box and under the dropdown. */
  description: string;
}

export const SURFACE_MODE_OPTIONS: SurfaceModeOption[] = [
  {
    value: 'direct',
    label: 'LLM Direct',
    description: 'Proxy each request straight to a single configured LLM.',
  },
  {
    value: 'route',
    label: 'Decide LLM based on content',
    description:
      'A router LLM reads each request and picks the single best candidate to answer; the chosen candidate serves the response.',
  },
  {
    value: 'collect',
    label: 'Compare output from multiple LLMs',
    description:
      'Each request is sent to every candidate at once and all answers are returned so a human can compare them. Streaming is off and every candidate is billed.',
  },
  {
    value: 'merge',
    label: 'Summarise output from multiple LLMs',
    description:
      'Each request is sent to every candidate at once, then a summariser LLM consolidates them into one best answer. Streaming is off and every candidate is billed.',
  },
];

/** The mode options that apply once a decider exists (everything but `direct`). */
export const DECIDER_MODE_OPTIONS = SURFACE_MODE_OPTIONS.filter(o => o.value !== 'direct');

/**
 * The canvas node name for the routing element, which reflects the mode: a
 * plain **Decider** when routing, a **Comparer** when comparing every answer,
 * and a **Summariser** when consolidating them into one.
 */
export function deciderNodeLabel(mode: SurfaceExecutionMode): string {
  switch (mode) {
    case 'collect':
      return 'Comparer';
    case 'merge':
      return 'Summariser';
    default:
      return 'Decider';
  }
}

/**
 * Upper bound on Mirror candidates, mirroring the backend `MAX_MIRROR_CANDIDATES`
 * (`src/pipes/judge_jury/config.rs`). Every candidate is called on every request,
 * so the fan-out is capped; the panel disables "Add candidate" at this limit.
 */
export const MAX_MIRROR_CANDIDATES = 10;

/** Look up the option (label + description) for a mode. */
export function surfaceModeOption(mode: SurfaceExecutionMode): SurfaceModeOption {
  return SURFACE_MODE_OPTIONS.find(o => o.value === mode) ?? SURFACE_MODE_OPTIONS[0];
}

/**
 * Derive the current [`SurfaceExecutionMode`] from a decider-level config. Pass
 * `null`/`undefined` (no decider node) to get `direct`.
 */
export function surfaceModeFromDecider(
  decider: { strategy?: string; mirror?: { mode?: string } } | null | undefined
): SurfaceExecutionMode {
  if (!decider) return 'direct';
  if (decider.strategy === 'mirror')
    return decider.mirror?.mode === 'collect' ? 'collect' : 'merge';
  return 'route';
}

/** A fresh decider-level config (router LLM + prompt), before a mode is applied. */
export function freshDeciderConfig(): Record<string, unknown> {
  return {
    enabled: true,
    llm: makeDefaultDeciderLlm(),
    system_prompt: DEFAULT_DECIDER_PROMPT,
    default_candidate_id: null,
  };
}

/**
 * The strategy/mirror fields that select a given (non-`direct`) mode, preserving
 * any existing merger/prompt so switching modes never discards configuration.
 */
export function modeToDeciderPatch(
  existing: { mirror?: MirrorConfig } | null | undefined,
  mode: Exclude<SurfaceExecutionMode, 'direct'>
): { strategy: DeciderStrategy; mirror?: MirrorConfig } {
  if (mode === 'route') return { strategy: 'route' };
  const mirror: MirrorConfig = {
    ...(existing?.mirror ?? {}),
    mode: mode === 'collect' ? 'collect' : 'merge',
  };
  if (mode === 'merge' && !mirror.merger) mirror.merger = makeDefaultDeciderLlm();
  return { strategy: 'mirror', mirror };
}

/**
 * Produce the full decider-level config for a (non-`direct`) mode, layering the
 * strategy/mirror patch over the existing config (or a fresh base).
 */
export function applyModeToDeciderConfig(
  existing: Record<string, unknown> | null | undefined,
  mode: Exclude<SurfaceExecutionMode, 'direct'>
): Record<string, unknown> {
  const base = existing ?? freshDeciderConfig();
  return { ...base, enabled: true, ...modeToDeciderPatch(base as { mirror?: MirrorConfig }, mode) };
}

/**
 * Place a candidate node beneath the Decider. Candidates always fan across a
 * horizontal row (there is no serial routing), so this reuses the juror row
 * layout with an undefined mode.
 */
export function candidateSlotPosition(
  ordinal: number,
  deciderX: number,
  deciderY: number
): { x: number; y: number } {
  return jurorSlotPosition('parallel', ordinal, deciderX, deciderY);
}
