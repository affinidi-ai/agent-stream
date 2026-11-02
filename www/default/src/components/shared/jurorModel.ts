import type { StrictnessLevel } from '../../pages/EditPipePage/tabs/JudgeTab';

/**
 * Juror / jury domain model shared by the pipe builder canvas (where each
 * juror is a first-class node) and the EditPipePage editors. Kept free of
 * React and the d3-backed pipe-flow so eagerly-loaded element panels can
 * import the defaults and prompt builder without pulling the heavy editor
 * chunk into module load.
 */

export interface JurorConfig {
  /**
   * Whether this juror participates in the verdict. Disabled jurors keep
   * their full config but are skipped by the executor (see
   * `src/pipes/judge_jury/executor.rs`). Defaults to true on the backend.
   */
  enabled?: boolean;
  name: string;
  llm: {
    provider_type: string;
    model: string;
    endpoint_url: string;
    api_key_secret?: string;
    parameters?: Record<string, any>;
    timeout_secs?: number;
    capabilities?: Record<string, any>;
    /** API wire format: "openai" (also Azure, Mistral, TogetherAI, Cohere, Ollama, Bedrock, Custom), "anthropic", "gemini", "replicate", "huggingface" */
    api_schema?: string;
  };
  system_prompt: string;
  decision: {
    mode: 'json' | 'regex';
    field?: string;
    approve_value?: string;
    approve_pattern?: string;
    reject_pattern?: string;
  };
  strictness?: StrictnessLevel;
  focus_areas?: string[];
  confidence_threshold?: number;
  custom_instructions?: string;
  disable_thinking?: boolean;
}

export interface JuryConfig {
  enabled: boolean;
  mode: 'parallel' | 'serial' | 'majority';
  jurors: JurorConfig[];
  max_retries?: number;
  retry_prompt?: string;
  rejection?: {
    status_code: number;
    body: string;
    content_type: string;
  };
}

export const JURY_STRICTNESS_PREAMBLES: Record<StrictnessLevel, string> = {
  strict: `You are a strict response quality reviewer. REJECT anything even slightly problematic. When in doubt, reject.`,
  balanced: `You are a response quality reviewer. Reject problematic responses. Allow legitimate content meeting reasonable standards.`,
  lenient: `You are a response quality reviewer. Only reject CLEARLY problematic responses. Allow everything else.`,
};

export const JURY_STRICTNESS_TEMPERATURES: Record<StrictnessLevel, number> = {
  strict: 0.0,
  balanced: 0.3,
  lenient: 0.5,
};

export const JURY_FOCUS_AREA_INSTRUCTIONS: Record<string, string> = {
  prompt_injection: 'prompt injection artifacts',
  jailbreaking: 'jailbreaking/safety bypass artifacts',
  pii_leakage: 'PII/data leakage (personal info, keys, secrets)',
  toxicity: 'toxicity/hate speech',
  illegal_content: 'illegal/dangerous content',
  system_prompt_extraction: 'system prompt leakage',
  social_engineering: 'social engineering/manipulation',
  off_topic: 'off-topic/irrelevant responses',
};

/**
 * Wrap an operator's free-text custom instructions so a reviewer LLM (judge or
 * juror) applies them to the RESPONSE under review rather than reading them as
 * directives about its own wording. Without this framing, a rule phrased in the
 * second person (e.g. "You must never use the word 'wheelbarrow'") is obeyed by
 * the reviewer itself — it simply avoids the word and approves — instead of
 * rejecting a response that violates the rule.
 */
export const frameCustomInstructions = (customInstructions: string): string =>
  `Additional rules for the RESPONSE you are reviewing. These describe what the response must or must not do — they are NOT instructions about your own wording. Reject the response if it violates any of them:\n${customInstructions.trim()}`;

/** Build a juror system prompt from structured strictness controls */
export const buildJurorPrompt = (
  strictness: StrictnessLevel,
  focusAreas: string[],
  confidenceThreshold: number | undefined,
  customInstructions: string
): string => {
  const sections: string[] = [];

  sections.push(JURY_STRICTNESS_PREAMBLES[strictness]);

  if (focusAreas.length > 0) {
    const areaList = focusAreas.map(id => JURY_FOCUS_AREA_INSTRUCTIONS[id] || id).join(', ');
    sections.push(`Check for: ${areaList}.`);
  } else {
    sections.push(
      `Check for: factual accuracy, tone, policy compliance, no leaked sensitive information, general quality.`
    );
  }

  if (customInstructions.trim()) {
    sections.push(frameCustomInstructions(customInstructions));
  }

  if (confidenceThreshold !== undefined && confidenceThreshold > 0) {
    sections.push(`OUTPUT EXACTLY THIS JSON (use these EXACT field names — do NOT rename them):
{"decision":"approve","confidence":0.95,"details":"reason"}
or
{"decision":"reject","confidence":0.95,"details":"reason"}
The field MUST be "decision" (not "approval", "verdict", or anything else).
The field MUST be "confidence" (not "confidence_score").
Confidence range: 0.0-1.0. Threshold: ${confidenceThreshold}.
No other text outside the JSON object.`);
  } else {
    sections.push(`OUTPUT EXACTLY THIS JSON (use these EXACT field names — do NOT rename them):
{"decision":"approve","details":"reason"}
or
{"decision":"reject","details":"reason"}
The field MUST be "decision" (not "approval", "verdict", or anything else).
No other text outside the JSON object.`);
  }

  return sections.join('\n\n');
};

export const DEFAULT_JUROR_PROMPT = buildJurorPrompt('balanced', [], undefined, '');

/** A fresh, enabled juror seeded with sensible defaults for the given index. */
export function makeDefaultJuror(index: number): JurorConfig {
  return {
    enabled: true,
    name: `Juror ${index + 1}`,
    llm: { provider_type: '', model: '', endpoint_url: '' },
    system_prompt: DEFAULT_JUROR_PROMPT,
    decision: { mode: 'json', field: 'decision', approve_value: 'approve' },
  };
}

/**
 * Canvas layout primitives for juror nodes, shared by the seed in
 * `nodesFromPipe`, the "Add juror" action, the mode switch and the auto-layout
 * tidy so they all place jurors identically for a given jury mode. Pure
 * numbers/functions — no React/d3.
 */
export const JUROR_ROW_GAP_X = 90;
export const JUROR_ROW_Y = 130;
export const JUROR_COL_GAP_Y = 100;

/**
 * Horizontal offset (from the Jury's x) for the juror at `ordinal`: ordinal 0
 * sits directly under the Jury, the rest fan out right then left, so at least
 * one juror is always vertically aligned with the Jury.
 */
export function jurorRowOffsetX(ordinal: number, gap: number = JUROR_ROW_GAP_X): number {
  if (ordinal <= 0) return 0;
  const step = Math.ceil(ordinal / 2);
  const dir = ordinal % 2 === 1 ? 1 : -1;
  return dir * step * gap;
}

/**
 * Absolute canvas position for the juror at `ordinal`, anchored to the Jury's
 * position. `parallel` and `majority` fan the jurors across one horizontal row
 * beneath the Jury (the deliberation is concurrent, so order is positional
 * only). `serial` stacks them in a vertical column so the canvas mirrors the
 * sequential hand-off — each juror passes its verdict down to the next.
 */
export function jurorSlotPosition(
  mode: string | undefined,
  ordinal: number,
  juryX: number,
  juryY: number,
  rowGap: number = JUROR_ROW_GAP_X,
  colGap: number = JUROR_COL_GAP_Y
): { x: number; y: number } {
  if (mode === 'serial') {
    return { x: juryX, y: juryY + JUROR_ROW_Y + ordinal * colGap };
  }
  return { x: juryX + jurorRowOffsetX(ordinal, rowGap), y: juryY + JUROR_ROW_Y };
}
