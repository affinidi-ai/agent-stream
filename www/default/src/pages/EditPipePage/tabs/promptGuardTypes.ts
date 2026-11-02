// Prompt Guard config types shared across the pipe editor. The live editor UI
// is `components/builder/elements/pipe/PipePromptGuardFullscreenPanel.tsx`; these
// types describe the `prompt_guard` block on the pipe config (mirrors the backend
// `PromptGuardConfig` in `src/pipes/prompt_guard/config.rs`).

export interface RegexRule {
  builtin?: string;
  pattern?: string;
  label?: string;
}

export interface RegexRules {
  action: 'reject' | 'mask';
  /** How matched content is rewritten when action = mask. Defaults to 'redact'. */
  mask_mode?: 'redact' | 'pseudonymize';
  /** Restore the original values in the final response. Request-side pseudonymize only. */
  restore_in_response?: boolean;
  rules: RegexRule[];
}

export interface RejectionConfig {
  status_code: number;
  body: string;
  content_type: string;
}

export interface RequestGuard {
  regex: RegexRules;
  rejection?: RejectionConfig | null;
}

export interface ResponseGuard {
  regex: RegexRules;
  rejection?: RejectionConfig | null;
}

export interface PromptGuardConfig {
  enabled?: boolean;
  request: RequestGuard[];
  response: ResponseGuard[];
  /** Model-backed AI PII detectors. Request-side only. */
  llm_pii?: unknown[];
  external?: unknown;
}
