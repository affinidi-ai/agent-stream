// Regex-guard config types (mirrors backend `RequestGuard`/`RegexRules`). Kept
// in their own module so the panel and the guard-body component share them.

import type { RejectionConfig } from './llmPii';

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
  /** Link gendered pronouns to a lone person's NER ID. Request-side pseudonymize only. */
  link_pronouns?: boolean;
  rules: RegexRule[];
}

export interface PromptGuard {
  regex: RegexRules;
  rejection?: RejectionConfig | null;
}

export function readGuards(value: unknown): PromptGuard[] {
  return Array.isArray(value) ? (value as PromptGuard[]) : [];
}
