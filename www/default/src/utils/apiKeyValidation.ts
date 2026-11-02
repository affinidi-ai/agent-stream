/**
 * API-key validation policy for an LLM provider.
 *
 * - `mandatory` — a key **must** be selected; the UX fails validation without one.
 * - `optional`  — a key may be selected but is not enforced.
 * - `none`      — the provider takes no key; the picker is greyed out.
 *
 * Authored on the provider catalogue (`llm.json`) as `api_key_validation`. The
 * legacy boolean `api_key_required` is honoured as a fallback so existing
 * catalogues keep working: `false` ⇒ `none`, anything else ⇒ `mandatory`.
 */
export type ApiKeyValidation = 'mandatory' | 'optional' | 'none';

interface ApiKeyProviderLike {
  api_key_validation?: string | null;
  api_key_required?: boolean;
}

/** Resolve a provider's API-key validation policy (see {@link ApiKeyValidation}). */
export function apiKeyValidation(
  provider: ApiKeyProviderLike | null | undefined
): ApiKeyValidation {
  const v = provider?.api_key_validation;
  if (v === 'mandatory' || v === 'optional' || v === 'none') return v;
  // Legacy fallback: only an explicit `api_key_required: false` opts out.
  if (provider && provider.api_key_required === false) return 'none';
  return 'mandatory';
}

/** True when a key must be selected for the provider to be valid. */
export const apiKeyMandatory = (p: ApiKeyProviderLike | null | undefined): boolean =>
  apiKeyValidation(p) === 'mandatory';

/** True when the provider takes no key (picker should be greyed out). */
export const apiKeyDisabled = (p: ApiKeyProviderLike | null | undefined): boolean =>
  apiKeyValidation(p) === 'none';
