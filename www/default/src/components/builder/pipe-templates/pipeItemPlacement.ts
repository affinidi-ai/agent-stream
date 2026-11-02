import type { PipeTemplateItem } from '../../../api';
import type { PipeFormData } from '../../../pages/EditPipePage/types';
import type { PromptGuardConfig } from '../../../pages/EditPipePage/tabs/promptGuardTypes';

/**
 * Apply a partial pipe template's `items[]` onto the current pipe form.
 *
 * A partial template is an incremental bundle (mirror of the surface
 * partial templates' placement engine): each item names an element
 * `kind` from the pipe registry and carries a partial `config` that maps
 * onto the flat editor form. Unlike a full template, a partial never
 * replaces the whole pipe — it merges its items, leaving every untouched
 * field as-is. Unknown kinds are skipped so older clients can load newer
 * templates.
 *
 * Pure — returns the patched form; the caller owns React state.
 */
export function applyPipeTemplateItems(
  formData: PipeFormData,
  items: PipeTemplateItem[]
): PipeFormData {
  let next: PipeFormData = { ...formData };
  for (const item of items) {
    const cfg = (item.config ?? {}) as Record<string, any>;
    switch (item.kind) {
      case 'pipe-body':
        next = {
          ...next,
          ...(typeof cfg.name === 'string' ? { name: cfg.name } : {}),
          ...(typeof cfg.description === 'string' ? { description: cfg.description } : {}),
          ...(typeof cfg.enabled === 'boolean' ? { enabled: cfg.enabled } : {}),
        };
        break;
      case 'pipe-source':
        next = {
          ...next,
          ...(typeof cfg.listen_address === 'string' ? { listen_address: cfg.listen_address } : {}),
        };
        break;
      case 'pipe-upstream':
        next = {
          ...next,
          ...(typeof cfg.provider === 'string' ? { provider: cfg.provider } : {}),
          ...(typeof cfg.model === 'string' ? { model: cfg.model } : {}),
          ...(typeof cfg.endpoint === 'string' ? { endpoint_url: cfg.endpoint } : {}),
          ...(typeof cfg.endpoint_url === 'string' ? { endpoint_url: cfg.endpoint_url } : {}),
          ...(typeof cfg.api_key_secret_id === 'string'
            ? { api_key_secret_id: cfg.api_key_secret_id }
            : {}),
        };
        break;
      case 'pipe-rate-limit':
        next = {
          ...next,
          rate_limit_enabled: cfg.enabled !== false,
          ...(typeof cfg.requests_per_minute === 'number'
            ? { requests_per_minute: cfg.requests_per_minute }
            : {}),
          ...(typeof cfg.tokens_per_minute === 'number'
            ? { tokens_per_minute: cfg.tokens_per_minute }
            : {}),
        };
        break;
      case 'pipe-cost-tracking':
        next = {
          ...next,
          cost_tracking_enabled: cfg.enabled !== false,
          ...(typeof cfg.input_price_per_1k === 'number'
            ? { input_price_per_1k: cfg.input_price_per_1k }
            : {}),
          ...(typeof cfg.output_price_per_1k === 'number'
            ? { output_price_per_1k: cfg.output_price_per_1k }
            : {}),
        };
        break;
      case 'pipe-override-policy': {
        const entries = Array.isArray(cfg.entries) ? cfg.entries : [];
        const merged: Record<string, string> = { ...next.override_policy };
        for (const e of entries) {
          if (e && typeof e.key === 'string') merged[e.key] = String(e.value ?? '');
        }
        if (cfg.overrides && typeof cfg.overrides === 'object') {
          for (const [k, v] of Object.entries(cfg.overrides)) merged[k] = String(v);
        }
        next = { ...next, override_policy: merged };
        break;
      }
      case 'pipe-prompt-guard':
        next = {
          ...next,
          prompt_guard: {
            request: Array.isArray(cfg.request) ? cfg.request : [],
            response: Array.isArray(cfg.response) ? cfg.response : [],
            llm_pii: Array.isArray(cfg.llm_pii) ? cfg.llm_pii : [],
          } as PromptGuardConfig,
        };
        break;
      case 'pipe-judge':
        next = { ...next, judge: (cfg.judge ?? cfg) as PipeFormData['judge'] };
        break;
      case 'pipe-jury':
        next = { ...next, jury: (cfg.jury ?? cfg) as PipeFormData['jury'] };
        break;
      case 'pipe-decider':
        next = { ...next, decider: (cfg.decider ?? cfg) as PipeFormData['decider'] };
        break;
      default:
        break;
    }
  }
  return next;
}
