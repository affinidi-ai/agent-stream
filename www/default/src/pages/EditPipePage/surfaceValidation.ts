import type { PipeRoutingRuleForm, UsageAlertForm, UsageAlertType } from './types';

/**
 * Client-side validation of the enable-first surface controls (Attribute-based
 * routing, Breach & anomaly alerts). Each validator returns `null` on pass or a
 * human-readable message describing the first fault. Consumed by
 * `EditPipePage.getBlockingReason` to block save and drive the "Show me" toast:
 * routing jumps to the **Router** element's fullscreen (`pipe-router` node),
 * alerts jump to the surface fullscreen editor (nodeId `__surface__`).
 *
 * These are pure functions with no React or store coupling so they are easy
 * to unit-test and to reuse from any editor surface (LLM or IDE).
 */

export function validateRoutingRules(
  enabled: boolean,
  rules: PipeRoutingRuleForm[] | undefined
): string | null {
  if (!enabled) return null;
  const list = rules ?? [];
  if (list.length === 0) {
    return 'Attribute-based routing is enabled but has no rules.';
  }
  for (let i = 0; i < list.length; i++) {
    const rule = list[i]!;
    const label = `Routing rule ${i + 1}`;
    const kind = rule.match?.kind;
    if (kind === 'header') {
      const name = (rule.match as { name?: string }).name ?? '';
      const equals = (rule.match as { equals?: string }).equals ?? '';
      if (name.trim() === '') {
        return `${label} is incomplete: missing header name.`;
      }
      if (equals.trim() === '') {
        return `${label} is incomplete: missing match value.`;
      }
    } else if (kind === 'body_field') {
      const field = (rule.match as { field?: string }).field ?? '';
      const equals = (rule.match as { equals?: string }).equals ?? '';
      if (field.trim() === '') {
        return `${label} is incomplete: missing body field name.`;
      }
      if (equals.trim() === '') {
        return `${label} is incomplete: missing match value.`;
      }
    } else if (kind === 'modality') {
      const has = (rule.match as { has?: string }).has ?? '';
      if (!['text', 'image', 'audio', 'document', 'realtime'].includes(has)) {
        return `${label} is incomplete: choose a modality.`;
      }
    } else {
      return `${label} is incomplete: unknown match kind.`;
    }
  }
  return null;
}

export function validateUsageAlerts(
  enabled: boolean,
  alerts: UsageAlertForm[] | undefined
): string | null {
  if (!enabled) return null;
  const list = alerts ?? [];
  if (list.length === 0) {
    return 'Breach & anomaly alerts is enabled but has no alerts configured.';
  }
  for (let i = 0; i < list.length; i++) {
    const alert = list[i]!;
    const label = `Alert ${i + 1}`;
    const t = alert.threshold;
    if (!Number.isFinite(t) || t <= 0) {
      return `${label} is incomplete: threshold must be a positive number.`;
    }
    const type = alert.alert_type as UsageAlertType;
    if (type === 'error_rate' && t > 1) {
      return `${label} is invalid: error-rate threshold must be a fraction between 0 and 1.`;
    }
    if (type === 'cost_spike' && t <= 1) {
      return `${label} is invalid: cost-spike threshold must be a multiplier greater than 1.`;
    }
    if ((alert.notification_channels ?? []).length === 0) {
      return `${label} is incomplete: select at least one notification integration.`;
    }
  }
  return null;
}

/**
 * Identity pass-through (`forward_caller_token`) is property-driven, not tied to
 * a specific provider id. Two backend rules are mirrored client-side so the
 * surface shows invalid before the round-trip:
 *
 *  1. A provider that *requires* forwarding (e.g. Microsoft 365 Copilot, or any
 *     provider carrying `requires_forward_caller_token`) must have forwarding
 *     enabled — `validateForwardTokenRequired`.
 *  2. When forwarding is enabled, the surface must validate the caller first via
 *     a **JWT bearer** Caller Context so the forwarded token is verified —
 *     `validateForwardTokenSource`.
 *
 * Both are pure so they are easy to unit-test and reuse.
 */
export function validateForwardTokenRequired(
  providerRequiresToken: boolean,
  forwardCallerToken: boolean | undefined
): string | null {
  if (providerRequiresToken && forwardCallerToken !== true) {
    return 'this provider requires identity pass-through — enable \u201CForward caller\u2019s token to the provider\u201D in Surface Configuration.';
  }
  return null;
}

export function validateForwardTokenSource(
  forwardCallerToken: boolean | undefined,
  callerAuthMethod: string | undefined | null
): string | null {
  if (forwardCallerToken !== true) return null;
  if (!callerAuthMethod) {
    return 'identity pass-through requires a JWT bearer Caller Context — add a Caller Context element on the inbound edge and select a JWT verification strategy.';
  }
  if (callerAuthMethod !== 'jwt_bearer') {
    return 'identity pass-through requires a JWT bearer Caller Context — set the Caller Context authentication method to JWT bearer.';
  }
  return null;
}

/**
 * Resolve `forward_caller_token` when the surface's LLM provider changes.
 *
 *  - The new provider *requires* forwarding → force it ON (mirrors the
 *    auto-enable on selection).
 *  - The surface *left* a requiring provider for one that doesn't → force it
 *    OFF, undoing the auto-enable so the Caller Context requirement clears
 *    instead of sticking.
 *  - Otherwise → keep the current value, preserving a manual toggle on a
 *    non-requiring provider.
 *
 * Pure so it is easy to unit-test and reuse from the editor's provider-change
 * effect.
 */
export function forwardTokenAfterProviderChange(
  prevProviderRequires: boolean,
  newProviderRequires: boolean,
  currentForward: boolean
): boolean {
  if (newProviderRequires) return true;
  if (prevProviderRequires) return false;
  return currentForward;
}
