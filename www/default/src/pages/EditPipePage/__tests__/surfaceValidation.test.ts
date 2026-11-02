import {
  forwardTokenAfterProviderChange,
  validateForwardTokenRequired,
  validateForwardTokenSource,
  validateRoutingRules,
  validateUsageAlerts,
} from '../surfaceValidation';
import type { PipeRoutingRuleForm, UsageAlertForm } from '../types';

/**
 * Client-side validators for the enable-first surface controls (attribute-based
 * routing, breach & anomaly alerts). These are the same functions consumed by
 * `EditPipePage.getBlockingReason` to block save with a "Show me" toast.
 */

describe('validateRoutingRules', () => {
  it('passes when disabled regardless of contents', () => {
    expect(validateRoutingRules(false, [])).toBeNull();
    expect(validateRoutingRules(false, undefined)).toBeNull();
    expect(
      validateRoutingRules(false, [
        { match: { kind: 'header', name: '', equals: '' }, target: { variant: null } },
      ])
    ).toBeNull();
  });

  it('flags enabled + empty', () => {
    expect(validateRoutingRules(true, [])).toMatch(/enabled but has no rules/i);
    expect(validateRoutingRules(true, undefined)).toMatch(/enabled but has no rules/i);
  });

  it('flags a header rule missing a name', () => {
    const rules: PipeRoutingRuleForm[] = [
      { match: { kind: 'header', name: '', equals: 'v' }, target: { variant: null } },
    ];
    expect(validateRoutingRules(true, rules)).toMatch(/missing header name/i);
  });

  it('flags a header rule missing an equals value', () => {
    const rules: PipeRoutingRuleForm[] = [
      { match: { kind: 'header', name: 'x-tenant', equals: '' }, target: { variant: null } },
    ];
    expect(validateRoutingRules(true, rules)).toMatch(/missing match value/i);
  });

  it('flags a body-field rule missing a field name', () => {
    const rules: PipeRoutingRuleForm[] = [
      { match: { kind: 'body_field', field: '', equals: 'v' }, target: { variant: null } },
    ];
    expect(validateRoutingRules(true, rules)).toMatch(/missing body field name/i);
  });

  it('passes a complete header rule targeting the base surface', () => {
    const rules: PipeRoutingRuleForm[] = [
      { match: { kind: 'header', name: 'x-tenant', equals: 'acme' }, target: { variant: null } },
    ];
    expect(validateRoutingRules(true, rules)).toBeNull();
  });

  it('passes a complete body-field rule targeting a variant', () => {
    const rules: PipeRoutingRuleForm[] = [
      {
        match: { kind: 'body_field', field: 'user_tier', equals: 'pro' },
        target: { variant: 'v1' },
      },
    ];
    expect(validateRoutingRules(true, rules)).toBeNull();
  });

  it('passes a modality rule routing an attachment type to a variant', () => {
    const rules: PipeRoutingRuleForm[] = [
      { match: { kind: 'modality', has: 'image' }, target: { variant: 'vision' } },
      { match: { kind: 'modality', has: 'realtime' }, target: { variant: 'voice' } },
    ];
    expect(validateRoutingRules(true, rules)).toBeNull();
  });

  it('flags a modality rule with an unknown modality', () => {
    const rules: PipeRoutingRuleForm[] = [
      { match: { kind: 'modality', has: 'video' }, target: { variant: 'v1' } },
    ];
    expect(validateRoutingRules(true, rules)).toMatch(/choose a modality/i);
  });

  it('reports the first fault by index', () => {
    const rules: PipeRoutingRuleForm[] = [
      { match: { kind: 'header', name: 'x', equals: 'y' }, target: { variant: null } },
      { match: { kind: 'header', name: '', equals: 'y' }, target: { variant: null } },
    ];
    expect(validateRoutingRules(true, rules)).toMatch(/Routing rule 2/);
  });
});

describe('validateUsageAlerts', () => {
  it('passes when disabled regardless of contents', () => {
    expect(validateUsageAlerts(false, [])).toBeNull();
    expect(validateUsageAlerts(false, undefined)).toBeNull();
  });

  it('flags enabled + empty', () => {
    expect(validateUsageAlerts(true, [])).toMatch(/enabled but has no alerts/i);
    expect(validateUsageAlerts(true, undefined)).toMatch(/enabled but has no alerts/i);
  });

  it('flags a non-positive threshold', () => {
    const alerts: UsageAlertForm[] = [
      { alert_type: 'cost_threshold', threshold: 0, notification_channels: [] },
    ];
    expect(validateUsageAlerts(true, alerts)).toMatch(/positive number/i);
  });

  it('flags an error-rate threshold above 1', () => {
    const alerts: UsageAlertForm[] = [
      { alert_type: 'error_rate', threshold: 2, notification_channels: [] },
    ];
    expect(validateUsageAlerts(true, alerts)).toMatch(/fraction between 0 and 1/i);
  });

  it('flags a cost-spike threshold at or below 1', () => {
    const alerts: UsageAlertForm[] = [
      { alert_type: 'cost_spike', threshold: 1, notification_channels: [] },
    ];
    expect(validateUsageAlerts(true, alerts)).toMatch(/multiplier greater than 1/i);
  });

  it('passes a valid cost threshold', () => {
    const alerts: UsageAlertForm[] = [
      { alert_type: 'cost_threshold', threshold: 5, notification_channels: ['int-1'] },
    ];
    expect(validateUsageAlerts(true, alerts)).toBeNull();
  });

  it('passes a valid error-rate + cost-spike combo', () => {
    const alerts: UsageAlertForm[] = [
      { alert_type: 'error_rate', threshold: 0.1, notification_channels: ['int-1'] },
      { alert_type: 'cost_spike', threshold: 3, notification_channels: ['int-1'] },
    ];
    expect(validateUsageAlerts(true, alerts)).toBeNull();
  });

  it('flags an alert with no notification integrations selected', () => {
    const alerts: UsageAlertForm[] = [
      { alert_type: 'cost_threshold', threshold: 5, notification_channels: [] },
    ];
    expect(validateUsageAlerts(true, alerts)).toMatch(
      /select at least one notification integration/i
    );
  });
});

describe('validateForwardTokenRequired', () => {
  it('blocks a provider that requires forwarding when it is off', () => {
    expect(validateForwardTokenRequired(true, false)).toMatch(/identity pass-through/i);
    expect(validateForwardTokenRequired(true, undefined)).toMatch(/identity pass-through/i);
  });

  it('passes a provider that requires forwarding when it is on', () => {
    expect(validateForwardTokenRequired(true, true)).toBeNull();
  });

  it('ignores providers that do not require forwarding', () => {
    expect(validateForwardTokenRequired(false, false)).toBeNull();
    expect(validateForwardTokenRequired(false, undefined)).toBeNull();
  });
});

describe('validateForwardTokenSource', () => {
  it('passes when forwarding is off regardless of caller-auth', () => {
    expect(validateForwardTokenSource(false, undefined)).toBeNull();
    expect(validateForwardTokenSource(undefined, 'api_key')).toBeNull();
  });

  it('blocks forwarding with no caller context', () => {
    expect(validateForwardTokenSource(true, undefined)).toMatch(/JWT bearer Caller Context/i);
    expect(validateForwardTokenSource(true, null)).toMatch(/JWT bearer Caller Context/i);
  });

  it('blocks forwarding with a non-JWT caller-auth method', () => {
    expect(validateForwardTokenSource(true, 'api_key')).toMatch(/JWT bearer/i);
    expect(validateForwardTokenSource(true, 'mtls')).toMatch(/JWT bearer/i);
  });

  it('passes forwarding with a JWT bearer caller-auth method', () => {
    expect(validateForwardTokenSource(true, 'jwt_bearer')).toBeNull();
  });
});

describe('forwardTokenAfterProviderChange', () => {
  it('forces forwarding ON when the new provider requires it', () => {
    // openai (off) → copilot: auto-enable.
    expect(forwardTokenAfterProviderChange(false, true, false)).toBe(true);
    // copilot → copilot-like: stays on.
    expect(forwardTokenAfterProviderChange(true, true, true)).toBe(true);
  });

  it('forces forwarding OFF when leaving a requiring provider for one that does not', () => {
    // copilot (on) → openai: undo the auto-enable so caller-context clears.
    expect(forwardTokenAfterProviderChange(true, false, true)).toBe(false);
  });

  it('preserves a manual toggle between non-requiring providers', () => {
    // openai (manually on) → anthropic: keep the operator's choice.
    expect(forwardTokenAfterProviderChange(false, false, true)).toBe(true);
    // openai (off) → anthropic: stays off.
    expect(forwardTokenAfterProviderChange(false, false, false)).toBe(false);
  });
});
