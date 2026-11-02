import { auditConfigurationChange } from './auditHelpers';
import { describeEntry } from './eventNarrative';
import { fieldGroups } from './fieldGroups';
import type { AuditEntry } from './types';

const entry: AuditEntry = {
  timestamp: '2026-08-13T14:00:00Z',
  trace_id: 'trace-1',
  event: {
    audit_configuration_changed: {
      actor_id: 'admin-1',
      operation: 'update',
      outcome: 'succeeded',
      previous: {
        enabled: true,
        policies: true,
        trust_checks: false,
        identity: false,
      },
      requested: {
        enabled: false,
        policies: false,
        trust_checks: false,
        identity: false,
      },
    },
  },
};

describe('audit configuration events', () => {
  it('surfaces the actor, operation, outcome, and state transition', () => {
    expect(auditConfigurationChange(entry)?.actor_id).toBe('admin-1');
    expect(describeEntry(entry)).toMatchObject({
      title: 'Audit configuration changed',
      tone: 'warn',
    });

    const auditGroup = fieldGroups(entry, null, null).find(
      group => group.label === 'Audit control'
    );
    expect(auditGroup?.items).toEqual([
      { term: 'Actor', value: 'admin-1', mono: true },
      { term: 'Operation', value: 'Update' },
      { term: 'Outcome', value: 'Succeeded' },
      {
        term: 'Previous',
        value: 'recording on, policies on, trust checks off, identity off',
      },
      {
        term: 'Requested',
        value: 'recording off, policies off, trust checks off, identity off',
      },
    ]);
  });

  it('does not classify unrelated events as audit configuration changes', () => {
    expect(
      auditConfigurationChange({
        timestamp: '2026-08-13T14:00:00Z',
        event: 'token_injected',
      })
    ).toBeNull();
  });
});
