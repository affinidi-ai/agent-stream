import {
  auditConfigurationChange,
  callerDidOf,
  fieldStr,
  flowLabel,
  scopeLabel,
  surfaceIdOf,
  traceTerminated,
} from './auditHelpers';
import { trustErrorClause } from './eventNarrative';
import type {
  AuditConfigurationState,
  AuditEntry,
  PolicyDecisionData,
  TrustCheckData,
} from './types';

function auditStateLabel(state: AuditConfigurationState): string {
  return [
    `recording ${state.enabled ? 'on' : 'off'}`,
    `policies ${state.policies ? 'on' : 'off'}`,
    `trust checks ${state.trust_checks ? 'on' : 'off'}`,
    `identity ${state.identity ? 'on' : 'off'}`,
  ].join(', ');
}

export interface FieldItem {
  term: string;
  value: string;
  /** Render the value in a monospace font (DIDs, hashes, paths). */
  mono?: boolean;
  /** Optional in-app link target for the value. */
  href?: string;
}

export interface FieldGroup {
  label: string;
  items: FieldItem[];
}

/**
 * Flattens an audit entry into ordered, grouped key/value rows for the "Details"
 * list. Deliberately omits fields the panel already shows elsewhere (timestamp,
 * event type, trace id, VP fingerprint) to avoid duplication. Pure and
 * order-stable so the list reads the same every render.
 */
export function fieldGroups(
  entry: AuditEntry,
  pd: PolicyDecisionData | null,
  tc: TrustCheckData | null
): FieldGroup[] {
  const caller = entry.caller;
  const surfaceId = surfaceIdOf(entry);
  const surfaceName = fieldStr(entry.channel_name) ?? surfaceId ?? undefined;
  const callerDid = callerDidOf(entry) ?? undefined;
  const providerId = fieldStr(entry.provider_id);
  const providerName = fieldStr(entry.provider_name);
  const scopes = Array.isArray(entry.scopes) ? (entry.scopes as string[]) : [];

  const add = (
    arr: FieldItem[],
    term: string,
    value?: string,
    extra?: Omit<FieldItem, 'term' | 'value'>
  ) => {
    if (value != null && value !== '') arr.push({ term, value, ...extra });
  };

  const identity: FieldItem[] = [];
  add(identity, 'Auth method', fieldStr(caller?.auth_method));
  add(identity, 'Caller DID', callerDid, { mono: true });
  if (entry.agent_did) add(identity, 'Agent DID', String(entry.agent_did), { mono: true });
  if (entry.agent_identity_did && entry.agent_identity_did !== entry.agent_did) {
    add(identity, 'Agent identity', String(entry.agent_identity_did), { mono: true });
  }
  add(identity, 'User hash', fieldStr(entry.user_identity_hash), { mono: true });
  add(identity, 'Issuer', fieldStr(caller?.iss), { mono: true });
  add(identity, 'Audience', fieldStr(caller?.aud), { mono: true });
  add(identity, 'Subject', fieldStr(caller?.sub), { mono: true });
  add(identity, 'Email', fieldStr(caller?.email ?? caller?.email_redacted));
  add(identity, 'Name', fieldStr(caller?.name ?? caller?.name_redacted));

  const routing: FieldItem[] = [];
  if (surfaceName) {
    // Agent Stream has no standalone surface-detail route, so this stays plain
    // text (unlike credential providers below, which do have a detail page).
    routing.push({ term: 'Agent surface', value: surfaceName, mono: true });
  }
  add(routing, 'Target', fieldStr(entry.target_endpoint), { mono: true });
  add(routing, 'Protocol', fieldStr(entry.protocol));
  add(routing, 'MCP tool', fieldStr(entry.mcp_tool_name), { mono: true });
  add(routing, 'Inject as', fieldStr(entry.inject_as), { mono: true });
  routing.push({ term: 'Via fabric', value: entry.via_fabric ? 'Yes (G2G)' : 'No' });

  const credentials: FieldItem[] = [];
  if (providerName || providerId) {
    credentials.push({
      term: 'Provider',
      value: providerName ?? providerId!,
      href: providerId ? `/credential-providers/${encodeURIComponent(providerId)}` : undefined,
    });
  }
  add(credentials, 'Token ID', fieldStr(entry.token_id), { mono: true });
  if (scopes.length) add(credentials, 'Scopes', scopes.join(', '));

  const policy: FieldItem[] = [];
  if (pd) {
    add(policy, 'Policy', fieldStr(pd.policy_name) ?? fieldStr(pd.policy_id), { mono: true });
    add(policy, 'Policy definition', fieldStr(pd.policy_definition_id), { mono: true });
    add(policy, 'Scope', scopeLabel(pd.scope));
    if (pd.flow) add(policy, 'Flow', flowLabel(pd.flow));
    add(policy, 'Decision', pd.decision);
    add(policy, 'Deny reason', fieldStr(pd.deny_reason));
    if (pd.http_method && pd.http_path) {
      add(policy, 'Request', `${pd.http_method} ${pd.http_path}`, { mono: true });
    }
  }
  if (tc) {
    add(policy, 'Trust leg', tc.leg);
    // `authority_id` / `entity_id` are omitted on the target-leg
    // "unavailable" paths (AGENT_CARD_UNAVAILABLE,
    // TRUST_REGISTRY_METADATA_UNAVAILABLE). `add()` already suppresses
    // blank values via `fieldStr`, but we route through it explicitly so
    // the two rows disappear entirely rather than showing an "n/a"
    // placeholder — matching the wire-shape "not applicable" semantics.
    add(policy, 'Authority', fieldStr(tc.authority_id), { mono: true });
    add(policy, 'Entity', fieldStr(tc.entity_id), { mono: true });
    policy.push({ term: 'Result', value: tc.ok ? 'Passed' : 'Failed' });
    if (!tc.ok) add(policy, 'Failure', trustErrorClause(tc.error_code, tc.leg));
  }

  // Trace-termination bridge: show the own → downstream mapping explicitly. The
  // raw `detail` (`downstream_trace_id=…`) is redundant with these fields, so it
  // is omitted from the Policy group below for this event type.
  const tt = traceTerminated(entry);
  const trace: FieldItem[] = [];
  if (tt) {
    add(trace, 'Own trace', tt.own_trace_id, { mono: true });
    add(trace, 'Downstream trace', tt.downstream_trace_id, { mono: true });
    add(trace, 'Flow', flowLabel(tt.flow));
  }

  if (!tt) add(policy, 'Detail', fieldStr(entry.detail));

  const auditChange = auditConfigurationChange(entry);
  const accountability: FieldItem[] = [];
  if (auditChange) {
    add(accountability, 'Actor', auditChange.actor_id, { mono: true });
    add(accountability, 'Operation', auditChange.operation === 'reset' ? 'Reset' : 'Update');
    add(
      accountability,
      'Outcome',
      auditChange.outcome === 'succeeded' ? 'Succeeded' : 'Persistence failed'
    );
    add(accountability, 'Previous', auditStateLabel(auditChange.previous));
    add(accountability, 'Requested', auditStateLabel(auditChange.requested));
  }

  return [
    { label: 'Identity', items: identity },
    { label: 'Surface & routing', items: routing },
    { label: 'Credentials', items: credentials },
    { label: 'Trace', items: trace },
    { label: 'Audit control', items: accountability },
    { label: 'Policy', items: policy },
  ];
}
