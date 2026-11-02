import type { EntityStatus } from '../../generated/EntityStatus';

export type MemberIdentifierKind = 'email' | 'subject' | 'api_key' | 'custom';

export type MemberIdentifier =
  | { kind: 'email'; email: string }
  | { kind: 'subject'; subject: string }
  | { kind: 'api_key'; key_name: string }
  | { kind: 'custom'; value: string };

export interface Member {
  id: string;
  name?: string | null;
  description?: string | null;
  status: EntityStatus;
  /** Built-in system member flag. System members can be disabled but never deleted. */
  system?: boolean;
  /**
   * The credentials this caller is recognised by. A member may carry several
   * (e.g. an email and a JWT subject) and resolves under any of them. At least
   * one is required.
   */
  identifiers: MemberIdentifier[];
  /** Set by the server when the member was minted by auto-provisioning. */
  auto_provisioned?: boolean;
  monthly_budget_usd?: number | null;
  monthly_token_cap?: number | null;
  /**
   * When set, the monthly caps reset on this instant's monthly anniversary
   * instead of on the 1st of the month (UTC). ISO-8601 UTC.
   */
  budget_period_anchor?: string | null;
  /** Per-minute request rate cap ("virtual key" RPM). Absent/null = unlimited. */
  requests_per_minute?: number | null;
  /** Per-minute token rate cap ("virtual key" TPM). Absent/null = unlimited. */
  tokens_per_minute?: number | null;
  /**
   * Model allow-list ("virtual key" scope). When non-empty, this caller may
   * only invoke these model names; empty/absent means no restriction.
   */
  allowed_models?: string[] | null;
  created_at?: string;
  updated_at?: string;
}

export const IDENTIFIER_LABELS: Record<MemberIdentifierKind, string> = {
  email: 'Email',
  subject: 'JWT subject',
  api_key: 'API key name',
  custom: 'Custom value',
};

export const IDENTIFIER_PLACEHOLDERS: Record<MemberIdentifierKind, string> = {
  email: 'alice@example.com',
  subject: 'auth0|abc123',
  api_key: 'service-account-key',
  custom: 'opaque-caller-id',
};

export const identifierValue = (identifier: MemberIdentifier): string => {
  switch (identifier.kind) {
    case 'email':
      return identifier.email;
    case 'subject':
      return identifier.subject;
    case 'api_key':
      return identifier.key_name;
    case 'custom':
      return identifier.value;
  }
};

export const makeIdentifier = (kind: MemberIdentifierKind, value: string): MemberIdentifier => {
  switch (kind) {
    case 'email':
      return { kind, email: value };
    case 'subject':
      return { kind, subject: value };
    case 'api_key':
      return { kind, key_name: value };
    case 'custom':
      return { kind, value };
  }
};

/** Every non-empty identifier a member carries, tolerant of legacy payloads
 * that still send a single `identifier` object. */
export const memberIdentifiers = (member: Member): MemberIdentifier[] => {
  const list = Array.isArray(member.identifiers)
    ? member.identifiers
    : // Legacy single-identifier payloads.
      [(member as unknown as { identifier?: MemberIdentifier }).identifier].filter(
        (i): i is MemberIdentifier => !!i
      );
  return list.filter(i => identifierValue(i).trim().length > 0);
};

/** The member's primary (first) identifier, or `null` when none. */
export const primaryIdentifier = (member: Member): MemberIdentifier | null =>
  memberIdentifiers(member)[0] ?? null;

/** The primary identifier's raw value (empty string when none). */
export const primaryIdentifierValue = (member: Member): string => {
  const primary = primaryIdentifier(member);
  return primary ? identifierValue(primary) : '';
};

export const memberLabel = (member: Member): string =>
  member.name?.trim() || primaryIdentifierValue(member) || member.id;

export const EMPTY_MEMBER = (): Member => ({
  id: '',
  name: '',
  description: '',
  status: 'enabled',
  identifiers: [{ kind: 'email', email: '' }],
  monthly_budget_usd: null,
  monthly_token_cap: null,
  budget_period_anchor: null,
  requests_per_minute: null,
  tokens_per_minute: null,
  allowed_models: null,
});

export const toOptionalNumber = (value: string): number | null => {
  const trimmed = value.trim();
  if (trimmed === '') return null;
  const parsed = Number(trimmed);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
};

export const numberOrEmpty = (value?: number | null): string =>
  value === null || value === undefined ? '' : String(value);

export const formatCap = (value?: number | null, prefix = ''): string =>
  value === null || value === undefined ? '—' : `${prefix}${value.toLocaleString()}`;

/** Parse a newline/comma-separated list of model names into a trimmed array
 * (or `null` when empty, meaning "no restriction"). */
export const parseAllowedModels = (value: string): string[] | null => {
  const list = value
    .split(/[\n,]/)
    .map(s => s.trim())
    .filter(s => s.length > 0);
  return list.length > 0 ? Array.from(new Set(list)) : null;
};

/** Render an allowed-models array as a newline-separated string for editing. */
export const allowedModelsText = (value?: string[] | null): string =>
  Array.isArray(value) ? value.join('\n') : '';

/** The member's spend in its current budget period, as enforcement counts it. */
export interface MemberPeriodUsage {
  total_cost: number;
  total_tokens: number;
  period_start: string;
  period_end: string;
}

const pad = (n: number): string => String(n).padStart(2, '0');

/** An ISO-8601 instant as a `datetime-local` value in the viewer's time zone. */
export const toDateTimeLocal = (iso?: string | null): string => {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
};

/** A `datetime-local` value (viewer's time zone) as an ISO-8601 UTC instant,
 * or `null` when empty or unparseable. */
export const fromDateTimeLocal = (value: string): string | null => {
  if (!value.trim()) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
};
