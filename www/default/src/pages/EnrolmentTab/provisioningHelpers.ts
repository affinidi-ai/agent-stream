export type ProvisioningSourceType =
  | 'jwt_claim'
  | 'jwt_subject'
  | 'mtls_subject_cn'
  | 'mtls_email_san'
  | 'api_key_name';

export type ProvisioningSource =
  | { type: 'jwt_claim'; claim: string }
  | { type: 'jwt_subject' }
  | { type: 'mtls_subject_cn' }
  | { type: 'mtls_email_san' }
  | { type: 'api_key_name' };

export type IdentifierKind = 'email' | 'subject' | 'api_key' | 'custom';

export interface ProvisioningIdentifierRule {
  source: ProvisioningSource;
  as_kind?: IdentifierKind | null;
}

export interface MemberDefaults {
  monthly_budget_usd?: number | null;
  monthly_token_cap?: number | null;
  requests_per_minute?: number | null;
  tokens_per_minute?: number | null;
  allowed_models?: string[] | null;
}

export interface TeamDefaults {
  monthly_budget_usd?: number | null;
  monthly_token_cap?: number | null;
}

export type TeamRuleMatchType = 'claim_equals' | 'claim_contains' | 'claim_present';

export type TeamRuleMatch =
  | { type: 'claim_equals'; claim: string; equals: string }
  | { type: 'claim_contains'; claim: string; contains: string }
  | { type: 'claim_present'; claim: string };

export interface TeamAssignmentRule {
  when?: TeamRuleMatch | null;
  team_id?: string | null;
  team_id_template?: string | null;
  ensure_team: boolean;
  team_name_template?: string | null;
  team_defaults?: TeamDefaults | null;
}

export interface MemberProvisioningConfig {
  enabled: boolean;
  identifier_rules: ProvisioningIdentifierRule[];
  name_claim?: string | null;
  member_defaults: MemberDefaults;
  team_rules: TeamAssignmentRule[];
  max_auto_provisioned_members?: number | null;
  creations_per_minute?: number | null;
}

export interface PreviewIdentifierResult {
  kind: string;
  value: string;
}

export interface PreviewTeamResult {
  team_id: string;
  name: string;
  would_create: boolean;
}

export interface ProvisionPreview {
  would_provision: boolean;
  identifiers: PreviewIdentifierResult[];
  name?: string | null;
  teams: PreviewTeamResult[];
  reason?: string | null;
}

export type PreviewIdentityType = 'jwt' | 'api_key' | 'mtls';

export type PreviewIdentityRequest =
  | { type: 'jwt'; subject: string; claims: Record<string, unknown> }
  | { type: 'api_key'; key_name: string }
  | {
      type: 'mtls';
      subject_dn: string;
      sans: { dns: string[]; uri: string[]; email: string[]; ip: string[] };
    };

export const SOURCE_LABELS: Record<ProvisioningSourceType, string> = {
  jwt_claim: 'JWT claim',
  jwt_subject: 'JWT subject (sub)',
  mtls_subject_cn: 'mTLS subject CN',
  mtls_email_san: 'mTLS email SAN',
  api_key_name: 'API key name',
};

export const IDENTIFIER_KIND_LABELS: Record<IdentifierKind, string> = {
  email: 'Email',
  subject: 'Subject',
  api_key: 'API key',
  custom: 'Custom',
};

export const TEAM_MATCH_LABELS: Record<TeamRuleMatchType, string> = {
  claim_equals: 'Claim equals',
  claim_contains: 'Claim contains',
  claim_present: 'Claim present',
};

export const emptyConfig = (): MemberProvisioningConfig => ({
  enabled: false,
  identifier_rules: [],
  name_claim: null,
  member_defaults: {},
  team_rules: [],
  max_auto_provisioned_members: null,
  creations_per_minute: null,
});

export const emptyIdentifierRule = (): ProvisioningIdentifierRule => ({
  source: { type: 'jwt_claim', claim: '' },
});

export const emptyTeamRule = (): TeamAssignmentRule => ({
  ensure_team: false,
});

export const sourceForType = (type: ProvisioningSourceType): ProvisioningSource => {
  switch (type) {
    case 'jwt_claim':
      return { type: 'jwt_claim', claim: '' };
    case 'jwt_subject':
      return { type: 'jwt_subject' };
    case 'mtls_subject_cn':
      return { type: 'mtls_subject_cn' };
    case 'mtls_email_san':
      return { type: 'mtls_email_san' };
    case 'api_key_name':
      return { type: 'api_key_name' };
  }
};

export const teamMatchForType = (type: TeamRuleMatchType): TeamRuleMatch => {
  switch (type) {
    case 'claim_equals':
      return { type: 'claim_equals', claim: '', equals: '' };
    case 'claim_contains':
      return { type: 'claim_contains', claim: '', contains: '' };
    case 'claim_present':
      return { type: 'claim_present', claim: '' };
  }
};

/** Parse a comma/newline-separated list into a trimmed, de-duped array. */
export const parseList = (raw: string): string[] => {
  const seen = new Set<string>();
  return raw
    .split(/[\n,]/)
    .map(s => s.trim())
    .filter(s => s.length > 0 && !seen.has(s) && (seen.add(s), true));
};

/** Coerce a numeric input string to a number or null (empty ⇒ null). */
export const numOrNull = (raw: string): number | null => {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  const value = Number(trimmed);
  return Number.isFinite(value) ? value : null;
};
