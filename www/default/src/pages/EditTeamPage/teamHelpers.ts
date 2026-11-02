import type { EntityStatus } from '../../generated/EntityStatus';

export interface Team {
  id: string;
  name: string;
  description?: string | null;
  status: EntityStatus;
  /** Built-in system team flag. System teams can be disabled but never deleted. */
  system?: boolean;
  monthly_budget_usd?: number | null;
  monthly_token_cap?: number | null;
  /** Member UUIDs that belong to this team. */
  members: string[];
  created_at?: string;
  updated_at?: string;
}

export interface MemberUsageReport {
  member_id: string;
  label: string;
  total_cost: number;
  total_tokens: number;
  monthly_budget_usd?: number | null;
  monthly_token_cap?: number | null;
}

export interface TeamUsageReport {
  team_id: string;
  name: string;
  total_cost: number;
  total_tokens: number;
  monthly_budget_usd?: number | null;
  monthly_token_cap?: number | null;
  members: MemberUsageReport[];
}

export const EMPTY_TEAM = (): Team => ({
  id: '',
  name: '',
  description: '',
  status: 'enabled',
  monthly_budget_usd: null,
  monthly_token_cap: null,
  members: [],
});

/** Parse a text input into an optional positive number, or null when blank. */
export const toOptionalNumber = (value: string): number | null => {
  const trimmed = value.trim();
  if (trimmed === '') return null;
  const parsed = Number(trimmed);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
};

export const numberOrEmpty = (value?: number | null): string =>
  value === null || value === undefined ? '' : String(value);

export const formatUsd = (value: number): string => `$${value.toFixed(2)}`;

export const formatCap = (value?: number | null, prefix = ''): string =>
  value === null || value === undefined ? '—' : `${prefix}${value.toLocaleString()}`;
