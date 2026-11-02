import type { GovernanceRecord, StageOutcome } from './types';

/** How many records to fetch per surface. */
export const RECORDS_LIMIT = 100;

type BadgeTone =
  | 'primary'
  | 'secondary'
  | 'success'
  | 'warning'
  | 'danger'
  | 'info'
  | 'light'
  | 'dark';

/** Badge tone for a stage/record outcome. */
export function outcomeTone(outcome: StageOutcome): BadgeTone {
  switch (outcome) {
    case 'allow':
      return 'success';
    case 'block':
      return 'danger';
    case 'error':
      return 'warning';
    case 'flag':
      return 'info';
    default:
      return 'secondary';
  }
}

/** The record's headline disposition: block/error/flag win over the observed
 * main call, so a stopped interaction reads as stopped at a glance. */
export function recordDisposition(record: GovernanceRecord): StageOutcome {
  const outcomes = record.stages.map(s => s.outcome);
  if (outcomes.includes('block')) return 'block';
  if (outcomes.includes('error')) return 'error';
  if (outcomes.includes('flag')) return 'flag';
  return 'allow';
}

/** Short digest form `sha256:abcd…1234` for display. */
export function shortDigest(digest?: string): string {
  if (!digest) return '—';
  const hex = digest.startsWith('sha256:') ? digest.slice(7) : digest;
  if (hex.length <= 12) return digest;
  return `sha256:${hex.slice(0, 6)}…${hex.slice(-4)}`;
}

/** USD cost formatted to a sensible precision. */
export function formatCost(cost: number): string {
  if (cost <= 0) return '$0.00';
  return cost < 0.01 ? `$${cost.toFixed(6)}` : `$${cost.toFixed(4)}`;
}
