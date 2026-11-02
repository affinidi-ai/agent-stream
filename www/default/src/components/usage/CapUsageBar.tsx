import React from 'react';
import { formatUsd } from './usageSeries';

export type CapKind = 'usd' | 'tokens';

interface CapUsageBarProps {
  /** Amount consumed this month (USD spend or tokens). */
  used: number;
  /** The monthly cap. `null`/`undefined`/`0` means no limit. */
  cap?: number | null;
  kind: CapKind;
  /** Thinner bar + smaller caption for table cells. */
  compact?: boolean;
}

const formatTokens = (n: number): string => {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return Math.round(n).toLocaleString();
};

const fmt = (value: number, kind: CapKind): string =>
  kind === 'usd' ? formatUsd(value) : formatTokens(value);

/** A progress-bar view of "how much of a monthly cap has been used". With no cap
 * it just shows the consumed amount; with a cap it draws a coloured bar that
 * turns amber past 75% and red past 90%. */
const CapUsageBar: React.FC<CapUsageBarProps> = ({ used, cap, kind, compact = false }) => {
  const hasCap = cap !== null && cap !== undefined && cap > 0;
  const usedLabel = fmt(used, kind);
  const cls = `cap-usage${compact ? ' cap-usage--compact' : ''}`;

  if (!hasCap) {
    return (
      <div className={cls}>
        <span className="cap-usage__caption">
          <strong>{usedLabel}</strong> <span className="text-muted">· no limit</span>
        </span>
      </div>
    );
  }

  const capNum = cap as number;
  const rawPct = (used / capNum) * 100;
  const pct = Math.max(0, Math.min(rawPct, 100));
  const state = rawPct >= 90 ? 'danger' : rawPct >= 75 ? 'warning' : 'success';
  const title = `${usedLabel} of ${fmt(capNum, kind)} (${rawPct.toFixed(1)}%)`;

  return (
    <div className={cls}>
      <div
        className="progress cap-usage__track"
        role="progressbar"
        aria-valuenow={Math.round(rawPct)}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={title}
        title={title}
      >
        <div
          className={`progress-bar cap-usage__fill cap-usage__fill--${state}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="cap-usage__caption text-muted">
        {usedLabel} / {fmt(capNum, kind)}{' '}
        <span className="cap-usage__pct">({Math.round(rawPct)}%)</span>
      </span>
    </div>
  );
};

export default CapUsageBar;
