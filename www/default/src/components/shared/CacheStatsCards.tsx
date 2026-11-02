import React from 'react';
import StatCard from '../StatCard';

export interface CacheStatsCardsProps {
  /** Number of requests served from the response cache. */
  cacheHits: number;
  /** Cumulative provider spend avoided by cache hits. */
  cacheSavedCost: number;
  /** Cumulative tokens avoided by cache hits. */
  cacheSavedTokens: number;
  /** Total requests (for the hit-rate denominator). */
  totalRequests: number;
  /** When true (default), render nothing if there are no cache hits. */
  hideWhenEmpty?: boolean;
  /**
   * Which host's card styling to match:
   * - `stat` (default): the main dashboard's `StatCard`s.
   * - `stage`: the surface Monitoring tab's per-stage cards (`pipe-stage-card`).
   */
  variant?: 'stat' | 'stage';
}

type Accent = 'primary' | 'success' | 'info' | 'warning';

const fmtCost = (n: number): string => `$${(Number.isFinite(n) ? n : 0).toFixed(4)}`;
const fmtInt = (n: number): string => Math.round(Number.isFinite(n) ? n : 0).toLocaleString();

/**
 * A four-card row summarising response-cache effectiveness: money saved, hits,
 * hit rate, and tokens avoided. Shared by the surface Monitoring tab and the
 * main dashboard; `variant` picks the host's card styling so the cards match
 * the surrounding ones exactly.
 */
const CacheStatsCards: React.FC<CacheStatsCardsProps> = ({
  cacheHits,
  cacheSavedCost,
  cacheSavedTokens,
  totalRequests,
  hideWhenEmpty = true,
  variant = 'stat',
}) => {
  if (hideWhenEmpty && cacheHits <= 0) return null;
  const hitRate = totalRequests > 0 ? (cacheHits / totalRequests) * 100 : 0;

  const cards: Array<{ accent: Accent; icon: string; title: string; value: string; meta: string }> =
    [
      {
        accent: 'success',
        icon: 'fa-piggy-bank',
        title: 'Cache Savings',
        value: fmtCost(cacheSavedCost),
        meta: 'saved vs. provider spend',
      },
      {
        accent: 'info',
        icon: 'fa-bolt',
        title: 'Cache Hits',
        value: fmtInt(cacheHits),
        meta: 'served from cache',
      },
      {
        accent: 'primary',
        icon: 'fa-percentage',
        title: 'Cache Hit Rate',
        value: `${hitRate.toFixed(1)}%`,
        meta: 'of all requests',
      },
      {
        accent: 'warning',
        icon: 'fa-coins',
        title: 'Tokens Saved',
        value: fmtInt(cacheSavedTokens),
        meta: 'not sent upstream',
      },
    ];

  if (variant === 'stage') {
    // Match the Monitoring tab's per-stage cards (padding + type scale come from
    // `.pipe-monitoring-tab .pipe-stage-card__*`).
    return (
      <div className="row" data-testid="cache-stats-cards">
        {cards.map(c => (
          <div className="col-xl-3 col-md-6 mb-4" key={c.title}>
            <div className={`card border-left-${c.accent} shadow h-100 pipe-stage-card`}>
              <div className="card-body pipe-stage-card__body">
                <div className="d-flex align-items-center justify-content-between">
                  <div className="pipe-stage-card__text">
                    <div className={`pipe-stage-card__label text-${c.accent} text-uppercase`}>
                      {c.title}
                    </div>
                    <div className="pipe-stage-card__value text-gray-800">{c.value}</div>
                    <div className="pipe-stage-card__meta text-muted">{c.meta}</div>
                  </div>
                  <i className={`fas ${c.icon} pipe-stage-card__icon text-gray-300`}></i>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    );
  }

  // Match the main dashboard's cards by reusing the StatCard component.
  return (
    <div className="row" data-testid="cache-stats-cards">
      {cards.map(c => (
        <StatCard
          key={c.title}
          title={c.title}
          value={c.value}
          icon={c.icon}
          color={c.accent}
          subtitle={c.meta}
        />
      ))}
    </div>
  );
};

export default CacheStatsCards;
