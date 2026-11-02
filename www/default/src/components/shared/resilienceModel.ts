import { DeciderLlm, makeDefaultDeciderLlm } from './deciderModel';

/**
 * Resilience domain model — mirrors the backend `FailoverConfig` /
 * `LoadBalancingConfig` in `src/pipes/config.rs`. Both reuse the judge/jury
 * `LLMTarget` (here {@link DeciderLlm}) to describe a backup provider, exactly
 * like a decider candidate. Failover retries ordered backups on a transport /
 * upstream failure; load balancing distributes requests across a weighted pool
 * and falls through on failure. Both are base-pipe-level (not variant
 * overridable) and mutually exclusive at runtime (load balancing wins).
 */
export interface FailoverTarget {
  llm: DeciderLlm;
}

export interface FailoverConfig {
  enabled: boolean;
  targets: FailoverTarget[];
}

export interface WeightedTarget {
  llm: DeciderLlm;
  weight: number;
}

/**
 * Pool selection strategy — mirrors the backend `LoadBalancingStrategy`.
 * `weighted` is deterministic weighted round-robin; `lowest_latency` routes to
 * the fastest-observed member (EWMA); `lowest_cost` routes to the cheapest
 * model by catalog price.
 */
export type LoadBalancingStrategy = 'weighted' | 'lowest_latency' | 'lowest_cost';

export interface LoadBalancingConfig {
  enabled: boolean;
  strategy: LoadBalancingStrategy;
  primary_weight: number;
  targets: WeightedTarget[];
}

/** A fresh failover config seeded with one empty backup target. */
export function makeDefaultFailover(): FailoverConfig {
  return { enabled: true, targets: [{ llm: makeDefaultDeciderLlm() }] };
}

/** A fresh load-balancing pool seeded with the primary plus one backup. */
export function makeDefaultLoadBalancing(): LoadBalancingConfig {
  return {
    enabled: true,
    strategy: 'weighted',
    primary_weight: 1,
    targets: [{ llm: makeDefaultDeciderLlm(), weight: 1 }],
  };
}
