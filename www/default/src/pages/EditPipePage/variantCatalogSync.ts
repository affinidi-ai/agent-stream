import type { PipeCanaryForm, PipeCanarySplitForm, PipeRoutingRuleForm } from './types';

const clampWeight = (weight: number): number => {
  if (!Number.isFinite(weight)) return 0;
  return Math.max(0, Math.round(weight));
};

export const normalizeCanarySplits = (splits: PipeCanarySplitForm[]): PipeCanarySplitForm[] => {
  if (splits.length === 0) return [];

  const prepared = splits.map(split => ({ ...split, weight: clampWeight(split.weight) }));
  const total = prepared.reduce((sum, split) => sum + split.weight, 0);

  if (total === 100) return prepared;

  if (total <= 0) {
    const baseIndex = prepared.findIndex(split => split.variant === '');
    const targetIndex = baseIndex >= 0 ? baseIndex : 0;
    return prepared.map((split, idx) => ({ ...split, weight: idx === targetIndex ? 100 : 0 }));
  }

  const normalized = prepared.map(split => ({
    ...split,
    weight: Math.round((split.weight / total) * 100),
  }));

  const drift = 100 - normalized.reduce((sum, split) => sum + split.weight, 0);
  if (drift === 0) return normalized;

  const baseIndex = normalized.findIndex(split => split.variant === '');
  const adjustIndex =
    baseIndex >= 0
      ? baseIndex
      : normalized.reduce(
          (best, split, idx, arr) => (split.weight > arr[best].weight ? idx : best),
          0
        );

  normalized[adjustIndex] = {
    ...normalized[adjustIndex],
    weight: Math.max(0, normalized[adjustIndex].weight + drift),
  };

  return normalized;
};

export const syncVariantCatalogReferences = (
  variantAliases: string[],
  canary: PipeCanaryForm | null,
  routingRules: PipeRoutingRuleForm[]
): {
  canary: PipeCanaryForm | null;
  routingRules: PipeRoutingRuleForm[];
} => {
  const aliasSet = new Set(variantAliases.filter(Boolean));

  const nextCanary = canary
    ? {
        ...canary,
        splits: normalizeCanarySplits(
          (canary.splits ?? []).filter(split => split.variant === '' || aliasSet.has(split.variant))
        ),
      }
    : null;

  const nextRoutingRules = (routingRules ?? []).map(rule => ({
    ...rule,
    target:
      rule.target.variant && !aliasSet.has(rule.target.variant)
        ? { ...rule.target, variant: null }
        : rule.target,
  }));

  return { canary: nextCanary, routingRules: nextRoutingRules };
};
