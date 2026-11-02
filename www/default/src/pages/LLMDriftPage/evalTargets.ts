import type { DriftSurface } from './types';

export interface EvalTargetOption {
  value: string;
  label: string;
}

/**
 * The variant options for a replay's **target surface**: **Base variant** first
 * (empty value = the surface's base config), then each named variant. A caller
 * treats a single option (only Base) as "this surface has no variants" and
 * shows the picker read-only.
 */
export function targetVariantOptions(
  surfaces: DriftSurface[],
  targetSurfaceId: string
): EvalTargetOption[] {
  const surface = surfaces.find(s => s.surface_id === targetSurfaceId);
  const options: EvalTargetOption[] = [{ value: '', label: 'Base variant' }];
  for (const v of surface?.variants ?? []) {
    options.push({ value: v.alias, label: v.name || v.alias });
  }
  return options;
}
