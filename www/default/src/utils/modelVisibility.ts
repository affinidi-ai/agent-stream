/**
 * Per-model enable/disable for the LLM provider catalog. A model is selectable
 * unless it is explicitly disabled (`enabled === false`); a missing flag means
 * enabled, so existing catalog entries stay visible without editing each one.
 */

export interface SelectableModel {
  value: string;
  enabled?: boolean;
}

export const isModelEnabled = (model: SelectableModel): boolean => model.enabled !== false;

/**
 * Models to offer in a picker: every enabled model plus the currently-selected
 * one, so a pipe already bound to a now-disabled model keeps showing its
 * selection instead of silently blanking it.
 */
export const selectableModels = <M extends SelectableModel>(
  models: M[],
  currentValue: string
): M[] => models.filter(model => isModelEnabled(model) || model.value === currentValue);

/** Value of the first enabled model, for defaulting when the provider changes. */
export const firstEnabledModelValue = (models: SelectableModel[]): string =>
  models.find(isModelEnabled)?.value ?? '';
