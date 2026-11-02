import { firstEnabledModelValue, isModelEnabled, selectableModels } from './modelVisibility';

describe('modelVisibility', () => {
  describe('isModelEnabled', () => {
    it('treats a missing flag as enabled', () => {
      expect(isModelEnabled({ value: 'gpt-4o' })).toBe(true);
    });

    it('treats enabled: true as enabled', () => {
      expect(isModelEnabled({ value: 'gpt-4o', enabled: true })).toBe(true);
    });

    it('treats enabled: false as disabled', () => {
      expect(isModelEnabled({ value: 'gpt-4o', enabled: false })).toBe(false);
    });
  });

  describe('selectableModels', () => {
    const models = [{ value: 'a' }, { value: 'b', enabled: false }, { value: 'c', enabled: true }];

    it('hides disabled models', () => {
      expect(selectableModels(models, '').map(m => m.value)).toEqual(['a', 'c']);
    });

    it('keeps the current selection visible even when it is disabled', () => {
      expect(selectableModels(models, 'b').map(m => m.value)).toEqual(['a', 'b', 'c']);
    });

    it('does not duplicate the current selection when it is enabled', () => {
      expect(selectableModels(models, 'c').map(m => m.value)).toEqual(['a', 'c']);
    });
  });

  describe('firstEnabledModelValue', () => {
    it('returns the first enabled model value, skipping disabled ones', () => {
      expect(firstEnabledModelValue([{ value: 'a', enabled: false }, { value: 'b' }])).toBe('b');
    });

    it('returns an empty string when every model is disabled', () => {
      expect(firstEnabledModelValue([{ value: 'a', enabled: false }])).toBe('');
    });

    it('returns an empty string for an empty list', () => {
      expect(firstEnabledModelValue([])).toBe('');
    });
  });
});
