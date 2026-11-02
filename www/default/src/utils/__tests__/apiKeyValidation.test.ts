import { apiKeyValidation, apiKeyMandatory, apiKeyDisabled } from '../apiKeyValidation';

describe('apiKeyValidation', () => {
  it('returns the explicit three-state field when present', () => {
    expect(apiKeyValidation({ api_key_validation: 'mandatory' })).toBe('mandatory');
    expect(apiKeyValidation({ api_key_validation: 'optional' })).toBe('optional');
    expect(apiKeyValidation({ api_key_validation: 'none' })).toBe('none');
  });

  it('ignores an unrecognised value and falls back to the legacy flag', () => {
    expect(apiKeyValidation({ api_key_validation: 'garbage', api_key_required: false })).toBe(
      'none'
    );
    expect(apiKeyValidation({ api_key_validation: '', api_key_required: true })).toBe('mandatory');
  });

  it('falls back to api_key_required when api_key_validation is absent', () => {
    expect(apiKeyValidation({ api_key_required: false })).toBe('none');
    expect(apiKeyValidation({ api_key_required: true })).toBe('mandatory');
  });

  it('defaults to mandatory for a provider with neither field', () => {
    expect(apiKeyValidation({})).toBe('mandatory');
  });

  it('defaults to mandatory for a missing provider', () => {
    expect(apiKeyValidation(null)).toBe('mandatory');
    expect(apiKeyValidation(undefined)).toBe('mandatory');
  });

  it('derives the mandatory/disabled convenience helpers', () => {
    expect(apiKeyMandatory({ api_key_validation: 'mandatory' })).toBe(true);
    expect(apiKeyMandatory({ api_key_validation: 'optional' })).toBe(false);
    expect(apiKeyMandatory({ api_key_validation: 'none' })).toBe(false);

    expect(apiKeyDisabled({ api_key_validation: 'none' })).toBe(true);
    expect(apiKeyDisabled({ api_key_validation: 'optional' })).toBe(false);
    expect(apiKeyDisabled({ api_key_validation: 'mandatory' })).toBe(false);
  });
});
