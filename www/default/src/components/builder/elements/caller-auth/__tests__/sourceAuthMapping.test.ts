import { callerAuthIncompleteReason } from '../sourceAuthMapping';

const jwt = (extra: Record<string, unknown>) => ({
  method_type: 'jwt_bearer',
  jwt_strategy_id: 'strategy',
  ...extra,
});

describe('callerAuthIncompleteReason', () => {
  it('requires an audience for JWT bearer', () => {
    expect(callerAuthIncompleteReason(jwt({}))).toBe('At least one accepted audience is required');
    expect(callerAuthIncompleteReason(jwt({ audiences: [] }))).toBe(
      'At least one accepted audience is required'
    );
  });

  it('accepts JWT bearer with an audience or the missing-audience opt-in', () => {
    expect(callerAuthIncompleteReason(jwt({ audiences: ['api://chat'] }))).toBeNull();
    expect(
      callerAuthIncompleteReason(jwt({ audiences: [], jwt_allow_missing_audience: true }))
    ).toBeNull();
  });

  it('asks for the strategy before the audience', () => {
    expect(callerAuthIncompleteReason({ method_type: 'jwt_bearer' })).toBe(
      'JWT strategy must be selected'
    );
  });

  it('does not ask other methods for an audience', () => {
    expect(
      callerAuthIncompleteReason({ method_type: 'api_key', api_key_secret_id: 'keys' })
    ).toBeNull();
    expect(callerAuthIncompleteReason({ method_type: 'api_key_provider' })).toBeNull();
    expect(callerAuthIncompleteReason({ method_type: 'mtls' })).toBe(
      'mTLS certificate must be selected'
    );
    expect(callerAuthIncompleteReason(undefined)).toBe('Authentication method must be selected');
  });
});
