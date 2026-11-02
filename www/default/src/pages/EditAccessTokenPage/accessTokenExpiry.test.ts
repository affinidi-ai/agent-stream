import {
  accessTokenExpiryBounds,
  newAccessTokenExpiry,
  toLocalDateTimeInput,
  validateAccessTokenExpiry,
} from './accessTokenExpiry';

describe('access token expiry', () => {
  const now = new Date('2026-01-01T00:00:00.000Z');

  it('defaults to a non-expiring token with a future local value ready', () => {
    const form = newAccessTokenExpiry(now);
    expect(form.neverExpires).toBe(true);
    expect(form.expiresAt).toBe(toLocalDateTimeInput(new Date(now.getTime() + 86_400_000)));
  });

  it('converts a selected local date-time to an exact UTC timestamp', () => {
    const expiry = new Date(now.getTime() + 3_600_000);
    expect(validateAccessTokenExpiry(false, toLocalDateTimeInput(expiry), now)).toEqual({
      expiresAt: expiry.toISOString(),
    });
  });

  it('accepts never and rejects missing, past, or over-limit values', () => {
    expect(validateAccessTokenExpiry(true, '', now)).toEqual({});
    expect(validateAccessTokenExpiry(false, '', now).error).toBe(
      'Choose an expiration date and time.'
    );
    expect(
      validateAccessTokenExpiry(false, toLocalDateTimeInput(new Date(now.getTime() - 60_000)), now)
        .error
    ).toBe('Expiration must be in the future.');
    expect(
      validateAccessTokenExpiry(
        false,
        toLocalDateTimeInput(new Date(now.getTime() + 3651 * 86_400_000)),
        now
      ).error
    ).toBe('Expiration must be within 3650 days.');
  });

  it('uses the same reference for the date-time input bounds', () => {
    expect(accessTokenExpiryBounds(now)).toEqual({
      min: toLocalDateTimeInput(now),
      max: toLocalDateTimeInput(new Date(now.getTime() + 3650 * 86_400_000)),
    });
  });
});
