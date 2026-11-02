import { extractErrorMessage, formatApiError } from './apiError';

describe('extractErrorMessage', () => {
  it('pulls the message from common JSON shapes', () => {
    expect(extractErrorMessage('{"message":"Limit reached"}')).toBe('Limit reached');
    expect(extractErrorMessage('{"error":"Bad request"}')).toBe('Bad request');
    expect(extractErrorMessage('{"error":{"message":"Nested"}}')).toBe('Nested');
    expect(extractErrorMessage('{"detail":"Not found"}')).toBe('Not found');
  });

  it('prefers the specific details over a generic error label', () => {
    expect(
      extractErrorMessage(
        '{"error":"Bad Request","details":"Pipe id may only contain letters, digits, \'-\' and \'_\'"}'
      )
    ).toBe("Pipe id may only contain letters, digits, '-' and '_'");
    expect(extractErrorMessage('{"error":"Bad Request","details":"  "}')).toBe('Bad Request');
  });

  it('falls back to the raw text when the body is not JSON', () => {
    expect(extractErrorMessage('plain text error')).toBe('plain text error');
  });

  it('returns null for empty/whitespace bodies', () => {
    expect(extractErrorMessage('')).toBeNull();
    expect(extractErrorMessage('   ')).toBeNull();
    expect(extractErrorMessage(null)).toBeNull();
    expect(extractErrorMessage(undefined)).toBeNull();
  });

  it('returns the raw JSON when no known message field is present', () => {
    expect(extractErrorMessage('{"code":42}')).toBe('{"code":42}');
  });
});

describe('formatApiError', () => {
  it('shows the message with the status in parentheses', () => {
    expect(
      formatApiError(
        403,
        '{"message":"Appliance limit reached for \'surfaces\': 10 of 10 in use."}',
        'Forbidden'
      )
    ).toBe("Appliance limit reached for 'surfaces': 10 of 10 in use. (403)");
  });

  it('falls back to the status text when there is no body', () => {
    expect(formatApiError(500, '', 'Internal Server Error')).toBe('Internal Server Error (500)');
  });

  it('falls back to a generic label when nothing is available', () => {
    expect(formatApiError(502, '', '')).toBe('Request failed (502)');
  });

  it('omits the parenthetical when no status is provided', () => {
    expect(formatApiError(undefined, '{"error":"boom"}')).toBe('boom');
  });
});
