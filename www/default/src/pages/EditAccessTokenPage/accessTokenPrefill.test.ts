import { toLocalDateTimeInput } from './accessTokenExpiry';
import { accessTokenPermalinkQuery, accessTokenPrefill } from './accessTokenPrefill';

describe('access token prefill', () => {
  const now = new Date('2026-01-01T00:00:00.000Z');
  const pattern = ['TENANT:', '$', '{x-account}:pipes:.*'].join('');

  it('returns empty values without query parameters', () => {
    expect(accessTokenPrefill(new URLSearchParams(), now)).toEqual({
      name: '',
      description: '',
      scopes: [],
      resourcePattern: '',
      requiredHeaders: [],
      expiry: undefined,
    });
  });

  it('reads every field from the query string', () => {
    const params = new URLSearchParams();
    params.set('name', 'metrics-dashboard');
    params.set('description', 'Read metrics');
    params.append('scopes', 'pipes.view, metrics.view');
    params.append('scope', 'secrets.view');
    params.append('scope', 'metrics.view');
    params.set('resource_pattern', pattern);
    params.append('header', 'x-account:tenant-a|tenant-b');
    params.set('expires_in_days', '30');

    expect(accessTokenPrefill(params, now)).toEqual({
      name: 'metrics-dashboard',
      description: 'Read metrics',
      scopes: ['metrics.view', 'pipes.view', 'secrets.view'],
      resourcePattern: pattern,
      requiredHeaders: [{ name: 'x-account', pattern: 'tenant-a|tenant-b' }],
      expiry: {
        neverExpires: false,
        expiresAt: toLocalDateTimeInput(new Date(now.getTime() + 30 * 86_400_000)),
      },
    });
  });

  it('keeps every preset scope and drops headers without a name', () => {
    const params = new URLSearchParams(
      'scopes=departments.view,metrics.view&header=nopattern&header=:x&header=x-account:'
    );
    const prefill = accessTokenPrefill(params, now);
    expect(prefill.scopes).toEqual(['departments.view', 'metrics.view']);
    expect(prefill.requiredHeaders).toEqual([{ name: 'x-account', pattern: '' }]);
  });

  it('prefers an exact expires_at and ignores invalid expiry values', () => {
    const at = '2026-02-01T12:00:00.000Z';
    expect(
      accessTokenPrefill(new URLSearchParams({ expires_at: at, expires_in_days: '5' }), now).expiry
    ).toEqual({ neverExpires: false, expiresAt: toLocalDateTimeInput(new Date(at)) });
    expect(
      accessTokenPrefill(new URLSearchParams({ expires_at: 'soon' }), now).expiry
    ).toBeUndefined();
    expect(
      accessTokenPrefill(new URLSearchParams({ expires_in_days: '-1' }), now).expiry
    ).toBeUndefined();
  });

  it('builds a permalink that round-trips the form', () => {
    const values = {
      name: ' metrics ',
      description: '',
      scopes: ['metrics.view', 'pipes.view'],
      resourcePattern: pattern,
      requiredHeaders: [
        { name: 'x-account', pattern: 'tenant-a' },
        { name: ' ', pattern: 'ignored' },
      ],
      expiry: {
        neverExpires: false,
        expiresAt: toLocalDateTimeInput(new Date(now.getTime() + 3_600_000)),
      },
    };
    const query = accessTokenPermalinkQuery(values);
    expect(query).not.toContain('description');
    expect(accessTokenPrefill(new URLSearchParams(query), now)).toEqual({
      ...values,
      name: 'metrics',
      requiredHeaders: [{ name: 'x-account', pattern: 'tenant-a' }],
    });
  });

  it('omits expiry from the permalink when the token never expires', () => {
    const query = accessTokenPermalinkQuery({
      name: 'n',
      description: '',
      scopes: [],
      resourcePattern: '',
      requiredHeaders: [],
      expiry: { neverExpires: true, expiresAt: toLocalDateTimeInput(now) },
    });
    expect(query).toBe('name=n');
  });
});
