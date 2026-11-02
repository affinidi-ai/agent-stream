import {
  accessTokenFormError,
  cleanRequiredHeaders,
  evaluateScopePreview,
  inferTenantSelection,
  tenantInferenceText,
  validateScopeConfig,
} from './accessTokenScopeHelpers';

const placeholder = (name: string) => `\${${name}}`;

describe('access token canonical scope helpers', () => {
  it('validates a multi-kind canonical pattern', () => {
    const pattern = `TENANT:${placeholder('x-tenant-id')}:(?:pipes:resource-.*|secrets:resource-.*)`;
    expect(validateScopeConfig(pattern, [{ name: 'x-tenant-id', pattern: 'tenant-a' }])).toEqual(
      []
    );
  });

  it('previews the canonical target rather than the raw entity id', () => {
    const result = evaluateScopePreview(
      `TENANT:${placeholder('account')}:gateways:gateway-.*`,
      [{ name: 'account', pattern: 'tenant-a' }],
      { account: 'tenant-a' },
      'gateways',
      'gateway-1'
    );

    expect(result.allowed).toBe(true);
    expect(result.target).toBe('TENANT:tenant-a:gateways:gateway-1');
  });

  it('infers and validates the raw canonical tenant scope', () => {
    const pattern = `TENANT:${placeholder('account')}:gateways:gateway-.*`;
    expect(inferTenantSelection(pattern)).toEqual({ mode: 'tenant', headerName: 'account' });
    expect(tenantInferenceText(inferTenantSelection(pattern))).toBe('Tenant selected by account');
    expect(validateScopeConfig(pattern, [{ name: 'account', pattern: 'tenant-a' }])).toEqual([]);
    expect(validateScopeConfig('gateways:.*', [])).toContain(
      `A non-empty resource pattern must use TENANT:${placeholder('header')}:<resource-kind>:<resource-id-pattern>.`
    );
  });

  it('rejects repeated occurrences of the same tenant placeholder', () => {
    const pattern = `TENANT:${placeholder('account')}:gateways:${placeholder('account')}-.*`;

    expect(inferTenantSelection(pattern)).toEqual({ mode: 'invalid', headerNames: ['account'] });
    expect(validateScopeConfig(pattern, [{ name: 'account', pattern: 'tenant-a' }])).toContain(
      'Resource pattern may contain only one tenant-header placeholder.'
    );
  });

  it('combines identity, scope, and expiry validation errors', () => {
    expect(accessTokenFormError('', '', [], undefined)).toBe('Name is required');
    expect(accessTokenFormError('service', '', [], undefined)).toBeNull();
    expect(accessTokenFormError('service', '', [], 'Expiration must be in the future.')).toBe(
      'Expiration must be in the future.'
    );
    expect(accessTokenFormError('service', '', [], undefined, ['departments.view'])).toBe(
      'Remove the red unavailable scopes before saving.'
    );
    expect(accessTokenFormError('service', 'pipes:.*', [], undefined)).toContain(
      'A non-empty resource pattern must use'
    );
    expect(cleanRequiredHeaders([{ name: ' x-tenant ', pattern: 'tenant-a' }])).toEqual([
      { name: 'x-tenant', pattern: 'tenant-a' },
    ]);
  });
});
