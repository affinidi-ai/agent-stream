import {
  authorityFor,
  sandboxAuthFromProfile,
  sandboxAuthUsable,
  tenantFromIssuer,
  type SandboxAuthConfig,
} from '../sandboxAuth';

describe('sandboxAuth config resolution', () => {
  it('derives the Entra authority from tenant id', () => {
    const cfg: SandboxAuthConfig = {
      type: 'oauth2_pkce',
      provider: 'entra',
      tenant_id: 'tenant-123',
    };
    expect(authorityFor(cfg)).toBe('https://login.microsoftonline.com/tenant-123');
  });

  it('prefers an explicit authority override and trims a trailing slash', () => {
    const cfg: SandboxAuthConfig = {
      type: 'oauth2_pkce',
      provider: 'entra',
      tenant_id: 'ignored',
      authority: 'https://login.example.com/x/',
    };
    expect(authorityFor(cfg)).toBe('https://login.example.com/x');
  });

  it('returns null when neither authority nor tenant is present', () => {
    expect(authorityFor({ type: 'oauth2_pkce', provider: 'entra' })).toBeNull();
  });

  it('treats a config as usable only when complete', () => {
    const complete: SandboxAuthConfig = {
      type: 'oauth2_pkce',
      provider: 'entra',
      tenant_id: 't',
      client_id: 'c',
      scopes: ['https://graph.microsoft.com/Sites.Read.All'],
    };
    expect(sandboxAuthUsable(complete)).toBe(true);

    // Missing client id.
    expect(sandboxAuthUsable({ ...complete, client_id: undefined })).toBe(false);
    // No scopes.
    expect(sandboxAuthUsable({ ...complete, scopes: [] })).toBe(false);
    // Unsupported flow type.
    expect(sandboxAuthUsable({ ...complete, type: 'api_key' })).toBe(false);
    // Not derivable authority.
    expect(sandboxAuthUsable({ ...complete, tenant_id: undefined })).toBe(false);
    // Absent config.
    expect(sandboxAuthUsable(null)).toBe(false);
    expect(sandboxAuthUsable(undefined)).toBe(false);
  });
});

describe('sandboxAuthFromProfile (OAuth Identifier → PKCE config)', () => {
  it('maps an Entra profile keeping the tenant id', () => {
    const cfg = sandboxAuthFromProfile({
      id: 'p1',
      name: 'Copilot',
      provider: 'entra',
      tenant_id: 'tenant-abc',
      client_id: 'client-abc',
      scopes: ['https://graph.microsoft.com/Sites.Read.All'],
    });
    expect(cfg).toEqual({
      type: 'oauth2_pkce',
      provider: 'entra',
      client_id: 'client-abc',
      scopes: ['https://graph.microsoft.com/Sites.Read.All'],
      tenant_id: 'tenant-abc',
    });
    expect(authorityFor(cfg!)).toBe('https://login.microsoftonline.com/tenant-abc');
  });

  it('maps an Okta profile to a concrete authority (default server when blank)', () => {
    const cfg = sandboxAuthFromProfile({
      id: 'p2',
      name: 'Okta',
      provider: 'okta',
      domain: 'dev-123.okta.com',
      client_id: 'c',
      scopes: ['openid'],
    });
    expect(cfg?.authority).toBe('https://dev-123.okta.com/oauth2/default');
    expect(sandboxAuthUsable(cfg)).toBe(true);
  });

  it('maps a generic OIDC profile to the issuer authority', () => {
    const cfg = sandboxAuthFromProfile({
      id: 'p3',
      name: 'OIDC',
      provider: 'oidc',
      issuer: 'https://accounts.example.com/',
      client_id: 'c',
      scopes: ['openid'],
    });
    expect(cfg?.authority).toBe('https://accounts.example.com');
  });

  it('returns null for an incomplete or missing profile', () => {
    expect(sandboxAuthFromProfile(null)).toBeNull();
    expect(sandboxAuthFromProfile({ id: 'x', name: 'x', provider: 'entra' })).toBeNull();
    // Entra without a tenant is not derivable.
    expect(
      sandboxAuthFromProfile({
        id: 'x',
        name: 'x',
        provider: 'entra',
        client_id: 'c',
        scopes: ['s'],
      })
    ).toBeNull();
  });
});

describe('tenantFromIssuer', () => {
  it('extracts the tenant from a v2 Entra issuer', () => {
    expect(tenantFromIssuer('https://login.microsoftonline.com/tenant-abc/v2.0')).toBe(
      'tenant-abc'
    );
  });

  it('extracts the tenant from a legacy sts.windows.net issuer', () => {
    expect(tenantFromIssuer('https://sts.windows.net/tenant-xyz/')).toBe('tenant-xyz');
  });

  it('returns null for multi-tenant placeholders', () => {
    expect(tenantFromIssuer('https://login.microsoftonline.com/common/v2.0')).toBeNull();
    expect(tenantFromIssuer('https://login.microsoftonline.com/organizations/v2.0')).toBeNull();
    expect(tenantFromIssuer('https://login.microsoftonline.com/consumers/v2.0')).toBeNull();
  });

  it('returns null for a non-Entra or empty issuer', () => {
    expect(tenantFromIssuer('https://idp.example.com/realms/foo')).toBeNull();
    expect(tenantFromIssuer('')).toBeNull();
    expect(tenantFromIssuer(undefined)).toBeNull();
  });
});
