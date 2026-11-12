import {
  DELETE_USER_TITLE,
  isDeletedKeptUser,
  keptAccountDetail,
  keptAccountLabel,
} from './userDelete';

describe('keptAccountLabel', () => {
  it('names the OpenID Connect account by subject and issuer', () => {
    expect(
      keptAccountLabel({ oidc: { issuer: 'https://idp.example.com', subject: 'sub-1' } })
    ).toBe('OpenID Connect account sub-1 at https://idp.example.com');
  });

  it('names the SAML account', () => {
    expect(keptAccountLabel({ saml_id: 'saml-1' })).toBe('SAML account saml-1');
  });

  it('has no label for a user whose record was not kept', () => {
    expect(keptAccountLabel({})).toBeNull();
  });
});

describe('DELETE_USER_TITLE', () => {
  it('says a federated user is kept and can return only when approved again', () => {
    expect(DELETE_USER_TITLE).toContain('OpenID Connect or SAML');
    expect(DELETE_USER_TITLE).toContain('approves them again');
  });

  it('says the access tokens the user holds are revoked', () => {
    expect(DELETE_USER_TITLE).toContain('Access tokens bound to the user');
    expect(DELETE_USER_TITLE).toContain('created or rotated for others');
  });
});

describe('keptAccountDetail', () => {
  it('says the record is kept disabled for the account', () => {
    expect(keptAccountDetail('SAML account saml-1')).toBe(
      'kept disabled for the SAML account saml-1'
    );
  });
});

describe('isDeletedKeptUser', () => {
  const oidc = { issuer: 'https://idp.example.com', subject: 'sub-1' };

  it('is true for a disabled user bound to a provider account', () => {
    expect(isDeletedKeptUser({ status: 'disabled', oidc })).toBe(true);
    expect(isDeletedKeptUser({ status: 'disabled', saml_id: 'saml-1' })).toBe(true);
  });

  it('is false for a user who is approved again or has no provider account', () => {
    expect(isDeletedKeptUser({ status: 'approved', oidc })).toBe(false);
    expect(isDeletedKeptUser({ status: 'disabled' })).toBe(false);
  });
});
