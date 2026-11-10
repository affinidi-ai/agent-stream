import { DELETE_USER_TITLE, keptAccountLabel } from './userDelete';

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
});
