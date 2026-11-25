import {
  DELETE_KEPT_USER_SUCCESS,
  DELETE_USER_SUCCESS,
  type SignInMethod,
  deleteButtonTitle,
  deleteConfirmNotice,
  deleteSuccessMessage,
  rejectSuccessMessage,
  isDeletedKeptUser,
  keptAccountDetail,
  keptAccountLabel,
} from './userDelete';

const passkey = { sign_in_method: 'passkey' as SignInMethod };
const oidc = { sign_in_method: 'oidc' as SignInMethod };
const saml = { sign_in_method: 'saml' as SignInMethod };

const FEDERATED_WORDING = /OpenID|OIDC|SAML/;

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

describe('deleteButtonTitle', () => {
  it('says a passkey user is removed, with no OpenID Connect or SAML wording', () => {
    const title = deleteButtonTitle(passkey);
    expect(title).toContain('Their record is removed');
    expect(title).not.toMatch(FEDERATED_WORDING);
    expect(deleteButtonTitle({})).toBe(title);
  });

  it.each([
    [oidc, 'OpenID Connect'],
    [saml, 'SAML'],
  ])('says a federated user is kept disabled and what approving again does', (user, name) => {
    const title = deleteButtonTitle(user);
    expect(title).toContain(`They sign in with ${name}`);
    expect(title).toContain('kept disabled instead of removed');
    expect(title).toContain('Approving them again lets that account sign in as the same user');
  });

  it('says the access tokens the user holds are revoked, for every user', () => {
    for (const user of [passkey, oidc, saml]) {
      expect(deleteButtonTitle(user)).toContain('Access tokens bound to the user');
      expect(deleteButtonTitle(user)).toContain('created or rotated for others');
    }
  });
});

describe('deleteConfirmNotice', () => {
  it('explains the kept record and the role mapping for an OpenID Connect user', () => {
    const notice = deleteConfirmNotice(oidc);
    expect(notice).toContain('signs in with OpenID Connect');
    expect(notice).toContain('kept disabled');
    expect(notice).toContain('role from the claim mapping');
  });

  it('explains the kept record and the role mapping for a SAML user', () => {
    const notice = deleteConfirmNotice(saml);
    expect(notice).toContain('signs in with SAML');
    expect(notice).toContain('kept disabled');
    expect(notice).toContain('role from the attribute mapping');
    expect(notice).not.toContain('OpenID');
  });

  it('says nothing for a passkey user or a user without a sign-in method', () => {
    expect(deleteConfirmNotice(passkey)).toBeUndefined();
    expect(deleteConfirmNotice({})).toBeUndefined();
    expect(deleteConfirmNotice(passkey, true)).toBeUndefined();
  });

  it('has a shorter form for the Users table that still says approving brings them back', () => {
    const short = deleteConfirmNotice(saml, true);
    expect(short).toBe(
      'SAML user: the record is kept disabled until an administrator approves it again.'
    );
    expect(short!.length).toBeLessThan(deleteConfirmNotice(saml)!.length);
    expect(deleteConfirmNotice(oidc, true)).toMatch(/^OpenID Connect user:/);
  });
});

describe('deleteSuccessMessage', () => {
  it.each([
    [oidc, 'OpenID Connect'],
    [saml, 'SAML'],
  ])('says the federated record was kept when the outcome is kept', (user, name) => {
    expect(deleteSuccessMessage('kept', user)).toBe(
      `User disabled. Their ${name} account stays on a disabled record and is refused at sign-in until an administrator approves them again.`
    );
  });

  it('does not name a provider for a kept user without a federated sign-in method', () => {
    const message = deleteSuccessMessage('kept', passkey);
    expect(message).toBe(DELETE_KEPT_USER_SUCCESS);
    expect(message).not.toMatch(FEDERATED_WORDING);
  });

  it('says deleted when the record was removed or no outcome came back', () => {
    expect(deleteSuccessMessage('removed', passkey)).toBe(DELETE_USER_SUCCESS);
    expect(deleteSuccessMessage('removed', oidc)).toBe(DELETE_USER_SUCCESS);
    expect(deleteSuccessMessage(undefined, {})).toBe(DELETE_USER_SUCCESS);
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
  it('is true for a record the API marks deleted', () => {
    expect(isDeletedKeptUser({ deleted_at: '2026-11-25T10:00:00Z' })).toBe(true);
  });

  it('is false for a user who was never deleted or was approved again', () => {
    expect(isDeletedKeptUser({})).toBe(false);
    expect(isDeletedKeptUser({ deleted_at: undefined })).toBe(false);
  });
});

describe('rejectSuccessMessage', () => {
  it('says the record was kept when the outcome is kept', () => {
    expect(rejectSuccessMessage('kept', 'bob')).toContain(
      "User 'bob' rejected. Their record is kept"
    );
  });

  it('says rejected and deleted otherwise', () => {
    expect(rejectSuccessMessage('removed', 'bob')).toBe("User 'bob' rejected and deleted");
    expect(rejectSuccessMessage(undefined, 'bob')).toBe("User 'bob' rejected and deleted");
  });
});
