export const DELETE_USER_TITLE =
  'Delete user. A user who signs in through OpenID Connect or SAML is disabled and kept instead, so they cannot sign in until an administrator approves them again.';

interface KeptAccount {
  oidc?: { issuer: string; subject: string };
  saml_id?: string;
}

export const keptAccountLabel = (user: KeptAccount): string | null => {
  if (user.oidc) {
    return `OpenID Connect account ${user.oidc.subject} at ${user.oidc.issuer}`;
  }
  if (user.saml_id) {
    return `SAML account ${user.saml_id}`;
  }
  return null;
};
