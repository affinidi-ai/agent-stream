export const DELETE_USER_TITLE =
  'Delete user. A user who signs in through OpenID Connect or SAML is disabled and kept instead, so they cannot sign in until an administrator approves them again. Access tokens bound to the user, and tokens the user created or rotated for others, are revoked.';

export const DELETE_USER_SUCCESS = 'User deleted successfully';

export const KEPT_ACCOUNT_HEADING = 'Deleted:';

export const PROVIDER_ACCOUNT_HEADING = 'Provider account:';

export const DELETED_USER_NOTICE =
  'This user was deleted. Their account stays refused at sign-in until an administrator approves them again.';

export interface KeptAccount {
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

export const keptAccountDetail = (label: string): string => `kept disabled for the ${label}`;

export const isDeletedKeptUser = (user: KeptAccount & { status: string }): boolean =>
  user.status === 'disabled' && keptAccountLabel(user) !== null;
