export type DeleteOutcome = 'removed' | 'kept';

export type SignInMethod = 'passkey' | 'oidc' | 'saml';

type KeptSignInMethod = Exclude<SignInMethod, 'passkey'>;

interface DeletableUser {
  sign_in_method?: SignInMethod;
}

const PROVIDER_NAME: Record<KeptSignInMethod, string> = {
  oidc: 'OpenID Connect',
  saml: 'SAML',
};

const ROLE_SOURCE: Record<KeptSignInMethod, string> = {
  oidc: 'claim',
  saml: 'attribute',
};

const keptSignInMethod = (user: DeletableUser): KeptSignInMethod | undefined =>
  user.sign_in_method === 'oidc' || user.sign_in_method === 'saml'
    ? user.sign_in_method
    : undefined;

const TOKENS_REVOKED =
  'Access tokens bound to the user, and tokens the user created or rotated for others, are revoked.';

export const DELETE_USER_SUCCESS = 'User deleted successfully';

export const DELETE_KEPT_USER_SUCCESS =
  'User disabled. Their record is kept and is refused at sign-in until an administrator approves them again.';

export const deleteButtonTitle = (user: DeletableUser): string => {
  const method = keptSignInMethod(user);
  if (!method) {
    return `Delete user. Their record is removed. ${TOKENS_REVOKED}`;
  }
  return `Delete user. They sign in with ${PROVIDER_NAME[method]}, so their record is kept disabled instead of removed and their next sign-in is refused. Approving them again lets that account sign in as the same user. ${TOKENS_REVOKED}`;
};

export const deleteConfirmNotice = (user: DeletableUser, compact = false): string | undefined => {
  const method = keptSignInMethod(user);
  if (!method) {
    return undefined;
  }
  if (compact) {
    return `${PROVIDER_NAME[method]} user: the record is kept disabled. Approving it again lets that account sign in as the same user.`;
  }
  return `This user signs in with ${PROVIDER_NAME[method]}. Their record is not removed: it is kept disabled under their provider account, so their next sign-in is refused. Approving them again lets that account sign in as the same user, with the role from the ${ROLE_SOURCE[method]} mapping.`;
};

export const deleteSuccessMessage = (
  outcome: DeleteOutcome | undefined,
  user: DeletableUser
): string => {
  if (outcome !== 'kept') {
    return DELETE_USER_SUCCESS;
  }
  const method = keptSignInMethod(user);
  if (!method) {
    return DELETE_KEPT_USER_SUCCESS;
  }
  return `User disabled. Their ${PROVIDER_NAME[method]} account stays on a disabled record and is refused at sign-in until an administrator approves them again.`;
};

export const DELETED_BADGE = 'DELETED';

export const KEPT_ACCOUNT_HEADING = 'Deleted:';

export const PROVIDER_ACCOUNT_HEADING = 'Provider account:';

export const DELETED_USER_NOTICE =
  'This user was deleted. Their account stays refused at sign-in until an administrator approves them again, which lets that account sign in as the same user.';

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

export const isDeletedKeptUser = (user: { deleted_at?: string }): boolean =>
  Boolean(user.deleted_at);

export const rejectSuccessMessage = (outcome: DeleteOutcome | undefined, name: string): string =>
  outcome === 'kept'
    ? `User '${name}' rejected. Their record is kept and is refused at sign-in until an administrator approves them again.`
    : `User '${name}' rejected and deleted`;
