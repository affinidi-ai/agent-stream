import React from 'react';
import CredentialSecretField from './CredentialSecretField';
import type { SecretOptions } from '../../hooks/useSecretOptions';
import type { PinnedDestination } from '../../utils/integrationCredentials';

interface UrlCredentialFieldProps {
  label: string;
  secretId: string;
  onChange: (secretId: string) => void;
  secretOptions: SecretOptions;
  helpText: string;
  testId: string;
  pinned?: PinnedDestination;
  savedWithoutReference?: boolean;
  disabled?: boolean;
}

export const LEGACY_URL_HINT =
  'This integration may still use a URL typed in earlier. Store it under Secrets and choose it here to save.';

const UrlCredentialField: React.FC<UrlCredentialFieldProps> = ({
  label,
  secretId,
  onChange,
  secretOptions,
  helpText,
  testId,
  pinned,
  savedWithoutReference = false,
  disabled = false,
}) => (
  <div>
    <CredentialSecretField
      label={label}
      secretOptions={secretOptions}
      selectedSecretId={secretId}
      onChange={onChange}
      required
      helpText={helpText}
      disabled={disabled}
      testId={testId}
    />
    {savedWithoutReference && !pinned && secretId === '' && (
      <small className="form-text text-warning d-block mb-3" data-testid={`${testId}-legacy-hint`}>
        <i className="fas fa-exclamation-triangle me-1" aria-hidden="true" />
        {LEGACY_URL_HINT}
      </small>
    )}
    {pinned && (
      <small
        className="form-text text-muted d-block mb-3"
        data-testid={`${testId}-pinned-destination`}
      >
        <i className="fas fa-lock me-1" aria-hidden="true" />
        Sends to <code>{pinned.host}</code>
        {secretId !== pinned.secretId &&
          '. The destination of the newly picked secret is checked when you save.'}
      </small>
    )}
  </div>
);

export default UrlCredentialField;
