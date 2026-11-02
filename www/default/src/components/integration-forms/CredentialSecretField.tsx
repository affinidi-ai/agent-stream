import React from 'react';
import SecretSelector from '../shared/SecretSelector';
import type { SecretOptions } from '../../hooks/useSecretOptions';
import { useOptionalPermissions } from '../../context/PermissionsContext';

interface CredentialSecretFieldProps {
  label: string;
  secretOptions: SecretOptions;
  selectedSecretId: string;
  onChange: (secretId: string) => void;
  testId: string;
  required?: boolean;
  helpText?: string;
  emptyLabel?: string;
  disabled?: boolean;
}

const CredentialSecretField: React.FC<CredentialSecretFieldProps> = ({
  label,
  secretOptions,
  selectedSecretId,
  onChange,
  testId,
  required = false,
  helpText = '',
  emptyLabel,
  disabled = false,
}) => {
  const permissions = useOptionalPermissions();
  const canCreateSecret =
    permissions === undefined ||
    (!permissions.loading && permissions.hasPermission('secrets.edit'));

  return (
    <div>
      <SecretSelector
        secrets={secretOptions.secrets}
        selectedSecretId={selectedSecretId}
        onChange={onChange}
        label={label}
        required={required}
        helpText={helpText}
        emptyLabel={emptyLabel}
        testId={testId}
        autoSelectSole={false}
        locked={disabled}
      />
      <div className="small mb-3">
        {secretOptions.loadFailed && (
          <span className="text-warning me-2" data-testid={`${testId}-secrets-unavailable`}>
            <i className="fas fa-exclamation-triangle me-1" aria-hidden="true" />
            Secrets could not be loaded.
          </span>
        )}
        {canCreateSecret && (
          <a
            href="/secrets/new"
            target="_blank"
            rel="noopener noreferrer"
            data-testid={`${testId}-create-secret-link`}
          >
            <i className="fas fa-plus me-1" aria-hidden="true" />
            Create secret
          </a>
        )}
      </div>
    </div>
  );
};

export default CredentialSecretField;
