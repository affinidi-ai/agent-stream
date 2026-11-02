import { useEffect, useState } from 'react';
import { apiClient } from '../api';
import { useOptionalPermissions } from '../context/PermissionsContext';
import type { Secret } from '../components/shared/SecretSelector';

interface StoredSecret {
  id: string;
  secret_id?: string;
  name: string;
  tags?: string[];
}

export interface SecretOptions {
  secrets: Secret[];
  loadFailed: boolean;
}

const toOption = (secret: StoredSecret): Secret => {
  const reference = secret.secret_id ?? secret.id;
  return { id: reference, name: `${secret.name} (${reference})`, tags: secret.tags };
};

const NO_SECRETS: SecretOptions = { secrets: [], loadFailed: false };

type SecretsAccess = 'pending' | 'allowed' | 'denied';

const useSecretsAccess = (): SecretsAccess => {
  const permissions = useOptionalPermissions();
  if (permissions === undefined) return 'allowed';
  if (permissions.loading) return 'pending';
  return permissions.hasPermission('secrets.view') ? 'allowed' : 'denied';
};

export const useSecretOptions = (): SecretOptions => {
  const access = useSecretsAccess();
  const [options, setOptions] = useState<SecretOptions>(NO_SECRETS);

  useEffect(() => {
    if (access !== 'allowed') return;
    let active = true;
    const load = () =>
      apiClient
        .get<StoredSecret[]>('/secrets/')
        .then(res => {
          if (active) {
            setOptions({
              secrets: Array.isArray(res.data) ? res.data.map(toOption) : [],
              loadFailed: false,
            });
          }
        })
        .catch(() => {
          if (active) setOptions({ secrets: [], loadFailed: true });
        });
    load();
    window.addEventListener('focus', load);
    return () => {
      active = false;
      window.removeEventListener('focus', load);
    };
  }, [access]);

  return access === 'allowed' ? options : NO_SECRETS;
};
