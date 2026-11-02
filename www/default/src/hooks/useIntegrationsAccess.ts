import { usePermissions } from '../context/PermissionsContext';

export type IntegrationsAccess = 'pending' | 'allowed' | 'denied';

export const useIntegrationsAccess = (): IntegrationsAccess => {
  const { hasPermission, loading } = usePermissions();
  if (loading) return 'pending';
  return hasPermission('integrations.view') ? 'allowed' : 'denied';
};
