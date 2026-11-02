import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { apiClient } from '../api';

export type Permissions = Record<string, boolean>;

interface PermissionsContextType {
  permissions: Permissions | null;
  loading: boolean;
  error: string | null;
  refetchPermissions: () => Promise<void>;
  hasPermission: (feature: string) => boolean;
}

const PermissionsContext = createContext<PermissionsContextType | undefined>(undefined);
PermissionsContext.displayName = 'PermissionsContext';

// Default permissions (all restricted until loaded)
const defaultPermissions: Permissions = {
  'users.view': false,
  'users.edit': false,
  'users.approve': false,
  'users.delete': false,
  'members.view': false,
  'members.edit': false,
  'members.delete': false,
  'enrolment.view': false,
  'enrolment.edit': false,
  'prompts.view': false,
  'prompts.edit': false,
  'prompts.delete': false,
  'teams.view': false,
  'teams.edit': false,
  'teams.delete': false,
  'gateways.view': false,
  'gateways.edit': false,
  'gateways.delete': false,
  'mediators.view': false,
  'mediators.edit': false,
  'mediators.delete': false,
  'integrations.view': false,
  'integrations.edit': false,
  'integrations.delete': false,
  'secrets.view': false,
  'secrets.edit': false,
  'secrets.delete': false,
  'api_keys.view': false,
  'api_keys.edit': false,
  'api_keys.delete': false,
  'certificates.view': false,
  'certificates.edit': false,
  'access_tokens.view': false,
  'access_tokens.edit': false,
  'access_tokens.delete': false,
  'tenant_ownership.manage': false,
  'vault_identities.edit': false,
  'credential_providers.view': false,
  'credential_providers.edit': false,
  'credential_providers.delete': false,
  'delegation_vault.view': false,
  'delegation_vault.delete': false,
  'storage.admin': false,
  'identity.issue': false,
  'identities.manage': false,
  'config.reload': false,
  'policies.view': false,
  'policies.edit': false,
  'policies.delete': false,
  'policies.publish': false,
  'notifications.view': false,
  'notifications.edit': false,
  'notifications.delete': false,
  'jwt_verification_strategies.view': false,
  'jwt_verification_strategies.edit': false,
  'jwt_verification_strategies.delete': false,
  'oauth_identifiers.view': false,
  'oauth_identifiers.edit': false,
  'oauth_identifiers.delete': false,
  'pipes.view': false,
  'pipes.edit': false,
  'pipes.delete': false,
  'pipes.execute': false,
  'llm_catalog.edit': false,
  'settings.view': false,
  'settings.edit': false,
  'terms.view': false,
  'terms.edit': false,
  'metrics.view': false,
  'metrics.view_attributed': false,
  'dashboard.view': false,
  'logs.view': false,
  'audit.view': false,
  'governance.view': false,
  'drift.view': false,
  'drift.manage': false,
};

export function PermissionsProvider({ children }: { children: ReactNode }) {
  const [permissions, setPermissions] = useState<Permissions | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchPermissions = async () => {
    try {
      setLoading(true);
      setError(null);
      const perms = await apiClient.getPermissions();
      setPermissions(perms);
    } catch (err) {
      console.error('Failed to fetch permissions:', err);
      setError('Failed to load permissions');
      // Set default restricted permissions on error
      setPermissions(defaultPermissions);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPermissions();
  }, []);

  const hasPermission = (feature: string): boolean => {
    if (!permissions) {
      console.debug(`[PERMISSIONS] hasPermission('${feature}'): false (permissions not loaded)`);
      return false;
    }
    const result = permissions[feature] === true;
    if (!result) {
      console.debug(
        `[PERMISSIONS] hasPermission('${feature}'): false (value: ${permissions[feature]})`
      );
    }
    return result;
  };

  const value: PermissionsContextType = {
    permissions,
    loading,
    error,
    refetchPermissions: fetchPermissions,
    hasPermission,
  };

  return <PermissionsContext.Provider value={value}>{children}</PermissionsContext.Provider>;
}

export function usePermissions(): PermissionsContextType {
  const context = useContext(PermissionsContext);
  if (context === undefined) {
    throw new Error('usePermissions must be used within a PermissionsProvider');
  }
  return context;
}

/** Like {@link usePermissions}, but `undefined` outside a PermissionsProvider,
 *  for shared components that also render where no permissions are loaded. */
export function useOptionalPermissions(): PermissionsContextType | undefined {
  return useContext(PermissionsContext);
}
