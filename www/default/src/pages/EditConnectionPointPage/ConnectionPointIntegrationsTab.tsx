import React, { useEffect, useState } from 'react';
import {
  IntegrationsStep,
  integrationIntegration,
} from '../../components/connection-points/IntegrationsStep';
import { apiClient } from '../../api';
import { getRuntimeVariablesForCategories } from '../../utils/runtimeVariables';
import { useIntegrationsAccess } from '../../hooks/useIntegrationsAccess';
import IntegrationsAdminOnlyNotice from '../../components/integrations/IntegrationsAdminOnlyNotice';

interface Integration {
  id: string;
  name: string;
  type: string;
  content?: any;
}

interface ConnectionPointIntegrationsTabProps {
  integrations: integrationIntegration[];
  onIntegrationsChange: (integrations: integrationIntegration[]) => void;
  onValidationChange?: (hasErrors: boolean) => void;
}

const ConnectionPointIntegrationsTab: React.FC<ConnectionPointIntegrationsTabProps> = ({
  integrations,
  onIntegrationsChange,
  onValidationChange,
}) => {
  const integrationsAccess = useIntegrationsAccess();
  const [availableIntegrations, setAvailableIntegrations] = useState<Integration[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [runtimeVariables, setRuntimeVariables] = useState<
    Record<string, { label: string; example: string; description?: string }>
  >({});

  useEffect(() => {
    if (integrationsAccess !== 'allowed') return;
    fetchIntegrations();
    fetchRuntimeVars();
  }, [integrationsAccess]);

  const fetchIntegrations = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await apiClient.get('/integrations');
      setAvailableIntegrations(response.data);
    } catch (error: any) {
      setError(error.message || 'Failed to load integrations');
    } finally {
      setLoading(false);
    }
  };

  const fetchRuntimeVars = async () => {
    try {
      const vars = await getRuntimeVariablesForCategories(['general', 'connection_point']);
      setRuntimeVariables(vars);
    } catch (error) {
      console.error('Failed to load runtime variables:', error);
    }
  };

  if (integrationsAccess === 'denied') {
    return (
      <IntegrationsAdminOnlyNotice
        className="alert alert-info"
        data-testid="integrations-admin-only-notice"
      />
    );
  }

  if (loading) {
    return (
      <div className="text-center py-4">
        <div className="spinner-border text-primary" role="status">
          <span className="visually-hidden"></span>
        </div>
        <p className="mt-2">Loading integrations...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="alert alert-danger">
        <i className="fas fa-exclamation-triangle me-2"></i>
        {error}
      </div>
    );
  }

  return (
    <IntegrationsStep
      integrations={integrations}
      onChange={onIntegrationsChange}
      availableIntegrations={availableIntegrations}
      runtimeVariables={runtimeVariables}
      onValidationChange={onValidationChange}
      category="connection_point"
    />
  );
};

export default ConnectionPointIntegrationsTab;
