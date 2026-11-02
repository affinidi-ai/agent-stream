import React, { useState, useEffect } from 'react';
import { apiClient } from '../../api';

interface Integration {
  id: string;
  name: string;
  integration_type: string;
  description: string;
  configuration: any;
  content: any;
  category?: string;
}

interface IntegrationSelectorProps {
  selectedNotifierId: string;
  integrationVariables: any;
  onNotifierChange: (notifierId: string) => void;
  onVariablesChange: (variables: any) => void;
}

const IntegrationSelector: React.FC<IntegrationSelectorProps> = ({
  selectedNotifierId,
  integrationVariables,
  onNotifierChange,
  onVariablesChange,
}) => {
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [loading, setLoading] = useState(false);
  const [templateVars, setTemplateVars] = useState<string[]>([]);

  useEffect(() => {
    const loadIntegrations = async () => {
      try {
        setLoading(true);
        const response = await apiClient.get('/integrations');
        setIntegrations(response.data || []);
      } catch (error) {
        console.error('Failed to load integrations:', error);
      } finally {
        setLoading(false);
      }
    };

    loadIntegrations();
  }, []);

  // Filter integrations to only show those matching 'connection_point' category or 'general'
  const filteredIntegrations = integrations.filter(integration => {
    // If no category is set on the integration, allow it (backward compatibility)
    if (!integration.category) return true;
    // Allow 'general' category integrations for all contexts
    if (integration.category === 'general') return true;
    // Allow integrations that match the connection_point category
    return integration.category === 'connection_point';
  });

  // Extract template variables (${VARIABLE}) from integration content
  useEffect(() => {
    if (!selectedNotifierId) {
      setTemplateVars([]);
      return;
    }

    const integration = integrations.find(n => n.id === selectedNotifierId);
    if (!integration) {
      setTemplateVars([]);
      return;
    }

    // Extract all ${VARIABLE} placeholders from content JSON
    const contentStr = JSON.stringify(integration.content || {});
    // Match ${VARIABLE} or ${VARIABLE:Label} formats
    const regex = /\$\{([^:}]+)(?::[^}]*)?\}/g;
    const matches = contentStr.match(regex);

    if (matches) {
      // Extract variable names from matches
      const vars = Array.from(
        new Set(
          matches.map(m => {
            const match = m.match(/^\$\{([^:}]+)/);
            return match ? match[1].trim() : m;
          })
        )
      );

      // Only show custom variables (those starting with _) - runtime variables don't need user input
      const customVars = vars.filter(v => v.startsWith('_'));
      setTemplateVars(customVars);

      // Initialize variables object if needed
      const currentVars = integrationVariables || {};
      const newVars = { ...currentVars };
      let hasChanges = false;

      customVars.forEach(varName => {
        if (!(varName in newVars)) {
          newVars[varName] = '';
          hasChanges = true;
        }
      });

      if (hasChanges) {
        onVariablesChange(newVars);
      }
    } else {
      setTemplateVars([]);
    }
  }, [selectedNotifierId, integrations]);

  const selectedIntegration = integrations.find(n => n.id === selectedNotifierId);

  const handleVariableChange = (varName: string, value: string) => {
    const newVars = { ...integrationVariables, [varName]: value };
    onVariablesChange(newVars);
  };

  const getIntegrationTypeBadge = (type: string) => {
    switch (type) {
      case 'email':
        return <span className="badge text-bg-primary">Email</span>;
      case 'slack':
        return <span className="badge text-bg-info">Slack</span>;
      case 'webhook':
        return <span className="badge text-bg-warning">Webhook</span>;
      case 'stream':
        return <span className="badge text-bg-info">Stream</span>;
      default:
        return <span className="badge text-bg-secondary">{type}</span>;
    }
  };

  return (
    <div>
      <label htmlFor="notifierSelect" className="form-label">
        Integration (Optional)
      </label>
      <select
        id="notifierSelect"
        className="form-control dropdown-styling mb-2"
        value={selectedNotifierId}
        onChange={e => onNotifierChange(e.target.value)}
        disabled={loading}
      >
        <option value="">{loading ? '-- Loading integrations... --' : 'No integration'}</option>
        {filteredIntegrations.map(integration => (
          <option key={integration.id} value={integration.id}>
            {integration.name}
          </option>
        ))}
      </select>
      <small className="form-text text-muted">
        <i className="fas fa-bell me-1"></i>
        Select a integration to automatically send notifications when messages are received
      </small>

      {filteredIntegrations.length === 0 && !loading && (
        <small className="form-text text-warning d-block mt-1">
          <i className="fas fa-exclamation-triangle me-1"></i>
          {integrations.length === 0
            ? 'No integrations configured. Create one in the Integrations section to enable notifications.'
            : 'No integrations available for connection points. Create a integration with category "connection_point" or "general" in the Integrations section.'}
        </small>
      )}

      {selectedIntegration && (
        <div className="alert alert-info mt-3">
          <strong>Integration Details:</strong>
          <div className="mt-2">
            <small>
              <strong>Type:</strong> {getIntegrationTypeBadge(selectedIntegration.integration_type)}
              <br />
              <strong>Description:</strong> {selectedIntegration.description}
            </small>
          </div>
        </div>
      )}

      {templateVars.length > 0 && (
        <div className="mt-3">
          <h6>Configure Custom Variables</h6>
          <p className="text-muted small">
            <i className="fas fa-info-circle me-1"></i>
            The selected integration uses custom variables (starting with _). Enter values for these
            variables. Runtime variables (like TIMESTAMP, CP_NAME, etc.) are automatically populated
            at runtime.
          </p>

          {templateVars.map(varName => (
            <div key={varName} className="mb-3">
              <label className="form-label">
                <code>${'${' + varName + '}'}</code>
              </label>
              <input
                type="text"
                className="form-control font-monospace"
                value={integrationVariables?.[varName] || ''}
                onChange={e => handleVariableChange(varName, e.target.value)}
                placeholder={`Enter value for ${varName}...`}
              />
              <small className="form-text text-muted">
                Custom variable - provide a literal value
              </small>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default IntegrationSelector;
