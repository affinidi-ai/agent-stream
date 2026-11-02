import React, { useState, useEffect, useMemo } from 'react';
import { showToast } from '../../utils/toaster';
import { generateRandomPath } from '../../utils/stringUtils';
import { apiClient } from '../../api';
import { validateTargetEndpoint } from '../../utils/urlValidation';

interface ConfigureStepProps {
  protocol: 'a2a' | 'mcp';
  capturedPayload: any;
  derivedSchema: any;
  initialFormState?: any;
  onConfigurationComplete: (config: any, formState: any) => void;
  onBack: () => void;
}

interface ChannelFormData {
  name: string;
  config_id: string;
  description: string;
  listen_address: string;
  target_endpoint: string;
  enabled: boolean;
  endpoint_type?: 'url' | 'gateway';
  gateway_id?: string;
  gateway_channel?: string;
}

interface ChannelPrefixInfo {
  id: string;
  name: string;
  prefix: string;
}

interface ChannelRoutingConfig {
  available_listen_addresses: string[];
  channel_path_prefix: ChannelPrefixInfo[];
}

interface Gateway {
  id: string;
  name: string;
}

interface GatewayChannel {
  config_id: string;
  name: string;
}

const ConfigureStep: React.FC<ConfigureStepProps> = ({
  protocol,
  capturedPayload,
  derivedSchema,
  initialFormState,
  onConfigurationComplete,
  onBack,
}) => {
  const [routingConfig, setRoutingConfig] = useState<ChannelRoutingConfig | null>(null);
  const [selectedHostPort, setSelectedHostPort] = useState<string>(
    initialFormState?.selectedHostPort || ''
  );
  const [selectedPrefix, setSelectedPrefix] = useState<string>(
    initialFormState?.selectedPrefix || ''
  );
  const [customPath, setCustomPath] = useState<string>(
    initialFormState?.customPath || generateRandomPath()
  );

  // Endpoint type state
  const [endpointType, setEndpointType] = useState<'url' | 'gateway'>(
    initialFormState?.endpoint_type || 'url'
  );

  // Gateway state
  const [gateways, setGateways] = useState<Gateway[]>([]);
  const [gatewayChannels, setGatewayChannels] = useState<GatewayChannel[]>([]);
  const [isLoadingChannels, setIsLoadingChannels] = useState(false);
  const loadedGatewayRef = React.useRef<string | undefined>();

  // Extension selector state for A2A protocol
  const [extensionType, setExtensionType] = useState<'standard' | 'ucp' | 'custom'>(
    initialFormState?.extensionType ||
      (initialFormState?.primary_extension?.includes('ucp.dev') ? 'ucp' : 'standard')
  );
  const [customExtension, setCustomExtension] = useState<string>(
    initialFormState?.customExtension ||
      (initialFormState?.primary_extension &&
      !initialFormState?.primary_extension.includes('ucp.dev')
        ? initialFormState.primary_extension
        : '')
  );

  const [formData, setFormData] = useState<ChannelFormData>({
    name:
      initialFormState?.name ||
      `${initialFormState?.extensionType === 'ucp' ? 'ucp' : protocol}-channel-${Date.now()}`,
    config_id: crypto.randomUUID(),
    description: initialFormState?.description || '',
    listen_address: '',
    target_endpoint: initialFormState?.target_endpoint || 'https://httpbin.org/anything',
    enabled: true,
    endpoint_type: initialFormState?.endpoint_type || 'url',
    gateway_id: initialFormState?.gateway_id,
    gateway_channel: initialFormState?.gateway_channel,
  });

  const [validationErrors, setValidationErrors] = useState<string[]>([]);

  // Compute full route for display - useMemo ensures this updates when dependencies change
  const fullRouteDisplay = useMemo(() => {
    if (selectedHostPort && selectedPrefix && customPath && customPath.trim()) {
      const normalizedPath = customPath.startsWith('/') ? customPath.substring(1) : customPath;
      return `${selectedHostPort}${selectedPrefix}/${normalizedPath}`;
    }
    return '(select address, prefix, and enter custom path)';
  }, [selectedHostPort, selectedPrefix, customPath]);

  // Fetch routing configuration on mount
  useEffect(() => {
    const fetchRoutingConfig = async () => {
      try {
        const response = await apiClient.fetch('/api/v1/config/surface-routing');
        if (!response.ok) {
          throw new Error('Failed to fetch routing configuration');
        }
        const config: ChannelRoutingConfig = await response.json();
        setRoutingConfig(config);
      } catch (error: any) {
        showToast('error', error.message || 'Failed to load routing configuration');
      }
    };

    fetchRoutingConfig();
  }, []);

  // Load gateways on mount
  useEffect(() => {
    const loadGateways = async () => {
      try {
        const response = await apiClient.get('/gateways');
        // Filter to only show user-created remote gateways (exclude self gateway)
        const userGateways = response.data.filter(
          (gw: any) => gw.gateway_type === 'remote' && gw.creation_type === 'user'
        );
        setGateways(userGateways);
      } catch (error) {
        console.error('Failed to load gateways:', error);
      }
    };

    loadGateways();
  }, []);

  // Load gateway channels when gateway is selected
  useEffect(() => {
    if (!formData.gateway_id) {
      setGatewayChannels([]);
      loadedGatewayRef.current = undefined;
      return;
    }

    // Don't reload if we've already loaded channels for this gateway
    if (loadedGatewayRef.current === formData.gateway_id) {
      return;
    }

    const loadGatewayChannels = async () => {
      setIsLoadingChannels(true);
      try {
        const response = await apiClient.get(`/gateways/${formData.gateway_id}/surfaces`);

        // Check if response has success and channels
        if (response.data && response.data.success && Array.isArray(response.data.channels)) {
          // Filter channels to match the current channel's protocol
          const currentProtocol = protocol || 'a2a';
          const allChannels = response.data.channels.map((ch: any) => ({
            config_id: ch.config_id,
            name: ch.name,
            description: ch.description,
            protocol: ch.protocol || 'a2a',
          }));

          // Only show channels that match the current protocol
          const channels = allChannels.filter((ch: any) => {
            const chProtocol = ch.protocol || 'a2a';
            return chProtocol === currentProtocol;
          });
          setGatewayChannels(channels);

          // Mark this gateway as loaded
          loadedGatewayRef.current = formData.gateway_id;
        } else {
          console.warn('Gateway returned unexpected response:', response.data);
          setGatewayChannels([]);
        }
      } catch (error: any) {
        // Silently handle errors for disconnected gateways
        if (error?.message?.includes('503') || error?.message?.includes('not connected')) {
          console.debug('Gateway is not connected - channel list unavailable');
        } else {
          console.error('Failed to load gateway channels:', error);
        }
        setGatewayChannels([]);
      } finally {
        setIsLoadingChannels(false);
      }
    };

    loadGatewayChannels();
  }, [formData.gateway_id, protocol]);

  // Update listen_address whenever host:port or custom path changes
  useEffect(() => {
    if (selectedHostPort && routingConfig && customPath) {
      // Strip protocol (http:// or https://) from the selected address
      const hostPort = selectedHostPort.replace(/^https?:\/\//, '');

      setFormData(prev => ({
        ...prev,
        listen_address: hostPort,
      }));
    }
  }, [selectedHostPort, customPath, routingConfig]);

  const handleInputChange = (field: keyof ChannelFormData, value: string | boolean) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  const validateForm = (): boolean => {
    const errors: string[] = [];

    if (!formData.name.trim()) {
      errors.push('Channel name is required');
    }

    if (!selectedHostPort) {
      errors.push('Please select a listen address');
    }

    if (!selectedPrefix) {
      errors.push('Please select a channel prefix');
    }

    if (!customPath.trim()) {
      errors.push('Channel path is required');
    }

    // Validate based on endpoint type
    if (endpointType === 'url') {
      if (!formData.target_endpoint.trim()) {
        errors.push('Target endpoint is required');
      } else {
        const targetCheck = validateTargetEndpoint(formData.target_endpoint);
        if (!targetCheck.valid) {
          errors.push(`Target endpoint: ${targetCheck.error}`);
        }
      }
    } else if (endpointType === 'gateway') {
      if (!formData.gateway_id) {
        errors.push('Please select a gateway');
      }
      if (!formData.gateway_channel) {
        errors.push('Please select a gateway channel');
      }
    }

    setValidationErrors(errors);
    return errors.length === 0;
  };

  const handleSaveChannel = () => {
    if (!validateForm()) {
      showToast('error', 'Please fix validation errors');
      return;
    }

    if (!routingConfig) {
      showToast('error', 'Routing configuration not loaded');
      return;
    }

    // Strip protocol (http:// or https://) from the selected address
    const hostPort = selectedHostPort.replace(/^https?:\/\//, '');

    // Normalize customPath to ensure it starts with /
    const normalizedPath = customPath.startsWith('/') ? customPath : `/${customPath}`;
    const route = `${selectedPrefix}${normalizedPath}`;

    // Prepare channel configuration (but don't create it yet)
    // Use the derived schema from the capture step, or fall back to default empty schema
    const jsonSchema = derivedSchema || {
      properties: {
        agentIdentity: {
          properties: {},
          required: [],
          type: 'object',
        },
      },
      required: [],
      type: 'object',
    };

    const channelConfig: any = {
      ...formData,
      listen_address: hostPort,
      route: route,
      full_listen_url: `${selectedHostPort}${route}`, // Full URL for display
      extension_rules: {
        json_schema: jsonSchema,
        rules: [],
      },
      custom_metadata: {
        enabled: false,
        payload: {},
      },
    };

    // Add extension fields for A2A protocol
    if (protocol === 'a2a') {
      if (extensionType === 'ucp') {
        const ucpExtension = 'https://ucp.dev/specification/reference?v=2026-01-11';
        channelConfig.primary_extension = ucpExtension;
        channelConfig.supported_extensions = [ucpExtension];
      } else if (extensionType === 'custom' && customExtension.trim()) {
        channelConfig.primary_extension = customExtension.trim();
        channelConfig.supported_extensions = [customExtension.trim()];
      }
    }

    // Capture form state to preserve across navigation
    const formState = {
      selectedHostPort,
      selectedPrefix,
      customPath,
      name: formData.name,
      description: formData.description,
      target_endpoint: formData.target_endpoint,
      mediator_id: '',
      extensionType,
      customExtension,
      primary_extension: channelConfig.primary_extension,
    };

    // Pass configuration to next step for confirmation (channel will be created in ConfirmStep)
    onConfigurationComplete(channelConfig, formState);
  };

  return (
    <div>
      <h5 className="mb-3">
        <i className="fas fa-cog me-2"></i>
        Configure Channel
      </h5>
      <p className="text-muted mb-3" style={{ fontSize: '14px' }}>
        {`Configure the basic settings for your new ${protocol.toUpperCase()} channel.`}
      </p>

      {validationErrors.length > 0 && (
        <div className="alert alert-danger">
          <strong>Validation Errors:</strong>
          <ul className="mb-0 mt-2">
            {validationErrors.map((error, index) => (
              <li key={index}>{error}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Section 1: Extension Type (A2A only) */}
      {protocol === 'a2a' && (
        <div className="card shadow mb-4">
          <div className="card-body">
            <h6 className="mb-3">
              <i className="fas fa-puzzle-piece me-2"></i>
              Extension Type
            </h6>
            <select
              className="form-control dropdown-styling"
              value={extensionType}
              onChange={e => setExtensionType(e.target.value as 'standard' | 'ucp' | 'custom')}
            >
              <option value="standard">Standard A2A</option>
              <option value="ucp">UCP Commerce</option>
              <option value="custom">Custom Extension</option>
            </select>

            {extensionType === 'standard' && (
              <small className="form-text text-muted">
                Standard Agent-to-Agent protocol without extensions
              </small>
            )}

            {extensionType === 'ucp' && (
              <div className="alert alert-info mt-2 mb-0" style={{ fontSize: '14px' }}>
                <i className="fas fa-info-circle me-2"></i>
                UCP (Universal Commerce Protocol) extension will be configured for e-commerce
                workflows
                <div className="mt-1 text-monospace" style={{ fontSize: '12px' }}>
                  https://ucp.dev/specification/reference?v=2026-01-11
                </div>
              </div>
            )}

            {extensionType === 'custom' && (
              <div className="mt-2">
                <input
                  type="text"
                  className="form-control"
                  value={customExtension}
                  onChange={e => setCustomExtension(e.target.value)}
                  placeholder="Enter custom extension URI (e.g., https://example.com/extension/v1)"
                />
                <small className="form-text text-muted">
                  Specify a custom extension URI for your A2A channel
                </small>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Section 2: Basic Configuration */}
      <div className="card shadow mb-4">
        <div className="card-body">
          <h6 className="mb-3">
            <i className="fas fa-info-circle me-2"></i>
            Basic Configuration
          </h6>
          <div className="row">
            <div className="col-md-6 mb-3">
              <label className="form-label font-weight-bold">
                Channel Name <span className="text-danger">*</span>
              </label>
              <input
                type="text"
                className="form-control"
                value={formData.name}
                onChange={e => handleInputChange('name', e.target.value)}
                placeholder="Enter the channel name"
              />
              <small className="form-text text-muted">A unique identifier for this channel</small>
            </div>

            <div className="col-md-6 mb-3">
              <label className="form-label font-weight-bold">Config ID</label>
              <input
                type="text"
                className="form-control"
                value={formData.config_id}
                readOnly
                disabled
              />
              <small className="form-text text-muted">Auto-generated unique identifier</small>
            </div>
          </div>

          <div className="mb-0">
            <label className="form-label font-weight-bold">Description</label>
            <input
              className="form-control"
              value={formData.description}
              onChange={e => handleInputChange('description', e.target.value)}
              placeholder="Brief description of this channel's purpose"
            />
          </div>
        </div>
      </div>

      {/* Section 3: Network Configuration */}
      <div className="card shadow mb-4">
        <div className="card-body">
          <h6 className="mb-3">
            <i className="fas fa-network-wired me-2"></i>
            Network Configuration
          </h6>
          <div className="row">
            <div className="col-md-6 mb-3">
              <label className="form-label font-weight-bold">
                Listen Address (Host:Port) <span className="text-danger">*</span>
              </label>
              <select
                className="form-control dropdown-styling"
                value={selectedHostPort}
                onChange={e => setSelectedHostPort(e.target.value)}
                disabled={!routingConfig || routingConfig.available_listen_addresses.length === 0}
              >
                {!routingConfig ? (
                  <option value="">Loading...</option>
                ) : routingConfig.available_listen_addresses.length === 0 ? (
                  <option value="">No addresses available</option>
                ) : (
                  <>
                    <option value="">-- Select listen address --</option>
                    {routingConfig.available_listen_addresses.map(addr => (
                      <option key={addr} value={addr}>
                        {addr}
                      </option>
                    ))}
                  </>
                )}
              </select>
              <small className="form-text text-muted">
                Select the host:port this server will listen on
              </small>
            </div>

            <div className="col-md-6 mb-3">
              <label className="form-label font-weight-bold">
                Channel Prefix <span className="text-danger">*</span>
              </label>
              <select
                className="form-control dropdown-styling"
                value={selectedPrefix}
                onChange={e => setSelectedPrefix(e.target.value)}
                disabled={!routingConfig || routingConfig.channel_path_prefix.length === 0}
              >
                {!routingConfig ? (
                  <option value="">Loading...</option>
                ) : routingConfig.channel_path_prefix.length === 0 ? (
                  <option value="">No prefixes available</option>
                ) : (
                  <>
                    <option value="">-- Select prefix --</option>
                    {routingConfig.channel_path_prefix.map(item => (
                      <option key={item.id} value={item.prefix}>
                        {item.name}
                      </option>
                    ))}
                  </>
                )}
              </select>
              <small className="form-text text-muted">
                Select the path prefix for your channel
              </small>
            </div>
          </div>

          <div className="row">
            <div className="col-md-12 mb-3">
              <label className="form-label font-weight-bold">
                Custom Path <span className="text-danger">*</span>
              </label>
              <input
                type="text"
                className="form-control"
                value={customPath.startsWith('/') ? customPath.substring(1) : customPath}
                onChange={e => setCustomPath(e.target.value)}
                placeholder="my/custom/path"
              />
              <small className="form-text text-muted">
                Your custom path (will be prefixed with {selectedPrefix || 'prefix'}/)
              </small>
            </div>
          </div>

          <div className="alert alert-info" style={{ fontSize: '16px' }}>
            <i className="fas fa-info-circle me-2"></i>
            <strong>Channel Route:</strong> {fullRouteDisplay}
          </div>

          <div className="row">
            <div className="col-md-12 mb-3">
              <label className="form-label font-weight-bold">
                Target Endpoint Type <span className="text-danger">*</span>
              </label>
              <select
                className="form-control dropdown-styling mb-3"
                value={endpointType}
                onChange={e => {
                  const newType = e.target.value as 'url' | 'gateway';
                  setEndpointType(newType);
                  setFormData(prev => ({
                    ...prev,
                    endpoint_type: newType,
                    target_endpoint: newType === 'url' ? prev.target_endpoint : '',
                    gateway_id: newType === 'gateway' ? prev.gateway_id : undefined,
                    gateway_channel: newType === 'gateway' ? prev.gateway_channel : undefined,
                  }));
                }}
              >
                <option value="url">Direct URL</option>
                <option value="gateway">via Gateway Connection</option>
              </select>

              {endpointType === 'url' ? (
                <>
                  <input
                    type="text"
                    className="form-control"
                    value={formData.target_endpoint}
                    onChange={e => handleInputChange('target_endpoint', e.target.value)}
                    placeholder="https://api.example.com"
                  />
                  <small className="form-text text-muted">
                    Enter the full URL including protocol (http:// or https://)
                  </small>
                </>
              ) : (
                <>
                  <select
                    className="form-control dropdown-styling mb-2"
                    value={formData.gateway_id || ''}
                    onChange={async e => {
                      const gatewayId = e.target.value;
                      // Reset loaded gateway ref to allow reloading when user changes gateway
                      loadedGatewayRef.current = undefined;
                      // Clear current channels immediately for better UX
                      setGatewayChannels([]);
                      setFormData(prev => ({
                        ...prev,
                        gateway_id: gatewayId,
                        gateway_channel: undefined,
                      }));
                    }}
                  >
                    <option value="">-- Select a Gateway --</option>
                    {gateways.map(gateway => (
                      <option key={gateway.id} value={gateway.id}>
                        {gateway.name}
                      </option>
                    ))}
                  </select>
                  <small className="form-text text-muted mb-2">Select the gateway connection</small>

                  {formData.gateway_id && (
                    <>
                      <select
                        className="form-control dropdown-styling mt-2"
                        value={formData.gateway_channel || ''}
                        onChange={e => {
                          const channelId = e.target.value;
                          setFormData(prev => ({
                            ...prev,
                            gateway_channel: channelId,
                            target_endpoint: `fabric://${prev.gateway_id}/${channelId}`,
                          }));
                        }}
                        disabled={isLoadingChannels || gatewayChannels.length === 0}
                      >
                        <option value="">
                          {isLoadingChannels
                            ? '-- Loading channels... --'
                            : '-- Select a Channel --'}
                        </option>
                        {Array.isArray(gatewayChannels) &&
                          gatewayChannels.map(channel => (
                            <option key={channel.config_id} value={channel.config_id}>
                              {channel.name}
                            </option>
                          ))}
                      </select>
                      <small className="form-text text-muted mt-1">
                        Select the channel on the gateway
                      </small>

                      {!isLoadingChannels && gatewayChannels.length === 0 && (
                        <div className="alert alert-danger mt-3" role="alert">
                          <i className="fas fa-exclamation-triangle me-2"></i>
                          The selected gateway is not publishing any{' '}
                          <strong>{protocol.toUpperCase()}</strong> channels - contact the
                          administrator of the gateway for more information
                        </div>
                      )}
                    </>
                  )}
                </>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Step Navigation */}
      <div className="step-navigation">
        <button className="btn btn-secondary" onClick={onBack}>
          <i className="fas fa-arrow-left me-2"></i>
          Back
        </button>
        <button className="btn btn-primary" onClick={handleSaveChannel}>
          Next: Review Details
          <i className="fas fa-arrow-right ms-2"></i>
        </button>
      </div>
    </div>
  );
};

export default ConfigureStep;
