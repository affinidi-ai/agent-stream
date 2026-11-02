import React, { useState } from 'react';
import { fieldHasMissingVariables } from '../../utils/fieldValidation';
import { useSecretOptions } from '../../hooks/useSecretOptions';
import {
  NO_PINNED_DESTINATIONS,
  NO_SECRET_REFERENCES,
  type PinnedDestinations,
} from '../../utils/integrationCredentials';
import CredentialSecretField from './CredentialSecretField';
import UrlCredentialField from './UrlCredentialField';

export interface StreamConfiguration {
  platform: string;
  topic: string;
  brokers?: string;
  region?: string;
  redis_url_secret_id?: string;
  auth_type?: string;
  sasl_username?: string;
  sasl_password_secret_id?: string;
}

export interface StreamContent {
  [key: string]: any;
}

interface StreamIntegrationFormProps {
  configuration: StreamConfiguration;
  content: StreamContent;
  onConfigurationChange: (config: StreamConfiguration) => void;
  onContentChange: (content: StreamContent) => void;
  disabled?: boolean;
  validRuntimeVars?: Set<string>;
  isEditMode?: boolean;
  loadedReferences?: ReadonlySet<string>;
  pinnedDestinations?: PinnedDestinations;
}

const KEEP_SAVED_HINT = 'Leave blank to keep the saved value.';

const StreamIntegrationForm: React.FC<StreamIntegrationFormProps> = ({
  configuration,
  content,
  onConfigurationChange,
  onContentChange,
  disabled = false,
  validRuntimeVars = new Set(),
  isEditMode = false,
  loadedReferences = NO_SECRET_REFERENCES,
  pinnedDestinations = NO_PINNED_DESTINATIONS,
}) => {
  const secretOptions = useSecretOptions();
  const [platform, setPlatform] = useState(configuration.platform || 'kafka');
  const [topic, setTopic] = useState(configuration.topic || '');
  const [brokers, setBrokers] = useState(configuration.brokers || '');
  const [region, setRegion] = useState(configuration.region || '');
  const [redisUrlSecretId, setRedisUrlSecretId] = useState(configuration.redis_url_secret_id || '');
  const [authType, setAuthType] = useState(configuration.auth_type || 'none');
  const [saslUsername, setSaslUsername] = useState(configuration.sasl_username || '');
  const [saslPasswordSecretId, setSaslPasswordSecretId] = useState(
    configuration.sasl_password_secret_id || ''
  );
  const keepsSavedSaslPassword = isEditMode && !loadedReferences.has('sasl_password_secret_id');

  const [payloadTemplate, setPayloadTemplate] = useState(JSON.stringify(content, null, 2));
  const [payloadError, setPayloadError] = useState('');

  // Build configuration object from current state
  const buildConfiguration = (
    overrides: Partial<{
      platform: string;
      topic: string;
      brokers: string;
      region: string;
      redisUrlSecretId: string;
      authType: string;
      saslUsername: string;
      saslPasswordSecretId: string;
    }> = {}
  ): StreamConfiguration => {
    const currentPlatform = overrides.platform ?? platform;
    const currentTopic = overrides.topic ?? topic;
    const currentBrokers = overrides.brokers ?? brokers;
    const currentRegion = overrides.region ?? region;
    const currentRedisUrlSecretId = overrides.redisUrlSecretId ?? redisUrlSecretId;
    const currentAuthType = overrides.authType ?? authType;
    const currentSaslUsername = overrides.saslUsername ?? saslUsername;
    const currentSaslPasswordSecretId = overrides.saslPasswordSecretId ?? saslPasswordSecretId;

    const config: StreamConfiguration = {
      platform: currentPlatform,
      topic: currentTopic,
    };

    if (currentPlatform === 'kafka' || currentPlatform === 'pulsar') {
      if (currentBrokers) config.brokers = currentBrokers;
      if (currentAuthType !== 'none') {
        config.auth_type = currentAuthType;
        if (currentAuthType === 'sasl' && currentSaslUsername) {
          config.sasl_username = currentSaslUsername;
          if (currentSaslPasswordSecretId) {
            config.sasl_password_secret_id = currentSaslPasswordSecretId;
          }
        }
      }
    } else if (currentPlatform === 'kinesis') {
      if (currentRegion) config.region = currentRegion;
    } else if (currentPlatform === 'redis') {
      if (currentRedisUrlSecretId) config.redis_url_secret_id = currentRedisUrlSecretId;
    }

    return config;
  };

  const handlePayloadTemplateChange = (value: string) => {
    setPayloadTemplate(value);
    try {
      const parsed = JSON.parse(value);
      setPayloadError('');
      onContentChange(parsed);
    } catch (e) {
      setPayloadError('Invalid JSON');
    }
  };

  return (
    <div className="stream-integration-form">
      {/* Configuration Section */}
      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-cog me-2"></i>
            Stream Configuration
          </h6>
        </div>
        <div className="card-body">
          <div className="mb-3">
            <label className="form-label">
              Streaming Platform <span className="text-danger">*</span>
            </label>
            <select
              className="form-control dropdown-styling"
              value={platform}
              onChange={e => {
                const newPlatform = e.target.value;
                setPlatform(newPlatform);
                onConfigurationChange(buildConfiguration({ platform: newPlatform }));
              }}
              disabled={disabled}
              required
            >
              <option value="kafka">Apache Kafka</option>
              <option value="kinesis">AWS Kinesis</option>
              <option value="pulsar">Apache Pulsar</option>
              <option value="redis">Redis Streams</option>
            </select>
            <small className="form-text text-muted">The streaming platform to send events to</small>
          </div>

          <div className="mb-3">
            <label className="form-label">
              Topic/Stream Name <span className="text-danger">*</span>
            </label>
            <input
              type="text"
              className={`form-control ${!topic.trim() ? 'is-invalid' : ''}`}
              value={topic}
              data-testid="stream-topic-input"
              onChange={e => {
                const newTopic = e.target.value;
                // console.log('[StreamIntegrationForm] Topic changed to:', newTopic);
                setTopic(newTopic);
                onConfigurationChange(buildConfiguration({ topic: newTopic }));
              }}
              disabled={disabled}
              required
            />
            {!topic.trim() && <div className="invalid-feedback">Topic/Stream Name is required</div>}
            <small className="form-text text-muted">
              The {platform === 'redis' ? 'stream' : 'topic'} name to publish events to
            </small>
          </div>

          {/* Kafka/Pulsar specific fields */}
          {(platform === 'kafka' || platform === 'pulsar') && (
            <>
              <div className="mb-3">
                <label className="form-label">
                  Broker URLs <span className="text-danger">*</span>
                </label>
                <input
                  type="text"
                  className={`form-control ${(platform === 'kafka' || platform === 'pulsar') && !brokers.trim() ? 'is-invalid' : ''}`}
                  value={brokers}
                  data-testid="stream-brokers-input"
                  onChange={e => {
                    const newBrokers = e.target.value;
                    setBrokers(newBrokers);
                    onConfigurationChange(buildConfiguration({ brokers: newBrokers }));
                  }}
                  disabled={disabled}
                  required
                />
                <small className="form-text text-muted">
                  {platform === 'pulsar'
                    ? 'Pulsar service URL: pulsar://host:6650 or pulsar+ssl://host:6651'
                    : 'Comma-separated host:port list (port 9092 if omitted)'}
                </small>
              </div>

              <div className="mb-3">
                <label className="form-label">Authentication Type</label>
                <select
                  className="form-control dropdown-styling"
                  value={authType}
                  onChange={e => {
                    const newAuthType = e.target.value;
                    setAuthType(newAuthType);
                    onConfigurationChange(buildConfiguration({ authType: newAuthType }));
                  }}
                  disabled={disabled}
                >
                  <option value="none">None</option>
                  <option value="sasl">SASL/PLAIN</option>
                </select>
              </div>

              {authType === 'sasl' && (
                <>
                  <div className="mb-3">
                    <label className="form-label">SASL Username</label>
                    <input
                      type="text"
                      className="form-control"
                      value={saslUsername}
                      onChange={e => {
                        const newUsername = e.target.value;
                        setSaslUsername(newUsername);
                        onConfigurationChange(buildConfiguration({ saslUsername: newUsername }));
                      }}
                      placeholder="kafka-user"
                      disabled={disabled}
                    />
                  </div>
                  <CredentialSecretField
                    label="SASL Password secret"
                    secretOptions={secretOptions}
                    selectedSecretId={saslPasswordSecretId}
                    onChange={secretId => {
                      setSaslPasswordSecretId(secretId);
                      onConfigurationChange(buildConfiguration({ saslPasswordSecretId: secretId }));
                    }}
                    helpText={keepsSavedSaslPassword ? KEEP_SAVED_HINT : ''}
                    disabled={disabled}
                    testId="stream-sasl-password-secret"
                  />
                </>
              )}
            </>
          )}

          {/* Kinesis specific fields */}
          {platform === 'kinesis' && (
            <>
              <div className="mb-3">
                <label className="form-label">
                  AWS Region <span className="text-danger">*</span>
                </label>
                <input
                  type="text"
                  className={`form-control ${platform === 'kinesis' && !region.trim() ? 'is-invalid' : ''}`}
                  value={region}
                  onChange={e => {
                    const newRegion = e.target.value;
                    setRegion(newRegion);
                    onConfigurationChange(buildConfiguration({ region: newRegion }));
                  }}
                  disabled={disabled}
                  required
                />
                <small className="form-text text-muted">
                  AWS region where the Kinesis stream is located
                </small>
              </div>

              <p className="form-text text-muted" data-testid="stream-kinesis-credentials-hint">
                <i className="fas fa-info-circle me-1" aria-hidden="true" />
                Kinesis uses the appliance's AWS credential chain (environment, profile or IAM
                role).
              </p>
            </>
          )}

          {/* Redis specific fields */}
          {platform === 'redis' && (
            <UrlCredentialField
              label="Redis URL secret"
              secretId={redisUrlSecretId}
              onChange={secretId => {
                setRedisUrlSecretId(secretId);
                onConfigurationChange(buildConfiguration({ redisUrlSecretId: secretId }));
              }}
              secretOptions={secretOptions}
              pinned={pinnedDestinations.redis_url}
              savedWithoutReference={isEditMode && !loadedReferences.has('redis_url_secret_id')}
              helpText="The secret holding the Redis connection URL: redis://host:port"
              disabled={disabled}
              testId="stream-redis-url"
            />
          )}
        </div>
      </div>

      {/* Content Template Section */}
      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-file-code me-2"></i>
            Content Template (JSON)
          </h6>
        </div>
        <div className="card-body">
          <div className="mb-3">
            <label className="form-label">
              Event Payload Template <span className="text-danger">*</span>
            </label>
            <textarea
              className={`form-control font-monospace ${payloadError || fieldHasMissingVariables(payloadTemplate, validRuntimeVars) ? 'is-invalid' : ''}`}
              rows={18}
              value={payloadTemplate}
              data-testid="stream-payload-template"
              onChange={e => handlePayloadTemplateChange(e.target.value)}
              style={{ fontSize: '0.875rem' }}
              disabled={disabled}
              required
            />
            {payloadError && <div className="invalid-feedback">{payloadError}</div>}
            <small className="form-text text-muted">
              <i className="fas fa-code me-1"></i>
              JSON template for events published to the stream. Use variables like{' '}
              <code>
                ${'{'}EVENT_TYPE{'}'}
              </code>{' '}
              or{' '}
              <code>
                ${'{'}CP_NAME:Label{'}'}
              </code>{' '}
              for runtime substitution.
            </small>
          </div>
        </div>
      </div>
    </div>
  );
};

export default StreamIntegrationForm;
