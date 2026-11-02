import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../api';
import './OnboardWizard.css';

// Import step components
import SelectMediatorStep from '../components/gateway-create-connection-point/SelectMediatorStep';
import EnterDetailsStep from '../components/gateway-create-connection-point/EnterDetailsStep';
import {
  integrationIntegration,
  IntegrationsStep,
} from '../components/connection-points/IntegrationsStep';
import CompleteStep from '../components/gateway-create-connection-point/CompleteStep';
import { getRuntimeVariablesForCategories } from '../utils/runtimeVariables';
import { useIntegrationsAccess } from '../hooks/useIntegrationsAccess';
import IntegrationsAdminOnlyNotice from '../components/integrations/IntegrationsAdminOnlyNotice';

// Define wizard steps
type WizardStep = 'select-mediator' | 'enter-details' | 'integrations' | 'complete';

interface WizardState {
  currentStep: WizardStep;
  mediatorId: string | null;
  gatewayId: string | null;
  name: string;
  description: string;
  secret: string;
  expirySeconds?: number;
  didMethod: string;
  integrations: integrationIntegration[];
  connectionPoint: any;
}

const CreateGatewayConnectionPointWizardPage: React.FC = () => {
  const navigate = useNavigate();

  const [wizardState, setWizardState] = useState<WizardState>({
    currentStep: 'select-mediator',
    mediatorId: null,
    gatewayId: null,
    name: '',
    description: '',
    secret: '',
    didMethod: 'web',
    integrations: [] as any[],
    connectionPoint: null,
  });

  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const integrationsAccess = useIntegrationsAccess();
  const [integrations, setIntegrations] = useState<any[]>([]);
  const [integrationValidationErrors, setIntegrationValidationErrors] = useState(false);
  const [runtimeVariables, setRuntimeVariables] = useState<
    Record<string, { label: string; example: string; description?: string }>
  >({});

  // Fetch integrations and runtime variables for integrations step
  useEffect(() => {
    const fetchIntegrations = async () => {
      try {
        const response = await apiClient.get('/integrations');
        setIntegrations(response.data || []);
      } catch (err) {
        console.error('Failed to fetch integrations:', err);
      }
    };

    const fetchRuntimeVars = async () => {
      try {
        const vars = await getRuntimeVariablesForCategories(['general', 'connection_point']);
        setRuntimeVariables(vars);
      } catch (err) {
        console.error('Failed to fetch runtime variables:', err);
      }
    };

    if (integrationsAccess !== 'allowed') return;
    fetchIntegrations();
    fetchRuntimeVars();
  }, [integrationsAccess]);

  const steps: { key: WizardStep; label: string }[] = [
    { key: 'select-mediator', label: 'Select Mediator' },
    { key: 'enter-details', label: 'Enter Details' },
    { key: 'integrations', label: 'Integrations' },
    { key: 'complete', label: 'Complete' },
  ];

  const currentStepIndex = steps.findIndex(s => s.key === wizardState.currentStep);

  const goToStep = (step: WizardStep) => {
    setWizardState(prev => ({ ...prev, currentStep: step }));
  };

  const nextStep = () => {
    const nextIndex = currentStepIndex + 1;
    if (nextIndex < steps.length) {
      goToStep(steps[nextIndex].key);
    }
  };

  const prevStep = () => {
    const prevIndex = currentStepIndex - 1;
    if (prevIndex >= 0) {
      goToStep(steps[prevIndex].key);
    }
  };

  const handleMediatorSelected = (mediatorId: string) => {
    setWizardState(prev => ({ ...prev, mediatorId }));
    nextStep();
  };

  const handleDetailsSubmit = (
    gatewayId: string,
    name: string,
    description: string,
    secret: string,
    expirySeconds?: number,
    didMethod?: string
  ) => {
    setWizardState(prev => ({
      ...prev,
      gatewayId,
      name,
      description,
      secret,
      expirySeconds,
      didMethod: didMethod || 'web',
    }));
    nextStep();
  };

  const handleIntegrationsSubmit = () => {
    nextStep();
  };

  const handleCreate = async () => {
    try {
      setSaving(true);
      setError('');

      // Create the connection point via the API
      const payload: any = {
        gateway_id: wizardState.gatewayId,
        mediator_id: wizardState.mediatorId,
        name: wizardState.name,
        description: wizardState.description,
        secret: wizardState.secret,
        expiry_seconds: wizardState.expirySeconds,
        integrations: wizardState.integrations,
        did_method: wizardState.didMethod,
      };

      const response = await apiClient.post('/connection-points', payload);

      setWizardState(prev => ({
        ...prev,
        connectionPoint: response.data.connection_point,
      }));
      nextStep();
    } catch (err: any) {
      console.error('Failed to create connection point:', err);
      setError(err.message || 'Failed to create connection point. Please try again.');
    } finally {
      setSaving(false);
    }
  };

  const handleFinish = () => {
    navigate('/connections?tab=gateways');
  };

  const handleCancel = () => {
    navigate('/connections?tab=gateways');
  };

  // Render current step
  const renderStep = () => {
    if (saving) {
      return (
        <div className="card shadow">
          <div className="card-body text-center py-5">
            <div className="spinner-border text-primary mb-3" role="status">
              <span className="visually-hidden"></span>
            </div>
            <p className="text-muted">Creating connection point...</p>
          </div>
        </div>
      );
    }

    switch (wizardState.currentStep) {
      case 'select-mediator':
        return (
          <SelectMediatorStep
            onNext={handleMediatorSelected}
            onCancel={handleCancel}
            initialMediatorId={wizardState.mediatorId}
          />
        );
      case 'enter-details':
        return (
          <EnterDetailsStep
            onCreate={handleDetailsSubmit}
            onBack={prevStep}
            onCancel={handleCancel}
            initialGatewayId={wizardState.gatewayId}
            initialName={wizardState.name}
            initialDescription={wizardState.description}
            initialSecret={wizardState.secret}
            initialExpirySeconds={wizardState.expirySeconds}
            initialDidMethod={wizardState.didMethod}
          />
        );
      case 'integrations':
        return (
          <div className="card shadow">
            <div className="card-body">
              {integrationsAccess === 'denied' ? (
                <IntegrationsAdminOnlyNotice
                  className="alert alert-info"
                  data-testid="integrations-admin-only-notice"
                />
              ) : (
                <IntegrationsStep
                  integrations={wizardState.integrations}
                  onChange={integrations => setWizardState(prev => ({ ...prev, integrations }))}
                  availableIntegrations={integrations}
                  onValidationChange={setIntegrationValidationErrors}
                  runtimeVariables={runtimeVariables}
                  category="connection_point"
                />
              )}
              <div className="mt-4 d-flex justify-content-between">
                <button className="btn btn-secondary" onClick={handleCancel}>
                  <i className="fas fa-times me-1"></i>
                  Cancel
                </button>
                <div>
                  <button className="btn btn-secondary me-2" onClick={prevStep}>
                    <i className="fas fa-arrow-left me-1"></i>
                    Back
                  </button>
                  <button
                    className="btn btn-primary"
                    onClick={handleCreate}
                    disabled={integrationValidationErrors}
                    title={
                      integrationValidationErrors
                        ? 'Please fill in all integration variable values'
                        : ''
                    }
                  >
                    Create
                    <i className="fas fa-arrow-right ms-1"></i>
                  </button>
                </div>
              </div>
            </div>
          </div>
        );
      case 'complete':
        return (
          <CompleteStep connectionPoint={wizardState.connectionPoint} onFinish={handleFinish} />
        );
      default:
        return null;
    }
  };

  return (
    <div className="container-fluid">
      {/* Page Header */}
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <h1 className="h3 mb-0 text-gray-800">
          <i className="fas fa-share-alt me-2"></i>
          Create Gateway Connection Point
        </h1>
      </div>

      {error && (
        <div className="alert alert-danger alert-dismissible fade show" role="alert">
          {error}
          <button
            type="button"
            className="btn-close"
            onClick={() => setError('')}
            aria-label="Close"
          />
        </div>
      )}

      {/* Progress Bar */}
      <div className="card shadow mb-4">
        <div className="card-body">
          <div className="wizard-progress">
            <div className="wizard-steps">
              {steps.map((step, index) => (
                <div
                  key={step.key}
                  className={`wizard-step ${
                    index === currentStepIndex
                      ? 'active'
                      : index < currentStepIndex
                        ? 'completed'
                        : ''
                  }`}
                >
                  <div className="wizard-step-circle">
                    {index < currentStepIndex ? (
                      <i className="fas fa-check"></i>
                    ) : (
                      <span>{index + 1}</span>
                    )}
                  </div>
                  <div className="wizard-step-label">{step.label}</div>
                  {index < steps.length - 1 && <div className="wizard-step-line"></div>}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Step Content */}
      <div className="wizard-content">{renderStep()}</div>
      <br />
    </div>
  );
};

export default CreateGatewayConnectionPointWizardPage;
