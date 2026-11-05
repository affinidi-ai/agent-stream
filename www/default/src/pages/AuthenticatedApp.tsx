import React, { Suspense, lazy, useEffect, useRef, useState } from 'react';
import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { AppProvider, useApp } from '../context/AppContext';
import { PermissionsProvider, usePermissions } from '../context/PermissionsContext';
import { PageTitleProvider } from '../context/PageTitleContext';
import { loadVariablePatterns } from '../utils/templateVariables';

// Load dashboard components - only when authenticated
import Sidebar from '../components/Sidebar';
import ProtectedRoute from '../components/ProtectedRoute';
import ScrollToTop from '../components/ScrollToTop';
import Header from '../components/Header';
import Dashboard from './Dashboard';

// Import the CSS - only when authenticated
import '../dashboard.css';
import { apiClient, sessionManager } from '../api';
import { ROUTES } from '../routes';

// Redirect legacy /pipes* deep links to the new /llm* routes.
const PipesRedirect: React.FC = () => {
  const location = useLocation();
  return (
    <Navigate to={`${location.pathname.replace(/^\/pipes/, '/llm')}${location.search}`} replace />
  );
};

// Loading fallback component
const PageLoader: React.FC = () => (
  <div
    style={{
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      minHeight: '400px',
      fontSize: '18px',
      color: '#6b7280',
    }}
  >
    <div className="spinner-border text-primary" role="status"></div>
  </div>
);

// Lazy load all pages
const GatewaysPage = lazy(() => import('./GatewaysPage'));
const ConnectionsPage = lazy(() => import('./ConnectionsPage'));
const IntegrationsPage = lazy(() => import('./IntegrationsPage'));
const MediatorsPage = lazy(() => import('./MediatorsPage'));
const PipesPage = lazy(() => import('./PipesPage'));
const ProfilePage = lazy(() => import('./ProfilePage'));
const EditUserPage = lazy(() => import('./EditUserPage'));
const EditMemberPage = lazy(() => import('./EditMemberPage'));
const PromptsPage = lazy(() => import('./PromptsPage'));
const EditPromptPage = lazy(() => import('./EditPromptPage'));
const TeamsPage = lazy(() => import('./TeamsPage'));
const EditTeamPage = lazy(() => import('./EditTeamPage'));
const NotificationsPage = lazy(() => import('./NotificationsPage'));
const TasksPage = lazy(() => import('./TasksPage'));
const SettingsPage = lazy(() => import('./SettingsPage'));
const LogsPage = lazy(() => import('./LogsPage'));
const SystemMetricsPage = lazy(() => import('./SystemMetricsPage'));
const MetricsConfigPage = lazy(() => import('./MetricsConfigPage'));
const SecretsPage = lazy(() => import('./SecretsPage'));
const CredentialsPage = lazy(() => import('./CredentialsPage'));
const PoliciesPage = lazy(() => import('./PoliciesPage'));
const AuditPage = lazy(() => import('./AuditPage'));
const GovernanceRecordsPage = lazy(() => import('./GovernanceRecordsPage'));
const LLMDriftPage = lazy(() => import('./LLMDriftPage'));
const EditGatewayPage = lazy(() => import('./EditGatewayPage'));
const EditConnectionPointPage = lazy(() => import('./EditConnectionPointPage'));
const EditMediatorPage = lazy(() => import('./EditMediatorPage'));
const EditNotificationPage = lazy(() => import('./EditNotificationPage'));
const EditIntegrationPage = lazy(() => import('./EditIntegrationPage'));
const EditSecretPage = lazy(() => import('./EditSecretPage'));
const EditApiKeyPage = lazy(() => import('./EditApiKeyPage'));
const ApiKeyDetailPage = lazy(() => import('./ApiKeyDetailPage'));
const EditCertificatePage = lazy(() => import('./EditCertificatePage'));
const EditAccessTokenPage = lazy(() => import('./EditAccessTokenPage'));
const EditPipePage = lazy(() => import('./EditPipePage'));
const EditIdePage = lazy(() => import('./EditIdePage'));
const IdeSurfacesPage = lazy(() => import('./IdeSurfacesPage'));
const MarketplacePage = lazy(() => import('./MarketplacePage'));
const CreateGatewayConnectionPointWizardPage = lazy(
  () => import('./CreateGatewayConnectionPointWizardPage')
);
const AddGatewayViaOOBWizardPage = lazy(() => import('./AddGatewayViaOOBWizardPage'));
const ApproveGatewayWizardPage = lazy(() => import('./ApproveGatewayWizardPage'));
const AddMediatorWizardPage = lazy(() => import('./AddMediatorWizardPage'));
const AddIntegrationWizardPage = lazy(() => import('./AddIntegrationWizardPage'));
const UserIntegrationsPage = lazy(() => import('./UserIntegrationsPage'));
const EditJwtVerificationStrategyPage = lazy(() => import('./EditJwtVerificationStrategyPage'));
const EditOAuthIdentifierPage = lazy(() => import('./EditOAuthIdentifierPage'));
const EditPolicyDefinitionPage = lazy(() => import('./SettingsPage/EditPolicyDefinitionPage'));
const EditCredentialProviderPage = lazy(() => import('./EditCredentialProviderPage'));
const OidcProvidersPage = lazy(() => import('./OidcProvidersPage'));
const EditOidcProviderPage = lazy(() => import('./EditOidcProviderPage'));
const LlmProvidersPage = lazy(() => import('./LlmProvidersPage'));
const EditLlmProviderPage = lazy(() => import('./EditLlmProviderPage'));

interface AuthenticatedAppProps {
  onLogout: () => void;
  termsEnabled: boolean;
}

const AppContent: React.FC<AuthenticatedAppProps> = ({ onLogout, termsEnabled }) => {
  const { state, actions } = useApp();
  const { loading: permissionsLoading } = usePermissions();
  const hasRefreshedCache = useRef<boolean>(false);
  const [version, setVersion] = useState('-.-.-');
  const [isInitializing, setIsInitializing] = useState(true);

  // Load variable patterns from config on mount
  useEffect(() => {
    loadVariablePatterns().catch(err => {
      console.warn('Failed to load variable patterns:', err);
    });
  }, []);

  // Add dashboard class
  useEffect(() => {
    document.body.classList.add('dashboard-mode');
    return () => {
      document.body.classList.remove('dashboard-mode');
    };
  }, []);

  // Connect WebSocket on mount ONCE
  useEffect(() => {
    //console.log('[AuthenticatedApp] Mounting - connecting WebSocket');
    actions.connectWebSocket();
    return () => {
      //console.log('[AuthenticatedApp] Unmounting - disconnecting WebSocket');
      actions.disconnectWebSocket();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // Empty deps - only run on mount/unmount

  // Refresh gateway channel cache after mounting
  useEffect(() => {
    if (!hasRefreshedCache.current) {
      hasRefreshedCache.current = true;
      apiClient
        .fetch('/api/v1/gateways/refresh-surfaces', {
          method: 'POST',
        })
        .then(response => response.json())
        .catch(error => {
          console.warn('Failed to refresh gateway channel cache:', error);
        });

      // Preload commonly accessed pages after login to improve perceived performance
      setTimeout(() => {
        const preloadPages = [import('./GatewaysPage'), import('./IntegrationsPage')];

        Promise.all(preloadPages).catch(err => {
          console.debug('Preload pages error (non-critical):', err);
        });
      }, 2000);
    }
  }, []);

  const handleLogout = () =>
    sessionManager
      .signOut(() => actions.disconnectWebSocket())
      .then(leaving => {
        if (!leaving) onLogout();
      });

  // Add body class for sidebar state
  useEffect(() => {
    if (state.sidebarCollapsed) {
      document.body.classList.add('sidebar-toggled');
    } else {
      document.body.classList.remove('sidebar-toggled');
    }
  }, [state.sidebarCollapsed]);

  // Wait for permissions to load before showing the app
  useEffect(() => {
    if (!permissionsLoading && isInitializing) {
      // Small delay to ensure everything is ready
      setTimeout(
        () =>
          Promise.all([
            setIsInitializing(false),
            apiClient
              .fetch(`/api/v1/version`)
              .then(response => response.json())
              .then(data => {
                console.info('version:', JSON.stringify(data));
                setVersion(data.version);
              })
              .catch(error => {
                console.warn('Failed to fetch version:', error);
              }),
          ]),
        100
      );
    }
  }, [permissionsLoading, isInitializing]);

  // Show loading state while permissions are loading or during initialization
  if (permissionsLoading || isInitializing) {
    return (
      <div
        style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          minHeight: '100vh',
          fontSize: '18px',
          color: '#6b7280',
        }}
      >
        <div className="spinner-border text-primary" role="status"></div>
      </div>
    );
  }

  return (
    <div className={`${state.theme === 'dark' ? 'dark-theme' : ''}`}>
      <ScrollToTop />

      <div id="wrapper">
        <Sidebar />

        <div
          id="content-wrapper"
          className="d-flex flex-column"
          style={{
            marginLeft: state.sidebarCollapsed ? '120px' : '220px',
            transition: 'margin-left 250ms ease',
          }}
        >
          <div id="content">
            <Header onLogout={handleLogout} />

            <Suspense fallback={<PageLoader />}>
              <Routes>
                <Route
                  path="/"
                  element={
                    <ProtectedRoute permission="dashboard.view">
                      <Dashboard />
                    </ProtectedRoute>
                  }
                />
                <Route path="/dashboard" element={<Navigate to="/" replace />} />
                <Route
                  path="/metrics/configure"
                  element={
                    <ProtectedRoute permission="settings.edit">
                      <MetricsConfigPage />
                    </ProtectedRoute>
                  }
                />
                <Route path="/identities" element={<Navigate to="/" replace />} />
                <Route
                  path="/connections"
                  element={
                    <ProtectedRoute permission="gateways.view">
                      <ConnectionsPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/gateways"
                  element={
                    <ProtectedRoute permission="gateways.view">
                      <GatewaysPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/gateways/view/:id"
                  element={
                    <ProtectedRoute permission="gateways.view">
                      <GatewaysPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/gateways/publish"
                  element={
                    <ProtectedRoute permission="gateways.edit">
                      <CreateGatewayConnectionPointWizardPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/gateways/connect"
                  element={
                    <ProtectedRoute permission="gateways.edit">
                      <AddGatewayViaOOBWizardPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/gateways/:id/approve"
                  element={
                    <ProtectedRoute permission="gateways.edit">
                      <ApproveGatewayWizardPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/gateways/new"
                  element={
                    <ProtectedRoute permission="gateways.edit">
                      <EditGatewayPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/gateways/:id"
                  element={
                    <ProtectedRoute permission="gateways.edit">
                      <EditGatewayPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/connection-points/:id"
                  element={
                    <ProtectedRoute permission="gateways.edit">
                      <EditConnectionPointPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/mediators"
                  element={
                    <ProtectedRoute permission="mediators.view">
                      <MediatorsPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/mediators/view/:id"
                  element={
                    <ProtectedRoute permission="mediators.view">
                      <MediatorsPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/mediators/wizard"
                  element={
                    <ProtectedRoute permission="mediators.edit">
                      <AddMediatorWizardPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/mediators/new"
                  element={
                    <ProtectedRoute permission="mediators.edit">
                      <EditMediatorPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/mediators/:id"
                  element={
                    <ProtectedRoute permission="mediators.edit">
                      <EditMediatorPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/integrations"
                  element={
                    <ProtectedRoute permission="integrations.view">
                      <IntegrationsPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path={ROUTES.INTEGRATION_WIZARD}
                  element={
                    <ProtectedRoute permission="integrations.edit">
                      <AddIntegrationWizardPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/integrations/integrations/:id"
                  element={
                    <ProtectedRoute permission="integrations.edit">
                      <EditIntegrationPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/llm"
                  element={
                    <ProtectedRoute permission="pipes.view">
                      <PipesPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/llm/new"
                  element={
                    <ProtectedRoute permission="pipes.edit">
                      <EditPipePage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/llm/:pipeId"
                  element={
                    <ProtectedRoute permission="pipes.edit">
                      <EditPipePage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/ide"
                  element={
                    <ProtectedRoute permission="pipes.view">
                      <IdeSurfacesPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/ide/new"
                  element={
                    <ProtectedRoute permission="pipes.edit">
                      <EditIdePage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/ide/:pipeId"
                  element={
                    <ProtectedRoute permission="pipes.edit">
                      <EditIdePage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/marketplace"
                  element={
                    <ProtectedRoute permission="pipes.edit">
                      <MarketplacePage />
                    </ProtectedRoute>
                  }
                />
                <Route path="/pipes" element={<Navigate to="/llm" replace />} />
                <Route path="/pipes/*" element={<PipesRedirect />} />
                <Route
                  path="/secrets"
                  element={
                    <ProtectedRoute permission="secrets.view">
                      <SecretsPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/credentials"
                  element={
                    <ProtectedRoute permission="credential_providers.view">
                      <CredentialsPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/policies"
                  element={
                    <ProtectedRoute permission="policies.view">
                      <PoliciesPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/secrets/new"
                  element={
                    <ProtectedRoute permission="secrets.edit">
                      <EditSecretPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/secrets/:id"
                  element={
                    <ProtectedRoute permission="secrets.edit">
                      <EditSecretPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/apikeys/new"
                  element={
                    <ProtectedRoute permission="api_keys.edit">
                      <EditApiKeyPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/apikeys/:id"
                  element={
                    <ProtectedRoute permission="api_keys.edit">
                      <EditApiKeyPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/api-keys/:agentId/:keyId"
                  element={
                    <ProtectedRoute permission="api_keys.view">
                      <ApiKeyDetailPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/certificates"
                  element={
                    <ProtectedRoute permission="certificates.view">
                      <SecretsPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/certificates/new"
                  element={
                    <ProtectedRoute permission="certificates.edit">
                      <EditCertificatePage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/certificates/:id"
                  element={
                    <ProtectedRoute permission="certificates.edit">
                      <EditCertificatePage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/access-tokens"
                  element={<Navigate to="/secrets?tab=access-tokens" replace />}
                />
                <Route
                  path="/access-tokens/new"
                  element={
                    <ProtectedRoute permission="access_tokens.edit">
                      <EditAccessTokenPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/access-tokens/:id"
                  element={
                    <ProtectedRoute permission="access_tokens.edit">
                      <EditAccessTokenPage />
                    </ProtectedRoute>
                  }
                />
                {/* Credential Providers — list is now a Credentials tab; redirect for back-compat */}
                <Route
                  path="/credential-providers"
                  element={<Navigate to="/credentials?tab=credential-providers" replace />}
                />
                <Route
                  path="/credential-providers/new"
                  element={
                    <ProtectedRoute permission="credential_providers.edit">
                      <EditCredentialProviderPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/credential-providers/:id"
                  element={
                    <ProtectedRoute permission="credential_providers.edit">
                      <EditCredentialProviderPage />
                    </ProtectedRoute>
                  }
                />
                {/* Delegation Vault — now part of Secrets page; redirect for back-compat */}
                <Route path="/delegation-vault" element={<Navigate to="/secrets" replace />} />
                {/* OIDC Providers */}
                <Route
                  path="/oidc-providers"
                  element={
                    <ProtectedRoute permission="settings.edit">
                      <OidcProvidersPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/oidc-providers/new"
                  element={
                    <ProtectedRoute permission="settings.edit">
                      <EditOidcProviderPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/oidc-providers/:id"
                  element={
                    <ProtectedRoute permission="settings.edit">
                      <EditOidcProviderPage />
                    </ProtectedRoute>
                  }
                />
                {/* LLM Providers catalog */}
                <Route
                  path="/llm-providers"
                  element={
                    <ProtectedRoute permission="llm_catalog.edit">
                      <LlmProvidersPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/llm-providers/:enumValue"
                  element={
                    <ProtectedRoute permission="llm_catalog.edit">
                      <EditLlmProviderPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/members/new"
                  element={
                    <ProtectedRoute permission="members.edit">
                      <EditMemberPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/members/:memberId"
                  element={
                    <ProtectedRoute permission="members.edit">
                      <EditMemberPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/prompts"
                  element={
                    <ProtectedRoute permission="prompts.view">
                      <PromptsPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/prompts/new"
                  element={
                    <ProtectedRoute permission="prompts.edit">
                      <EditPromptPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/prompts/:promptId"
                  element={
                    <ProtectedRoute permission="prompts.edit">
                      <EditPromptPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/teams"
                  element={
                    <ProtectedRoute permission="teams.view">
                      <TeamsPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/teams/new"
                  element={
                    <ProtectedRoute permission="teams.edit">
                      <EditTeamPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/teams/:teamId"
                  element={
                    <ProtectedRoute permission="teams.edit">
                      <EditTeamPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/users/integrations"
                  element={
                    <ProtectedRoute permission="users.edit">
                      <UserIntegrationsPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/users/:userId"
                  element={
                    <ProtectedRoute permission="users.edit">
                      <EditUserPage />
                    </ProtectedRoute>
                  }
                />
                <Route path="/profile" element={<ProfilePage />} />
                <Route
                  path="/notifications"
                  element={
                    <ProtectedRoute permission="notifications.view">
                      <NotificationsPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/notifications/new"
                  element={
                    <ProtectedRoute permission="notifications.edit">
                      <EditNotificationPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/notifications/:id"
                  element={
                    <ProtectedRoute permission="notifications.edit">
                      <EditNotificationPage />
                    </ProtectedRoute>
                  }
                />
                <Route path="/tasks" element={<TasksPage />} />
                <Route
                  path="/audit"
                  element={
                    <ProtectedRoute permission="audit.view">
                      <AuditPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/governance"
                  element={
                    <ProtectedRoute permission="governance.view">
                      <GovernanceRecordsPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/drift"
                  element={
                    <ProtectedRoute permission="drift.view">
                      <LLMDriftPage />
                    </ProtectedRoute>
                  }
                />
                <Route path="/settings" element={<SettingsPage termsEnabled={termsEnabled} />} />
                <Route
                  path="/policy-definitions/new"
                  element={
                    <ProtectedRoute permission="settings.edit">
                      <EditPolicyDefinitionPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/policy-definitions/:id"
                  element={
                    <ProtectedRoute permission="settings.edit">
                      <EditPolicyDefinitionPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/logs"
                  element={
                    <ProtectedRoute permission="logs.view">
                      <LogsPage />
                    </ProtectedRoute>
                  }
                />
                <Route path="/system-metrics" element={<SystemMetricsPage />} />
                <Route
                  path="/jwt-verification-strategies/new"
                  element={
                    <ProtectedRoute permission="jwt_verification_strategies.edit">
                      <EditJwtVerificationStrategyPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/jwt-verification-strategies/:id"
                  element={
                    <ProtectedRoute permission="jwt_verification_strategies.edit">
                      <EditJwtVerificationStrategyPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/oauth-identifiers/new"
                  element={
                    <ProtectedRoute permission="oauth_identifiers.edit">
                      <EditOAuthIdentifierPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/oauth-identifiers/:id"
                  element={
                    <ProtectedRoute permission="oauth_identifiers.edit">
                      <EditOAuthIdentifierPage />
                    </ProtectedRoute>
                  }
                />
              </Routes>
            </Suspense>
          </div>

          <footer className="sticky-footer">
            <div className="container my-auto">
              <div className="copyright text-center my-auto">
                <span>
                  Copyright © Affinidi Pte Ltd {new Date().getFullYear()}. Licensed under the Apache
                  License 2.0.
                  {version && <> · v{version}</>}
                </span>
              </div>
            </div>
          </footer>
        </div>
      </div>

      <button
        className="scroll-to-top rounded"
        onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
        style={{ display: 'none' }}
        title="Scroll to top"
      >
        <i className="fas fa-angle-up"></i>
      </button>

      {state.error && (
        <div
          className="position-fixed alert alert-danger alert-dismissible fade show"
          style={{
            top: '20px',
            right: '20px',
            zIndex: 1055,
            maxWidth: '400px',
          }}
        >
          <strong>Error!</strong> {state.error}
          <button type="button" className="btn-close" onClick={() => {}} aria-label="Close" />
        </div>
      )}

      {/* Reconnecting Modal - shows when WebSocket is trying to reconnect */}
      {state.showReconnectingModal && (
        <>
          <div className="modal-backdrop fade show" style={{ zIndex: 1050 }}></div>
          <div
            className="modal fade show"
            style={{
              display: 'block',
              zIndex: 1055,
            }}
            tabIndex={-1}
          >
            <div className="modal-dialog modal-dialog-centered">
              <div className="modal-content">
                <div className="modal-body text-center py-5">
                  <div
                    className="spinner-border text-primary mb-3"
                    role="status"
                    style={{ width: '3rem', height: '3rem' }}
                  ></div>
                  <h5 className="mb-2">Reconnecting to Agent Stream...</h5>
                  <p className="text-muted mb-0">
                    Connection was interrupted - attempting to restore it
                  </p>
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
};

const AuthenticatedApp: React.FC<AuthenticatedAppProps> = ({ onLogout, termsEnabled }) => {
  return (
    <AppProvider>
      <PermissionsProvider>
        <PageTitleProvider>
          <AppContent onLogout={onLogout} termsEnabled={termsEnabled} />
        </PageTitleProvider>
      </PermissionsProvider>
    </AppProvider>
  );
};

export default AuthenticatedApp;
