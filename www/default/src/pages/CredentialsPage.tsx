import React, { useEffect, useState } from 'react';
import { Tab, Tabs } from 'react-bootstrap';
import { useSearchParams } from 'react-router-dom';
import SearchInput from '../components/shared/SearchInput';
import StrategiesTab from './SettingsPage/StrategiesTab';
import CredentialProvidersTab from './SettingsPage/CredentialProvidersTab';
import CredentialTokensTab from './CredentialsPage/CredentialTokensTab';
import CredentialAuditTab from './CredentialsPage/CredentialAuditTab';
import OAuthIdentifiersTab from './CredentialsPage/OAuthIdentifiersTab';
import { usePermissions } from '../context/PermissionsContext';

type TabKey =
  | 'jwt-verification'
  | 'oauth-identifiers'
  | 'credential-providers'
  | 'credential-tokens'
  | 'credential-audit';
const VALID_TABS: TabKey[] = [
  'jwt-verification',
  'oauth-identifiers',
  'credential-providers',
  'credential-tokens',
  'credential-audit',
];

const CredentialsPage: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const tabFromUrl = searchParams.get('tab') as TabKey | null;
  const initialTab: TabKey =
    tabFromUrl && VALID_TABS.includes(tabFromUrl) ? tabFromUrl : 'jwt-verification';
  const [activeTab, setActiveTab] = useState<TabKey>(initialTab);
  const [searchTerm, setSearchTerm] = useState('');
  const { hasPermission, loading: permissionsLoading } = usePermissions();
  const canViewAudit = !permissionsLoading && hasPermission('audit.view');

  const [strategiesCount, setStrategiesCount] = useState(0);
  const [oauthCount, setOauthCount] = useState(0);
  const [providersCount, setProvidersCount] = useState(0);
  const [tokensCount, setTokensCount] = useState(0);
  const [auditCount, setAuditCount] = useState(0);

  useEffect(() => {
    if (!permissionsLoading && !canViewAudit && activeTab === 'credential-audit') {
      setActiveTab('jwt-verification');
      setSearchParams({ tab: 'jwt-verification' }, { replace: true });
    }
  }, [activeTab, canViewAudit, permissionsLoading, setSearchParams]);

  const filterActive = searchTerm.trim().length > 0;
  const tabBadge = (count: number) => {
    if (!filterActive) return null;
    return (
      <span className="badge text-bg-primary ms-2" style={{ verticalAlign: 'middle' }}>
        {count}
      </span>
    );
  };

  return (
    <div className="container-fluid">
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <div className="d-flex align-items-center">
          <SearchInput
            value={searchTerm}
            onChange={setSearchTerm}
            placeholder="Filter JWT Verification, Providers, Tokens, Audit..."
            width="384px"
          />
        </div>
      </div>

      <Tabs
        activeKey={activeTab}
        onSelect={k => {
          const next = (k as TabKey) || 'jwt-verification';
          setActiveTab(next);
          setSearchParams({ tab: next }, { replace: true });
        }}
        className="mb-4 custom-channel-tabs"
      >
        <Tab
          eventKey="jwt-verification"
          title={
            <>
              <i className="fas fa-id-badge"></i> JWT Verification {tabBadge(strategiesCount)}
            </>
          }
        >
          <StrategiesTab
            externalSearchTerm={searchTerm}
            onFilteredCountChange={setStrategiesCount}
          />
        </Tab>

        <Tab
          eventKey="oauth-identifiers"
          title={
            <>
              <i className="fas fa-fingerprint"></i> OAuth Identifiers {tabBadge(oauthCount)}
            </>
          }
        >
          <OAuthIdentifiersTab
            externalSearchTerm={searchTerm}
            onFilteredCountChange={setOauthCount}
          />
        </Tab>

        <Tab
          eventKey="credential-providers"
          title={
            <>
              <i className="fas fa-id-card"></i> Credential Providers {tabBadge(providersCount)}
            </>
          }
        >
          <CredentialProvidersTab
            externalSearchTerm={searchTerm}
            onFilteredCountChange={setProvidersCount}
          />
        </Tab>

        <Tab
          eventKey="credential-tokens"
          title={
            <>
              <i className="fas fa-lock"></i> Credential Tokens {tabBadge(tokensCount)}
            </>
          }
        >
          <CredentialTokensTab
            externalSearchTerm={searchTerm}
            onFilteredCountChange={setTokensCount}
          />
        </Tab>

        {canViewAudit && (
          <Tab
            eventKey="credential-audit"
            title={
              <>
                <i className="fas fa-clipboard-list"></i> Credential Delegation Audit{' '}
                {tabBadge(auditCount)}
              </>
            }
          >
            <CredentialAuditTab
              externalSearchTerm={searchTerm}
              onFilteredCountChange={setAuditCount}
            />
          </Tab>
        )}
      </Tabs>
    </div>
  );
};

export default CredentialsPage;
