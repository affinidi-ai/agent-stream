import React, { useState } from 'react';
import { Tab, Tabs } from 'react-bootstrap';
import { useSearchParams } from 'react-router-dom';
import SearchInput from '../components/shared/SearchInput';
import PolicyListTab from './PoliciesPage/PolicyListTab';

type TabKey = 'appliance' | 'llm' | 'ide';

const PoliciesPage: React.FC = () => {
  const validTabs: TabKey[] = ['appliance', 'llm', 'ide'];

  const [searchParams, setSearchParams] = useSearchParams();
  const tabFromUrl = searchParams.get('tab') as TabKey | null;
  const initialTab: TabKey =
    tabFromUrl && validTabs.includes(tabFromUrl) ? tabFromUrl : 'appliance';
  const [activeTab, setActiveTab] = useState<TabKey>(initialTab);
  const [searchTerm, setSearchTerm] = useState('');

  const [applianceCount, setApplianceCount] = useState(0);
  const [llmCount, setLlmCount] = useState(0);
  const [ideCount, setIdeCount] = useState(0);

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
        <SearchInput
          value={searchTerm}
          onChange={setSearchTerm}
          placeholder="Filter policies..."
          width="384px"
        />
      </div>

      <Tabs
        activeKey={activeTab}
        onSelect={k => {
          const next = (k as TabKey) || 'appliance';
          setActiveTab(next);
          setSearchParams({ tab: next }, { replace: true });
        }}
        className="mb-4 custom-channel-tabs"
      >
        <Tab
          eventKey="appliance"
          title={
            <>
              <i className="fas fa-shield-alt"></i> Trust Fabric {tabBadge(applianceCount)}
            </>
          }
        >
          <PolicyListTab
            policyType="appliance"
            label="Trust Fabric"
            icon="fa-shield-alt"
            externalSearchTerm={searchTerm}
            onFilteredCountChange={setApplianceCount}
          />
        </Tab>

        <Tab
          eventKey="llm"
          title={
            <>
              <i className="fas fa-project-diagram"></i> LLM Policies {tabBadge(llmCount)}
            </>
          }
        >
          <PolicyListTab
            policyType="llm"
            label="LLM"
            icon="fa-project-diagram"
            externalSearchTerm={searchTerm}
            onFilteredCountChange={setLlmCount}
          />
        </Tab>

        <Tab
          eventKey="ide"
          title={
            <>
              <i className="fas fa-laptop-code"></i> IDE Policies {tabBadge(ideCount)}
            </>
          }
        >
          <PolicyListTab
            policyType="ide"
            label="IDE"
            icon="fa-laptop-code"
            externalSearchTerm={searchTerm}
            onFilteredCountChange={setIdeCount}
          />
        </Tab>
      </Tabs>
    </div>
  );
};

export default PoliciesPage;
