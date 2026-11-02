import React, { useCallback, useState } from 'react';
import { Tab, Tabs } from 'react-bootstrap';
import { useSearchParams } from 'react-router-dom';
import SearchInput from '../components/shared/SearchInput';
import GatewaysPage from './GatewaysPage';
import MediatorsPage from './MediatorsPage';

type TabKey = 'gateways' | 'mediators';

interface TabCount {
  filtered: number;
  total: number;
}

const VALID_TABS: TabKey[] = ['gateways', 'mediators'];

const ConnectionsPage: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const tabFromUrl = searchParams.get('tab') as TabKey | null;
  const initialTab: TabKey =
    tabFromUrl && VALID_TABS.includes(tabFromUrl) ? tabFromUrl : 'gateways';
  const [activeTab, setActiveTab] = useState<TabKey>(initialTab);
  const [searchTerm, setSearchTerm] = useState('');
  const [counts, setCounts] = useState<Record<TabKey, TabCount>>({
    gateways: { filtered: 0, total: 0 },
    mediators: { filtered: 0, total: 0 },
  });

  // Stable per-tab count setters so the embedded pages' useEffect deps
  // don't churn on every parent render.
  const setGatewaysCount = useCallback((filtered: number, total: number) => {
    setCounts(prev =>
      prev.gateways.filtered === filtered && prev.gateways.total === total
        ? prev
        : { ...prev, gateways: { filtered, total } }
    );
  }, []);
  const setMediatorsCount = useCallback((filtered: number, total: number) => {
    setCounts(prev =>
      prev.mediators.filtered === filtered && prev.mediators.total === total
        ? prev
        : { ...prev, mediators: { filtered, total } }
    );
  }, []);

  const filterActive = searchTerm.trim().length > 0;

  const tabBadge = (key: TabKey) => {
    if (!filterActive) return null;
    const c = counts[key];
    return (
      <span className="badge text-bg-primary ms-2" style={{ verticalAlign: 'middle' }}>
        {c.filtered}
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
            placeholder="Filter Connections..."
            width="384px"
          />
        </div>
      </div>

      <Tabs
        activeKey={activeTab}
        onSelect={k => {
          const next = (k as TabKey) || 'gateways';
          setActiveTab(next);
          setSearchParams({ tab: next }, { replace: true });
        }}
        className="mb-4 custom-channel-tabs"
      >
        <Tab
          eventKey="gateways"
          title={
            <>
              <i className="fas fa-server"></i> Gateways {tabBadge('gateways')}
            </>
          }
        >
          <GatewaysPage externalSearchTerm={searchTerm} onCountChange={setGatewaysCount} />
        </Tab>

        <Tab
          eventKey="mediators"
          title={
            <>
              <i className="fas fa-exchange-alt"></i> Mediators {tabBadge('mediators')}
            </>
          }
        >
          <MediatorsPage externalSearchTerm={searchTerm} onCountChange={setMediatorsCount} />
        </Tab>
      </Tabs>
    </div>
  );
};

export default ConnectionsPage;
