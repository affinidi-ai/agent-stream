import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Tab, Tabs } from 'react-bootstrap';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { apiClient } from '../api';
import SearchInput from '../components/shared/SearchInput';
import { AppButton } from '../components/shared/AppButton';
import { Badge } from '../components/shared/Badge';
import type { LlmProviderSummary } from './EditLlmProviderPage/types';
import ProviderTable from './LlmProvidersPage/ProviderTable';
import CustomCatalogTab from './LlmProvidersPage/CustomCatalogTab';

const PAGE = 'llm-providers';

type TabKey = 'built-in' | 'custom' | 'json';
const VALID_TABS: TabKey[] = ['built-in', 'custom', 'json'];

const extractError = (message: string): string => {
  const dash = message.indexOf(' - ');
  const tail = dash >= 0 ? message.slice(dash + 3) : message;
  try {
    const parsed = JSON.parse(tail);
    if (parsed && typeof parsed.error === 'string') return parsed.error;
  } catch {
    /* not JSON — fall through */
  }
  return tail || message;
};

const LlmProvidersPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const tabFromUrl = searchParams.get('tab') as TabKey | null;
  const initialTab: TabKey =
    tabFromUrl && VALID_TABS.includes(tabFromUrl) ? tabFromUrl : 'built-in';
  const [activeTab, setActiveTab] = useState<TabKey>(initialTab);

  const [providers, setProviders] = useState<LlmProviderSummary[]>([]);
  const [customProviders, setCustomProviders] = useState<LlmProviderSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [builtInFiltered, setBuiltInFiltered] = useState(0);
  const [customFiltered, setCustomFiltered] = useState(0);

  const [refreshing, setRefreshing] = useState(false);
  const [rollingBack, setRollingBack] = useState(false);
  const [canRollback, setCanRollback] = useState(false);
  const [refreshAvailable, setRefreshAvailable] = useState(false);
  const [refreshMsg, setRefreshMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(
    null
  );
  const loadProviders = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiClient.get<{ providers: LlmProviderSummary[] }>('/llm-providers');
      setProviders(res.data.providers ?? []);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load providers');
    } finally {
      setLoading(false);
    }
  }, []);

  const loadCustomProviders = useCallback(async () => {
    try {
      const res = await apiClient.get<{ providers: LlmProviderSummary[] }>('/llm-providers/custom');
      setCustomProviders(res.data.providers ?? []);
    } catch {
      // A missing/invalid custom file is non-fatal — the tab simply shows empty.
      setCustomProviders([]);
    }
  }, []);

  const loadRefreshStatus = useCallback(async () => {
    try {
      const res = await apiClient.get<{ available: boolean }>('/llm-providers/refresh');
      setRefreshAvailable(res.data.available === true);
    } catch {
      // If availability can't be determined, hide the action rather than risk a
      // guaranteed-to-fail click.
      setRefreshAvailable(false);
    }
  }, []);

  useEffect(() => {
    loadProviders();
    loadCustomProviders();
    loadRefreshStatus();
  }, [loadProviders, loadCustomProviders, loadRefreshStatus]);

  const handleTab = (key: string | null) => {
    if (!key || !VALID_TABS.includes(key as TabKey)) return;
    const tab = key as TabKey;
    setActiveTab(tab);
    setSearchParams(prev => {
      const next = new URLSearchParams(prev);
      next.set('tab', tab);
      return next;
    });
  };

  const builtInEnumValues = useMemo(
    () => new Set(providers.map(p => p.enum_value.toLowerCase())),
    [providers]
  );

  const onView = useCallback(
    (enumValue: string) =>
      navigate(`/llm-providers/${encodeURIComponent(enumValue)}?tab=${activeTab}`),
    [navigate, activeTab]
  );

  const onBuiltInCount = useCallback((filtered: number) => setBuiltInFiltered(filtered), []);
  const onCustomCount = useCallback((filtered: number) => setCustomFiltered(filtered), []);

  const handleRefresh = async () => {
    if (
      !window.confirm(
        'Refresh the built-in models from the published catalog?\n\nThis overwrites the current built-in llm.json.'
      )
    ) {
      return;
    }
    setRefreshing(true);
    setRefreshMsg(null);
    try {
      const res = await apiClient.post<{ providers: number }>('/llm-providers/refresh');
      setRefreshMsg({
        type: 'success',
        text: `Built-in models refreshed — ${res.data.providers} providers loaded.`,
      });
      setCanRollback(true);
      await loadProviders();
    } catch (e) {
      setRefreshMsg({
        type: 'error',
        text: e instanceof Error ? extractError(e.message) : 'Refresh failed',
      });
    } finally {
      setRefreshing(false);
    }
  };

  const handleRollback = async () => {
    setRollingBack(true);
    try {
      const res = await apiClient.post<{ providers: number }>('/llm-providers/refresh/rollback');
      setRefreshMsg({
        type: 'success',
        text: `Restored the previous built-in catalog — ${res.data.providers} providers.`,
      });
      setCanRollback(false);
      await loadProviders();
    } catch (e) {
      setRefreshMsg({
        type: 'error',
        text: e instanceof Error ? extractError(e.message) : 'Rollback failed',
      });
    } finally {
      setRollingBack(false);
    }
  };

  const filterActive = searchTerm.trim().length > 0;
  const tabBadge = (count: number) =>
    filterActive ? (
      <span className="badge text-bg-primary ms-2" style={{ verticalAlign: 'middle' }}>
        {count}
      </span>
    ) : null;

  return (
    <div className="container-fluid" data-testid={`page-${PAGE}`}>
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <div>
          <SearchInput
            value={searchTerm}
            onChange={setSearchTerm}
            placeholder="Filter providers..."
            width="384px"
          />
        </div>
      </div>

      <Tabs activeKey={activeTab} onSelect={handleTab} className="mb-4 custom-channel-tabs">
        <Tab
          eventKey="built-in"
          title={
            <>
              <i className="fas fa-cubes me-1"></i>Built In
              {tabBadge(builtInFiltered)}
            </>
          }
        >
          <div className="card shadow mb-4">
            <div className="card-header py-3 d-flex justify-content-between align-items-center">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-cubes"></i> Built-In
                <Badge
                  value={builtInFiltered}
                  suffix={filterActive ? ` of ${providers.length}` : undefined}
                  className="ms-2"
                  ariaLabel={`${builtInFiltered}${filterActive ? ` of ${providers.length}` : ''} built-in providers`}
                />
              </h6>
              {refreshAvailable && (
                <AppButton
                  variant="outline-primary"
                  size="sm"
                  onClick={handleRefresh}
                  loading={refreshing}
                  loadingLabel="Refreshing…"
                  iconStart={<i className="fas fa-rotate me-1" aria-hidden="true" />}
                  data-testid="llm-refresh-builtin"
                  title="Download the latest published built-in model catalog and reload"
                >
                  Refresh Builtin Models
                </AppButton>
              )}
            </div>
            <div className="card-body">
              {refreshMsg && (
                <div
                  className={`alert alert-${refreshMsg.type === 'success' ? 'success' : 'danger'} d-flex align-items-center justify-content-between`}
                  data-testid="llm-refresh-msg"
                >
                  <span>
                    <i
                      className={`fas ${refreshMsg.type === 'success' ? 'fa-check-circle' : 'fa-exclamation-triangle'} me-2`}
                    ></i>
                    {refreshMsg.text}
                  </span>
                  <span className="d-flex align-items-center gap-2">
                    {canRollback && (
                      <button
                        type="button"
                        className="btn btn-sm btn-outline-secondary"
                        onClick={handleRollback}
                        disabled={rollingBack}
                        data-testid="llm-refresh-rollback"
                      >
                        {rollingBack ? 'Restoring…' : 'Undo (restore previous)'}
                      </button>
                    )}
                    <button
                      type="button"
                      className="btn-close"
                      aria-label="Dismiss"
                      onClick={() => setRefreshMsg(null)}
                    ></button>
                  </span>
                </div>
              )}

              {error && !loading && (
                <div className="alert alert-danger" data-testid={`${PAGE}-error`}>
                  <i className="fas fa-exclamation-triangle me-2"></i>
                  {error}
                  <button className="btn btn-sm btn-outline-danger ms-3" onClick={loadProviders}>
                    Retry
                  </button>
                </div>
              )}

              {loading ? (
                <div className="text-center py-5">
                  <div className="spinner-border text-primary" role="status" />
                </div>
              ) : (
                <ProviderTable
                  providers={providers}
                  searchTerm={searchTerm}
                  testIdPrefix={`${PAGE}-builtin`}
                  onView={onView}
                  onFilteredCountChange={onBuiltInCount}
                  emptyTitle="No built-in providers yet"
                />
              )}
            </div>
          </div>
        </Tab>

        <Tab
          eventKey="custom"
          title={
            <>
              <i className="fas fa-screwdriver-wrench me-1"></i>Custom
              {tabBadge(customFiltered)}
            </>
          }
        >
          <div className="card shadow mb-4">
            <div className="card-header py-3 d-flex justify-content-between align-items-center">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-screwdriver-wrench"></i> Custom
                <Badge
                  value={customFiltered}
                  suffix={filterActive ? ` of ${customProviders.length}` : undefined}
                  className="ms-2"
                  ariaLabel={`${customFiltered}${filterActive ? ` of ${customProviders.length}` : ''} custom providers`}
                />
              </h6>
            </div>
            <div className="card-body">
              <ProviderTable
                providers={customProviders}
                searchTerm={searchTerm}
                testIdPrefix={`${PAGE}-custom`}
                onView={onView}
                onFilteredCountChange={onCustomCount}
                emptyTitle="No custom providers yet"
                emptyLabel="Define your own providers and models as JSON. They're validated on save and appear everywhere the built-ins do."
                emptyCtaLabel="Add via JSON"
                emptyCtaIcon="fa-code"
                emptyCtaClick={() => handleTab('json')}
              />
            </div>
          </div>
        </Tab>

        <Tab
          eventKey="json"
          title={
            <>
              <i className="fas fa-code me-1"></i>JSON
            </>
          }
        >
          <div className="card shadow mb-4">
            <div className="card-header py-3 d-flex justify-content-between align-items-center">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-code"></i> Custom Model (JSON)
              </h6>
            </div>
            <div className="card-body">
              <CustomCatalogTab
                builtInEnumValues={builtInEnumValues}
                onSaved={loadCustomProviders}
                active={activeTab === 'json'}
              />
            </div>
          </div>
        </Tab>
      </Tabs>
    </div>
  );
};

export default LlmProvidersPage;
