import React, { useState } from 'react';
import { Tab, Tabs } from 'react-bootstrap';
import { useNavigate, useSearchParams } from 'react-router-dom';
import EndpointsSection from './EndpointsSection';
import ModelsSection from './ModelsSection';
import ProviderDetailsSection from './ProviderDetailsSection';
import RawSection from './RawSection';
import { useLlmProviderForm } from './useLlmProviderForm';

type TabKey = 'details' | 'endpoints' | 'models' | 'raw';

const PAGE = 'edit-llm-provider';

const EditLlmProviderPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const backTab = searchParams.get('tab');
  const { form, loading, error } = useLlmProviderForm();
  const [tab, setTab] = useState<TabKey>('details');

  if (loading) {
    return (
      <div className="container-fluid text-center py-5" data-testid={`page-${PAGE}`}>
        <div className="spinner-border text-primary" role="status" />
      </div>
    );
  }

  const tabs: { id: TabKey; label: string; icon: string; count?: number }[] = [
    { id: 'details', label: 'Details', icon: 'fa-sliders-h' },
    { id: 'endpoints', label: 'Endpoints', icon: 'fa-plug', count: form.endpoints.length },
    { id: 'models', label: 'Models', icon: 'fa-cube', count: form.models.length },
    { id: 'raw', label: 'JSON', icon: 'fa-code' },
  ];

  return (
    <div className="container-fluid" data-testid={`page-${PAGE}`}>
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <h1 className="h3 mb-0 text-gray-800">
          <i className="fas fa-microchip me-2"></i>
          {form.name || form.enum_value}
        </h1>
        <div>
          <button
            className="btn btn-outline-secondary btn-sm shadow-sm"
            onClick={() => navigate(backTab ? `/llm-providers?tab=${backTab}` : '/llm-providers')}
            data-testid={`${PAGE}-back-button`}
          >
            <i className="fas fa-arrow-left fa-sm me-1"></i> Back
          </button>
        </div>
      </div>

      {error && (
        <div className="alert alert-danger" data-testid={`${PAGE}-error`}>
          <i className="fas fa-exclamation-triangle me-2"></i>
          {error}
        </div>
      )}

      <div className="card shadow mb-4 channel-editor-card">
        <div className="card-body-channel-editor">
          <Tabs
            activeKey={tab}
            onSelect={k => setTab((k as TabKey) || 'details')}
            className="mb-3 custom-channel-tabs"
          >
            {tabs.map(item => (
              <Tab
                key={item.id}
                eventKey={item.id}
                title={
                  <span data-testid={`${PAGE}-tab-${item.id}`}>
                    <i className={`fas ${item.icon}`}></i> {item.label}
                    {item.count !== undefined && (
                      <span className="badge bg-secondary ms-2">{item.count}</span>
                    )}
                  </span>
                }
              >
                {item.id === 'details' && (
                  <ProviderDetailsSection form={form} testId={`${PAGE}-details`} />
                )}
                {item.id === 'endpoints' && (
                  <EndpointsSection endpoints={form.endpoints} testId={`${PAGE}-endpoints`} />
                )}
                {item.id === 'models' && (
                  <ModelsSection models={form.models} testId={`${PAGE}-models`} />
                )}
                {item.id === 'raw' && <RawSection form={form} testId={`${PAGE}-raw`} />}
              </Tab>
            ))}
          </Tabs>
        </div>
      </div>
    </div>
  );
};

export default EditLlmProviderPage;
