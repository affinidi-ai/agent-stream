import React, { useEffect, useState } from 'react';
import { apiClient } from '../../../../api';
import type { DriftForm } from '../../../../pages/EditPipePage/types';
import { useIntegrationsAccess } from '../../../../hooks/useIntegrationsAccess';
import IntegrationsAdminOnlyNotice from '../../../integrations/IntegrationsAdminOnlyNotice';

/** Minimal `/integrations` row. Drift alerts fire to integrations in the
 * dedicated `llm_drift` ("LLM Drift") category. */
interface IntegrationRow {
  id: string;
  name?: string;
  category?: string;
  status?: string;
  integration_type?: string;
}

interface DriftAlertControlsProps {
  value: DriftForm | null;
  onChange: (v: DriftForm) => void;
  disabled?: boolean;
}

/**
 * Drift-alert delivery: pick the integrations that receive the `drift.detected`
 * alert (from the dedicated **LLM Drift** integration category), and tune how
 * often it re-fires while a surface stays drifting. Blank cadence fields fall
 * back to the gateway `[drift]` defaults.
 */
const DriftAlertControls: React.FC<DriftAlertControlsProps> = ({ value, onChange, disabled }) => {
  const cfg = value ?? { enabled: true };
  const integrationsAccess = useIntegrationsAccess();
  const [integrations, setIntegrations] = useState<IntegrationRow[]>([]);

  useEffect(() => {
    if (integrationsAccess !== 'allowed') return;
    apiClient
      .get<IntegrationRow[]>('/integrations')
      .then(r => setIntegrations(Array.isArray(r.data) ? r.data : []))
      .catch(() => setIntegrations([]));
  }, [integrationsAccess]);

  const driftIntegrations = integrations.filter(
    i => (i.status ?? 'active') === 'active' && i.category === 'llm_drift'
  );
  const selected = cfg.alert_integrations ?? [];
  const toggle = (id: string) => {
    const next = selected.includes(id) ? selected.filter(x => x !== id) : [...selected, id];
    onChange({ ...cfg, enabled: true, alert_integrations: next });
  };

  const cadence = cfg.alert_cadence ?? {};
  const setCadence = (patch: { re_alert_interval_mins?: number; max_alerts?: number }) =>
    onChange({ ...cfg, enabled: true, alert_cadence: { ...cadence, ...patch } });
  const numOrUndef = (raw: string): number | undefined => {
    const n = Number(raw);
    return raw.trim() === '' || Number.isNaN(n) ? undefined : Math.max(0, n);
  };

  return (
    <div>
      <div className="alert alert-info py-2 mb-3" style={{ fontSize: '12px' }}>
        <i className="fas fa-bell me-1" /> When this surface drifts past its baseline, a{' '}
        <strong>drift.detected</strong> alert fires to the integrations you pick here. Create them
        under <strong>Integrations</strong> in the <strong>LLM Drift</strong> category.
      </div>

      <label className="form-label small fw-semibold mb-1">Alert integrations</label>
      {integrationsAccess === 'denied' ? (
        <IntegrationsAdminOnlyNotice
          className="form-text mb-3"
          data-testid="drift-alert-integrations-admin-only"
        />
      ) : driftIntegrations.length === 0 ? (
        <p className="form-text mb-3" data-testid="drift-alert-none">
          No <strong>LLM Drift</strong> integrations yet. Add one (email, Slack, webhook, …) under
          Integrations and choose the <strong>LLM Drift</strong> category, then pick it here.{' '}
          <a
            href="/integrations/integrations/wizard?category=llm_drift"
            target="_blank"
            rel="noopener noreferrer"
            data-testid="drift-alert-create"
          >
            Create one
          </a>
          .
        </p>
      ) : (
        <div className="mb-3" data-testid="drift-alert-integrations">
          {driftIntegrations.map(i => (
            <div className="form-check" key={i.id}>
              <input
                className="form-check-input"
                type="checkbox"
                id={`drift-int-${i.id}`}
                checked={selected.includes(i.id)}
                disabled={disabled}
                onChange={() => toggle(i.id)}
              />
              <label className="form-check-label small" htmlFor={`drift-int-${i.id}`}>
                {i.name || i.id}
                {i.integration_type && <span className="text-muted"> · {i.integration_type}</span>}
              </label>
            </div>
          ))}
        </div>
      )}

      <label className="form-label small fw-semibold mb-1">Alert cadence</label>
      <p className="form-text mt-0 mb-2">
        The alert fires once when the surface enters drift, then re-fires on this cadence while it
        stays drifting (capped per baseline). It goes quiet once the surface recovers or you re-pin
        the baseline. Leave a field blank to use the gateway default.
      </p>
      <div className="row g-2" style={{ maxWidth: 460 }}>
        <div className="col-6">
          <label htmlFor="drift-realert" className="form-label small mb-1">
            Re-alert every (minutes)
          </label>
          <input
            type="number"
            className="form-control form-control-sm"
            id="drift-realert"
            data-testid="drift-realert"
            min={1}
            step={5}
            placeholder="gateway default"
            value={cadence.re_alert_interval_mins ?? ''}
            disabled={disabled}
            onChange={e => setCadence({ re_alert_interval_mins: numOrUndef(e.target.value) })}
          />
        </div>
        <div className="col-6">
          <label htmlFor="drift-maxalerts" className="form-label small mb-1">
            Max alerts per baseline
          </label>
          <input
            type="number"
            className="form-control form-control-sm"
            id="drift-maxalerts"
            data-testid="drift-maxalerts"
            min={0}
            step={1}
            placeholder="gateway default"
            value={cadence.max_alerts ?? ''}
            disabled={disabled}
            onChange={e => setCadence({ max_alerts: numOrUndef(e.target.value) })}
          />
          <div className="form-text">0 = unlimited</div>
        </div>
      </div>
    </div>
  );
};

export default DriftAlertControls;
