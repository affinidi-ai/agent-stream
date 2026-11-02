import React from 'react';
import type { ConfigPanelProps } from '../types';
import { useOptionalSurfaceMeta } from '../../SurfaceMetaContext';

/**
 * Sidebar summary for the **Router** element. The rules are edited in the
 * full-page editor; the sidebar shows the enable state + a rule-count summary
 * and a Configure button. The node sits first on the inbound edge (routing is
 * the first thing the gateway does); its presence + enable flag gate whether the
 * surface's `routing_rules` are enforced.
 */
const RouterPanel: React.FC<ConfigPanelProps> = ({ config, updateField, openFullscreenEditor }) => {
  const meta = useOptionalSurfaceMeta();
  const rules = meta?.routingRules ?? [];
  const enabled = config?.enabled !== false;
  const setEnabled = (v: boolean) => {
    updateField('enabled', v);
    meta?.setRoutingEnabled?.(v);
  };
  const modalityCount = rules.filter(r => r.match?.kind === 'modality').length;

  return (
    <div className="surface-config-panel">
      <p className="text-muted small">
        Deterministic request routing: match a header, a body field, or an attachment type (image,
        audio, document, realtime voice) and route to a variant. Runs first at the front door.
        Toggle <strong>Enforce routing</strong> off to stop routing (the rules are kept).
      </p>
      <div className="form-check form-switch mb-3">
        <input
          className="form-check-input"
          type="checkbox"
          role="switch"
          id="router-enabled"
          checked={enabled}
          onChange={e => setEnabled(e.target.checked)}
        />
        <label className="form-check-label" htmlFor="router-enabled">
          Enforce routing
        </label>
      </div>
      <div className="small text-muted mb-3">
        {rules.length === 0
          ? 'No rules yet.'
          : `${rules.length} rule${rules.length === 1 ? '' : 's'}${
              modalityCount ? ` · ${modalityCount} by attachment type` : ''
            }.`}
      </div>
      <button
        type="button"
        className="btn btn-outline-primary btn-sm w-100"
        onClick={() => openFullscreenEditor?.()}
        disabled={!openFullscreenEditor}
      >
        <i className="fas fa-sliders me-1" />
        Configure routing rules…
      </button>
    </div>
  );
};

export default RouterPanel;
