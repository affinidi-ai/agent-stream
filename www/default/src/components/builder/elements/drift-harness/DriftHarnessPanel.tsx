import React from 'react';
import type { ConfigPanelProps } from '../types';
import { useOptionalSurfaceMeta } from '../../SurfaceMetaContext';
import { summarizeDrift } from '../surface/SurfacePanel';

/**
 * Sidebar summary for the **Drift Harness** element. All drift configuration
 * (monitoring, replay evaluation, alerting) lives in the full-page editor; the
 * sidebar carries only the enable switch + a short status line and a Configure
 * button. Drift is a base-pipe field, so the switch writes through the surface
 * meta ({@link useOptionalSurfaceMeta}); the node keeps a mirror enable flag.
 */
const DriftHarnessPanel: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  openFullscreenEditor,
}) => {
  const meta = useOptionalSurfaceMeta();
  const drift = meta?.drift ?? null;
  const enabled = drift?.enabled === true;

  const setEnabled = (v: boolean) => {
    updateField('enabled', v);
    if (!meta?.setDrift) return;
    if (v) {
      meta.setDrift({ ...(drift ?? {}), enabled: true, sample_rate: drift?.sample_rate ?? 1 });
    } else if (drift) {
      meta.setDrift({ ...drift, enabled: false });
    }
  };

  const evalOn = drift?.eval?.enabled === true;
  const alertCount = drift?.alert_integrations?.length ?? 0;
  const status = enabled
    ? [
        summarizeDrift(drift),
        evalOn ? 'replay eval' : null,
        alertCount ? `${alertCount} alert integration${alertCount === 1 ? '' : 's'}` : null,
      ]
        .filter(Boolean)
        .join(' · ')
    : 'Off.';

  return (
    <div className="surface-config-panel">
      <p className="text-muted small">
        Monitor this LLM surface&apos;s behavioural <strong>drift</strong> — refusal rate, safety
        flags, response length, latency, schema validity, plus replay-graded semantic drift — and
        alert when it moves past its pinned baseline. Everything is configured in the full-page
        editor.
      </p>
      <div className="form-check form-switch mb-3">
        <input
          className="form-check-input"
          type="checkbox"
          role="switch"
          id="drift-harness-enabled"
          checked={enabled}
          onChange={e => setEnabled(e.target.checked)}
        />
        <label className="form-check-label" htmlFor="drift-harness-enabled">
          Monitor drift
        </label>
      </div>
      <div className="small text-muted mb-3">{status}</div>
      <button
        type="button"
        className="btn btn-outline-primary btn-sm w-100"
        onClick={() => openFullscreenEditor?.()}
        disabled={!openFullscreenEditor}
      >
        <i className="fas fa-sliders me-1" />
        Configure drift harness…
      </button>
    </div>
  );
};

export default DriftHarnessPanel;
