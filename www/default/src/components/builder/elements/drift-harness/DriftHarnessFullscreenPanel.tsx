import React from 'react';
import type { ConfigPanelProps } from '../types';
import type { DriftForm } from '../../../../pages/EditPipePage/types';
import { useOptionalSurfaceMeta } from '../../SurfaceMetaContext';
import { DriftMonitoringControls } from '../surface/SurfacePanel';
import DriftAlertControls from './DriftAlertControls';

/**
 * Full-page editor for the **Drift Harness** element. All of a surface's drift
 * configuration lives here — monitoring + replay evaluation ({@link
 * DriftMonitoringControls}) and alerting ({@link DriftAlertControls}) — read and
 * written through the surface meta (`drift` is a base-pipe field), so the small
 * sidebar carries only the enable switch. Mirrors the surface-config fullscreen
 * card so the "Close tab" control is consistent across editors.
 */
const DriftHarnessFullscreenPanel: React.FC<ConfigPanelProps> = ({
  updateField,
  closeFullscreenEditor,
}) => {
  const meta = useOptionalSurfaceMeta();
  // Mirror the enable flag onto the node config so the canvas greys the element
  // out when monitoring is switched off here (muting reads the node config).
  const setDrift = meta?.setDrift
    ? (v: DriftForm | null) => {
        meta.setDrift?.(v);
        updateField('enabled', v?.enabled === true);
      }
    : undefined;

  return (
    <div className="surface-config-fullscreen">
      {setDrift ? (
        <>
          <div className="card shadow-sm mb-4">
            <div className="card-header bg-light d-flex justify-content-between align-items-center">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-wave-square me-2" />
                Drift Harness — behavioural drift monitoring
              </h6>
              {closeFullscreenEditor && (
                <button
                  type="button"
                  className="btn btn-sm btn-outline-secondary"
                  onClick={closeFullscreenEditor}
                >
                  <i className="fas fa-times me-1" />
                  Close tab
                </button>
              )}
            </div>
            <div className="card-body">
              <DriftMonitoringControls value={meta?.drift ?? null} onChange={setDrift} />
            </div>
          </div>

          <div className="card shadow-sm mb-4">
            <div className="card-header bg-light d-flex align-items-center">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-bell me-2" />
                Drift alerts
              </h6>
            </div>
            <div className="card-body">
              <DriftAlertControls value={meta?.drift ?? null} onChange={setDrift} />
            </div>
          </div>
        </>
      ) : (
        <div className="card shadow-sm mb-4">
          <div className="card-body">
            <div className="text-muted small">Drift monitoring is unavailable in this context.</div>
          </div>
        </div>
      )}
    </div>
  );
};

export default DriftHarnessFullscreenPanel;
