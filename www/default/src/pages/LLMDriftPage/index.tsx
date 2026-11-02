import React, { useState } from 'react';
import { Tab, Tabs } from 'react-bootstrap';
import { AppButton } from '../../components/shared/AppButton';
import DriftDimensionChart from './DriftDimensionChart';
import HistoryTab from './HistoryTab';
import IndicativeDataSection from './IndicativeDataSection';
import { DRIFT_RANGE_PRESETS, driftStatusTone } from './types';
import { useDriftSeries } from './useDriftSeries';

/**
 * LLM Drift page: pick a drift-monitored surface and a window, and watch each
 * drift dimension (refusal rate, safety-flag rate, response length, latency,
 * schema validity) over time. Read-only, backed by the administrator-gated
 * `/drift/{series,dimensions}` API. These charts live only here — the drift
 * series are a dedicated store the main dashboard never reads.
 */
const LLMDriftPage: React.FC = () => {
  const drift = useDriftSeries();
  const noSurfaces = !drift.loadingSurfaces && drift.surfaces.length === 0;
  const [tab, setTab] = useState<'charts' | 'eval' | 'history'>('charts');

  return (
    <div className="container-fluid drift-page" data-testid="page-drift">
      <Tabs
        activeKey={tab}
        onSelect={k => setTab((k as 'charts' | 'eval' | 'history') || 'charts')}
        className="mb-4 custom-channel-tabs"
      >
        <Tab
          eventKey="charts"
          title={
            <>
              <i className="fas fa-wave-square"></i> Drift over time
            </>
          }
        >
          <div className="card shadow drift-card">
            <div className="card-header py-3 d-flex justify-content-between align-items-center flex-wrap gap-2">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-wave-square me-1" aria-hidden="true"></i> LLM Drift
                {drift.selectedSurfaceId && (
                  <span
                    className={`badge text-bg-${driftStatusTone(drift.overallStatus).tone} ms-2`}
                    data-testid="drift-overall-status"
                  >
                    {driftStatusTone(drift.overallStatus).label}
                  </span>
                )}
              </h6>
              <div className="d-flex align-items-center gap-2 flex-wrap">
                <label htmlFor="drift-surface" className="small text-muted mb-0">
                  Surface
                </label>
                <select
                  id="drift-surface"
                  className="form-select form-select-sm"
                  style={{ width: 'auto' }}
                  data-testid="drift-surface-select"
                  value={drift.selectedSurfaceId ?? ''}
                  disabled={drift.loadingSurfaces || drift.surfaces.length === 0}
                  onChange={e => drift.selectSurface(e.target.value)}
                >
                  {drift.surfaces.length === 0 && <option value="">No surfaces</option>}
                  {drift.surfaces.map(s => (
                    <option key={s.surface_id} value={s.surface_id}>
                      {s.surface_name || s.surface_id}
                    </option>
                  ))}
                </select>

                <div className="btn-group btn-group-sm" role="group" aria-label="Time range">
                  {DRIFT_RANGE_PRESETS.map(preset => (
                    <button
                      key={preset.label}
                      type="button"
                      className={`btn btn-outline-secondary ${
                        drift.rangeSecs === preset.secs ? 'active' : ''
                      }`}
                      data-testid={`drift-range-${preset.label}`}
                      onClick={() => drift.setRangeSecs(preset.secs)}
                    >
                      {preset.label}
                    </button>
                  ))}
                </div>

                <AppButton
                  variant="outline-secondary"
                  size="sm"
                  disabled={!drift.selectedSurfaceId || drift.loadingSeries}
                  onClick={drift.reload}
                  data-testid="drift-refresh"
                  iconStart={<i className="fas fa-sync-alt me-1" aria-hidden="true" />}
                >
                  Refresh
                </AppButton>
                {drift.canManage && (
                  <AppButton
                    variant="primary"
                    size="sm"
                    loading={drift.capturing}
                    loadingLabel="Pinning"
                    disabled={!drift.selectedSurfaceId || drift.loadingSeries}
                    onClick={drift.captureBaseline}
                    data-testid="drift-set-baseline"
                    iconStart={<i className="fas fa-crosshairs me-1" aria-hidden="true" />}
                  >
                    Set baseline
                  </AppButton>
                )}
              </div>
            </div>

            <div className="card-body drift-card-body">
              {!noSurfaces && (
                <p className="small text-muted mb-3" data-testid="drift-baseline-caption">
                  {drift.baselineCapturedAt
                    ? `Baseline pinned ${new Date(drift.baselineCapturedAt).toLocaleString()}. Charts show the current window against the baseline (dashed line).`
                    : 'No baseline pinned yet — set one to start detecting drift against it.'}
                </p>
              )}
              {noSurfaces ? (
                <div className="text-center text-muted py-5" data-testid="drift-no-surfaces">
                  <i className="fas fa-wave-square fa-2x mb-3 d-block" aria-hidden="true"></i>
                  <p className="mb-1">No surfaces are being monitored for drift yet.</p>
                  <p className="small mb-0">
                    Enable drift monitoring on an LLM surface (its <code>drift</code> config block)
                    to start tracking its behavioural drift dimensions over time.
                  </p>
                </div>
              ) : (
                <div className="drift-grid" data-testid="drift-grid">
                  {drift.dimensions.map(info => (
                    <DriftDimensionChart
                      key={info.id}
                      info={info}
                      series={drift.series[info.id]}
                      verdict={drift.verdictByDim[info.id]}
                    />
                  ))}
                </div>
              )}
            </div>
          </div>
        </Tab>
        <Tab
          eventKey="eval"
          title={
            <>
              <i className="fas fa-flask"></i> Evaluation
            </>
          }
        >
          {drift.selectedSurfaceId ? (
            <IndicativeDataSection
              key={drift.selectedSurfaceId}
              surfaceId={drift.selectedSurfaceId}
              surfaces={drift.surfaces}
              canManage={drift.canManage}
              onRan={drift.reload}
              dimensions={drift.dimensions}
            />
          ) : (
            <div className="card shadow drift-card">
              <div
                className="card-body text-center text-muted py-5"
                data-testid="drift-eval-no-surface"
              >
                No drift-monitored surfaces yet. Enable drift monitoring on an LLM surface to run an
                evaluation.
              </div>
            </div>
          )}
        </Tab>
        <Tab
          eventKey="history"
          title={
            <>
              <i className="fas fa-clock-rotate-left"></i> History
            </>
          }
        >
          <HistoryTab
            surfaces={drift.surfaces}
            dimensions={drift.dimensions}
            canManage={drift.canManage}
          />
        </Tab>
      </Tabs>
    </div>
  );
};

export default LLMDriftPage;
