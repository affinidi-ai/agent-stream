import React, { useEffect, useMemo, useState } from 'react';
import { AppButton } from '../../components/shared/AppButton';
import { Badge } from '../../components/shared/Badge';
import GovernanceRecordDetail from './GovernanceRecordDetail';
import GovernanceRecordList from './GovernanceRecordList';
import { useGovernanceRecords } from './useGovernanceRecords';

/**
 * Governance records viewer: pick a surface, scan its signed, chained records,
 * inspect any record's prompt/stages/completion/VC, and verify the surface's
 * tamper-evident hash chain on demand. Read-only — backed by the
 * administrator-gated `/governance/{surfaces,records,verify}` API.
 */
const GovernanceRecordsPage: React.FC = () => {
  const gov = useGovernanceRecords();
  const [selectedRecordId, setSelectedRecordId] = useState<string | null>(null);

  // Keep the selection valid as the record set changes; default to the newest.
  useEffect(() => {
    if (gov.records.length === 0) {
      setSelectedRecordId(null);
    } else if (!gov.records.some(r => r.record.record_id === selectedRecordId)) {
      setSelectedRecordId(gov.records[0].record.record_id);
    }
  }, [gov.records, selectedRecordId]);

  const selected = useMemo(
    () => gov.records.find(r => r.record.record_id === selectedRecordId) ?? null,
    [gov.records, selectedRecordId]
  );

  const noSurfaces = !gov.loadingSurfaces && gov.surfaces.length === 0;

  return (
    <div className="container-fluid governance-page" data-testid="page-governance">
      <div className="card shadow governance-card">
        <div className="card-header py-3 d-flex justify-content-between align-items-center flex-wrap gap-2">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-file-shield me-1" aria-hidden="true"></i> Governance Records
            {gov.records.length > 0 && (
              <Badge value={gov.records.length} tone="secondary" className="ms-2" />
            )}
          </h6>
          <div className="d-flex align-items-center gap-2 flex-wrap">
            <label htmlFor="governance-surface" className="small text-muted mb-0">
              Surface
            </label>
            <select
              id="governance-surface"
              className="form-select form-select-sm"
              style={{ width: 'auto' }}
              data-testid="governance-surface-select"
              value={gov.selectedSurfaceId ?? ''}
              disabled={gov.loadingSurfaces || gov.surfaces.length === 0}
              onChange={e => gov.selectSurface(e.target.value)}
            >
              {gov.surfaces.length === 0 && <option value="">No surfaces</option>}
              {gov.surfaces.map(s => (
                <option key={s.surface_id} value={s.surface_id}>
                  {s.surface_name || s.surface_id}
                </option>
              ))}
            </select>
            <AppButton
              variant="outline-secondary"
              size="sm"
              disabled={!gov.selectedSurfaceId || gov.loadingRecords}
              onClick={gov.reload}
              data-testid="governance-refresh"
              iconStart={<i className="fas fa-sync-alt me-1" aria-hidden="true" />}
            >
              Refresh
            </AppButton>
            <AppButton
              variant="primary"
              size="sm"
              loading={gov.verifying}
              loadingLabel="Verifying"
              disabled={!gov.selectedSurfaceId || gov.records.length === 0}
              onClick={gov.verify}
              data-testid="governance-verify"
              iconStart={<i className="fas fa-shield-halved me-1" aria-hidden="true" />}
            >
              Verify chain
            </AppButton>
          </div>
        </div>

        <div className="card-body governance-card-body">
          {gov.verdict && (
            <div
              className={`alert ${gov.verdict.valid ? 'alert-success' : 'alert-danger'} py-2 px-3 d-flex align-items-center`}
              data-testid="governance-verdict"
              role="status"
            >
              <i
                className={`fas ${gov.verdict.valid ? 'fa-circle-check' : 'fa-circle-xmark'} me-2`}
                aria-hidden="true"
              ></i>
              {gov.verdict.valid
                ? `Chain valid — ${gov.verdict.count} record${gov.verdict.count === 1 ? '' : 's'} verified.`
                : `Chain verification failed: ${gov.verdict.error ?? 'unknown error'}`}
            </div>
          )}

          {noSurfaces ? (
            <div className="text-center text-muted py-5" data-testid="governance-no-surfaces">
              <i className="fas fa-file-shield fa-2x mb-3 d-block" aria-hidden="true"></i>
              <p className="mb-1">No governance records yet.</p>
              <p className="small mb-0">
                Enable governance recording on an LLM surface to start capturing signed,
                tamper-evident records of its interactions.
              </p>
            </div>
          ) : (
            <div className="governance-shell">
              <div className="governance-shell-list">
                <GovernanceRecordList
                  records={gov.records}
                  loading={gov.loadingRecords}
                  selectedId={selectedRecordId}
                  onSelect={setSelectedRecordId}
                  surface={gov.selectedSurface}
                />
              </div>
              <div className="governance-shell-detail">
                <GovernanceRecordDetail stored={selected} surface={gov.selectedSurface} />
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default GovernanceRecordsPage;
