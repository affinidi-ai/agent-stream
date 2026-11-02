import React from 'react';
import { Badge } from '../../components/shared/Badge';
import { formatCost, outcomeTone, recordDisposition } from './governanceHelpers';
import { formatDateTime } from '../../utils/stringUtils';
import type { StoredRecord, SurfaceSummary } from './types';

interface Props {
  records: StoredRecord[];
  loading: boolean;
  selectedId: string | null;
  onSelect: (id: string) => void;
  surface?: SurfaceSummary | null;
}

/** Left-pane list of a surface's signed records, newest first. Each row shows
 * the surface name, description, and id plus the record's disposition and
 * timestamp so an operator can scan the chain before opening a record. */
const GovernanceRecordList: React.FC<Props> = ({
  records,
  loading,
  selectedId,
  onSelect,
  surface,
}) => {
  if (loading) {
    return (
      <div className="text-center text-muted py-5" data-testid="governance-list-loading">
        <div className="spinner-border text-primary" role="status">
          <span className="visually-hidden">Loading…</span>
        </div>
      </div>
    );
  }

  if (records.length === 0) {
    return (
      <div className="text-center text-muted py-5" data-testid="governance-list-empty">
        <i className="fas fa-inbox fa-2x mb-3 d-block" aria-hidden="true"></i>
        No signed records for this surface yet.
      </div>
    );
  }

  return (
    <div className="d-flex flex-column gap-2" data-testid="governance-list">
      {records.map(stored => {
        const { record } = stored;
        const disposition = recordDisposition(record);
        const active = record.record_id === selectedId;
        const name = record.surface_name ?? surface?.surface_name ?? record.surface_id;
        const description = surface?.surface_description;
        return (
          <button
            key={record.record_id}
            type="button"
            className={`governance-record-item text-start${active ? ' governance-record-item--active' : ''}`}
            data-testid={`governance-row-${record.record_id}`}
            aria-pressed={active}
            onClick={() => onSelect(record.record_id)}
          >
            <div className="d-flex justify-content-between align-items-center gap-2">
              <Badge value={disposition} tone={outcomeTone(disposition)} size="sm" />
              <span className="small text-muted">{formatDateTime(record.timestamp, true)}</span>
            </div>
            <div className="small fw-semibold text-truncate mt-1" title={name}>
              {name}
            </div>
            {description && (
              <div className="text-xs text-muted text-truncate" title={description}>
                {description}
              </div>
            )}
            <div
              className="text-xs text-muted font-monospace text-truncate mt-1"
              title={record.surface_id}
            >
              {record.surface_id}
            </div>
            <div className="text-xs text-muted mt-1">
              {record.metrics.total_tokens.toLocaleString()} tok · {formatCost(record.metrics.cost)}
            </div>
          </button>
        );
      })}
    </div>
  );
};

export default GovernanceRecordList;
