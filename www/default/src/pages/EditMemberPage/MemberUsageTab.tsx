import React, { useEffect, useMemo, useState } from 'react';
import { apiClient } from '../../api';
import LoadingOverlay from '../../components/usage/LoadingOverlay';
import RejectionBreakdown from '../../components/usage/RejectionBreakdown';
import RejectionTimeline from '../../components/usage/RejectionTimeline';
import TimeRangeScrubber from '../../components/usage/TimeRangeScrubber';
import UsageCharts from '../../components/usage/UsageCharts';
import UsageSummary from '../../components/usage/UsageSummary';
import { useUsageSeries } from '../../components/usage/useUsageSeries';
import {
  memberKey,
  memberSurfaceKey,
  rejectionMemberScope,
  type BreakdownItem,
} from '../../components/usage/usageSeries';

interface MemberUsageTabProps {
  memberId: string;
}

interface PipeSummary {
  id: string;
  name: string;
  pipe_type?: { type?: string };
}

// Telemetry caps a request at 256 keys; reserve one for the member grand total.
const MAX_SURFACE_KEYS = 250;

/**
 * Usage tab for a member: a single time-range slider drives both a window-scoped
 * summary and the spend/token charts, broken down by the surfaces they called —
 * drawn from the same telemetry source as the dashboard and team views so the
 * figures and graphs stay in sync.
 */
const MemberUsageTab: React.FC<MemberUsageTabProps> = ({ memberId }) => {
  const [pipes, setPipes] = useState<PipeSummary[]>([]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const { data } = await apiClient.get<PipeSummary[]>('/pipes');
        if (!cancelled) {
          setPipes((data ?? []).filter(p => p.pipe_type?.type === 'llm'));
        }
      } catch {
        if (!cancelled) setPipes([]);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const breakdownItems = useMemo<BreakdownItem[]>(
    () =>
      pipes.slice(0, MAX_SURFACE_KEYS).map(p => ({
        id: p.id,
        label: p.name || p.id,
        key: memberSurfaceKey(memberId, p.id),
      })),
    [pipes, memberId]
  );
  const keys = useMemo(
    () => (memberId ? [memberKey(memberId), ...breakdownItems.map(b => b.key)] : []),
    [memberId, breakdownItems]
  );

  const u = useUsageSeries(keys, !!memberId);

  // Both the top rail and the one between the charts read the same window state,
  // so dragging either keeps every chart in sync — just like the dashboard.
  const renderScrubber = () => (
    <TimeRangeScrubber
      windowSecs={u.windowSecs}
      endOffsetSecs={u.endOffset}
      domainSecs={u.domainSecs}
      overview={u.overview}
      relevantMetrics={['cost', 'tokens']}
      resolution={u.resolution}
      loading={u.loading}
      resolutionPref={u.resolutionPref}
      onResolution={u.onResolution}
      zoom={u.zoom}
      onZoom={u.onZoom}
      onPreset={u.onPreset}
      onWindowChange={u.onWindowChange}
      onWindowCommit={u.onWindowCommit}
      onLive={u.onLive}
    />
  );

  return (
    <div style={{ position: 'relative' }}>
      <LoadingOverlay active={u.loading} variant="page" />
      <div className="card shadow mb-4">
        <div className="card-body">{renderScrubber()}</div>
      </div>
      <UsageSummary
        series={u.series}
        primaryKey={memberKey(memberId)}
        items={breakdownItems}
        itemHeading="Surface"
        itemsTitle="Per surface"
        emptyItemsText="No surface activity."
      />
      <RejectionTimeline
        scope={rejectionMemberScope(memberId)}
        windowSecs={u.committed.windowSecs}
        endOffset={u.committed.endOffset}
        resolution={u.resolutionPref}
        enabled={!!memberId}
        chartKindPrefix="member"
      />
      <RejectionBreakdown
        scope={rejectionMemberScope(memberId)}
        windowSecs={u.committed.windowSecs}
        endOffset={u.committed.endOffset}
        enabled={!!memberId}
      />
      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-chart-line"></i> Usage over time
          </h6>
        </div>
        <div className="card-body">
          <UsageCharts
            series={u.series}
            stepSecs={u.stepSecs}
            primaryKey={memberKey(memberId)}
            primaryTitle="Member spend & tokens over time"
            breakdownItems={breakdownItems}
            breakdownTitle="Spend by surface"
            chartKindPrefix="member"
            renderScrubber={renderScrubber}
          />
        </div>
      </div>
    </div>
  );
};

export default MemberUsageTab;
