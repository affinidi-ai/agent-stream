import React, { useMemo } from 'react';
import LoadingOverlay from '../../components/usage/LoadingOverlay';
import RejectionBreakdown from '../../components/usage/RejectionBreakdown';
import RejectionTimeline from '../../components/usage/RejectionTimeline';
import TimeRangeScrubber from '../../components/usage/TimeRangeScrubber';
import UsageCharts from '../../components/usage/UsageCharts';
import UsageSummary from '../../components/usage/UsageSummary';
import { useUsageSeries } from '../../components/usage/useUsageSeries';
import {
  memberKey,
  rejectionTeamScope,
  teamKey,
  type BreakdownItem,
} from '../../components/usage/usageSeries';
import { type TeamUsageReport } from './teamHelpers';

interface TeamUsageTabProps {
  teamId: string;
  usage: TeamUsageReport | null;
  usageLoading: boolean;
}

/**
 * Usage tab: a single time-range slider drives both a window-scoped summary and
 * the spend/token charts, all from one telemetry source so the figures and the
 * graphs stay in sync. The `/teams/{id}/usage` report supplies only the member
 * roster + labels; every spend/token figure comes from the series.
 */
const TeamUsageTab: React.FC<TeamUsageTabProps> = ({ teamId, usage, usageLoading }) => {
  const breakdownItems = useMemo<BreakdownItem[]>(
    () =>
      (usage?.members ?? []).map(m => ({
        id: m.member_id,
        label: m.label,
        key: memberKey(m.member_id),
      })),
    [usage]
  );
  const keys = useMemo(
    () => (teamId ? [teamKey(teamId), ...breakdownItems.map(b => b.key)] : []),
    [teamId, breakdownItems]
  );

  const u = useUsageSeries(keys, !!teamId);

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
      <LoadingOverlay active={u.loading || usageLoading} variant="page" />
      <div className="card shadow mb-4">
        <div className="card-body">{renderScrubber()}</div>
      </div>
      <UsageSummary
        series={u.series}
        primaryKey={teamKey(teamId)}
        items={breakdownItems}
        itemHeading="Member"
        itemsTitle="Per member"
        emptyItemsText="No members."
      />
      <RejectionTimeline
        scope={rejectionTeamScope(teamId)}
        windowSecs={u.committed.windowSecs}
        endOffset={u.committed.endOffset}
        resolution={u.resolutionPref}
        enabled={!!teamId}
        chartKindPrefix="team"
      />
      <RejectionBreakdown
        scope={rejectionTeamScope(teamId)}
        windowSecs={u.committed.windowSecs}
        endOffset={u.committed.endOffset}
        enabled={!!teamId}
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
            primaryKey={teamKey(teamId)}
            primaryTitle="Team spend & tokens over time"
            breakdownItems={breakdownItems}
            breakdownTitle="Member spend over time"
            chartKindPrefix="team"
            renderScrubber={renderScrubber}
          />
        </div>
      </div>
    </div>
  );
};

export default TeamUsageTab;
