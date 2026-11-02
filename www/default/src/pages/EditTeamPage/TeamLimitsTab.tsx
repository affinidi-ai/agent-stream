import React from 'react';
import CapUsageBar from '../../components/usage/CapUsageBar';
import { teamKey } from '../../components/usage/usageSeries';
import { useCapUsage } from '../../components/usage/useCapUsage';
import { numberOrEmpty, toOptionalNumber, type Team } from './teamHelpers';

interface TeamLimitsTabProps {
  team: Team;
  onUpdate: (patch: Partial<Team>) => void;
}

const TeamLimitsTab: React.FC<TeamLimitsTabProps> = ({ team, onUpdate }) => {
  const usage = useCapUsage(team.id ? teamKey(team.id) : null);
  return (
    <>
      <h6 className="text-primary mt-2">Team-wide monthly caps</h6>
      <p className="text-muted">
        <small>
          Applied to the team&apos;s combined spend and tokens across every surface its members
          call, on top of each member&apos;s own caps.
        </small>
      </p>
      <div className="row">
        <div className="col-md-6 mb-3">
          <label className="form-label">Budget (USD)</label>
          <input
            type="number"
            min="0"
            className="form-control"
            value={numberOrEmpty(team.monthly_budget_usd)}
            onChange={e => onUpdate({ monthly_budget_usd: toOptionalNumber(e.target.value) })}
            placeholder="No limit"
          />
          {usage && (
            <div className="mt-2">
              <CapUsageBar used={usage.cost} cap={team.monthly_budget_usd} kind="usd" />
            </div>
          )}
        </div>
        <div className="col-md-6 mb-3">
          <label className="form-label">Token cap</label>
          <input
            type="number"
            min="0"
            className="form-control"
            value={numberOrEmpty(team.monthly_token_cap)}
            onChange={e => onUpdate({ monthly_token_cap: toOptionalNumber(e.target.value) })}
            placeholder="No limit"
          />
          {usage && (
            <div className="mt-2">
              <CapUsageBar used={usage.tokens} cap={team.monthly_token_cap} kind="tokens" />
            </div>
          )}
        </div>
      </div>
    </>
  );
};

export default TeamLimitsTab;
