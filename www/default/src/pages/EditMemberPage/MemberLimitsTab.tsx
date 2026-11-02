import React from 'react';
import CapUsageBar from '../../components/usage/CapUsageBar';
import {
  allowedModelsText,
  fromDateTimeLocal,
  numberOrEmpty,
  parseAllowedModels,
  toDateTimeLocal,
  toOptionalNumber,
  type Member,
} from './memberHelpers';
import { useMemberPeriodUsage } from './useMemberPeriodUsage';

const formatPeriodBound = (iso: string): string =>
  new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });

interface MemberLimitsTabProps {
  member: Member;
  onUpdate: (patch: Partial<Member>) => void;
}

const MemberLimitsTab: React.FC<MemberLimitsTabProps> = ({ member, onUpdate }) => {
  const usage = useMemberPeriodUsage(member.id);
  return (
    <>
      <h6 className="text-primary mt-2">Monthly caps</h6>
      <p className="text-muted">
        <small>
          Applied across every surface this member calls, on top of any team caps they belong to.
        </small>
      </p>
      <div className="row">
        <div className="col-md-6 mb-3">
          <label className="form-label">Budget (USD)</label>
          <input
            type="number"
            min="0"
            className="form-control"
            value={numberOrEmpty(member.monthly_budget_usd)}
            onChange={e => onUpdate({ monthly_budget_usd: toOptionalNumber(e.target.value) })}
            placeholder="No limit"
          />
          {usage && (
            <div className="mt-2">
              <CapUsageBar used={usage.total_cost} cap={member.monthly_budget_usd} kind="usd" />
            </div>
          )}
        </div>
        <div className="col-md-6 mb-3">
          <label className="form-label">Token cap</label>
          <input
            type="number"
            min="0"
            className="form-control"
            value={numberOrEmpty(member.monthly_token_cap)}
            onChange={e => onUpdate({ monthly_token_cap: toOptionalNumber(e.target.value) })}
            placeholder="No limit"
          />
          {usage && (
            <div className="mt-2">
              <CapUsageBar used={usage.total_tokens} cap={member.monthly_token_cap} kind="tokens" />
            </div>
          )}
        </div>
      </div>

      <h6 className="text-primary mt-2">Budget period</h6>
      <p className="text-muted">
        <small>
          The monthly caps reset on the 1st of each month (UTC). Set a start to reset them on its
          monthly anniversary instead, for example the day a subscription began.
        </small>
      </p>
      <div className="row">
        <div className="col-md-6 mb-3">
          <label className="form-label" htmlFor="member-budget-anchor">
            Resets monthly from
          </label>
          <div className="input-group">
            <input
              id="member-budget-anchor"
              type="datetime-local"
              className="form-control"
              data-testid="member-budget-anchor-input"
              value={toDateTimeLocal(member.budget_period_anchor)}
              onChange={e => onUpdate({ budget_period_anchor: fromDateTimeLocal(e.target.value) })}
            />
            <button
              type="button"
              className="btn btn-outline-secondary"
              data-testid="member-budget-anchor-clear-button"
              disabled={!member.budget_period_anchor}
              onClick={() => onUpdate({ budget_period_anchor: null })}
            >
              Use calendar month
            </button>
          </div>
          {usage && (
            <small className="form-text text-muted" data-testid="member-budget-period">
              Current period: {formatPeriodBound(usage.period_start)} to{' '}
              {formatPeriodBound(usage.period_end)}
            </small>
          )}
        </div>
      </div>

      <h6 className="text-primary mt-2">Per-minute rate limits ("virtual key" RPM/TPM)</h6>
      <p className="text-muted">
        <small>
          Bound this member's short-term burst rate over a trailing 60-second window, across every
          surface they call. Leave empty for no limit. A request over the cap is rejected with{' '}
          <code>429 member_rate_limit_exceeded</code>. Enforced on surfaces that have team
          attribution enforcement on.
        </small>
      </p>
      <div className="row">
        <div className="col-md-6 mb-3">
          <label className="form-label">Requests / minute</label>
          <input
            type="number"
            min="0"
            className="form-control"
            value={numberOrEmpty(member.requests_per_minute)}
            onChange={e => onUpdate({ requests_per_minute: toOptionalNumber(e.target.value) })}
            placeholder="No limit"
          />
        </div>
        <div className="col-md-6 mb-3">
          <label className="form-label">Tokens / minute</label>
          <input
            type="number"
            min="0"
            className="form-control"
            value={numberOrEmpty(member.tokens_per_minute)}
            onChange={e => onUpdate({ tokens_per_minute: toOptionalNumber(e.target.value) })}
            placeholder="No limit"
          />
        </div>
      </div>

      <h6 className="text-primary mt-2">Model access ("virtual key" scope)</h6>
      <p className="text-muted">
        <small>
          Restrict which models this member may invoke. One model name per line (or
          comma-separated). Leave empty for no restriction. A request for a model not in this list
          is rejected with <code>403 model_not_allowed</code>.
        </small>
      </p>
      <div className="mb-3">
        <label className="form-label">Allowed models</label>
        <textarea
          className="form-control"
          rows={4}
          value={allowedModelsText(member.allowed_models)}
          onChange={e => onUpdate({ allowed_models: parseAllowedModels(e.target.value) })}
          placeholder={'gpt-4o-mini\ntext-embedding-3-small'}
        />
      </div>
    </>
  );
};

export default MemberLimitsTab;
