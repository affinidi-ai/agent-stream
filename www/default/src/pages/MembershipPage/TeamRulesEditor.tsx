import React from 'react';
import {
  TEAM_MATCH_LABELS,
  emptyTeamRule,
  numOrNull,
  teamMatchForType,
  type TeamAssignmentRule,
  type TeamRuleMatch,
  type TeamRuleMatchType,
} from './provisioningHelpers';

interface TeamRulesEditorProps {
  rules: TeamAssignmentRule[];
  disabled: boolean;
  onChange: (rules: TeamAssignmentRule[]) => void;
}

const MATCH_TYPES: TeamRuleMatchType[] = ['claim_equals', 'claim_contains', 'claim_present'];

const matchValue = (match: TeamRuleMatch): string => {
  if (match.type === 'claim_equals') return match.equals;
  if (match.type === 'claim_contains') return match.contains;
  return '';
};

const withMatchValue = (match: TeamRuleMatch, value: string): TeamRuleMatch => {
  if (match.type === 'claim_equals') return { ...match, equals: value };
  if (match.type === 'claim_contains') return { ...match, contains: value };
  return match;
};

const TeamRulesEditor: React.FC<TeamRulesEditorProps> = ({ rules, disabled, onChange }) => {
  const update = (index: number, next: TeamAssignmentRule) => {
    onChange(rules.map((rule, i) => (i === index ? next : rule)));
  };

  const remove = (index: number) => onChange(rules.filter((_, i) => i !== index));

  return (
    <div className="mb-3">
      <label className="form-label fw-bold">Team assignment rules</label>
      <p className="text-muted small mb-2">
        Evaluated top-down; a member may match several. Each rule adds the member to a fixed team id
        or one derived from claims (e.g. <code>tenant-&#123;&#123;claim.tid&#125;&#125;</code>).
      </p>

      {rules.map((rule, index) => {
        const when = rule.when ?? null;
        return (
          <div className="border rounded p-2 mb-2" key={index}>
            <div className="row g-2 align-items-center mb-2">
              <div className="col-md-3">
                <select
                  className="form-select"
                  value={when ? when.type : ''}
                  disabled={disabled}
                  data-testid={`team-rule-when-type-${index}`}
                  onChange={e =>
                    update(index, {
                      ...rule,
                      when: e.target.value
                        ? teamMatchForType(e.target.value as TeamRuleMatchType)
                        : null,
                    })
                  }
                >
                  <option value="">Always applies</option>
                  {MATCH_TYPES.map(type => (
                    <option key={type} value={type}>
                      {TEAM_MATCH_LABELS[type]}
                    </option>
                  ))}
                </select>
              </div>
              {when && (
                <>
                  <div className="col-md-4">
                    <input
                      type="text"
                      className="form-control"
                      placeholder="claim name"
                      value={when.claim}
                      disabled={disabled}
                      data-testid={`team-rule-when-claim-${index}`}
                      onChange={e =>
                        update(index, { ...rule, when: { ...when, claim: e.target.value } })
                      }
                    />
                  </div>
                  {when.type !== 'claim_present' && (
                    <div className="col-md-4">
                      <input
                        type="text"
                        className="form-control"
                        placeholder="expected value"
                        value={matchValue(when)}
                        disabled={disabled}
                        data-testid={`team-rule-when-value-${index}`}
                        onChange={e =>
                          update(index, { ...rule, when: withMatchValue(when, e.target.value) })
                        }
                      />
                    </div>
                  )}
                </>
              )}
              <div className="col-md-1 d-grid ms-auto">
                <button
                  type="button"
                  className="btn btn-outline-danger"
                  disabled={disabled}
                  title="Remove rule"
                  data-testid={`team-rule-remove-${index}`}
                  onClick={() => remove(index)}
                >
                  <i className="fas fa-times"></i>
                </button>
              </div>
            </div>

            <div className="row g-2 align-items-center mb-2">
              <div className="col-md-6">
                <label className="form-label small mb-1">Team id</label>
                <input
                  type="text"
                  className="form-control"
                  placeholder="fixed team id"
                  value={rule.team_id ?? ''}
                  disabled={disabled}
                  data-testid={`team-rule-team-id-${index}`}
                  onChange={e => update(index, { ...rule, team_id: e.target.value || null })}
                />
              </div>
              <div className="col-md-6">
                <label className="form-label small mb-1">Team id template</label>
                <input
                  type="text"
                  className="form-control"
                  placeholder="tenant-{{claim.tid}}"
                  value={rule.team_id_template ?? ''}
                  disabled={disabled}
                  data-testid={`team-rule-team-template-${index}`}
                  onChange={e =>
                    update(index, { ...rule, team_id_template: e.target.value || null })
                  }
                />
              </div>
            </div>

            <div className="form-check form-switch mb-2">
              <input
                className="form-check-input"
                type="checkbox"
                id={`team-rule-ensure-${index}`}
                checked={rule.ensure_team}
                disabled={disabled}
                data-testid={`team-rule-ensure-${index}`}
                onChange={e => update(index, { ...rule, ensure_team: e.target.checked })}
              />
              <label className="form-check-label" htmlFor={`team-rule-ensure-${index}`}>
                Create the team if it doesn&apos;t exist
              </label>
            </div>

            {rule.ensure_team && (
              <div className="row g-2 align-items-center">
                <div className="col-md-4">
                  <input
                    type="text"
                    className="form-control"
                    placeholder="team name template"
                    value={rule.team_name_template ?? ''}
                    disabled={disabled}
                    data-testid={`team-rule-name-template-${index}`}
                    onChange={e =>
                      update(index, { ...rule, team_name_template: e.target.value || null })
                    }
                  />
                </div>
                <div className="col-md-4">
                  <input
                    type="number"
                    className="form-control"
                    placeholder="monthly budget USD"
                    value={rule.team_defaults?.monthly_budget_usd ?? ''}
                    disabled={disabled}
                    data-testid={`team-rule-budget-${index}`}
                    onChange={e =>
                      update(index, {
                        ...rule,
                        team_defaults: {
                          ...rule.team_defaults,
                          monthly_budget_usd: numOrNull(e.target.value),
                        },
                      })
                    }
                  />
                </div>
                <div className="col-md-4">
                  <input
                    type="number"
                    className="form-control"
                    placeholder="monthly token cap"
                    value={rule.team_defaults?.monthly_token_cap ?? ''}
                    disabled={disabled}
                    data-testid={`team-rule-tokens-${index}`}
                    onChange={e =>
                      update(index, {
                        ...rule,
                        team_defaults: {
                          ...rule.team_defaults,
                          monthly_token_cap: numOrNull(e.target.value),
                        },
                      })
                    }
                  />
                </div>
              </div>
            )}
          </div>
        );
      })}

      <button
        type="button"
        className="btn btn-outline-secondary btn-sm"
        disabled={disabled}
        data-testid="team-rule-add"
        onClick={() => onChange([...rules, emptyTeamRule()])}
      >
        <i className="fas fa-plus"></i> Add team rule
      </button>
    </div>
  );
};

export default TeamRulesEditor;
