import React, { useEffect, useState } from 'react';
import { apiClient } from '../../api';
import InfoTooltip from './InfoTooltip';
import { AppButton } from '../../components/shared/AppButton';
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
  const [teams, setTeams] = useState<Array<{ id: string; name: string }>>([]);

  useEffect(() => {
    let alive = true;
    apiClient
      .get<Array<{ id: string; name: string; status?: string }>>('/teams')
      .then(r => {
        if (!alive) return;
        const list = Array.isArray(r.data) ? r.data : [];
        setTeams(list.filter(t => t.status !== 'deleted').map(t => ({ id: t.id, name: t.name })));
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);

  const update = (index: number, next: TeamAssignmentRule) => {
    onChange(rules.map((rule, i) => (i === index ? next : rule)));
  };

  const remove = (index: number) => onChange(rules.filter((_, i) => i !== index));

  return (
    <div className="mb-3">
      <label className="form-label fw-bold">
        Team assignment rules
        <InfoTooltip
          title="Team assignment rules"
          text="Which teams a newly enrolled member joins. Rules run top-down and a member can match several. 'When' limits a rule to callers whose claim matches (e.g. a group); leave it 'Always applies' to add every matched caller."
        />
      </label>
      <p className="text-muted small mb-2">
        Evaluated top-down; a member may match several. Each rule adds the matched member to an
        existing team you pick, or (advanced) to a team derived per-claim so each distinct claim
        value gets its own team.
      </p>

      {rules.map((rule, index) => {
        const when = rule.when ?? null;
        const usesTemplate = rule.team_id_template != null;
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
                <AppButton
                  type="button"
                  variant="outline-danger"
                  size="sm"
                  disabled={disabled}
                  title="Remove rule"
                  data-testid={`team-rule-remove-${index}`}
                  onClick={() => remove(index)}
                >
                  <i className="fas fa-times"></i>
                </AppButton>
              </div>
            </div>

            <div className="row g-2 align-items-start mb-2">
              <div className="col-md-4">
                <label className="form-label small mb-1">
                  Assign to
                  <InfoTooltip
                    title="Assign to"
                    text="'An existing team' adds matched callers to a team you pick from the list. 'A team per claim value' builds a separate team for each distinct value of a claim — e.g. one team per Entra tenant — and can create it automatically on first sight."
                  />
                </label>
                <select
                  className="form-select"
                  value={usesTemplate ? 'template' : 'existing'}
                  disabled={disabled}
                  data-testid={`team-rule-target-mode-${index}`}
                  onChange={e =>
                    update(
                      index,
                      e.target.value === 'template'
                        ? { ...rule, team_id: null, team_id_template: rule.team_id_template ?? '' }
                        : {
                            ...rule,
                            team_id_template: null,
                            ensure_team: false,
                            team_name_template: null,
                            team_defaults: null,
                          }
                    )
                  }
                >
                  <option value="existing">An existing team</option>
                  <option value="template">A team per claim value</option>
                </select>
              </div>
              <div className="col-md-8">
                {usesTemplate ? (
                  <>
                    <label className="form-label small mb-1">Team id template</label>
                    <input
                      type="text"
                      className="form-control"
                      placeholder="tenant-{{claim.tid}}"
                      value={rule.team_id_template ?? ''}
                      disabled={disabled}
                      data-testid={`team-rule-team-template-${index}`}
                      onChange={e => update(index, { ...rule, team_id_template: e.target.value })}
                    />
                    <small className="text-muted">
                      One team per distinct value — e.g.{' '}
                      <code>tenant-&#123;&#123;claim.tid&#125;&#125;</code> gives each Entra tenant
                      its own team. Turn on “Create the team…” below to make it on first sight.
                    </small>
                  </>
                ) : (
                  <>
                    <label className="form-label small mb-1">Team</label>
                    <select
                      className="form-select"
                      value={rule.team_id ?? ''}
                      disabled={disabled}
                      data-testid={`team-rule-team-id-${index}`}
                      onChange={e => update(index, { ...rule, team_id: e.target.value || null })}
                    >
                      <option value="">— select a team —</option>
                      {rule.team_id && !teams.some(t => t.id === rule.team_id) && (
                        <option value={rule.team_id}>{rule.team_id} (not found)</option>
                      )}
                      {teams.map(t => (
                        <option key={t.id} value={t.id}>
                          {t.name}
                        </option>
                      ))}
                    </select>
                    <small className="text-muted">
                      Matched callers are added to this existing team — no need to know its id.
                    </small>
                  </>
                )}
              </div>
            </div>

            {usesTemplate && (
              <>
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
                    <InfoTooltip
                      title="Create the team"
                      text="When on, the derived team is created the first time a caller needs it, using the name template and caps below. When off, a rule pointing at a team that doesn't exist is skipped."
                    />
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
              </>
            )}
          </div>
        );
      })}

      <AppButton
        type="button"
        variant="outline-secondary"
        size="sm"
        disabled={disabled}
        data-testid="team-rule-add"
        onClick={() => onChange([...rules, emptyTeamRule()])}
        iconStart={<i className="fas fa-plus"></i>}
      >
        Add team rule
      </AppButton>
    </div>
  );
};

export default TeamRulesEditor;
