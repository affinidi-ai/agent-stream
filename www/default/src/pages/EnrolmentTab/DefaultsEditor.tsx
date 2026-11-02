import React from 'react';
import InfoTooltip from './InfoTooltip';
import {
  numOrNull,
  parseList,
  type MemberDefaults,
  type MemberProvisioningConfig,
} from './provisioningHelpers';

interface DefaultsEditorProps {
  config: MemberProvisioningConfig;
  disabled: boolean;
  onChange: (patch: Partial<MemberProvisioningConfig>) => void;
}

const DefaultsEditor: React.FC<DefaultsEditorProps> = ({ config, disabled, onChange }) => {
  const defaults = config.member_defaults;

  const patchDefaults = (patch: Partial<MemberDefaults>) => {
    onChange({ member_defaults: { ...defaults, ...patch } });
  };

  return (
    <div className="mb-3">
      <label className="form-label fw-bold">
        Member defaults &amp; safety caps
        <InfoTooltip
          title="Defaults & safety caps"
          text="Limits stamped on each new member at creation, plus appliance-wide guards so a hostile or misconfigured token issuer can't mint members without bound. Blank fields mean no limit."
        />
      </label>
      <p className="text-muted small mb-2">
        Limits stamped on each new member, plus appliance-wide guards against a hostile token issuer
        minting members without bound.
      </p>

      <div className="row g-2 mb-2">
        <div className="col-md-6">
          <label className="form-label small mb-1">
            Name claim
            <InfoTooltip
              title="Name claim"
              text="JWT claim to use as the member's display name, e.g. 'name' or 'preferred_username'. Blank leaves new members unnamed (they show by their identifier)."
            />
          </label>
          <input
            type="text"
            className="form-control"
            placeholder="JWT claim for display name (e.g. name)"
            value={config.name_claim ?? ''}
            disabled={disabled}
            data-testid="provisioning-name-claim"
            onChange={e => onChange({ name_claim: e.target.value || null })}
          />
        </div>
        <div className="col-md-6">
          <label className="form-label small mb-1">
            Allowed models
            <InfoTooltip
              title="Allowed models"
              text="Restricts new members to these model ids (comma-separated), like a per-member virtual-key scope. Blank = no per-member model restriction."
            />
          </label>
          <input
            type="text"
            className="form-control"
            placeholder="comma-separated (blank = inherit)"
            value={(defaults.allowed_models ?? []).join(', ')}
            disabled={disabled}
            data-testid="provisioning-allowed-models"
            onChange={e => {
              const list = parseList(e.target.value);
              patchDefaults({ allowed_models: list.length > 0 ? list : null });
            }}
          />
        </div>
      </div>

      <div className="row g-2 mb-2">
        <div className="col-md-3">
          <label className="form-label small mb-1">
            Monthly budget (USD)
            <InfoTooltip
              title="Monthly budget"
              text="Per-member spend ceiling per calendar month, in USD. Leave blank for unlimited."
            />
          </label>
          <input
            type="number"
            className="form-control"
            value={defaults.monthly_budget_usd ?? ''}
            disabled={disabled}
            data-testid="provisioning-monthly-budget"
            onChange={e => patchDefaults({ monthly_budget_usd: numOrNull(e.target.value) })}
          />
        </div>
        <div className="col-md-3">
          <label className="form-label small mb-1">
            Monthly token cap
            <InfoTooltip
              title="Monthly token cap"
              text="Per-member total-token ceiling per calendar month. Leave blank for unlimited."
            />
          </label>
          <input
            type="number"
            className="form-control"
            value={defaults.monthly_token_cap ?? ''}
            disabled={disabled}
            data-testid="provisioning-monthly-tokens"
            onChange={e => patchDefaults({ monthly_token_cap: numOrNull(e.target.value) })}
          />
        </div>
        <div className="col-md-3">
          <label className="form-label small mb-1">
            Requests / minute
            <InfoTooltip
              title="Requests per minute"
              text="Per-member request rate limit over a trailing 60s window. Leave blank for unlimited."
            />
          </label>
          <input
            type="number"
            className="form-control"
            value={defaults.requests_per_minute ?? ''}
            disabled={disabled}
            data-testid="provisioning-rpm"
            onChange={e => patchDefaults({ requests_per_minute: numOrNull(e.target.value) })}
          />
        </div>
        <div className="col-md-3">
          <label className="form-label small mb-1">
            Tokens / minute
            <InfoTooltip
              title="Tokens per minute"
              text="Per-member token rate limit over a trailing 60s window. Leave blank for unlimited."
            />
          </label>
          <input
            type="number"
            className="form-control"
            value={defaults.tokens_per_minute ?? ''}
            disabled={disabled}
            data-testid="provisioning-tpm"
            onChange={e => patchDefaults({ tokens_per_minute: numOrNull(e.target.value) })}
          />
        </div>
      </div>

      <div className="row g-2">
        <div className="col-md-6">
          <label className="form-label small mb-1">
            Max auto-provisioned members
            <InfoTooltip
              title="Max auto-provisioned members"
              text="Hard ceiling on how many members auto-provisioning may ever create — a guard against a hostile token issuer flooding the registry. Leave blank for unbounded."
            />
          </label>
          <input
            type="number"
            className="form-control"
            value={config.max_auto_provisioned_members ?? ''}
            disabled={disabled}
            data-testid="provisioning-max-members"
            onChange={e => onChange({ max_auto_provisioned_members: numOrNull(e.target.value) })}
          />
        </div>
        <div className="col-md-6">
          <label className="form-label small mb-1">
            Creations / minute
            <InfoTooltip
              title="Creations per minute"
              text="Rate limit on how fast new members can be auto-created, smoothing a burst of first-time callers. Leave blank for unbounded."
            />
          </label>
          <input
            type="number"
            className="form-control"
            value={config.creations_per_minute ?? ''}
            disabled={disabled}
            data-testid="provisioning-cpm"
            onChange={e => onChange({ creations_per_minute: numOrNull(e.target.value) })}
          />
        </div>
      </div>
    </div>
  );
};

export default DefaultsEditor;
