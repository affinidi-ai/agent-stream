import React from 'react';
import InfoTooltip from './InfoTooltip';
import {
  IDENTIFIER_KIND_LABELS,
  SOURCE_LABELS,
  emptyIdentifierRule,
  sourceForType,
  type IdentifierKind,
  type ProvisioningIdentifierRule,
  type ProvisioningSourceType,
} from './provisioningHelpers';

interface IdentifierRulesEditorProps {
  rules: ProvisioningIdentifierRule[];
  disabled: boolean;
  onChange: (rules: ProvisioningIdentifierRule[]) => void;
}

const SOURCE_TYPES: ProvisioningSourceType[] = [
  'jwt_claim',
  'jwt_subject',
  'mtls_subject_cn',
  'mtls_email_san',
  'api_key_name',
];

const KIND_OPTIONS: IdentifierKind[] = ['email', 'subject', 'api_key', 'custom'];

const IdentifierRulesEditor: React.FC<IdentifierRulesEditorProps> = ({
  rules,
  disabled,
  onChange,
}) => {
  const update = (index: number, next: ProvisioningIdentifierRule) => {
    onChange(rules.map((rule, i) => (i === index ? next : rule)));
  };

  const remove = (index: number) => {
    onChange(rules.filter((_, i) => i !== index));
  };

  return (
    <div className="mb-3">
      <label className="form-label fw-bold">
        Identifier rules
        <InfoTooltip
          title="Identifier rules"
          text="How a member's identity is read from the verified caller. Each rule picks a source — a JWT claim, the JWT subject, an mTLS subject CN or email SAN, or the API-key name — and stores that value as an identifier. Rules run top-down and every one that resolves is saved, so the caller is matched by any of them next time. At least one is required."
        />
      </label>
      <p className="text-muted small mb-2">
        Ordered rules deriving a member identifier from the verified caller. Every rule that
        resolves is stored, so the same caller is recognised under any of them next time. At least
        one is required when auto-provisioning is enabled.
      </p>

      {rules.length === 0 && (
        <div className="alert alert-warning py-2 small" role="alert">
          No identifier rules yet — add at least one to enable provisioning.
        </div>
      )}

      {rules.map((rule, index) => (
        <div className="row g-2 align-items-start mb-2" key={index}>
          <div className="col-md-4">
            <select
              className="form-select"
              value={rule.source.type}
              disabled={disabled}
              data-testid={`identifier-rule-source-${index}`}
              onChange={e =>
                update(index, {
                  ...rule,
                  source: sourceForType(e.target.value as ProvisioningSourceType),
                })
              }
            >
              {SOURCE_TYPES.map(type => (
                <option key={type} value={type}>
                  {SOURCE_LABELS[type]}
                </option>
              ))}
            </select>
          </div>
          <div className="col-md-4">
            {rule.source.type === 'jwt_claim' ? (
              <input
                type="text"
                className="form-control"
                placeholder="claim name (e.g. email, oid)"
                value={rule.source.claim}
                disabled={disabled}
                data-testid={`identifier-rule-claim-${index}`}
                onChange={e =>
                  update(index, {
                    ...rule,
                    source: { type: 'jwt_claim', claim: e.target.value },
                  })
                }
              />
            ) : (
              <input type="text" className="form-control" value="—" disabled readOnly />
            )}
          </div>
          <div className="col-md-3">
            <select
              className="form-select"
              value={rule.as_kind ?? ''}
              disabled={disabled}
              data-testid={`identifier-rule-kind-${index}`}
              onChange={e =>
                update(index, {
                  ...rule,
                  as_kind: e.target.value ? (e.target.value as IdentifierKind) : null,
                })
              }
            >
              <option value="">Auto kind</option>
              {KIND_OPTIONS.map(kind => (
                <option key={kind} value={kind}>
                  {IDENTIFIER_KIND_LABELS[kind]}
                </option>
              ))}
            </select>
          </div>
          <div className="col-md-1 d-grid">
            <button
              type="button"
              className="btn btn-outline-danger"
              disabled={disabled}
              title="Remove rule"
              data-testid={`identifier-rule-remove-${index}`}
              onClick={() => remove(index)}
            >
              <i className="fas fa-times"></i>
            </button>
          </div>
        </div>
      ))}

      <button
        type="button"
        className="btn btn-outline-secondary btn-sm"
        disabled={disabled}
        data-testid="identifier-rule-add"
        onClick={() => onChange([...rules, emptyIdentifierRule()])}
      >
        <i className="fas fa-plus"></i> Add identifier rule
      </button>
    </div>
  );
};

export default IdentifierRulesEditor;
