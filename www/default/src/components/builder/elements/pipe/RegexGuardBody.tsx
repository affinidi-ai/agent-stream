import React from 'react';
import { type PipePromptGuardPattern } from './pipePanelData';
import WhenDetected, { type HandlingChoice } from './WhenDetected';
import { DEFAULT_REJECTION, type RejectionConfig } from './llmPii';
import { type PromptGuard, type RegexRule } from './regexGuard';

const BADGE_WIDTH = 110;

const RuleRow: React.FC<{
  rule: RegexRule;
  index: number;
  patterns: PipePromptGuardPattern[];
  onUpdate: (index: number, rule: RegexRule) => void;
  onRemove: (index: number) => void;
}> = ({ rule, index, patterns, onUpdate, onRemove }) => {
  const isBuiltin = !!rule.builtin;
  const builtinInfo = patterns.find(b => b.key === rule.builtin);

  return (
    <div
      className="d-flex align-items-center mb-2 p-2 rounded"
      style={{ background: 'rgba(0,0,0,0.02)', border: '1px solid rgba(0,0,0,0.06)' }}
    >
      <span
        className={`badge ${isBuiltin ? 'text-bg-info' : 'text-bg-secondary'} me-2 d-inline-flex align-items-center justify-content-center`}
        style={{
          fontSize: '12px',
          width: BADGE_WIDTH,
          minWidth: BADGE_WIDTH,
          maxWidth: BADGE_WIDTH,
        }}
      >
        <i
          className={`fas ${isBuiltin ? builtinInfo?.icon || 'fa-shield-alt' : 'fa-code'} me-1`}
        ></i>
        {isBuiltin ? 'Built-in' : 'Custom'}
      </span>

      {isBuiltin ? (
        <select
          className="form-control form-control-sm dropdown-styling me-2"
          style={{ width: '220px', minWidth: '220px', maxWidth: '220px' }}
          value={rule.builtin || ''}
          onChange={e => onUpdate(index, { builtin: e.target.value })}
        >
          {patterns.map(bp => (
            <option key={bp.key} value={bp.key}>
              {bp.label}
            </option>
          ))}
        </select>
      ) : (
        <input
          type="text"
          className="form-control form-control-sm me-2"
          style={{ width: '220px', minWidth: '220px', maxWidth: '220px' }}
          placeholder="Label (optional)"
          value={rule.label || ''}
          onChange={e => onUpdate(index, { ...rule, label: e.target.value || undefined })}
        />
      )}

      <input
        type="text"
        className="form-control form-control-sm flex-grow-1"
        style={{ fontFamily: 'monospace', fontSize: '13px' }}
        placeholder={isBuiltin ? '' : 'Regex pattern, e.g. password[=:]\\s*\\S+'}
        value={isBuiltin ? builtinInfo?.regex || '' : rule.pattern || ''}
        readOnly={isBuiltin}
        onChange={
          isBuiltin ? undefined : e => onUpdate(index, { ...rule, pattern: e.target.value })
        }
      />

      <button
        type="button"
        className="btn btn-sm btn-outline-danger ms-2"
        onClick={() => onRemove(index)}
        title="Remove rule"
        style={{ minWidth: '32px' }}
      >
        <i className="fas fa-times"></i>
      </button>
    </div>
  );
};

interface RegexGuardBodyProps {
  guard: PromptGuard;
  phase: 'request' | 'response';
  patterns: PipePromptGuardPattern[];
  idPrefix: string;
  onChange: (guard: PromptGuard) => void;
}

/** Detect-then-act body for a regex Prompt Guard: the rule list, then (once at
 *  least one rule exists) the shared "When detected" control. */
const RegexGuardBody: React.FC<RegexGuardBodyProps> = ({
  guard,
  phase,
  patterns,
  idPrefix,
  onChange,
}) => {
  const rules = guard.regex.rules ?? [];

  const updateRule = (ruleIndex: number, rule: RegexRule) => {
    const next = [...rules];
    next[ruleIndex] = rule;
    onChange({ ...guard, regex: { ...guard.regex, rules: next } });
  };
  const removeRule = (ruleIndex: number) =>
    onChange({
      ...guard,
      regex: { ...guard.regex, rules: rules.filter((_, i) => i !== ruleIndex) },
    });
  const addBuiltinRule = () => {
    const used = rules.filter(r => r.builtin).map(r => r.builtin);
    const available = patterns.find(bp => !used.includes(bp.key));
    const rule: RegexRule = { builtin: available?.key || patterns[0]?.key || 'ssn' };
    onChange({ ...guard, regex: { ...guard.regex, rules: [...rules, rule] } });
  };
  const addCustomRule = () =>
    onChange({
      ...guard,
      regex: { ...guard.regex, rules: [...rules, { pattern: '', label: '' }] },
    });

  const handling: HandlingChoice =
    guard.regex.action === 'reject'
      ? 'reject'
      : guard.regex.mask_mode === 'pseudonymize'
        ? 'pseudonymize'
        : 'redact';
  const setHandling = (choice: HandlingChoice) => {
    if (choice === 'reject') onChange({ ...guard, regex: { ...guard.regex, action: 'reject' } });
    else onChange({ ...guard, regex: { ...guard.regex, action: 'mask', mask_mode: choice } });
  };
  const updateRejection = (field: keyof RejectionConfig, value: unknown) => {
    const current = guard.rejection || { ...DEFAULT_REJECTION };
    onChange({ ...guard, rejection: { ...current, [field]: value } as RejectionConfig });
  };

  return (
    <>
      <div className="mb-3">
        <label className="font-weight-bold" style={{ fontSize: '13px' }}>
          Detect these patterns
          <small className="text-muted ms-2">({rules.length})</small>
        </label>

        {rules.length === 0 && (
          <div className="alert alert-danger py-2 mb-0" style={{ fontSize: '13px' }}>
            <i className="fas fa-exclamation-circle me-1"></i>
            No patterns yet. Add a built-in PII pattern or a custom regex below.
          </div>
        )}

        {rules.map((rule, ri) => (
          <RuleRow
            key={ri}
            rule={rule}
            index={ri}
            patterns={patterns}
            onUpdate={updateRule}
            onRemove={removeRule}
          />
        ))}

        <div className="mt-2">
          <button
            type="button"
            className="btn btn-sm btn-outline-primary me-2"
            onClick={addBuiltinRule}
          >
            <i className="fas fa-plus me-1"></i>Built-in Pattern
          </button>
          <button
            type="button"
            className="btn btn-sm btn-outline-secondary"
            onClick={addCustomRule}
          >
            <i className="fas fa-plus me-1"></i>Custom Regex
          </button>
        </div>
      </div>

      {rules.length > 0 && (
        <WhenDetected
          idPrefix={idPrefix}
          value={handling}
          onChange={setHandling}
          rejection={guard.rejection}
          onRejectionChange={updateRejection}
          pseudonymizeOptions={
            phase === 'request' ? (
              <>
                <div className="custom-control custom-switch mt-2">
                  <input
                    type="checkbox"
                    className="custom-control-input"
                    id={`${idPrefix}-restore`}
                    data-testid="prompt-guard-restore-in-response"
                    checked={guard.regex.restore_in_response === true}
                    onChange={e =>
                      onChange({
                        ...guard,
                        regex: { ...guard.regex, restore_in_response: e.target.checked },
                      })
                    }
                  />
                  <label
                    className="custom-control-label"
                    htmlFor={`${idPrefix}-restore`}
                    style={{ fontSize: '13px' }}
                  >
                    Restore original values in the response
                  </label>
                  <small className="form-text text-muted">
                    The models (provider, Judge/Jury, witnesses) only ever see the NER IDs; the real
                    values are put back in the completion before it reaches the caller. Buffered
                    (non-streaming) responses only.
                  </small>
                </div>
                <div className="custom-control custom-switch mt-2">
                  <input
                    type="checkbox"
                    className="custom-control-input"
                    id={`${idPrefix}-pronouns`}
                    data-testid="prompt-guard-link-pronouns"
                    checked={guard.regex.link_pronouns === true}
                    onChange={e =>
                      onChange({
                        ...guard,
                        regex: { ...guard.regex, link_pronouns: e.target.checked },
                      })
                    }
                  />
                  <label
                    className="custom-control-label"
                    htmlFor={`${idPrefix}-pronouns`}
                    style={{ fontSize: '13px' }}
                  >
                    Link pronouns to a person's NER ID
                  </label>
                  <small className="form-text text-muted">
                    When exactly one person is named, gendered pronouns (he/she) that follow reuse
                    that person's NER ID. Left untouched when two or more people are present.
                  </small>
                </div>
              </>
            ) : undefined
          }
        />
      )}
    </>
  );
};

export default RegexGuardBody;
