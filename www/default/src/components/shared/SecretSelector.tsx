import React, { useId, useState, useEffect, useRef } from 'react';
import { useOptionalPermissions } from '../../context/PermissionsContext';

/** Sentinel option value: turn the tag filter off and show every secret. */
const SHOW_ALL_VALUE = '__show_all_secrets__';

export interface Secret {
  id: string;
  /** Stable public reference the gateway resolves by; preferred over `id`. */
  secret_id?: string;
  name: string;
  secret_type?: string;
  tags?: string[];
}

interface SecretSelectorProps {
  secrets: Secret[];
  selectedSecretId: string;
  onChange: (secretId: string) => void;
  label?: string;
  required?: boolean;
  /**
   * Grey out the picker — the provider takes no API key
   * (`api_key_validation: "none"`). Shows an explanatory note in place of the
   * dropdown options.
   */
  disabled?: boolean;
  /** Make the picker read-only (e.g. while a form saves) but keep the selection and help text. */
  locked?: boolean;
  helpText?: string;
  /**
   * Case-insensitive regex from the LLM provider definition. A "Filter tags" checkbox always sits
   * to the right of the label so the layout never shifts between providers; it is only enabled when
   * this pattern is non-empty and the provider takes a key, and while enabled the dropdown only
   * offers secrets carrying a matching tag (plus the current selection, so it never silently
   * disappears). An empty or invalid pattern leaves the checkbox disabled.
   */
  filterRegex?: string;
  /** Text for the empty option (default 'Select a secret...'); use 'None' for an optional secret. */
  emptyLabel?: string;
  /** Optional test id applied to the select; the checkbox derives `${testId}-filter-toggle`. */
  testId?: string;
  /**
   * Pick the sole listed secret when nothing is chosen (default true). Turn off where a blank
   * picker means something, such as keeping a saved credential or using a typed value instead.
   */
  autoSelectSole?: boolean;
}

const SecretSelector: React.FC<SecretSelectorProps> = ({
  secrets,
  selectedSecretId,
  onChange,
  label = 'API Key Secret',
  required = false,
  disabled = false,
  locked = false,
  helpText = 'API key secret for authentication with the LLM provider',
  filterRegex = '',
  emptyLabel = 'Select a secret...',
  testId,
  autoSelectSole = true,
}) => {
  const permissions = useOptionalPermissions();
  // Without secrets.view the secret list comes back empty, so a saved reference
  // is unlisted rather than missing.
  const secretsHidden =
    permissions !== undefined && !permissions.loading && !permissions.hasPermission('secrets.view');
  const pattern = filterRegex.trim();
  const hasFilter = pattern.length > 0;
  const [filterEnabled, setFilterEnabled] = useState(hasFilter);
  const checkboxId = useId();
  const selectId = useId();

  // A secret is referenced by its stable secret_id (what the gateway resolves
  // by); fall back to id for callers that already pass the reference as id.
  const keyOf = (s: Secret) => s.secret_id ?? s.id;

  const tagMatcher = React.useMemo<RegExp | null>(() => {
    if (!pattern) return null;
    try {
      return new RegExp(pattern, 'i');
    } catch {
      return null;
    }
  }, [pattern]);

  const matchesTags = (secret: Secret): boolean =>
    tagMatcher !== null && (secret.tags ?? []).some(tag => tagMatcher.test(tag));

  const filterActive = hasFilter && filterEnabled && tagMatcher !== null;
  const visibleSecrets = filterActive
    ? secrets.filter(secret => matchesTags(secret) || keyOf(secret) === selectedSecretId)
    : secrets;

  // Auto-select the sole secret in the (possibly filtered) list when nothing is
  // chosen yet, so a single obvious key doesn't need a manual pick. Tracked per
  // distinct sole id so a deliberate clear isn't immediately undone.
  const soleVisibleId = visibleSecrets.length === 1 ? keyOf(visibleSecrets[0]) : null;
  const autoSelectedRef = useRef<string | null>(null);
  useEffect(() => {
    if (!autoSelectSole || disabled || selectedSecretId || !soleVisibleId) return;
    if (autoSelectedRef.current === soleVisibleId) return;
    autoSelectedRef.current = soleVisibleId;
    onChange(soleVisibleId);
  }, [autoSelectSole, disabled, selectedSecretId, soleVisibleId, onChange]);

  // When the tag filter hides every secret, offer an escape hatch that turns the
  // filter off (repopulating the full list) — only when secrets exist to reveal.
  const showAllOption = filterActive && visibleSecrets.length === 0 && secrets.length > 0;

  const selectionUnlisted =
    !disabled &&
    Boolean(selectedSecretId) &&
    !visibleSecrets.some(secret => keyOf(secret) === selectedSecretId);

  const handleSelect = (value: string) => {
    if (value === SHOW_ALL_VALUE) {
      setFilterEnabled(false);
      return;
    }
    onChange(value);
  };

  return (
    <div className="mb-3">
      <div className="d-flex justify-content-between align-items-center">
        <label className="m-0" htmlFor={selectId}>
          {label}
          {required && !disabled && ' *'}
        </label>
        <div className="form-check m-0">
          <input
            className="form-check-input"
            type="checkbox"
            id={checkboxId}
            checked={hasFilter && !disabled && filterEnabled}
            disabled={disabled || locked || !hasFilter}
            onChange={e => setFilterEnabled(e.target.checked)}
            data-testid={testId ? `${testId}-filter-toggle` : 'secret-filter-tags-toggle'}
          />
          <label className="form-check-label small" htmlFor={checkboxId}>
            Filter tags
          </label>
        </div>
      </div>
      <select
        className="form-control dropdown-styling"
        id={selectId}
        value={disabled ? '' : selectedSecretId}
        onChange={e => handleSelect(e.target.value)}
        required={required && !disabled}
        disabled={disabled || locked}
        data-testid={testId}
      >
        <option value="">{disabled ? 'Not required for this provider' : emptyLabel}</option>
        {!disabled && showAllOption && <option value={SHOW_ALL_VALUE}>(show all secrets)</option>}
        {!disabled &&
          visibleSecrets.map(secret => {
            const mismatch = filterActive && !matchesTags(secret);
            return (
              <option key={keyOf(secret)} value={keyOf(secret)}>
                {secret.name}
                {mismatch ? ' (no matching tag)' : ''}
              </option>
            );
          })}
        {selectionUnlisted && (
          <option value={selectedSecretId}>
            {selectedSecretId} {secretsHidden ? '(hidden)' : '(not found)'}
          </option>
        )}
      </select>
      {disabled ? (
        <small className="form-text text-muted">This provider does not use an API key.</small>
      ) : selectionUnlisted && secretsHidden ? (
        <small className="form-text text-muted" data-testid="secret-selector-hidden-note">
          You don&apos;t have permission to view secrets, so this saved key can&apos;t be shown.
        </small>
      ) : (
        helpText && <small className="form-text text-muted">{helpText}</small>
      )}
    </div>
  );
};

export default SecretSelector;
