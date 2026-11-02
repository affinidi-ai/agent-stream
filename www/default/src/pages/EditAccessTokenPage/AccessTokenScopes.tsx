import React, { useMemo, useState } from 'react';

interface AccessTokenScopesProps {
  /** RBAC permission names the operator can grant. */
  allScopes: string[];
  selected: string[];
  /** Selected scopes the operator cannot grant; shown red and blocking save. */
  unavailable?: string[];
  onChange: (scopes: string[]) => void;
  disabled?: boolean;
}

/**
 * Scope allow-list picker. Selected permissions render as removable pills; the
 * filterable list below adds a permission on click. An empty selection means
 * the token inherits the bound user's full role.
 */
const AccessTokenScopes: React.FC<AccessTokenScopesProps> = ({
  allScopes,
  selected,
  unavailable = [],
  onChange,
  disabled,
}) => {
  const [filter, setFilter] = useState('');
  const selectedSet = useMemo(() => new Set(selected), [selected]);
  const unavailableSet = useMemo(() => new Set(unavailable), [unavailable]);

  const add = (scope: string) => {
    if (selectedSet.has(scope)) return;
    onChange([...selected, scope].sort());
  };

  const remove = (scope: string) => {
    onChange(selected.filter(s => s !== scope));
  };

  const available = useMemo(() => {
    const term = filter.trim().toLowerCase();
    return [...allScopes]
      .sort()
      .filter(s => !selectedSet.has(s) && (!term || s.toLowerCase().includes(term)));
  }, [allScopes, selectedSet, filter]);

  return (
    <div>
      <div className="d-flex justify-content-between align-items-center mb-1">
        <small className="fw-semibold text-muted">
          Selected scopes{selected.length > 0 ? ` (${selected.length})` : ''}
        </small>
        {selected.length > 0 && !disabled && (
          <button type="button" className="btn btn-link btn-sm p-0" onClick={() => onChange([])}>
            Clear all
          </button>
        )}
      </div>
      <div className="access-token-selected border rounded p-2 mb-2">
        {selected.length === 0 ? (
          <small className="text-muted">
            No scopes selected — the token gets the bound user&rsquo;s full role. Add scopes to
            limit it to fewer permissions.
          </small>
        ) : (
          <div className="d-flex flex-wrap gap-2">
            {[...selected].sort().map(scope => (
              <span
                key={scope}
                className={`badge ${
                  unavailableSet.has(scope) ? 'text-bg-danger' : 'text-bg-primary'
                } d-inline-flex align-items-center`}
                style={{ fontSize: '0.8em' }}
                data-testid={`access-token-selected-scope-${scope}`}
              >
                {scope}
                {!disabled && (
                  <button
                    type="button"
                    className="btn btn-link btn-sm text-white ms-1 p-0 lh-1"
                    onClick={() => remove(scope)}
                    title={`Remove ${scope}`}
                    style={{ textDecoration: 'none' }}
                    data-testid={
                      unavailableSet.has(scope)
                        ? `access-token-remove-unavailable-scope-${scope}`
                        : `access-token-scope-remove-${scope}`
                    }
                  >
                    <i className="fas fa-times" aria-hidden="true" />
                  </button>
                )}
              </span>
            ))}
          </div>
        )}
      </div>

      <input
        type="text"
        className="form-control form-control-sm mb-2"
        placeholder="Filter scopes…"
        value={filter}
        disabled={disabled}
        onChange={e => setFilter(e.target.value)}
        data-testid="access-token-scope-filter"
      />

      <div className="access-token-scopes border rounded p-2">
        {available.length === 0 ? (
          <small className="text-muted">
            {filter.trim() ? 'No scopes match your filter.' : 'All scopes selected.'}
          </small>
        ) : (
          <div className="d-flex flex-wrap gap-2">
            {available.map(scope => (
              <button
                key={scope}
                type="button"
                className="badge access-token-scope-pill d-inline-flex align-items-center"
                disabled={disabled}
                onClick={() => add(scope)}
                title={`Add ${scope}`}
                style={{ fontSize: '0.8em', cursor: 'pointer' }}
                data-testid={`access-token-scope-add-${scope}`}
              >
                <i className="fas fa-plus me-1" aria-hidden="true" />
                {scope}
              </button>
            ))}
          </div>
        )}
      </div>
      {unavailable.length > 0 && (
        <div
          className="alert alert-danger py-2 mt-2 mb-0"
          data-testid="access-token-unavailable-scopes"
        >
          Remove the red unavailable scopes before saving.
        </div>
      )}
    </div>
  );
};

export default AccessTokenScopes;
