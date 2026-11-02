import React, { useState } from 'react';

/** Normalize a user-entered domain or URL to a bare, lowercased host. */
export function normalizeDomain(input: string): string {
  let s = input.trim().toLowerCase();
  if (!s) return '';
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, ''); // strip scheme
  s = s.split('/')[0].split('?')[0].split('#')[0]; // drop path/query/fragment
  s = s.replace(/:\d+$/, ''); // drop port
  return s.trim();
}

interface DomainListEditorProps {
  domains: string[];
  onChange: (domains: string[]) => void;
  placeholder?: string;
  addLabel?: string;
  emptyText?: string;
  testId?: string;
}

/**
 * Reusable editor for a list of domains: an entry field with an Add button and
 * a list of the added domains, each removable via a trash button. Replaces
 * error-prone comma-separated text inputs. Pasted URLs are normalized to their
 * bare host; duplicates are ignored.
 */
const DomainListEditor: React.FC<DomainListEditorProps> = ({
  domains,
  onChange,
  placeholder = 'example.com',
  addLabel = 'Add',
  emptyText = 'No domains added yet.',
  testId,
}) => {
  const [draft, setDraft] = useState('');
  const candidate = normalizeDomain(draft);

  const add = () => {
    if (!candidate) return;
    if (!domains.some(d => d.toLowerCase() === candidate)) {
      onChange([...domains, candidate]);
    }
    setDraft('');
  };
  const remove = (d: string) => onChange(domains.filter(x => x !== d));

  return (
    <div>
      <div className="input-group mb-2">
        <input
          type="text"
          className="form-control"
          value={draft}
          placeholder={placeholder}
          onChange={e => setDraft(e.target.value)}
          onKeyDown={e => {
            if (e.key === 'Enter') {
              e.preventDefault();
              add();
            }
          }}
          data-testid={testId ? `${testId}-input` : undefined}
        />
        <button
          type="button"
          className="btn btn-outline-primary"
          onClick={add}
          disabled={candidate === ''}
          data-testid={testId ? `${testId}-add` : undefined}
        >
          <i className="fas fa-plus me-1" />
          {addLabel}
        </button>
      </div>
      {domains.length === 0 ? (
        <p className="text-muted small mb-0">{emptyText}</p>
      ) : (
        <ul className="list-group" data-testid={testId ? `${testId}-list` : undefined}>
          {domains.map(d => (
            <li
              key={d}
              className="list-group-item d-flex justify-content-between align-items-center py-2"
            >
              <span className="text-break">{d}</span>
              <button
                type="button"
                className="btn btn-sm btn-outline-danger"
                onClick={() => remove(d)}
                aria-label={`Remove ${d}`}
                title="Remove"
              >
                <i className="fas fa-trash" />
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};

export default DomainListEditor;
