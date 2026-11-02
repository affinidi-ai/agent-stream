import React, { useEffect, useId, useMemo, useRef, useState } from 'react';

/**
 * Curated set of Font Awesome (solid) icons offered in the picker dropdown. Stored without the
 * `fa-` prefix; the picker normalises both ways so a value like `fa-brain` or `brain` round-trips.
 */
export const ICON_CHOICES = [
  'brain',
  'robot',
  'microchip',
  'cube',
  'cubes',
  'bolt',
  'wand-magic-sparkles',
  'comment',
  'comments',
  'message',
  'cloud',
  'server',
  'database',
  'network-wired',
  'plug',
  'key',
  'lock',
  'shield-halved',
  'gavel',
  'scale-balanced',
  'users',
  'user',
  'gear',
  'sliders',
  'star',
  'fire',
  'rocket',
  'flask',
  'atom',
  'lightbulb',
  'eye',
  'feather',
  'leaf',
  'globe',
  'compass',
  'diagram-project',
  'code',
  'terminal',
  'gem',
  'crown',
  'puzzle-piece',
  'wave-square',
  'circle-nodes',
  'layer-group',
  'box',
  'store',
  'tag',
  'bell',
  'heart',
];

const normalise = (raw: string): string =>
  raw
    .trim()
    .replace(/^fas\s+/, '')
    .replace(/^fa-/, '');

interface IconPickerProps {
  /** Current icon value, e.g. `fa-brain` or `brain`. */
  value: string;
  /** Called with the selected icon in `fa-<name>` form (empty string when cleared). */
  onChange: (icon: string) => void;
  placeholder?: string;
  /** Test id applied to the toggle button; the search input derives `${testId}-search`. */
  testId?: string;
  choices?: string[];
}

const IconPicker: React.FC<IconPickerProps> = ({
  value,
  onChange,
  placeholder = 'fa-brain',
  testId,
  choices = ICON_CHOICES,
}) => {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const containerRef = useRef<HTMLDivElement>(null);
  const searchId = useId();

  const current = normalise(value);

  useEffect(() => {
    if (!open) return;
    const handleClickOutside = (event: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [open]);

  const filtered = useMemo(() => {
    const term = search.trim().toLowerCase();
    if (!term) return choices;
    return choices.filter(name => name.includes(term));
  }, [choices, search]);

  const select = (name: string) => {
    onChange(name ? `fa-${name}` : '');
    setOpen(false);
    setSearch('');
  };

  return (
    <div className="position-relative" ref={containerRef}>
      <div className="input-group">
        <span
          className="input-group-text justify-content-center p-0"
          style={{ width: 'calc(1.5em + 0.75rem + 2px)' }}
        >
          {current ? (
            <i className={`fas fa-${current}`}></i>
          ) : (
            <i className="fas fa-icons text-muted"></i>
          )}
        </span>
        <input
          type="text"
          className="form-control font-monospace"
          value={value}
          placeholder={placeholder}
          onChange={e => onChange(e.target.value)}
          onFocus={() => setOpen(true)}
          data-testid={testId}
        />
        <button
          type="button"
          className="btn btn-outline-secondary"
          onClick={() => setOpen(o => !o)}
          aria-label="Browse icons"
          aria-expanded={open}
          data-testid={testId ? `${testId}-toggle` : undefined}
        >
          <i className={`fas fa-chevron-${open ? 'up' : 'down'}`}></i>
        </button>
      </div>

      {open && (
        <div
          className="card shadow position-absolute w-100"
          style={{ zIndex: 1050, marginTop: '0.25rem' }}
        >
          <div className="card-body p-2">
            <input
              type="text"
              id={searchId}
              className="form-control form-control-sm mb-2"
              placeholder="Search icons…"
              value={search}
              onChange={e => setSearch(e.target.value)}
              autoFocus
              data-testid={testId ? `${testId}-search` : undefined}
            />
            <div
              className="d-flex flex-wrap gap-1"
              style={{ maxHeight: '180px', overflowY: 'auto' }}
            >
              {filtered.length === 0 && (
                <div className="text-muted small fst-italic p-2">No icons match.</div>
              )}
              {filtered.map(name => (
                <button
                  key={name}
                  type="button"
                  className={`btn btn-sm ${
                    name === current ? 'btn-primary' : 'btn-outline-secondary'
                  }`}
                  style={{ width: '2.25rem', height: '2.25rem' }}
                  title={name}
                  onClick={() => select(name)}
                  data-testid={testId ? `${testId}-option-${name}` : undefined}
                >
                  <i className={`fas fa-${name}`}></i>
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default IconPicker;
