import React, { useEffect, useRef, useState } from 'react';
import { BASE_VARIANT_ID, type PipeVariantMeta } from './usePipeVariantSnapshots';

/**
 * Top-left canvas overlay for pipe variants — the pipe analogue of the
 * surface `SurfaceVariantsWidget`. Acts as a switcher when the pipe has
 * named variants and as an "open editor" affordance otherwise. Switching
 * a variant swaps the whole pipe canvas to that variant's snapshot (the
 * host page drives this via the snapshot manager). "Manage variants…"
 * opens the props panel where the catalog is edited.
 */

export interface PipeVariantSwitcherProps {
  /** Named variants (base is implicit, never in this list). */
  variants: PipeVariantMeta[];
  /** Default variant id, or null when base is the implicit default. */
  defaultVariantId: string | null;
  /** Currently active variant id (BASE_VARIANT_ID / null = base active). */
  activeVariantId: string | null;
  /** Whether the variants panel is the current selection (highlights the chip). */
  selected: boolean;
  /** Open the variants panel. */
  onOpen: () => void;
  /** Open the panel AND seed a new variant (zero-state "+" and dropdown "Add…"). */
  onAddVariant: () => void;
  /** Switch the active variant; the page swaps the canvas via the snapshot manager. */
  onSwitchVariant: (variantId: string) => void;
}

const PipeVariantSwitcher: React.FC<PipeVariantSwitcherProps> = ({
  variants,
  defaultVariantId,
  activeVariantId,
  selected,
  onOpen,
  onAddVariant,
  onSwitchVariant,
}) => {
  const defaultId = defaultVariantId || undefined;
  const baseIsDefault = !defaultId;
  const isBaseActive = activeVariantId === BASE_VARIANT_ID || activeVariantId == null;
  const count = variants.length;
  const active = variants.find(v => v.id === activeVariantId);
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (!rootRef.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  if (count === 0) {
    return (
      <div
        ref={rootRef}
        className={`surface-variants-widget surface-variants-widget--zero${selected ? ' is-selected' : ''}`}
      >
        <button
          type="button"
          className="surface-variants-widget-row"
          onClick={onOpen}
          title="Open variants editor"
        >
          <i className="fas fa-code-branch widget-icon" />
          <span className="widget-body">
            <span className="widget-title">Variant</span>
            <span className="widget-meta">
              <strong>base</strong>
            </span>
          </span>
        </button>
        <button
          type="button"
          className="surface-variants-widget-add"
          onClick={e => {
            e.stopPropagation();
            onAddVariant();
          }}
          title="Add a new variant"
          aria-label="Add a new variant"
        >
          <i className="fas fa-plus" />
        </button>
      </div>
    );
  }

  const displayLabel = isBaseActive ? 'base' : active?.name || active?.alias || '—';
  const displayAlias = isBaseActive ? null : active?.alias;

  return (
    <div ref={rootRef} className="surface-variants-widget-wrapper">
      <div
        role="button"
        tabIndex={0}
        className={`surface-variants-widget${selected ? ' is-selected' : ''}${open ? ' is-open' : ''}`}
        onClick={() => setOpen(o => !o)}
        onKeyDown={e => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            setOpen(o => !o);
          }
        }}
        title={`Active variant: ${displayLabel}`}
      >
        <i className="fas fa-code-branch widget-icon" />
        <span className="widget-body">
          <span className="widget-title">Variant</span>
          <span className="widget-meta">
            <strong>{displayLabel}</strong>
            {displayAlias && (
              <>
                {' '}
                <code
                  className="surface-variants-widget-alias-link"
                  role="button"
                  tabIndex={0}
                  title="Open variants properties"
                  onClick={e => {
                    e.stopPropagation();
                    setOpen(false);
                    onOpen();
                  }}
                  onKeyDown={e => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      e.stopPropagation();
                      setOpen(false);
                      onOpen();
                    }
                  }}
                >
                  ${displayAlias}
                </code>
              </>
            )}
          </span>
        </span>
        <i className={`fas fa-chevron-${open ? 'up' : 'down'} widget-caret`} />
      </div>
      {open && (
        <div className="surface-variants-widget-menu" role="menu">
          <button
            key={BASE_VARIANT_ID}
            type="button"
            role="menuitem"
            className={`surface-variants-widget-item${isBaseActive ? ' is-active' : ''}`}
            onClick={() => {
              setOpen(false);
              if (!isBaseActive) onSwitchVariant(BASE_VARIANT_ID);
            }}
          >
            <span className="item-name">
              <strong>base</strong>
              {baseIsDefault && (
                <span className="badge bg-secondary ms-1" style={{ fontSize: '8px' }}>
                  default
                </span>
              )}
            </span>
          </button>
          {variants.map(v => {
            const isActive = v.id === activeVariantId;
            const isDefault = v.id === defaultId;
            return (
              <button
                key={v.id}
                type="button"
                role="menuitem"
                className={`surface-variants-widget-item${isActive ? ' is-active' : ''}`}
                onClick={() => {
                  setOpen(false);
                  if (!isActive) onSwitchVariant(v.id);
                }}
              >
                <span className="item-name">
                  {v.name || <span className="text-muted">(unnamed)</span>}
                  {isDefault && (
                    <span className="badge bg-secondary ms-1" style={{ fontSize: '8px' }}>
                      default
                    </span>
                  )}
                  {v.enabled === false && (
                    <span className="badge bg-warning text-dark ms-1" style={{ fontSize: '8px' }}>
                      disabled
                    </span>
                  )}
                </span>
                <code
                  className="item-alias surface-variants-widget-alias-link"
                  role="button"
                  tabIndex={0}
                  title="Open variants properties"
                  onClick={e => {
                    e.stopPropagation();
                    setOpen(false);
                    onOpen();
                  }}
                  onKeyDown={e => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      e.stopPropagation();
                      setOpen(false);
                      onOpen();
                    }
                  }}
                >
                  ${v.alias}
                </code>
              </button>
            );
          })}
          <div className="surface-variants-widget-divider" />
          <button
            type="button"
            role="menuitem"
            className="surface-variants-widget-item is-action"
            onClick={() => {
              setOpen(false);
              onOpen();
            }}
          >
            <i className="fas fa-cog me-1" />
            Manage variants…
          </button>
        </div>
      )}
    </div>
  );
};

export default PipeVariantSwitcher;
