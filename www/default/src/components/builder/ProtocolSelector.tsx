import React from 'react';
import type { Protocol } from './elements/types';
import { PROTOCOL_META } from './protocols';
import '../../styles/protocol-selector.css';

export interface ProtocolSelectorProps {
  /** Protocol ids to render as selectable cards. */
  options: Protocol[];
  /** Currently selected protocol, or `null` if none. */
  value: Protocol | null;
  /** Called with the selected protocol id. Ignored when `disabled`. */
  onChange: (protocol: Protocol) => void;
  /** Disable all interaction; selected card stays highlighted. */
  disabled?: boolean;
  /** Render the smaller `--compact` variant (≈60% of full size). */
  compact?: boolean;
  /** Justification of the card row (defaults to `center`). */
  align?: 'start' | 'center';
  /** Optional prefix for `data-testid` on each card (`${prefix}-${protocol}`). */
  testIdPrefix?: string;
}

/**
 * Card-row protocol picker shared by every "select a protocol" surface
 * (Add Channel, Onboard, Add Surface). Single component so cards stay
 * visually identical and metadata (label/icon/description) lives in one
 * place — see {@link PROTOCOL_META}.
 */
const ProtocolSelector: React.FC<ProtocolSelectorProps> = ({
  options,
  value,
  onChange,
  disabled = false,
  compact = false,
  align = 'center',
  testIdPrefix,
}) => {
  const rowClass = `protocol-selection${compact ? ' protocol-selection--compact' : ''}`;
  const buttonClass = (sel: boolean) =>
    `protocol-button${compact ? ' protocol-button--compact' : ''}${sel ? ' selected' : ''}`;
  const justify = align === 'start' ? 'flex-start' : 'center';
  return (
    <div className={rowClass} style={{ justifyContent: justify }}>
      {options.map(p => {
        const meta = (
          PROTOCOL_META as Record<string, { label: string; icon: string; description: string }>
        )[p];
        if (!meta) return null;
        const isSelected = value === p;
        return (
          <button
            key={p}
            type="button"
            className={buttonClass(isSelected)}
            onClick={() => {
              if (disabled) return;
              onChange(p);
            }}
            disabled={disabled}
            aria-pressed={isSelected}
            data-testid={testIdPrefix ? `${testIdPrefix}-${p}` : undefined}
          >
            <div className="protocol-icon">
              <i className={meta.icon}></i>
            </div>
            <div className="protocol-name">{meta.label}</div>
            <div className="protocol-description">{meta.description}</div>
          </button>
        );
      })}
    </div>
  );
};

export default ProtocolSelector;
