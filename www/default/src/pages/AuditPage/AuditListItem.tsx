import React from 'react';
import { formatDateTime, timeAgo } from '../../utils/stringUtils';
import { auditConfigurationChange, callerDidOf, policyDecision, trustCheck } from './auditHelpers';
import { decisionLabel, decisionTone, describeEntry } from './eventNarrative';
import type { AuditEntry } from './types';

interface AuditListItemProps {
  entry: AuditEntry;
  idx: number;
  isSelected: boolean;
  onSelect: () => void;
}

/** Short "actor" label for the footnote: caller name → caller DID → auth method. */
function actorOf(entry: AuditEntry): string {
  return (
    auditConfigurationChange(entry)?.actor_id ||
    entry.caller?.name ||
    entry.caller?.name_redacted ||
    callerDidOf(entry) ||
    entry.caller?.auth_method ||
    'system'
  );
}

/**
 * One governance event in the master list. The whole row is a button; the title
 * is tone-coloured (green allow / red deny / amber warn), followed by the plain
 * message, an optional detail line, and a "timestamp · actor" footnote. A
 * trailing arrow turns accent-blue when the row is selected.
 */
const AuditListItem: React.FC<AuditListItemProps> = ({ entry, idx, isSelected, onSelect }) => {
  const { title, tone, summary, detail } = describeEntry(entry);
  const pd = policyDecision(entry);
  const tc = trustCheck(entry);
  const verdict = pd?.decision ?? (tc ? (tc.ok ? 'allow' : 'deny') : undefined);
  // Three-way tone: allow (green) · deny (red) · warn (amber, for evaluation
  // failures — `error` / `missing_engine`), so a failure isn't shown as a deny.
  const verdictTone = decisionTone(verdict);
  const verdictIcon =
    verdictTone === 'allow' ? 'check' : verdictTone === 'warn' ? 'triangle-exclamation' : 'xmark';

  return (
    <li className="audit-item-wrap">
      <button
        type="button"
        className={`audit-item audit-item--${tone} ${isSelected ? 'audit-item--selected' : ''}`}
        aria-current={isSelected}
        data-testid={`audit-item-${idx}`}
        onClick={onSelect}
      >
        <span className="audit-item-body">
          <span className="audit-item-headline">
            <span className={`audit-item-title audit-item-title--${tone}`}>{title}</span>
            {verdict !== undefined && (
              <span className={`audit-decision audit-decision--${verdictTone}`}>
                <i className={`fas fa-${verdictIcon}`} aria-hidden="true" />
                {decisionLabel(verdict)}
              </span>
            )}
          </span>
          <span className="audit-item-summary">{summary}</span>
          {detail && <span className="audit-item-detail">{detail}</span>}
          <span className="audit-item-foot" title={formatDateTime(entry.timestamp, true)}>
            <span className="audit-item-foot-time">{timeAgo(entry.timestamp)}</span>
            <span aria-hidden="true"> · </span>
            <span className="audit-item-foot-actor">{actorOf(entry)}</span>
          </span>
        </span>
        <i
          className={`fas fa-arrow-right audit-item-arrow ${isSelected ? 'audit-item-arrow--active' : ''}`}
          aria-hidden="true"
        />
      </button>
    </li>
  );
};

export default AuditListItem;
