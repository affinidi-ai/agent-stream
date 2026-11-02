import React from 'react';
import { OverlayTrigger, Tooltip } from 'react-bootstrap';
import './InfoTooltip.css';

interface InfoTooltipProps {
  /** Concise explanation revealed on hover or keyboard focus. */
  text: React.ReactNode;
  /** Optional bold heading shown above the text. */
  title?: string;
}

let idCounter = 0;

/**
 * A small info icon that reveals a tooltip on hover or focus. Used to explain
 * enrolment fields inline without cluttering the form.
 */
const InfoTooltip: React.FC<InfoTooltipProps> = ({ text, title }) => {
  const id = React.useMemo(() => `enrolment-info-${++idCounter}`, []);
  const ariaLabel =
    typeof text === 'string' ? (title ? `${title}: ${text}` : text) : (title ?? 'More information');

  return (
    <OverlayTrigger
      placement="top"
      overlay={
        <Tooltip id={id} className="enrolment-info-tip">
          {title && <div className="enrolment-info-tip__title">{title}</div>}
          <div className="text-start">{text}</div>
        </Tooltip>
      }
    >
      <i
        className="fas fa-circle-info text-muted ms-1"
        style={{ cursor: 'help', fontSize: '0.8em' }}
        tabIndex={0}
        role="img"
        aria-label={ariaLabel}
      />
    </OverlayTrigger>
  );
};

export default InfoTooltip;
