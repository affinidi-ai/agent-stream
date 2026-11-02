import React from 'react';

interface FieldProps {
  label: React.ReactNode;
  value: string;
  mono?: boolean;
  small?: boolean;
  hint?: React.ReactNode;
  testId?: string;
}

/** Read-only value rendered as a disabled form field so it matches the dashboard editors. */
export const Field: React.FC<FieldProps> = ({ label, value, mono, small, hint, testId }) => (
  <div className="mb-3">
    <label className={`form-label${small ? ' small mb-1' : ''}`}>{label}</label>
    <input
      type="text"
      className={`form-control${small ? ' form-control-sm' : ''}${mono ? ' font-monospace' : ''}`}
      value={value}
      placeholder="—"
      readOnly
      data-testid={testId}
    />
    {hint && <small className="form-text text-muted">{hint}</small>}
  </div>
);

interface BadgeFieldProps {
  label: React.ReactNode;
  children: React.ReactNode;
  small?: boolean;
  hint?: React.ReactNode;
}

/** Read-only field whose value is a badge (or badges) rather than text. */
export const BadgeField: React.FC<BadgeFieldProps> = ({ label, children, small, hint }) => (
  <div className="mb-3">
    <label className={`form-label${small ? ' small mb-1' : ''}`}>{label}</label>
    <div>{children}</div>
    {hint && <small className="form-text text-muted d-block">{hint}</small>}
  </div>
);

interface BadgeListProps {
  values: string[];
  emptyLabel?: string;
  testId?: string;
}

/** A wrapping row of monospace badges, with a muted placeholder when empty. */
export const BadgeList: React.FC<BadgeListProps> = ({ values, emptyLabel = 'None', testId }) =>
  values.length === 0 ? (
    <span
      className="text-muted small fst-italic"
      data-testid={testId ? `${testId}-empty` : undefined}
    >
      {emptyLabel}
    </span>
  ) : (
    <div className="d-flex flex-wrap gap-1" data-testid={testId}>
      {values.map((value, index) => (
        <span className="badge bg-secondary font-monospace fw-normal" key={`${value}-${index}`}>
          {value}
        </span>
      ))}
    </div>
  );

/** Section sub-heading used inside the provider detail tabs. */
export const SectionHeading: React.FC<{ icon?: string; children: React.ReactNode }> = ({
  icon,
  children,
}) => (
  <h6 className="font-weight-bold text-primary text-uppercase small mb-3">
    {icon && <i className={`fas ${icon} me-2`}></i>}
    {children}
  </h6>
);
