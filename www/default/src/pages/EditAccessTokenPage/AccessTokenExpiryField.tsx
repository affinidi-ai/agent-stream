import React from 'react';
import { Form } from 'react-bootstrap';
import {
  AccessTokenExpiryForm,
  accessTokenExpiryBounds,
  validateAccessTokenExpiry,
} from './accessTokenExpiry';

interface AccessTokenExpiryFieldProps {
  value: AccessTokenExpiryForm;
  referenceNow: Date;
  validationAttempted: boolean;
  onChange: (value: AccessTokenExpiryForm) => void;
}

const AccessTokenExpiryField: React.FC<AccessTokenExpiryFieldProps> = ({
  value,
  referenceNow,
  validationAttempted,
  onChange,
}) => {
  const bounds = accessTokenExpiryBounds(referenceNow);
  const error = validationAttempted
    ? validateAccessTokenExpiry(value.neverExpires, value.expiresAt).error
    : undefined;

  return (
    <Form.Group className="mb-3">
      <div className="d-flex align-items-center justify-content-between gap-3 mb-2">
        <Form.Label className="mb-0" htmlFor="access-token-expiry-date-time-input">
          Expires at {!value.neverExpires && <span className="text-danger">*</span>}
        </Form.Label>
        <Form.Check
          type="switch"
          id="access-token-never-expires"
          label="Never expires"
          checked={value.neverExpires}
          onChange={event => onChange({ ...value, neverExpires: event.target.checked })}
          data-testid="access-token-never-expires"
        />
      </div>
      {value.neverExpires ? (
        <Form.Control
          id="access-token-expiry-date-time-input"
          type="text"
          value="Never"
          readOnly
          disabled
          data-testid="access-token-expiry-date-time"
        />
      ) : (
        <Form.Control
          id="access-token-expiry-date-time-input"
          type="datetime-local"
          value={value.expiresAt}
          onChange={event => onChange({ ...value, expiresAt: event.target.value })}
          min={bounds.min}
          max={bounds.max}
          required
          isInvalid={Boolean(error)}
          data-testid="access-token-expiry-date-time"
        />
      )}
      <Form.Control.Feedback type="invalid" data-testid="access-token-expiry-error">
        {error}
      </Form.Control.Feedback>
      <Form.Text muted>The date and time use your local timezone.</Form.Text>
    </Form.Group>
  );
};

export default AccessTokenExpiryField;
