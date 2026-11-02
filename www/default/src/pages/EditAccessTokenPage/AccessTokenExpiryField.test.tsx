import React, { useState } from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import AccessTokenExpiryField from './AccessTokenExpiryField';
import { newAccessTokenExpiry } from './accessTokenExpiry';

const REFERENCE_NOW = new Date();

function Harness() {
  const [value, setValue] = useState(() => newAccessTokenExpiry(REFERENCE_NOW));
  return (
    <AccessTokenExpiryField
      value={value}
      referenceNow={REFERENCE_NOW}
      validationAttempted
      onChange={setValue}
    />
  );
}

describe('AccessTokenExpiryField', () => {
  it('switches between Never and an exact local date-time', () => {
    render(<Harness />);

    const neverSwitch = screen.getByTestId('access-token-never-expires');
    expect(neverSwitch).toBeChecked();
    expect(screen.getByTestId('access-token-expiry-date-time')).toBeDisabled();
    expect(screen.getByTestId('access-token-expiry-date-time')).toHaveValue('Never');

    fireEvent.click(neverSwitch);

    expect(neverSwitch).not.toBeChecked();
    expect(screen.getByTestId('access-token-expiry-date-time')).toHaveAttribute(
      'type',
      'datetime-local'
    );
    expect(screen.getByTestId('access-token-expiry-date-time')).toBeRequired();
  });
});
