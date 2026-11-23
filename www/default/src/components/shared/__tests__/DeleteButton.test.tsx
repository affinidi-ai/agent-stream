import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { DeleteButton } from '../DeleteButton';

describe('DeleteButton confirm notice', () => {
  it('keeps the status region mounted and fills it during the confirm step only', () => {
    render(<DeleteButton onDelete={jest.fn()} confirmNotice="Record is kept." />);

    const region = screen.getByRole('status');
    expect(region.textContent).toBe('');

    fireEvent.click(screen.getByRole('button'));

    expect(screen.getByRole('status')).toBe(region);
    expect(region.textContent).toBe('Record is kept.');
  });

  it('shows no notice when none is given', () => {
    render(<DeleteButton onDelete={jest.fn()} />);

    fireEvent.click(screen.getByRole('button'));

    expect(screen.queryByTestId('delete-confirm-notice')).toBeNull();
  });
});
