import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { DeleteButton } from '../DeleteButton';

describe('DeleteButton confirm notice', () => {
  it('shows the notice as visible text during the confirm step only', () => {
    render(<DeleteButton onDelete={jest.fn()} confirmNotice="Record is kept." />);

    expect(screen.queryByTestId('delete-confirm-notice')).toBeNull();

    fireEvent.click(screen.getByRole('button'));

    expect(screen.getByTestId('delete-confirm-notice').textContent).toBe('Record is kept.');
  });

  it('shows no notice when none is given', () => {
    render(<DeleteButton onDelete={jest.fn()} />);

    fireEvent.click(screen.getByRole('button'));

    expect(screen.queryByTestId('delete-confirm-notice')).toBeNull();
  });
});
