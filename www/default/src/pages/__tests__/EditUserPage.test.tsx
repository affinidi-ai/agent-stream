import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import EditUserPage from '../EditUserPage';
import { apiClient } from '../../api';
import { showToast } from '../../utils/toaster';

jest.mock('../../api', () => ({
  apiClient: {
    get: jest.fn(),
    put: jest.fn(),
    delete: jest.fn(),
  },
}));

jest.mock('../../utils/toaster', () => ({
  showToast: jest.fn(),
}));

const mockGet = apiClient.get as jest.Mock;
const mockPut = apiClient.put as jest.Mock;
const mockDelete = apiClient.delete as jest.Mock;

const SAML_USER = {
  user_id: 'saml-1',
  username: 'sam',
  role: 'user',
  status: 'approved',
  created_at: '2026-11-01T00:00:00Z',
  updated_at: '2026-11-01T00:00:00Z',
  sign_in_method: 'saml',
};

const KEPT_USER = {
  ...SAML_USER,
  user_id: 'kept-1',
  username: 'kept-1',
  status: 'disabled',
  saml_id: 'saml-account',
  deleted_at: '2026-11-20T00:00:00Z',
};

const renderPage = async (userId: string) => {
  render(
    <MemoryRouter initialEntries={[`/users/${userId}`]}>
      <Routes>
        <Route path="/users/:userId" element={<EditUserPage />} />
        <Route path="/settings" element={<div>settings</div>} />
      </Routes>
    </MemoryRouter>
  );
  await screen.findByDisplayValue(userId === 'kept-1' ? 'kept-1' : 'sam');
};

describe('EditUserPage save', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockPut.mockResolvedValue({ data: SAML_USER });
  });

  it('sends only the fields the administrator changed, so a stale status never re-approves', async () => {
    mockGet.mockResolvedValue({ data: SAML_USER });

    await renderPage('saml-1');
    fireEvent.change(screen.getByPlaceholderText('Enter first name'), {
      target: { value: 'Sam' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Save/ }));
    await screen.findByText('settings');

    expect(mockPut).toHaveBeenCalledWith('/users/saml-1', { first_name: 'Sam' });
  });

  it('sends the status when the administrator changes it', async () => {
    mockGet.mockResolvedValue({ data: SAML_USER });

    await renderPage('saml-1');
    fireEvent.click(screen.getByLabelText(/Cannot sign in/));
    fireEvent.click(screen.getByRole('button', { name: /Save/ }));
    await screen.findByText('settings');

    expect(mockPut).toHaveBeenCalledWith('/users/saml-1', { status: 'disabled' });
  });

  it('sends nothing, and offers no save, when the user did not load', async () => {
    mockGet.mockRejectedValue(new Error('Failed to load user'));
    render(
      <MemoryRouter initialEntries={['/users/saml-1']}>
        <Routes>
          <Route path="/users/:userId" element={<EditUserPage />} />
        </Routes>
      </MemoryRouter>
    );
    await screen.findByText('Failed to load user');

    const save = screen.getByTestId('edit-user-save-button');
    expect(save).toBeDisabled();
    fireEvent.click(save);
    fireEvent.keyDown(document, { key: 's', ctrlKey: true });

    expect(mockPut).not.toHaveBeenCalled();
    expect(screen.queryByTestId('edit-user-delete-button')).not.toBeInTheDocument();
  });

  it('encodes the user id, so a crafted id cannot reach another API path', async () => {
    mockGet.mockResolvedValue({ data: { ...SAML_USER, user_id: 'other' } });
    render(
      <MemoryRouter initialEntries={['/users/..%2Fpipes%2Fp-1']}>
        <Routes>
          <Route path="/users/:userId" element={<EditUserPage />} />
        </Routes>
      </MemoryRouter>
    );
    await screen.findByDisplayValue('sam');

    expect(mockGet).toHaveBeenCalledWith('/users/..%2Fpipes%2Fp-1');
    expect(screen.queryByTestId('edit-user-delete-button')).not.toBeInTheDocument();
  });

  it('sends nothing when nothing changed', async () => {
    mockGet.mockResolvedValue({ data: SAML_USER });

    await renderPage('saml-1');
    fireEvent.click(screen.getByRole('button', { name: /Save/ }));
    await screen.findByText('settings');

    expect(mockPut).not.toHaveBeenCalled();
  });
});

describe('EditUserPage delete', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('marks a kept record as deleted and offers no delete button', async () => {
    mockGet.mockResolvedValue({ data: KEPT_USER });

    await renderPage('kept-1');

    expect(screen.getByTestId('edit-user-deleted-badge')).toHaveTextContent('DELETED');
    expect(screen.getByTestId('edit-user-kept-account')).toHaveTextContent(
      'SAML account saml-account'
    );
    expect(screen.queryByTestId('edit-user-delete-button')).not.toBeInTheDocument();
  });

  it('says after the delete that the SAML record was kept', async () => {
    mockGet.mockResolvedValue({ data: SAML_USER });
    mockDelete.mockResolvedValue({ data: { outcome: 'kept' } });

    await renderPage('saml-1');
    const button = screen.getByTestId('edit-user-delete-button');
    expect(screen.queryByTestId('edit-user-deleted-badge')).not.toBeInTheDocument();
    fireEvent.click(button);
    fireEvent.click(button);
    await screen.findByText('settings');

    expect(mockDelete).toHaveBeenCalledWith('/users/saml-1');
    expect(showToast).toHaveBeenCalledWith(
      'success',
      'User disabled. Their SAML account stays on a disabled record and is refused at sign-in until an administrator approves them again.'
    );
  });
});
