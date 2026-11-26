import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import UsersPage from '../UsersPage';
import { apiClient } from '../../api';

jest.mock('../../api', () => ({
  apiClient: {
    get: jest.fn(),
    put: jest.fn(),
    delete: jest.fn(),
  },
}));

jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({
    hasPermission: (feature: string) => ['users.edit', 'users.delete'].includes(feature),
    loading: false,
  }),
}));

const mockGet = apiClient.get as jest.Mock;

const user = (overrides: Record<string, unknown>) => ({
  role: 'user',
  status: 'approved',
  created_at: '2026-11-01T00:00:00Z',
  updated_at: '2026-11-01T00:00:00Z',
  sign_in_method: 'passkey',
  ...overrides,
});

const PASSKEY_USER = user({ user_id: 'passkey-1', username: 'pat' });
const SAML_USER = user({ user_id: 'saml-1', username: 'sam', sign_in_method: 'saml' });
const KEPT_USER = user({
  user_id: 'kept-1',
  username: 'kept-1',
  status: 'disabled',
  sign_in_method: 'oidc',
  oidc: { issuer: 'https://idp.example.com', subject: 'sub-1' },
  deleted_at: '2026-11-20T00:00:00Z',
});

const renderPage = async () => {
  render(
    <MemoryRouter>
      <UsersPage />
    </MemoryRouter>
  );
  await screen.findByText('pat');
};

describe('UsersPage kept records', () => {
  beforeEach(() => {
    mockGet.mockImplementation((url: string) =>
      Promise.resolve({
        data: url === '/users' ? [PASSKEY_USER, SAML_USER, KEPT_USER] : { user_id: 'admin-1' },
      })
    );
  });

  it('marks a kept record as deleted and offers no delete button for it', async () => {
    await renderPage();

    expect(screen.getByTestId('users-deleted-badge-kept-1')).toHaveTextContent('DELETED');
    expect(screen.queryByTestId('users-delete-button-kept-1')).not.toBeInTheDocument();
    expect(screen.queryByTestId('users-deleted-badge-passkey-1')).not.toBeInTheDocument();
    expect(screen.getByTestId('users-delete-button-passkey-1')).toBeInTheDocument();
  });

  it('words the delete button from how the user signs in', async () => {
    await renderPage();

    const passkeyTitle = screen.getByTestId('users-delete-button-passkey-1').getAttribute('title');
    const samlTitle = screen.getByTestId('users-delete-button-saml-1').getAttribute('title');
    expect(passkeyTitle).toContain('Their record is removed');
    expect(passkeyTitle).not.toMatch(/OpenID|SAML/);
    expect(samlTitle).toContain('They sign in with SAML');
  });

  it('filters the list down to kept records with the Deleted status', async () => {
    await renderPage();

    fireEvent.change(screen.getByTestId('users-status-filter'), { target: { value: 'deleted' } });

    expect(screen.getByTestId('users-deleted-badge-kept-1')).toBeInTheDocument();
    expect(screen.queryByText('pat')).not.toBeInTheDocument();
    expect(screen.queryByText('sam')).not.toBeInTheDocument();
  });

  it('shows the badge and no delete button in the details of a kept record', async () => {
    await renderPage();

    fireEvent.click(screen.getByTestId('users-kept-account-kept-1'));

    expect(screen.getByTestId('users-modal-deleted-badge')).toHaveTextContent('DELETED');
    expect(screen.queryByTestId('users-modal-delete-button')).not.toBeInTheDocument();
  });
});
