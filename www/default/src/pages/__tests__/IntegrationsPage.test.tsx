import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import IntegrationsPage from '../IntegrationsPage';
import { apiClient } from '../../api';

jest.mock('../../api', () => ({
  apiClient: {
    get: jest.fn(),
    post: jest.fn(),
    delete: jest.fn(),
  },
}));

jest.mock('../../hooks/useLimitGuard', () => ({
  useLimitGuard: () => ({ guard: jest.fn(), balloonNode: null }),
}));

let mockPermissions: Record<string, boolean> = {};
jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({
    hasPermission: (feature: string) => mockPermissions[feature] === true,
    loading: false,
  }),
}));

const mockGet = apiClient.get as jest.Mock;

const SAVED_INTEGRATION = {
  id: 'integration-1',
  name: 'Ops mail',
  description: 'Alerts for the operations team',
  type: 'email',
  category: 'general',
  configuration: {},
  content: {},
  status: 'active',
  created_at: '2026-10-20T00:00:00Z',
};

const renderPage = async () => {
  render(
    <MemoryRouter>
      <IntegrationsPage />
    </MemoryRouter>
  );
  await screen.findByText('Ops mail');
};

describe('IntegrationsPage test button', () => {
  beforeEach(() => {
    mockGet.mockResolvedValue({ data: [SAVED_INTEGRATION] });
  });

  it('is hidden from a viewer without integrations.edit', async () => {
    mockPermissions = { 'integrations.view': true };

    await renderPage();

    expect(screen.queryByTitle('Test')).not.toBeInTheDocument();
  });

  it('is shown to a holder of integrations.edit', async () => {
    mockPermissions = { 'integrations.view': true, 'integrations.edit': true };

    await renderPage();

    expect(screen.getByTitle('Test')).toBeInTheDocument();
  });
});
