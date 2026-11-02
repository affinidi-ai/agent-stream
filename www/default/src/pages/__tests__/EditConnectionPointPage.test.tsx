import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import EditConnectionPointPage from '../EditConnectionPointPage';
import { apiClient } from '../../api';

jest.mock('../../api', () => ({
  apiClient: { get: jest.fn(), put: jest.fn(), post: jest.fn(), delete: jest.fn() },
}));

jest.mock('../../utils/runtimeVariables', () => ({
  getRuntimeVariablesForCategories: jest.fn().mockResolvedValue({}),
}));

jest.mock('../EditConnectionPointPage/ConnectionPointOverviewTab', () => ({
  __esModule: true,
  default: () => <div />,
}));

jest.mock('../EditConnectionPointPage/ConnectionPointMetadataTab', () => ({
  __esModule: true,
  default: () => <div />,
}));

let mockPermissions: Record<string, boolean> = {};
jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({
    hasPermission: (feature: string) => mockPermissions[feature] === true,
    loading: false,
  }),
}));

const mockGet = apiClient.get as jest.Mock;

const CONNECTION_POINT = {
  id: 'cp-1',
  gateway_id: '',
  mediator_id: 'med-1',
  name: 'Front desk',
  description: '',
  oob_url: 'https://example.com/oob',
  use_count: 0,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
  integrations: [{ integration_id: 'int-1', variables: {} }],
};

const integrationListCalls = () => mockGet.mock.calls.filter(([url]) => url === '/integrations');

async function mountPage() {
  render(
    <MemoryRouter initialEntries={['/connection-points/cp-1']}>
      <Routes>
        <Route path="/connection-points/:id" element={<EditConnectionPointPage />} />
      </Routes>
    </MemoryRouter>
  );
  expect(await screen.findByText(/Edit Connection Point Details: Front desk/)).toBeInTheDocument();
}

describe('EditConnectionPointPage integrations access', () => {
  beforeEach(() => {
    mockPermissions = {};
    mockGet.mockReset();
    mockGet.mockImplementation((url: string) =>
      Promise.resolve({
        data:
          url === '/integrations'
            ? [{ id: 'int-1', name: 'Alerts', type: 'slack', category: 'connection_point' }]
            : CONNECTION_POINT,
      })
    );
  });

  it('hides Test Integrations and shows the administrators notice without integrations.view', async () => {
    await mountPage();

    expect(screen.queryByTestId('connection-point-test-integrations-button')).toBeNull();
    expect(screen.getByTestId('integrations-admin-only-notice')).toHaveTextContent(
      'Integrations are managed by administrators.'
    );
    expect(integrationListCalls()).toHaveLength(0);
  });

  it('hides Test Integrations for a user who can view but not edit integrations', async () => {
    mockPermissions = { 'integrations.view': true };
    await mountPage();

    await waitFor(() => expect(integrationListCalls().length).toBeGreaterThan(0));
    expect(screen.queryByTestId('connection-point-test-integrations-button')).toBeNull();
    expect(screen.queryByTestId('integrations-admin-only-notice')).toBeNull();
  });

  it('shows Test Integrations with integrations.view and integrations.edit', async () => {
    mockPermissions = { 'integrations.view': true, 'integrations.edit': true };
    await mountPage();

    expect(screen.getByTestId('connection-point-test-integrations-button')).toBeEnabled();
  });
});
