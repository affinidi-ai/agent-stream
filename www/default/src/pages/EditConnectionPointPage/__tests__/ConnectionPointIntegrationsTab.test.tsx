import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import ConnectionPointIntegrationsTab from '../ConnectionPointIntegrationsTab';
import { apiClient } from '../../../api';

jest.mock('../../../api', () => ({
  apiClient: { get: jest.fn() },
}));

jest.mock('../../../utils/runtimeVariables', () => ({
  getRuntimeVariablesForCategories: jest.fn().mockResolvedValue({}),
}));

let mockPermissions: Record<string, boolean> = {};
jest.mock('../../../context/PermissionsContext', () => ({
  usePermissions: () => ({
    hasPermission: (feature: string) => mockPermissions[feature] === true,
    loading: false,
  }),
}));

const mockGet = apiClient.get as jest.Mock;

function mountTab() {
  const onIntegrationsChange = jest.fn();
  render(
    <MemoryRouter>
      <ConnectionPointIntegrationsTab
        integrations={[{ integration_id: 'int-1', variables: {} }]}
        onIntegrationsChange={onIntegrationsChange}
      />
    </MemoryRouter>
  );
  return onIntegrationsChange;
}

describe('ConnectionPointIntegrationsTab integrations access', () => {
  beforeEach(() => {
    mockPermissions = {};
    mockGet.mockReset();
    mockGet.mockResolvedValue({
      data: [{ id: 'int-1', name: 'Alerts', type: 'slack', category: 'connection_point' }],
    });
  });

  it('shows the administrators notice and does not read integrations without integrations.view', () => {
    const onIntegrationsChange = mountTab();

    expect(screen.getByTestId('integrations-admin-only-notice')).toHaveTextContent(
      'Integrations are managed by administrators.'
    );
    expect(screen.queryByText('Loading integrations...')).toBeNull();
    expect(mockGet).not.toHaveBeenCalled();
    expect(onIntegrationsChange).not.toHaveBeenCalled();
  });

  it('reads integrations with integrations.view', async () => {
    mockPermissions = { 'integrations.view': true };
    mountTab();

    await waitFor(() => expect(mockGet).toHaveBeenCalledWith('/integrations'));
    await waitFor(() => expect(screen.queryByText('Loading integrations...')).toBeNull());
    expect(screen.queryByTestId('integrations-admin-only-notice')).toBeNull();
  });
});
