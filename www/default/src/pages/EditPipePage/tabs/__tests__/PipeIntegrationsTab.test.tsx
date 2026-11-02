import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import PipeIntegrationsTab from '../PipeIntegrationsTab';
import { apiClient } from '../../../../api';

jest.mock('../../../../api', () => ({
  apiClient: { get: jest.fn() },
}));

jest.mock('../../../../utils/runtimeVariables', () => ({
  getRuntimeVariablesForCategories: jest.fn().mockResolvedValue({}),
}));

let mockPermissions: Record<string, boolean> = {};
let mockPermissionsLoading = false;
jest.mock('../../../../context/PermissionsContext', () => ({
  usePermissions: () => ({
    hasPermission: (feature: string) => mockPermissions[feature] === true,
    loading: mockPermissionsLoading,
  }),
}));

const mockGet = apiClient.get as jest.Mock;

const SAVED = [{ integration_id: 'int-1', variables: {} }];

function mountTab() {
  const onIntegrationsChange = jest.fn();
  render(
    <MemoryRouter>
      <PipeIntegrationsTab
        pipeId="pipe-1"
        integrations={SAVED}
        onIntegrationsChange={onIntegrationsChange}
        onSave={jest.fn()}
      />
    </MemoryRouter>
  );
  return onIntegrationsChange;
}

const integrationListCalls = () => mockGet.mock.calls.filter(([url]) => url === '/integrations');

describe('PipeIntegrationsTab integrations access', () => {
  beforeEach(() => {
    mockPermissions = {};
    mockPermissionsLoading = false;
    mockGet.mockReset();
    mockGet.mockImplementation((url: string) =>
      Promise.resolve({
        data:
          url === '/integrations'
            ? [{ id: 'int-1', name: 'Alerts', type: 'slack', category: 'pipe' }]
            : { categories: [] },
      })
    );
  });

  it('shows the administrators notice and does not read integrations without integrations.view', async () => {
    const onIntegrationsChange = mountTab();

    expect(await screen.findByTestId('integrations-admin-only-notice')).toHaveTextContent(
      'Integrations are managed by administrators.'
    );
    await waitFor(() => expect(mockGet).toHaveBeenCalledWith('/integrations/config'));
    expect(integrationListCalls()).toHaveLength(0);
    expect(screen.queryByText(/Failed to load integrations/)).toBeNull();
    expect(screen.queryByRole('button', { name: /Save Integrations/ })).toBeNull();
    expect(onIntegrationsChange).not.toHaveBeenCalled();
  });

  it('waits for permissions before reading integrations', async () => {
    mockPermissionsLoading = true;
    mountTab();

    await waitFor(() => expect(mockGet).toHaveBeenCalledWith('/integrations/config'));
    expect(integrationListCalls()).toHaveLength(0);
    expect(screen.queryByTestId('integrations-admin-only-notice')).toBeNull();
  });

  it('reads integrations and offers the picker with integrations.view', async () => {
    mockPermissions = { 'integrations.view': true };
    mountTab();

    await waitFor(() => expect(integrationListCalls()).toHaveLength(1));
    expect(await screen.findByRole('option', { name: /Alerts \(slack\)/ })).toBeInTheDocument();
    expect(screen.queryByTestId('integrations-admin-only-notice')).toBeNull();
  });
});
