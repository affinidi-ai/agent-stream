import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import CreateGatewayConnectionPointWizardPage from '../CreateGatewayConnectionPointWizardPage';
import { apiClient } from '../../api';

jest.mock('../../api', () => ({
  apiClient: { get: jest.fn(), post: jest.fn() },
}));

jest.mock('../../utils/runtimeVariables', () => ({
  getRuntimeVariablesForCategories: jest.fn().mockResolvedValue({}),
}));

jest.mock('../../components/gateway-create-connection-point/SelectMediatorStep', () => ({
  __esModule: true,
  default: ({ onNext }: { onNext: (mediatorId: string) => void }) => (
    <button type="button" onClick={() => onNext('med-1')}>
      Pick mediator
    </button>
  ),
}));

jest.mock('../../components/gateway-create-connection-point/EnterDetailsStep', () => ({
  __esModule: true,
  default: ({ onCreate }: { onCreate: (gatewayId: string, name: string) => void }) => (
    <button type="button" onClick={() => onCreate('gw-1', 'CP')}>
      Enter details
    </button>
  ),
}));

let mockPermissions: Record<string, boolean> = {};
jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({
    hasPermission: (feature: string) => mockPermissions[feature] === true,
    loading: false,
  }),
}));

const mockGet = apiClient.get as jest.Mock;

const goToIntegrationsStep = () => {
  render(
    <MemoryRouter>
      <CreateGatewayConnectionPointWizardPage />
    </MemoryRouter>
  );
  fireEvent.click(screen.getByText('Pick mediator'));
  fireEvent.click(screen.getByText('Enter details'));
};

describe('CreateGatewayConnectionPointWizardPage integrations access', () => {
  beforeEach(() => {
    mockPermissions = {};
    mockGet.mockReset();
    mockGet.mockResolvedValue({
      data: [{ id: 'int-1', name: 'Alerts', type: 'slack', category: 'connection_point' }],
    });
  });

  it('shows the administrators notice on the Integrations step without integrations.view', () => {
    goToIntegrationsStep();

    expect(screen.getByTestId('integrations-admin-only-notice')).toHaveTextContent(
      'Integrations are managed by administrators.'
    );
    expect(mockGet).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: /Create/ })).toBeEnabled();
  });

  it('reads integrations and offers the picker with integrations.view', async () => {
    mockPermissions = { 'integrations.view': true };
    goToIntegrationsStep();

    await waitFor(() => expect(mockGet).toHaveBeenCalledWith('/integrations'));
    expect(screen.queryByTestId('integrations-admin-only-notice')).toBeNull();
  });
});
