import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import DriftAlertControls from '../DriftAlertControls';
import { apiClient } from '../../../../../api';

jest.mock('../../../../../api', () => ({
  apiClient: { get: jest.fn() },
}));

let mockPermissions: Record<string, boolean> = {};
jest.mock('../../../../../context/PermissionsContext', () => ({
  usePermissions: () => ({
    hasPermission: (feature: string) => mockPermissions[feature] === true,
    loading: false,
  }),
}));

const mockGet = apiClient.get as jest.Mock;

describe('DriftAlertControls integrations access', () => {
  beforeEach(() => {
    mockPermissions = {};
    mockGet.mockReset();
    mockGet.mockResolvedValue({
      data: [{ id: 'int-1', name: 'Drift Slack', category: 'llm_drift', status: 'active' }],
    });
  });

  it('shows the administrators notice and does not read integrations without integrations.view', () => {
    const onChange = jest.fn();
    render(
      <DriftAlertControls
        value={{ enabled: true, alert_integrations: ['int-1'] }}
        onChange={onChange}
      />
    );

    expect(screen.getByTestId('drift-alert-integrations-admin-only')).toHaveTextContent(
      'Integrations are managed by administrators.'
    );
    expect(screen.queryByTestId('drift-alert-integrations')).toBeNull();
    expect(screen.queryByTestId('drift-alert-none')).toBeNull();
    expect(mockGet).not.toHaveBeenCalled();
    expect(onChange).not.toHaveBeenCalled();
  });

  it('lists the LLM Drift integrations with integrations.view', async () => {
    mockPermissions = { 'integrations.view': true };
    render(<DriftAlertControls value={{ enabled: true }} onChange={jest.fn()} />);

    expect(await screen.findByLabelText(/Drift Slack/)).toBeInTheDocument();
    expect(mockGet).toHaveBeenCalledWith('/integrations');
    expect(screen.queryByTestId('drift-alert-integrations-admin-only')).toBeNull();
  });
});
