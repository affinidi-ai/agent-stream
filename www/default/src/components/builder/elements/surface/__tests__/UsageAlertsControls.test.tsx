import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { UsageAlertsControls } from '../SurfacePanel';
import type { UsageAlertForm } from '../../../../../pages/EditPipePage/types';

jest.mock('../../../../../api', () => ({
  apiClient: { get: jest.fn() },
}));

const { apiClient } = jest.requireMock('../../../../../api') as { apiClient: { get: jest.Mock } };

let mockPermissions: Record<string, boolean> = {};
jest.mock('../../../../../context/PermissionsContext', () => ({
  usePermissions: () => ({
    hasPermission: (feature: string) => mockPermissions[feature] === true,
    loading: false,
  }),
}));

const ALERTS: UsageAlertForm[] = [
  { alert_type: 'cost_threshold', threshold: 1, notification_channels: ['int-1'] },
];

function mountControls() {
  const onChange = jest.fn();
  render(
    <UsageAlertsControls value={ALERTS} enabled onEnabledChange={jest.fn()} onChange={onChange} />
  );
  return onChange;
}

describe('UsageAlertsControls integrations access', () => {
  beforeEach(() => {
    mockPermissions = {};
    apiClient.get.mockReset();
    apiClient.get.mockResolvedValue({ data: [{ id: 'int-1', name: 'Ops Slack' }] });
  });

  it('shows the administrators notice instead of the Notify via picker without integrations.view', () => {
    const onChange = mountControls();

    expect(screen.getByTestId('usage-alert-0-admin-only')).toHaveTextContent(
      'Integrations are managed by administrators.'
    );
    expect(screen.queryByTestId('usage-alert-0-channel-int-1')).toBeNull();
    expect(apiClient.get).not.toHaveBeenCalled();
    expect(onChange).not.toHaveBeenCalled();
  });

  it('offers the integrations to notify with integrations.view', async () => {
    mockPermissions = { 'integrations.view': true };
    mountControls();

    expect(await screen.findByTestId('usage-alert-0-channel-int-1')).toBeChecked();
    expect(apiClient.get).toHaveBeenCalledWith('/integrations');
    expect(screen.queryByTestId('usage-alert-0-admin-only')).toBeNull();
  });
});
