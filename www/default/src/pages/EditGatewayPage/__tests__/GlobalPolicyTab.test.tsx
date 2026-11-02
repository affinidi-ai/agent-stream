import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import GlobalPolicyTab from '../GlobalPolicyTab';

jest.mock('../../../api', () => ({
  apiClient: {
    get: jest.fn(),
    put: jest.fn(),
    fetch: jest.fn(),
  },
}));

const { apiClient } = jest.requireMock('../../../api') as {
  apiClient: { get: jest.Mock; put: jest.Mock; fetch: jest.Mock };
};

const policyDefs = [
  {
    id: 'p1',
    name: 'Baseline',
    description: 'base',
    policy_type: 'appliance',
    policy: 'package agentstream.policy',
    enabled: true,
  },
  {
    id: 'p2',
    name: 'Strict',
    description: 'strict',
    policy_type: 'appliance',
    policy: 'package agentstream.policy',
    enabled: true,
  },
];

function renderTab() {
  return render(
    <MemoryRouter>
      <GlobalPolicyTab gatewayId="gw-1" isSelfGateway={true} />
    </MemoryRouter>
  );
}

describe('GlobalPolicyTab multi-policy', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    apiClient.fetch.mockResolvedValue({ ok: true, json: async () => policyDefs });
  });

  it('renders each Trust Fabric policy as a checkbox with the enforced set pre-checked', async () => {
    apiClient.get.mockResolvedValue({
      data: { opa_policy_config: { enabled: true, policy: '', policy_definition_ids: ['p1'] } },
    });
    renderTab();
    const opt1 = (await screen.findByTestId('gateway-policy-option-p1')) as HTMLInputElement;
    const opt2 = screen.getByTestId('gateway-policy-option-p2') as HTMLInputElement;
    expect(opt1.checked).toBe(true);
    expect(opt2.checked).toBe(false);
  });

  it('adds a second policy to the enforced set on toggle (a set, not a single choice)', async () => {
    apiClient.get.mockResolvedValue({
      data: { opa_policy_config: { enabled: true, policy: '', policy_definition_ids: ['p1'] } },
    });
    renderTab();
    const opt2 = (await screen.findByTestId('gateway-policy-option-p2')) as HTMLInputElement;
    expect(opt2.checked).toBe(false);
    fireEvent.click(opt2);
    await waitFor(() =>
      expect((screen.getByTestId('gateway-policy-option-p2') as HTMLInputElement).checked).toBe(
        true
      )
    );
    // The first stays selected — both are enforced under deny-overrides.
    expect((screen.getByTestId('gateway-policy-option-p1') as HTMLInputElement).checked).toBe(true);
  });

  it('merges the legacy single policy_definition_id into the checkbox set', async () => {
    apiClient.get.mockResolvedValue({
      data: { opa_policy_config: { enabled: true, policy: '', policy_definition_id: 'p2' } },
    });
    renderTab();
    const opt2 = (await screen.findByTestId('gateway-policy-option-p2')) as HTMLInputElement;
    expect(opt2.checked).toBe(true);
  });
});
