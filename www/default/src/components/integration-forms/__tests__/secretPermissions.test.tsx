import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import SlackIntegrationForm from '../SlackIntegrationForm';
import { apiClient } from '../../../api';

jest.mock('../../../api', () => ({
  apiClient: { get: jest.fn() },
}));

let mockPermissions: Record<string, boolean> = {};
let mockPermissionsLoading = false;
jest.mock('../../../context/PermissionsContext', () => {
  const current = () => ({
    hasPermission: (feature: string) => mockPermissions[feature] === true,
    loading: mockPermissionsLoading,
  });
  return { usePermissions: current, useOptionalPermissions: current };
});

const mockGet = apiClient.get as jest.Mock;

const secretListCalls = () => mockGet.mock.calls.filter(([url]) => url === '/secrets/');

const slackForm = () => (
  <SlackIntegrationForm
    configuration={{}}
    content={{ text: 'hello' }}
    onConfigurationChange={jest.fn()}
    onContentChange={jest.fn()}
  />
);

describe('integration secret pickers and secrets permissions', () => {
  beforeEach(() => {
    mockPermissions = {};
    mockPermissionsLoading = false;
    mockGet.mockReset();
    mockGet.mockResolvedValue({ data: [{ id: 'i-1', secret_id: 'hook', name: 'Hook' }] });
  });

  it('does not read the secrets without secrets.view, not even on focus', async () => {
    render(slackForm());
    fireEvent.focus(window);
    expect(await screen.findByTestId('slack-webhook-url')).toBeInTheDocument();

    expect(secretListCalls()).toHaveLength(0);
    expect(screen.queryByRole('option', { name: /Hook/ })).toBeNull();
    expect(screen.queryByTestId('slack-webhook-url-secrets-unavailable')).toBeNull();
  });

  it('reads the secrets, and again on focus, with secrets.view', async () => {
    mockPermissions = { 'secrets.view': true };
    render(slackForm());

    expect(await screen.findByRole('option', { name: /Hook/ })).toBeInTheDocument();
    expect(secretListCalls()).toHaveLength(1);

    fireEvent.focus(window);
    await waitFor(() => expect(secretListCalls()).toHaveLength(2));
  });

  it('waits for permissions to load before reading the secrets', async () => {
    mockPermissionsLoading = true;
    mockPermissions = { 'secrets.view': true };
    const { rerender } = render(slackForm());
    fireEvent.focus(window);
    expect(secretListCalls()).toHaveLength(0);

    mockPermissionsLoading = false;
    rerender(slackForm());
    expect(await screen.findByRole('option', { name: /Hook/ })).toBeInTheDocument();
    expect(secretListCalls()).toHaveLength(1);
  });

  it('hides the Create secret link without secrets.edit', () => {
    mockPermissions = { 'secrets.view': true };
    render(slackForm());

    expect(screen.queryByTestId('slack-webhook-url-create-secret-link')).toBeNull();
  });

  it('shows the Create secret link with secrets.edit', () => {
    mockPermissions = { 'secrets.edit': true };
    render(slackForm());

    expect(screen.getByTestId('slack-webhook-url-create-secret-link')).toHaveAttribute(
      'href',
      '/secrets/new'
    );
  });
});
