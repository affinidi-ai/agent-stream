import React from 'react';
import { MemoryRouter } from 'react-router-dom';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import CallerAuthFullscreen from '../CallerAuthFullscreen';

jest.mock('../../../../../api', () => ({
  apiClient: {
    fetch: jest.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve([]),
    }),
    get: jest.fn(),
  },
}));

const { apiClient } = jest.requireMock('../../../../../api') as {
  apiClient: { fetch: jest.Mock; get: jest.Mock };
};

function renderEditor(config: any, onField: jest.Mock, onFields: jest.Mock) {
  return render(
    <MemoryRouter>
      <CallerAuthFullscreen
        node={{ id: 'x', type: 'caller-auth', config } as any}
        config={config}
        updateField={onField}
        updateFields={onFields}
        protocol="a2a"
      />
    </MemoryRouter>
  );
}

describe('CallerAuthFullscreen — API-key secret dropdown', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    apiClient.fetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve([]),
    } as any);
    apiClient.get.mockResolvedValue({ data: [] });
  });

  it('loads /secrets/ and lets the user pick an ApiKey secret from a dropdown', async () => {
    apiClient.get.mockResolvedValueOnce({
      data: [
        { id: 'sec-1', name: 'Team keys', secret_type: 'ApiKey' },
        { id: 'sec-2', name: 'Vendor token', secret_type: 'OAuthToken' },
        { id: 'sec-3', name: 'Legacy keys' },
      ],
    });

    const updateField = jest.fn();
    const updateFields = jest.fn();
    renderEditor({ method_type: 'api_key' }, updateField, updateFields);

    await waitFor(() => expect(apiClient.get).toHaveBeenCalledWith('/secrets/'));

    // OAuth-typed secret is filtered out; ApiKey and typeless secrets survive.
    await waitFor(() => {
      expect(screen.getByRole('option', { name: 'Team keys' })).toBeInTheDocument();
    });
    expect(screen.getByRole('option', { name: 'Legacy keys' })).toBeInTheDocument();
    expect(screen.queryByRole('option', { name: 'Vendor token' })).not.toBeInTheDocument();

    const select = (await screen.findByTestId('caller-auth-secret-id')) as HTMLSelectElement;
    fireEvent.change(select, { target: { value: 'sec-1' } });
    expect(updateField).toHaveBeenCalledWith('api_key_secret_id', 'sec-1');
  });

  it('shows the "no secrets configured" alert when the list is empty', async () => {
    apiClient.get.mockResolvedValueOnce({ data: [] });

    renderEditor({ method_type: 'api_key' }, jest.fn(), jest.fn());

    await screen.findByText(/No API-key secrets are configured/i);
    expect(screen.queryByLabelText(/^Secret/i)).not.toBeInTheDocument();
  });

  it('surfaces a previously-selected secret id that is no longer in the list as "(not found)"', async () => {
    apiClient.get.mockResolvedValueOnce({
      data: [{ id: 'sec-current', name: 'Current', secret_type: 'ApiKey' }],
    });

    renderEditor(
      { method_type: 'api_key', api_key_secret_id: 'sec-deleted' },
      jest.fn(),
      jest.fn()
    );

    await waitFor(() => {
      expect(
        screen.getByRole('option', { name: /sec-deleted \(not found\)/i })
      ).toBeInTheDocument();
    });
  });

  it('resolves a preconfigured secret by its secret_id and shows its name (any type)', async () => {
    apiClient.get.mockResolvedValueOnce({
      data: [
        {
          id: 'uuid-abc',
          secret_id: 'external-inbound-key',
          name: 'Inbound key',
          secret_type: 'General',
        },
      ],
    });

    renderEditor(
      { method_type: 'api_key', api_key_secret_id: 'external-inbound-key' },
      jest.fn(),
      jest.fn()
    );

    await waitFor(() => expect(apiClient.get).toHaveBeenCalledWith('/secrets/'));
    // Matched by secret_id (not the UUID) and shown by name — no "(not found)".
    const option = (await screen.findByRole('option', {
      name: 'Inbound key',
    })) as HTMLOptionElement;
    expect(option.value).toBe('external-inbound-key');
    expect(screen.queryByRole('option', { name: /not found/i })).not.toBeInTheDocument();
    const select = (await screen.findByTestId('caller-auth-secret-id')) as HTMLSelectElement;
    expect(select.value).toBe('external-inbound-key');
  });
});
