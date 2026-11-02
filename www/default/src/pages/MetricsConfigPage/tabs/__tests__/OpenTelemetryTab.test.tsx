import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import OpenTelemetryTab from '../OpenTelemetryTab';
import { MetricsConfig, OtlpAuthConfig } from '../../types';
import { apiClient } from '../../../../api';

jest.mock('../../../../api', () => ({
  apiClient: {
    get: jest.fn(),
    testOtlpConnection: jest.fn(),
  },
}));

jest.mock('../../../../context/AppContext', () => ({
  useApp: () => ({ state: { settings: null }, actions: { updateSettings: jest.fn() } }),
}));

function metricsConfig(auth?: OtlpAuthConfig): MetricsConfig {
  return {
    opentelemetry: {
      enabled: true,
      endpoint: 'https://collector.example.com:4317',
      protocol: 'grpc',
      auth,
      service_name: 'agent-stream',
      environment: 'test',
      traces: { enabled: true, sample_rate: 1, target_crates: [] },
      metrics: { enabled: true, export_interval_seconds: 30 },
      logs: { enabled: true },
    },
    cloudwatch: { enabled: false, region: '', namespace: '' },
    retention: { local_logs_hours: 24, collector_log_mb: 10 },
    advanced: {
      batch_size: 512,
      batch_delay_ms: 5000,
      batch_queue_size: 2048,
      host_metrics: { enabled: false },
    },
  } as MetricsConfig;
}

async function renderTab(auth?: OtlpAuthConfig, secretConfigured = !!auth) {
  const updateConfig = jest.fn();
  const view = render(
    <OpenTelemetryTab
      config={metricsConfig(auth)}
      updateConfig={updateConfig}
      secretConfigured={secretConfigured}
    />
  );
  await waitFor(() => expect(apiClient.get).toHaveBeenCalledWith('/secrets/'));
  if (auth) {
    await screen.findByText(/Admin API key/);
  }
  return { updateConfig, view };
}

describe('OpenTelemetryTab collector authentication', () => {
  beforeEach(() => {
    (apiClient.get as jest.Mock).mockResolvedValue({
      data: [
        { id: 'collector-token', secret_id: 'collector-token', name: 'Collector token' },
        { id: 'admin-api-key', secret_id: 'admin-api-key', name: 'Admin API key' },
      ],
    });
  });

  it('keeps the configured secret that the API no longer names', async () => {
    const { updateConfig } = await renderTab({
      header_name: 'Authorization',
      header_format: 'Bearer {value}',
    });

    const select = screen.getByTestId('otelAuthSecret') as HTMLSelectElement;
    expect(select.value).toBe('');
    expect(select.options[select.selectedIndex].text).toBe('Keep the configured secret');
    expect(screen.getByText(/A secret is configured; it is not shown/)).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Header Name'), { target: { value: 'X-Api-Key' } });

    expect(updateConfig).toHaveBeenCalledTimes(1);
    const [path, saved] = updateConfig.mock.calls[0];
    expect(path).toEqual(['opentelemetry', 'auth']);
    expect(saved).toEqual({ header_name: 'X-Api-Key', header_format: 'Bearer {value}' });
    expect('secret_id' in saved).toBe(false);
  });

  it('sends a newly chosen secret', async () => {
    const { updateConfig } = await renderTab({
      header_name: 'Authorization',
      header_format: 'Bearer {value}',
    });

    fireEvent.change(screen.getByTestId('otelAuthSecret'), { target: { value: 'admin-api-key' } });

    expect(updateConfig).toHaveBeenCalledWith(['opentelemetry', 'auth'], {
      header_name: 'Authorization',
      header_format: 'Bearer {value}',
      secret_id: 'admin-api-key',
    });
  });

  it('asks for a secret when authentication is newly enabled', async () => {
    const { updateConfig, view } = await renderTab();

    fireEvent.click(screen.getByLabelText('Authenticate to the collector'));

    const [, enabled] = updateConfig.mock.calls[0];
    expect(enabled.secret_id).toBe('');
    view.rerender(
      <OpenTelemetryTab
        config={metricsConfig(enabled)}
        updateConfig={updateConfig}
        secretConfigured={false}
      />
    );
    const select = screen.getByTestId('otelAuthSecret') as HTMLSelectElement;
    expect(select.options[select.selectedIndex].text).toBe('Select a secret...');
    expect(screen.queryByText(/A secret is configured/)).not.toBeInTheDocument();
  });

  it('keeps showing the configured secret when auth is re-ticked or the empty option is chosen', async () => {
    const { view } = await renderTab(
      { header_name: 'Authorization', header_format: 'Bearer {value}' },
      true
    );

    for (const secret_id of ['', undefined]) {
      view.rerender(
        <OpenTelemetryTab
          config={metricsConfig({
            header_name: 'Authorization',
            header_format: 'Bearer {value}',
            secret_id,
          })}
          updateConfig={jest.fn()}
          secretConfigured
        />
      );
      const select = screen.getByTestId('otelAuthSecret') as HTMLSelectElement;
      expect(select.options[select.selectedIndex].text).toBe('Keep the configured secret');
    }
  });
});
