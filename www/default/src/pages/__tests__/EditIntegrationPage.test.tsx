import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import EditIntegrationPage from '../EditIntegrationPage';
import {
  KEEP_SAVED_SIGNING_SECRET_HINT,
  SIGNING_SECRET_TOO_SHORT,
} from '../../components/integration-forms/WebhookIntegrationForm';
import { apiClient } from '../../api';

jest.mock('../../api', () => ({
  apiClient: {
    get: jest.fn(),
    put: jest.fn(),
    post: jest.fn(),
    delete: jest.fn(),
  },
}));

jest.mock('../../utils/toaster', () => ({
  showToast: jest.fn(),
}));

let mockPermissions: Record<string, boolean> = {};
jest.mock('../../context/PermissionsContext', () => {
  const permissions = () => ({
    hasPermission: (feature: string) => mockPermissions[feature] === true,
    loading: false,
  });
  return { usePermissions: permissions, useOptionalPermissions: permissions };
});

const mockGet = apiClient.get as jest.Mock;
const mockPut = apiClient.put as jest.Mock;

const INTEGRATION_CONFIG = {
  types: [
    { enum_value: 'stream', name: 'Stream', description: 'Stream', metadata: {} },
    { enum_value: 'webhook', name: 'Webhook', description: 'Webhook', metadata: {} },
  ],
  categories: [
    { enum_value: 'general', name: 'General', description: 'General purpose', metadata: {} },
    {
      enum_value: 'audit',
      name: 'Governance Audit',
      description: 'Forwards every record written to the VP Audit Log',
      metadata: {},
    },
  ],
};

const variable = (name: string, category: string) => ({
  name,
  label: name,
  description: name,
  example: name,
  category,
});

const RUNTIME_VARIABLES = {
  categories: [
    {
      category: 'general',
      label: 'General',
      description: 'General',
      variables: ['APPLIANCE_ID', 'EVENT_TYPE', 'TIMESTAMP'].map(name => variable(name, 'general')),
    },
    {
      category: 'audit',
      label: 'Governance Audit',
      description: 'Governance Audit',
      variables: ['AUDIT_RECORD', 'AUDIT_CATEGORY', 'AUDIT_TRACE_ID', 'AUDIT_SURFACE_ID'].map(
        name => variable(name, 'audit')
      ),
    },
  ],
};

const STREAM_INTEGRATION = {
  id: 'int-1',
  name: 'Events to Kafka',
  description: '',
  type: 'stream',
  category: 'general',
  configuration: { platform: 'kafka', topic: 'events', brokers: 'kafka-1:9092' },
  content: { event_type: '${EVENT_TYPE}' }, // eslint-disable-line no-template-curly-in-string
  status: 'active',
};

// The Webhook form generates its signing secret with crypto.randomUUID, which jsdom lacks.
if (typeof globalThis.crypto?.randomUUID !== 'function') {
  Object.defineProperty(globalThis, 'crypto', {
    value: { randomUUID: () => '00000000-0000-4000-8000-000000000000' },
    configurable: true,
  });
}

function renderEditor(integration: Record<string, unknown> = STREAM_INTEGRATION) {
  mockGet.mockImplementation((url: string) =>
    Promise.resolve({
      data:
        url === '/integrations/config'
          ? INTEGRATION_CONFIG
          : url === '/integrations/int-1'
            ? integration
            : RUNTIME_VARIABLES,
    })
  );
  return render(
    <MemoryRouter initialEntries={['/integrations/integrations/int-1']}>
      <Routes>
        <Route path="/integrations/integrations/:id" element={<EditIntegrationPage />} />
      </Routes>
    </MemoryRouter>
  );
}

function payloadTemplate(type = 'stream'): Record<string, unknown> {
  return JSON.parse((screen.getByTestId(`${type}-payload-template`) as HTMLTextAreaElement).value);
}

describe('EditIntegrationPage governance audit', () => {
  beforeEach(() => {
    mockPermissions = { 'audit.view': true };
    mockGet.mockReset();
    mockPut.mockReset();
    mockPut.mockResolvedValue({ data: {} });
  });

  it('moves an existing stream into the audit category with the audit record template', async () => {
    renderEditor();

    const select = (await screen.findByTestId('integration-category-select')) as HTMLSelectElement;
    await waitFor(() => expect(select.value).toBe('general'));
    expect(screen.queryByTestId('integration-audit-card')).not.toBeInTheDocument();

    fireEvent.change(select, { target: { value: 'audit' } });
    expect(screen.getByTestId('integration-audit-card')).toBeInTheDocument();
    expect(payloadTemplate()).toEqual(STREAM_INTEGRATION.content);

    fireEvent.click(screen.getByTestId('integration-audit-template-button'));
    expect(payloadTemplate()).toHaveProperty('record', '${AUDIT_RECORD}'); // eslint-disable-line no-template-curly-in-string

    const saveButton = screen.getByRole('button', { name: /Save Changes/ });
    await waitFor(() => expect(saveButton).toBeEnabled());
    fireEvent.submit(screen.getByTestId('integration-form'));

    await waitFor(() => expect(mockPut).toHaveBeenCalledTimes(1));
    const [url, body] = mockPut.mock.calls[0];
    expect(url).toBe('/integrations/int-1');
    expect(body).toMatchObject({ category: 'audit', type: 'stream' });
    expect(body.content).toHaveProperty('record', '${AUDIT_RECORD}'); // eslint-disable-line no-template-curly-in-string
  });

  it('moves a webhook stored with the untouched sample into the audit template', async () => {
    /* eslint-disable no-template-curly-in-string */
    const storedSample = {
      timestamp: '${TIMESTAMP}',
      event_type: '${EVENT_TYPE}',
      appliance_id: '${APPLIANCE_ID}',
    };
    /* eslint-enable no-template-curly-in-string */
    renderEditor({
      ...STREAM_INTEGRATION,
      type: 'webhook',
      configuration: { url_secret_id: 'hook', method: 'POST' },
      content: storedSample,
    });

    const select = (await screen.findByTestId('integration-category-select')) as HTMLSelectElement;
    await waitFor(() => expect(select.value).toBe('general'));
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 0));
    });
    expect(payloadTemplate('webhook')).toEqual(storedSample);

    fireEvent.change(select, { target: { value: 'audit' } });
    await waitFor(
      () => expect(payloadTemplate('webhook')).toHaveProperty('record', '${AUDIT_RECORD}') // eslint-disable-line no-template-curly-in-string
    );
  });

  it('hides the audit category from callers without audit.view', async () => {
    mockPermissions = {};
    renderEditor();

    const select = (await screen.findByTestId('integration-category-select')) as HTMLSelectElement;
    await waitFor(() => expect(select.value).toBe('general'));
    expect(Array.from(select.options).map(option => option.value)).toEqual(['general']);
  });
});

describe('EditIntegrationPage saved credentials', () => {
  const SECRETS = [{ id: 'internal-1', secret_id: 'api-token', name: 'API token' }];

  function renderWithSecrets(integration: Record<string, unknown>) {
    renderEditor(integration);
    const base = mockGet.getMockImplementation() as (url: string) => Promise<unknown>;
    mockGet.mockImplementation((url: string) =>
      url === '/secrets/' ? Promise.resolve({ data: SECRETS }) : base(url)
    );
  }

  async function savedConfiguration(): Promise<Record<string, unknown>> {
    fireEvent.submit(await screen.findByTestId('integration-form'));
    await waitFor(() => expect(mockPut).toHaveBeenCalledTimes(1));
    return mockPut.mock.calls[0][1].configuration;
  }

  const expectNoCredentialAndReference = (configuration: Record<string, unknown>) => {
    expect(JSON.stringify(configuration)).not.toContain('********');
    Object.keys(configuration)
      .filter(key => key.endsWith('_secret_id') && key !== 'headers_secret_id')
      .forEach(key => expect(configuration).not.toHaveProperty(key.slice(0, -'_secret_id'.length)));
  };

  beforeEach(() => {
    mockPermissions = { 'secrets.view': true };
    mockGet.mockReset();
    mockPut.mockReset();
    mockPut.mockResolvedValue({ data: {} });
  });

  it('saves an email integration without re-entering the SMTP password', async () => {
    renderWithSecrets({
      ...STREAM_INTEGRATION,
      type: 'email',
      configuration: {
        smtp_host: 'smtp.example.com',
        smtp_port: 587,
        smtp_username: 'user',
        from: 'a@example.com',
        to: ['b@example.com'],
        use_starttls: true,
      },
      content: { subject: 's', body: 'b' },
    });

    expect(await screen.findByTestId('email-smtp-password-secret')).not.toBeRequired();
    const configuration = await savedConfiguration();
    expect(configuration).not.toHaveProperty('smtp_password');
    expect(configuration).not.toHaveProperty('smtp_password_secret_id');
    expect(screen.queryByText(/fill in all required email/)).not.toBeInTheDocument();
  });

  it('sends the URL reference back, keeps the signing secret and drops the pinned destination', async () => {
    renderWithSecrets({
      ...STREAM_INTEGRATION,
      type: 'webhook',
      configuration: {
        method: 'POST',
        url_secret_id: 'api-token',
        headers: { 'X-Trace': '1' },
        headers_secret_id: { Authorization: 'api-token' },
        pinned_destination: { url: 'api.example.com:443', headers: { host: 'ab12' } },
      },
      content: { event_type: '${EVENT_TYPE}' }, // eslint-disable-line no-template-curly-in-string
    });

    expect(await screen.findByTestId('webhook-url-pinned-destination')).toHaveTextContent(
      'Sends to api.example.com:443'
    );
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 0));
    });
    const configuration = await savedConfiguration();
    expect(configuration).toEqual({
      method: 'POST',
      url_secret_id: 'api-token',
      headers: { 'X-Trace': '1' },
      headers_secret_id: { Authorization: 'api-token' },
    });
    expectNoCredentialAndReference(configuration);
  });

  it('sends a loaded Slack URL reference and shows where it sends', async () => {
    renderWithSecrets({
      ...STREAM_INTEGRATION,
      type: 'slack',
      configuration: {
        webhook_url_secret_id: 'api-token',
        pinned_destination: { webhook_url: 'hooks.slack.com:443' },
      },
      content: { text: 'hello' },
    });

    expect(await screen.findByTestId('slack-webhook-url')).toHaveValue('api-token');
    expect(screen.getByTestId('slack-webhook-url-pinned-destination')).toHaveTextContent(
      'Sends to hooks.slack.com:443'
    );
    const configuration = await savedConfiguration();
    expect(configuration).toEqual({ webhook_url_secret_id: 'api-token' });
  });

  it('keeps asking for a URL secret after a category change remounts the form', async () => {
    mockPermissions = { 'audit.view': true, 'secrets.view': true };
    renderWithSecrets({
      ...STREAM_INTEGRATION,
      type: 'webhook',
      configuration: { method: 'POST' },
      content: {},
    });

    const hint = await screen.findByTestId('webhook-url-legacy-hint');
    fireEvent.change(screen.getByTestId('integration-category-select'), {
      target: { value: 'audit' },
    });
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 0));
    });

    expect(screen.getByTestId('webhook-url-legacy-hint')).not.toBe(hint);
  });

  describe('required URL secrets and loaded references', () => {
    const WEBHOOK = {
      ...STREAM_INTEGRATION,
      type: 'webhook',
      content: { event_type: '${EVENT_TYPE}' }, // eslint-disable-line no-template-curly-in-string
    };

    const pressSave = () => fireEvent.keyDown(window, { key: 's', ctrlKey: true });

    const settle = () =>
      act(async () => {
        await new Promise(resolve => setTimeout(resolve, 0));
      });

    it('is not saved with Ctrl+S once the URL picker is cleared', async () => {
      renderWithSecrets({
        ...WEBHOOK,
        configuration: { method: 'POST', url_secret_id: 'api-token' },
      });

      await waitFor(() => expect(screen.getByTestId('webhook-url')).toHaveValue('api-token'));
      await settle();
      fireEvent.change(screen.getByTestId('webhook-url'), { target: { value: '' } });

      expect(screen.getByTestId('webhook-url')).toBeInvalid();
      pressSave();
      await settle();
      expect(mockPut).not.toHaveBeenCalled();
    });

    it('refuses a blank URL secret even when the form is submitted directly', async () => {
      renderWithSecrets({ ...WEBHOOK, configuration: { method: 'POST' } });

      await screen.findByTestId('webhook-url');
      await settle();
      expect(screen.queryByText(/keep the saved URL/)).toBeNull();
      fireEvent.submit(screen.getByTestId('integration-form'));

      expect(
        await screen.findByText('Choose the secret holding the webhook URL')
      ).toBeInTheDocument();
      expect(mockPut).not.toHaveBeenCalled();
    });

    it('blocks a typed signing secret shorter than 32 characters', async () => {
      renderWithSecrets({
        ...WEBHOOK,
        configuration: { method: 'POST', url_secret_id: 'api-token' },
      });

      await screen.findByTestId('webhook-signing-secret-input');
      await settle();
      fireEvent.change(screen.getByTestId('webhook-signing-secret-input'), {
        target: { value: 'too-short' },
      });
      fireEvent.submit(screen.getByTestId('integration-form'));

      await waitFor(() =>
        expect(screen.getAllByText(SIGNING_SECRET_TOO_SHORT).length).toBeGreaterThan(1)
      );
      expect(mockPut).not.toHaveBeenCalled();
    });

    it('remembers a cleared signing secret reference after a category change remounts the form', async () => {
      mockPermissions = { 'audit.view': true, 'secrets.view': true };
      renderWithSecrets({
        ...WEBHOOK,
        configuration: {
          method: 'POST',
          url_secret_id: 'api-token',
          signing_secret_secret_id: 'api-token',
        },
        content: {},
      });

      await screen.findByTestId('webhook-signing-secret-input');
      await settle();
      const input = screen.getByTestId('webhook-signing-secret-input');
      fireEvent.change(input, { target: { value: 'x'.repeat(32) } });
      fireEvent.change(input, { target: { value: '' } });
      fireEvent.change(screen.getByTestId('integration-category-select'), {
        target: { value: 'audit' },
      });
      await settle();

      expect(screen.getByTestId('webhook-signing-secret-input')).not.toBe(input);
      expect(screen.queryByText(KEEP_SAVED_SIGNING_SECRET_HINT)).toBeNull();
    });

    it('refuses to drop a signing secret loaded as a reference', async () => {
      renderWithSecrets({
        ...WEBHOOK,
        configuration: {
          method: 'POST',
          url_secret_id: 'api-token',
          signing_secret_secret_id: 'api-token',
        },
      });

      await screen.findByTestId('webhook-signing-secret-input');
      await settle();
      const input = screen.getByTestId('webhook-signing-secret-input');
      fireEvent.change(input, { target: { value: 'x'.repeat(32) } });
      fireEvent.change(input, { target: { value: '' } });
      await settle();
      pressSave();

      expect(
        await screen.findByText('Enter a signing secret, or revert to keep the stored one')
      ).toBeInTheDocument();
      expect(mockPut).not.toHaveBeenCalled();
    });
  });
});
