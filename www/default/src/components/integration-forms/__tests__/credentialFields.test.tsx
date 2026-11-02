import React from 'react';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import SlackIntegrationForm, { SlackConfiguration } from '../SlackIntegrationForm';
import WebhookIntegrationForm, {
  KEEP_SAVED_SIGNING_SECRET_HINT,
  SIGNING_SECRET_TOO_SHORT,
  WebhookConfiguration,
} from '../WebhookIntegrationForm';
import EmailIntegrationForm, { EmailConfiguration } from '../EmailIntegrationForm';
import StreamIntegrationForm from '../StreamIntegrationForm';
import type { PinnedDestinations } from '../../../utils/integrationCredentials';
import { LEGACY_URL_HINT } from '../UrlCredentialField';
import { apiClient } from '../../../api';

jest.mock('../../../api', () => ({
  apiClient: { get: jest.fn() },
}));

const mockGet = apiClient.get as jest.Mock;

const STREAM_KEEP_SAVED_HINT = 'Leave blank to keep the saved value.';

const SECRETS = [
  { id: 'internal-1', secret_id: 'slack-hook', name: 'Slack hook' },
  { id: 'internal-2', secret_id: 'api-token', name: 'API token' },
];

if (typeof globalThis.crypto?.randomUUID !== 'function') {
  Object.defineProperty(globalThis, 'crypto', {
    value: { randomUUID: () => '00000000-0000-4000-8000-000000000000' },
    configurable: true,
  });
}

const inRouter = (ui: React.ReactElement) => render(<MemoryRouter>{ui}</MemoryRouter>);

const lastCall = <T,>(fn: jest.Mock): T => fn.mock.calls[fn.mock.calls.length - 1][0] as T;

const waitForSecrets = () =>
  waitFor(() =>
    expect(screen.getAllByRole('option', { name: /Slack hook/ }).length).toBeGreaterThan(0)
  );

const EMAIL: EmailConfiguration = {
  smtp_host: 'smtp.example.com',
  smtp_port: 587,
  smtp_username: 'user',
  from: 'a@example.com',
  to: ['b@example.com'],
  use_tls: false,
  use_starttls: true,
};

beforeEach(() => {
  mockGet.mockReset();
  mockGet.mockResolvedValue({ data: SECRETS });
});

describe('URL credential fields', () => {
  function mountSlack(configuration: SlackConfiguration, pinnedDestinations?: PinnedDestinations) {
    const onConfigurationChange = jest.fn();
    inRouter(
      <SlackIntegrationForm
        configuration={configuration}
        content={{ text: 'hello' }}
        onConfigurationChange={onConfigurationChange}
        onContentChange={jest.fn()}
        pinnedDestinations={pinnedDestinations}
      />
    );
    return onConfigurationChange;
  }

  it('renders only a required secret picker for each URL', async () => {
    mountSlack({});
    await waitForSecrets();

    const picker = screen.getByTestId('slack-webhook-url') as HTMLSelectElement;
    expect(picker.tagName).toBe('SELECT');
    expect(picker).toBeRequired();
    expect(picker.checkValidity()).toBe(false);
    expect(screen.queryByRole('textbox', { name: /webhook url/i })).toBeNull();
    expect(screen.queryByTestId('slack-webhook-url-input')).toBeNull();
    expect(screen.queryByText(/keep the saved URL/)).toBeNull();
  });

  it.each([
    [
      'Webhook',
      () => (
        <WebhookIntegrationForm
          configuration={{}}
          content={{}}
          onConfigurationChange={jest.fn()}
          onContentChange={jest.fn()}
          isEditMode
        />
      ),
      'webhook-url',
    ],
    [
      'Redis',
      () => (
        <StreamIntegrationForm
          configuration={{ platform: 'redis', topic: 't' }}
          content={{}}
          onConfigurationChange={jest.fn()}
          onContentChange={jest.fn()}
          isEditMode
        />
      ),
      'stream-redis-url',
    ],
  ])('requires the %s URL secret in edit mode too', async (_name, ui, testId) => {
    inRouter(ui());
    await waitForSecrets();

    expect(screen.getByTestId(testId).tagName).toBe('SELECT');
    expect(screen.getByTestId(testId)).toBeRequired();
    expect(screen.queryByTestId(`${testId}-input`)).toBeNull();
  });

  it('sends the picked secret reference', async () => {
    const onChange = mountSlack({});
    await waitForSecrets();

    fireEvent.change(screen.getByTestId('slack-webhook-url'), {
      target: { value: 'slack-hook' },
    });
    expect(lastCall<SlackConfiguration>(onChange)).toEqual({
      webhook_url_secret_id: 'slack-hook',
    });
  });

  it('does not auto-pick the only secret for a URL field', async () => {
    mockGet.mockResolvedValue({ data: [SECRETS[0]] });
    const onChange = mountSlack({});
    await waitForSecrets();

    expect(onChange).not.toHaveBeenCalled();
  });

  it('shows where a saved URL sends and that a new pick is checked on save', async () => {
    const pinned = { webhook_url: { host: 'hooks.slack.com:443', secretId: 'slack-hook' } };
    mountSlack({ webhook_url_secret_id: 'slack-hook' }, pinned);
    await waitForSecrets();

    const destination = screen.getByTestId('slack-webhook-url-pinned-destination');
    expect(destination).toHaveTextContent('Sends to hooks.slack.com:443');
    expect(destination).not.toHaveTextContent(/checked when you save/);

    cleanup();
    mountSlack({ webhook_url_secret_id: 'api-token' }, pinned);
    await waitForSecrets();
    expect(screen.getByTestId('slack-webhook-url-pinned-destination')).toHaveTextContent(
      /checked when you save/
    );
  });

  describe('a URL that may still be stored inline', () => {
    const mountEditSlack = (configuration: SlackConfiguration, references: string[] = []) => {
      const onConfigurationChange = jest.fn();
      inRouter(
        <SlackIntegrationForm
          configuration={configuration}
          content={{ text: 'hello' }}
          onConfigurationChange={onConfigurationChange}
          onContentChange={jest.fn()}
          isEditMode
          loadedReferences={new Set(references)}
        />
      );
      return onConfigurationChange;
    };

    it('asks for a secret when an edited integration loaded without a reference or pin', async () => {
      mountEditSlack({});
      await waitForSecrets();

      expect(screen.getByTestId('slack-webhook-url-legacy-hint')).toHaveTextContent(
        LEGACY_URL_HINT
      );
    });

    it('shows no hint when the integration loaded with a reference', async () => {
      mountEditSlack({ webhook_url_secret_id: 'slack-hook' }, ['webhook_url_secret_id']);
      await waitForSecrets();
      expect(screen.queryByTestId('slack-webhook-url-legacy-hint')).toBeNull();

      cleanup();
      mountEditSlack({}, ['webhook_url_secret_id']);
      await waitForSecrets();
      expect(screen.queryByTestId('slack-webhook-url-legacy-hint')).toBeNull();
    });

    it('shows no hint when creating', async () => {
      mountSlack({});
      await waitForSecrets();

      expect(screen.queryByTestId('slack-webhook-url-legacy-hint')).toBeNull();
    });

    it('hides the hint once a secret is picked', async () => {
      inRouter(
        <WebhookIntegrationForm
          configuration={{}}
          content={{}}
          onConfigurationChange={jest.fn()}
          onContentChange={jest.fn()}
          isEditMode
        />
      );
      await waitForSecrets();
      expect(screen.getByTestId('webhook-url-legacy-hint')).toBeInTheDocument();

      fireEvent.change(screen.getByTestId('webhook-url'), { target: { value: 'slack-hook' } });
      expect(screen.queryByTestId('webhook-url-legacy-hint')).toBeNull();
    });
  });

  it('shows no destination when none was pinned', async () => {
    mountSlack({ webhook_url_secret_id: 'slack-hook' });
    await waitForSecrets();

    expect(screen.queryByTestId('slack-webhook-url-pinned-destination')).toBeNull();
  });

  it('shows the create-secret link and a notice when secrets cannot be loaded', async () => {
    mockGet.mockRejectedValue({ response: { status: 403 } });
    mountSlack({});

    expect(await screen.findByTestId('slack-webhook-url-secrets-unavailable')).toBeInTheDocument();
    const link = screen.getByTestId('slack-webhook-url-create-secret-link');
    expect(link).toHaveAttribute('href', '/secrets/new');
    expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('rel', 'noopener noreferrer');
  });

  it('reloads the secrets when the window regains focus', async () => {
    mountSlack({});
    await waitForSecrets();
    expect(mockGet).toHaveBeenCalledTimes(1);

    mockGet.mockResolvedValue({
      data: [...SECRETS, { id: 'internal-3', secret_id: 'new-hook', name: 'New hook' }],
    });
    fireEvent.focus(window);

    expect(await screen.findByRole('option', { name: /New hook/ })).toBeInTheDocument();
    expect(mockGet).toHaveBeenCalledTimes(2);
    expect(mockGet).toHaveBeenLastCalledWith('/secrets/');
  });

  it('stops reloading the secrets on focus once unmounted', async () => {
    mountSlack({});
    await waitForSecrets();
    cleanup();

    fireEvent.focus(window);
    expect(mockGet).toHaveBeenCalledTimes(1);
  });

  it('disables the secret picker with the form and keeps the selection', async () => {
    inRouter(
      <SlackIntegrationForm
        configuration={{ webhook_url_secret_id: 'slack-hook' }}
        content={{ text: 'hello' }}
        onConfigurationChange={jest.fn()}
        onContentChange={jest.fn()}
        disabled
      />
    );
    await waitForSecrets();

    const picker = screen.getByTestId('slack-webhook-url');
    expect(picker).toBeDisabled();
    expect(picker).toHaveValue('slack-hook');
  });
});

describe('Email SMTP password', () => {
  it('is a required secret picker when creating', async () => {
    const onChange = jest.fn();
    inRouter(
      <EmailIntegrationForm
        configuration={EMAIL}
        content={{ subject: 's', body: 'b' }}
        onConfigurationChange={onChange}
        onContentChange={jest.fn()}
      />
    );
    await waitForSecrets();

    expect(screen.queryByLabelText(/^Password \*/)).not.toBeInTheDocument();
    const picker = screen.getByTestId('email-smtp-password-secret');
    expect(picker.tagName).toBe('SELECT');
    expect(picker).toBeRequired();

    fireEvent.change(picker, { target: { value: 'api-token' } });
    expect(lastCall<EmailConfiguration>(onChange)).toEqual({
      ...EMAIL,
      smtp_password_secret_id: 'api-token',
    });
  });

  it('is optional in edit mode', async () => {
    inRouter(
      <EmailIntegrationForm
        configuration={EMAIL}
        content={{ subject: 's', body: 'b' }}
        onConfigurationChange={jest.fn()}
        onContentChange={jest.fn()}
        isEditMode
      />
    );
    await waitForSecrets();

    expect(screen.getByTestId('email-smtp-password-secret')).not.toBeRequired();
    expect(screen.getByText(/Leave blank to keep the saved password/)).toBeInTheDocument();
  });

  it('stays required in edit mode when it was loaded as a secret reference', async () => {
    inRouter(
      <EmailIntegrationForm
        configuration={{ ...EMAIL, smtp_password_secret_id: 'api-token' }}
        content={{ subject: 's', body: 'b' }}
        onConfigurationChange={jest.fn()}
        onContentChange={jest.fn()}
        isEditMode
        loadedReferences={new Set(['smtp_password_secret_id'])}
      />
    );
    await waitForSecrets();

    expect(screen.getByTestId('email-smtp-password-secret')).toBeRequired();
    expect(screen.queryByText(/Leave blank to keep the saved password/)).toBeNull();
  });
});

describe('Webhook signing secret and secret headers', () => {
  function mountWebhook(
    configuration: WebhookConfiguration,
    isEditMode: boolean,
    loadedReferences?: ReadonlySet<string>
  ) {
    const onConfigurationChange = jest.fn();
    inRouter(
      <WebhookIntegrationForm
        configuration={configuration}
        content={{}}
        onConfigurationChange={onConfigurationChange}
        onContentChange={jest.fn()}
        isEditMode={isEditMode}
        loadedReferences={loadedReferences}
      />
    );
    return onConfigurationChange;
  }

  it('generates a signing secret when creating', async () => {
    const onChange = mountWebhook({}, false);
    await waitForSecrets();

    expect(screen.getByTestId('webhook-signing-secret-input')).not.toHaveValue('');
    expect(lastCall<WebhookConfiguration>(onChange).signing_secret).toBeTruthy();
  });

  it('keeps the saved signing secret in edit mode instead of rotating it', async () => {
    const onChange = mountWebhook({}, true);
    await waitForSecrets();

    expect(screen.getByTestId('webhook-signing-secret-input')).toHaveValue('');
    expect(screen.getByTestId('webhook-signing-secret-hint')).toHaveTextContent(
      KEEP_SAVED_SIGNING_SECRET_HINT
    );
    expect(lastCall<WebhookConfiguration>(onChange).signing_secret).toBeUndefined();

    fireEvent.click(screen.getByTestId('webhook-signing-secret-generate-button'));
    expect(lastCall<WebhookConfiguration>(onChange).signing_secret).toBeTruthy();
  });

  it('blocks a typed signing secret shorter than 32 characters', async () => {
    mountWebhook({}, true);
    await waitForSecrets();

    expect(screen.getByText(/at least 32 characters/)).toBeInTheDocument();
    const input = screen.getByTestId('webhook-signing-secret-input');
    fireEvent.change(input, { target: { value: 'too-short' } });

    expect(input).toHaveClass('is-invalid');
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(screen.getByTestId('webhook-signing-secret-error')).toHaveTextContent(
      SIGNING_SECRET_TOO_SHORT
    );

    fireEvent.change(input, { target: { value: 'x'.repeat(32) } });
    expect(input).not.toHaveClass('is-invalid');
    expect(screen.queryByTestId('webhook-signing-secret-error')).toBeNull();
  });

  it('accepts the generated signing secret', async () => {
    mountWebhook({}, false);
    await waitForSecrets();

    expect(screen.getByTestId('webhook-signing-secret-input')).not.toHaveClass('is-invalid');
  });

  it('disables the signing secret controls with the form', async () => {
    inRouter(
      <WebhookIntegrationForm
        configuration={{}}
        content={{}}
        onConfigurationChange={jest.fn()}
        onContentChange={jest.fn()}
        isEditMode
        disabled
      />
    );
    await waitForSecrets();

    expect(screen.getByTestId('webhook-signing-secret-input')).toBeDisabled();
    expect(screen.getByTestId('webhook-signing-secret-generate-button')).toBeDisabled();
  });

  it('does not offer to keep a signing secret that was loaded as a secret reference', async () => {
    mountWebhook(
      { signing_secret_secret_id: 'api-token' },
      true,
      new Set(['signing_secret_secret_id'])
    );
    await waitForSecrets();

    expect(screen.getByTestId('webhook-signing-secret-hint')).toHaveTextContent(
      /Signed with the stored secret api-token/
    );

    const input = screen.getByTestId('webhook-signing-secret-input');
    fireEvent.change(input, { target: { value: 'typed' } });
    fireEvent.change(input, { target: { value: '' } });
    expect(screen.queryByTestId('webhook-signing-secret-hint')).toBeNull();
  });

  it('round-trips headers_secret_id through the secret header rows', async () => {
    const onChange = mountWebhook({ headers_secret_id: { Authorization: 'api-token' } }, true);
    await waitForSecrets();

    expect(screen.getByTestId('webhook-secret-header-name-0')).toHaveValue('Authorization');
    expect(screen.getByTestId('webhook-secret-header-secret-0')).toHaveValue('api-token');
    expect(lastCall<WebhookConfiguration>(onChange).headers_secret_id).toEqual({
      Authorization: 'api-token',
    });

    fireEvent.click(screen.getByTestId('webhook-secret-header-add-button'));
    fireEvent.change(screen.getByTestId('webhook-secret-header-name-1'), {
      target: { value: 'X-Api-Key' },
    });
    fireEvent.change(screen.getByTestId('webhook-secret-header-secret-1'), {
      target: { value: 'slack-hook' },
    });
    expect(lastCall<WebhookConfiguration>(onChange).headers_secret_id).toEqual({
      Authorization: 'api-token',
      'X-Api-Key': 'slack-hook',
    });

    fireEvent.click(screen.getByTestId('webhook-secret-header-remove-0'));
    expect(lastCall<WebhookConfiguration>(onChange).headers_secret_id).toEqual({
      'X-Api-Key': 'slack-hook',
    });
  });

  it('ignores a secret header row without a name', async () => {
    const onChange = mountWebhook({}, true);
    await waitForSecrets();

    fireEvent.click(screen.getByTestId('webhook-secret-header-add-button'));
    fireEvent.change(screen.getByTestId('webhook-secret-header-secret-0'), {
      target: { value: 'api-token' },
    });
    expect(lastCall<WebhookConfiguration>(onChange).headers_secret_id).toBeUndefined();
  });

  it('explains how saved credential headers are kept and removed', async () => {
    mountWebhook({}, true);
    await waitForSecrets();

    expect(screen.getByTestId('webhook-headers-hint')).toHaveTextContent(
      /not shown and are kept when left out/
    );
    const hint = screen.getByTestId('webhook-headers-hint');
    expect(hint).toHaveTextContent('"Authorization": null');
    expect(hint).toHaveTextContent(
      /containing auth, cookie, cred, key, pass, secret, session or token/
    );
    expect(hint).toHaveTextContent(/X-Session-Id/);
  });
});

describe('Stream credentials', () => {
  it('sends secret references for SASL', async () => {
    const onChange = jest.fn();
    inRouter(
      <StreamIntegrationForm
        configuration={{
          platform: 'kafka',
          topic: 't',
          brokers: 'b:9092',
          auth_type: 'sasl',
          sasl_username: 'u',
        }}
        content={{}}
        onConfigurationChange={onChange}
        onContentChange={jest.fn()}
        isEditMode
      />
    );
    await waitForSecrets();

    fireEvent.change(screen.getByTestId('stream-sasl-password-secret'), {
      target: { value: 'api-token' },
    });
    const config = lastCall<Record<string, unknown>>(onChange);
    expect(config).toMatchObject({ sasl_username: 'u', sasl_password_secret_id: 'api-token' });
    expect(config).not.toHaveProperty('sasl_password');
  });

  it('offers to keep the saved SASL password only when it was not loaded as a reference', async () => {
    const mountKafka = (sasl_password_secret_id?: string) =>
      inRouter(
        <StreamIntegrationForm
          configuration={{
            platform: 'kafka',
            topic: 't',
            brokers: 'b:9092',
            auth_type: 'sasl',
            sasl_username: 'u',
            sasl_password_secret_id,
          }}
          content={{}}
          onConfigurationChange={jest.fn()}
          onContentChange={jest.fn()}
          isEditMode
          loadedReferences={
            sasl_password_secret_id ? new Set(['sasl_password_secret_id']) : undefined
          }
        />
      );

    const first = mountKafka();
    await waitForSecrets();
    expect(screen.getByText(STREAM_KEEP_SAVED_HINT)).toBeInTheDocument();
    first.unmount();

    mountKafka('api-token');
    await waitForSecrets();
    expect(screen.getByTestId('stream-sasl-password-secret')).toHaveValue('api-token');
    expect(screen.queryByText(STREAM_KEEP_SAVED_HINT)).toBeNull();
  });

  it('uses the AWS credential chain for Kinesis instead of key pickers', async () => {
    const onChange = jest.fn();
    inRouter(
      <StreamIntegrationForm
        configuration={{ platform: 'kinesis', topic: 't', region: 'eu-west-1' }}
        content={{}}
        onConfigurationChange={onChange}
        onContentChange={jest.fn()}
        isEditMode
      />
    );
    await waitFor(() => expect(mockGet).toHaveBeenCalledWith('/secrets/'));

    expect(screen.getByTestId('stream-kinesis-credentials-hint')).toHaveTextContent(
      /AWS credential chain/
    );
    expect(screen.queryByTestId('stream-access-key-secret')).toBeNull();
    expect(screen.queryByTestId('stream-secret-key-secret')).toBeNull();

    fireEvent.change(screen.getByTestId('stream-topic-input'), { target: { value: 't2' } });
    expect(lastCall<Record<string, unknown>>(onChange)).toEqual({
      platform: 'kinesis',
      topic: 't2',
      region: 'eu-west-1',
    });
  });

  it('sends the Redis URL as a secret reference', async () => {
    const onChange = jest.fn();
    inRouter(
      <StreamIntegrationForm
        configuration={{ platform: 'redis', topic: 't' }}
        content={{}}
        onConfigurationChange={onChange}
        onContentChange={jest.fn()}
      />
    );
    await waitForSecrets();

    fireEvent.change(screen.getByTestId('stream-redis-url'), { target: { value: 'api-token' } });
    expect(lastCall<Record<string, unknown>>(onChange)).toEqual({
      platform: 'redis',
      topic: 't',
      redis_url_secret_id: 'api-token',
    });
  });
});
