import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import LoginPage from '../LoginPage';
import { apiClient } from '../../api';

jest.mock('../../api', () => ({
  apiClient: { fetch: jest.fn() },
  sessionManager: {
    didSessionExpire: () => false,
    clearSessionExpiredError: jest.fn(),
    getSessionToken: () => null,
    getCookie: () => null,
  },
}));

jest.mock('../../utils/passkeys', () => ({
  isWebAuthnSupported: () => true,
  isPlatformAuthenticatorAvailable: () => Promise.resolve(false),
  registerPasskey: jest.fn(),
  authenticateWithPasskey: jest.fn(),
}));

jest.mock('../../utils/postLoginPath', () => ({
  rememberPostLoginPath: jest.fn(),
}));

const mockFetch = apiClient.fetch as jest.Mock;

const answerAuthMode = (body: { mode: string; label?: string | null }) =>
  mockFetch.mockResolvedValue({ ok: true, json: () => Promise.resolve(body) });

describe('LoginPage single sign-on', () => {
  beforeEach(() => {
    mockFetch.mockReset();
    Object.defineProperty(window, 'location', { value: { href: '/' }, writable: true });
  });

  it('offers OIDC sign-in under the provider label and starts it at /api/oidc/login', async () => {
    answerAuthMode({ mode: 'oidc', label: 'Example IdP' });
    render(<LoginPage onLogin={jest.fn()} />);

    const button = await screen.findByTestId('login-oidc-button');
    expect(button).toHaveTextContent('Sign in with Example IdP');
    expect(screen.queryByTestId('login-username')).not.toBeInTheDocument();

    fireEvent.click(button);
    await waitFor(() => expect(window.location.href).toBe('/api/oidc/login'));
  });

  it('falls back to SSO when the OIDC mode has no label', async () => {
    answerAuthMode({ mode: 'oidc', label: null });
    render(<LoginPage onLogin={jest.fn()} />);

    expect(await screen.findByTestId('login-oidc-button')).toHaveTextContent('Sign in with SSO');
  });

  it('keeps SAML sign-in at /api/saml/login', async () => {
    answerAuthMode({ mode: 'saml', label: null });
    render(<LoginPage onLogin={jest.fn()} />);

    const button = await screen.findByTestId('login-saml-button');
    expect(button).toHaveTextContent('Sign in with SSO');

    fireEvent.click(button);
    await waitFor(() => expect(window.location.href).toBe('/api/saml/login'));
  });
});
