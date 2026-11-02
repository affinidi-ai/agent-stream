import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import App from './App';
import { apiClient, TERMS_ACCEPTANCE_REQUIRED_EVENT, TERMS_OPERATIONAL_FAILURE_EVENT } from './api';

jest.mock('./api', () => ({
  TERMS_ACCEPTANCE_REQUIRED_EVENT: 'terms-acceptance-required',
  TERMS_OPERATIONAL_FAILURE_EVENT: 'terms-operational-failure',
  apiClient: { fetch: jest.fn() },
  sessionManager: { logout: jest.fn().mockResolvedValue(undefined) },
}));
jest.mock('./pages/LoginPage', () => () => <div data-testid="mock-login" />);
jest.mock('./pages/AuthenticatedApp', () => ({ termsEnabled }: { termsEnabled: boolean }) => (
  <div data-testid="mock-authenticated" data-terms-enabled={String(termsEnabled)} />
));
jest.mock('./pages/TermsConsentPage', () => () => <div data-testid="mock-terms-consent" />);
jest.mock('./pages/SandboxOAuthCallback', () => () => <div data-testid="mock-sandbox" />);

beforeEach(() => {
  (apiClient.fetch as jest.Mock).mockReset();
});

test('moves an authenticated app into consent state after a protected API rejection', async () => {
  (apiClient.fetch as jest.Mock).mockResolvedValue(
    new Response(JSON.stringify({ authenticated: true, consent_required: false }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })
  );

  render(<App />);
  expect(await screen.findByTestId('mock-authenticated')).toBeInTheDocument();

  act(() => window.dispatchEvent(new Event(TERMS_ACCEPTANCE_REQUIRED_EVENT)));

  expect(await screen.findByTestId('mock-terms-consent')).toBeInTheDocument();
  expect(screen.queryByTestId('mock-authenticated')).not.toBeInTheDocument();
});

test('passes disabled Terms state into authenticated navigation', async () => {
  (apiClient.fetch as jest.Mock).mockResolvedValue(
    new Response(
      JSON.stringify({ authenticated: true, consent_required: false, terms_enabled: false }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    )
  );

  render(<App />);

  expect(await screen.findByTestId('mock-authenticated')).toHaveAttribute(
    'data-terms-enabled',
    'false'
  );
});

test('blocks on a runtime Terms operational failure and retries authentication', async () => {
  (apiClient.fetch as jest.Mock).mockImplementation(() =>
    Promise.resolve(
      new Response(
        JSON.stringify({ authenticated: true, consent_required: false, terms_enabled: true }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      )
    )
  );

  render(<App />);
  expect(await screen.findByTestId('mock-authenticated')).toBeInTheDocument();

  act(() => window.dispatchEvent(new Event(TERMS_OPERATIONAL_FAILURE_EVENT)));
  expect(await screen.findByTestId('page-terms-operational-error')).toBeInTheDocument();

  fireEvent.click(screen.getByTestId('terms-retry-button'));
  expect(await screen.findByTestId('mock-authenticated')).toBeInTheDocument();
  expect(apiClient.fetch).toHaveBeenCalledTimes(2);
});
