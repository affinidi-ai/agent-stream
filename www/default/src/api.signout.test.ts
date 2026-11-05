import { sessionManager } from './api';

const fetchMock = jest.fn();
const assign = jest.fn();
const reload = jest.fn();

const answer = (body: string, status = 200) =>
  fetchMock.mockResolvedValue(
    new Response(body, { status, headers: { 'Content-Type': 'application/json' } })
  );

beforeEach(() => {
  fetchMock.mockReset();
  assign.mockReset();
  reload.mockReset();
  global.fetch = fetchMock;
  Object.defineProperty(window, 'location', {
    value: { assign, reload, href: '/', pathname: '/', search: '', hash: '' },
    writable: true,
  });
  sessionStorage.setItem('session_token', 'tok');
});

test('logout resolves to the identity provider sign-out address when the server gives one', async () => {
  answer(JSON.stringify({ end_session_url: 'https://idp.example.com/logout?state=s' }));

  await expect(sessionManager.logout()).resolves.toBe('https://idp.example.com/logout?state=s');
  expect(sessionStorage.getItem('session_token')).toBeNull();
});

test('logout resolves to nothing for an empty, non-JSON or unsafe answer', async () => {
  for (const body of [
    '{}',
    '',
    'not json',
    JSON.stringify({ end_session_url: `${'javascript'}:alert(1)` }),
  ]) {
    answer(body);
    await expect(sessionManager.logout()).resolves.toBeUndefined();
  }
  answer(JSON.stringify({ end_session_url: 'https://idp.example.com/logout' }), 500);
  await expect(sessionManager.logout()).resolves.toBeUndefined();
});

test('an explicit sign-out goes to the provider sign-out address', async () => {
  answer(JSON.stringify({ end_session_url: 'https://idp.example.com/logout?state=s' }));

  await expect(sessionManager.signOut()).resolves.toBe(true);
  expect(assign).toHaveBeenCalledWith('https://idp.example.com/logout?state=s');
});

test('an explicit sign-out without a provider address stays in the dashboard', async () => {
  answer('{}');

  await expect(sessionManager.signOut()).resolves.toBe(false);
  expect(assign).not.toHaveBeenCalled();
});

test('an expired session never signs the person out of the identity provider', async () => {
  answer(JSON.stringify({ end_session_url: 'https://idp.example.com/logout?state=s' }));

  sessionManager.expireSession();

  await new Promise(resolve => setTimeout(resolve, 0));
  expect(reload).toHaveBeenCalled();
  expect(assign).not.toHaveBeenCalled();
});
