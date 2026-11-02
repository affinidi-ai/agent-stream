import { isSafePostLoginPath, rememberPostLoginPath, restorePostLoginPath } from './postLoginPath';

describe('post-login path', () => {
  const deepLink = '/access-tokens/new?name=metrics&scopes=metrics.view';

  beforeEach(() => {
    sessionStorage.clear();
    window.history.replaceState(null, '', '/');
  });

  it('restores a remembered deep link once after sign-in lands on the root', () => {
    window.history.replaceState(null, '', deepLink);
    rememberPostLoginPath();
    window.history.replaceState(null, '', '/');

    restorePostLoginPath();
    expect(`${window.location.pathname}${window.location.search}`).toBe(deepLink);

    window.history.replaceState(null, '', '/');
    restorePostLoginPath();
    expect(window.location.pathname).toBe('/');
  });

  it('does not remember the root and leaves other landing pages alone', () => {
    rememberPostLoginPath();
    expect(sessionStorage.length).toBe(0);

    sessionStorage.setItem('post_login_path', deepLink);
    window.history.replaceState(null, '', '/llm');
    restorePostLoginPath();
    expect(window.location.pathname).toBe('/llm');
  });

  it('refuses paths that could leave the dashboard', () => {
    expect(isSafePostLoginPath(deepLink)).toBe(true);
    for (const path of [
      '//evil.example',
      '/\\evil.example',
      'https://evil.example',
      '/api/saml/login',
      '/a\r\nb',
    ]) {
      expect(isSafePostLoginPath(path)).toBe(false);
    }
    sessionStorage.setItem('post_login_path', '//evil.example');
    restorePostLoginPath();
    expect(window.location.pathname).toBe('/');
  });
});
