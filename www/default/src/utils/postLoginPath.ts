const POST_LOGIN_PATH_KEY = 'post_login_path';

/** Only same-origin dashboard paths; never protocol-relative, backslash or API targets. */
export const isSafePostLoginPath = (path: string): boolean =>
  path.startsWith('/') &&
  !path.startsWith('//') &&
  !path.startsWith('/\\') &&
  !path.startsWith('/api/') &&
  !/[\r\n]/.test(path);

/**
 * Remember the current dashboard path and query before a sign-in that leaves
 * the page (SSO), so a deep link such as a preset `/access-tokens/new?…` survives.
 */
export const rememberPostLoginPath = (): void => {
  const path = `${window.location.pathname}${window.location.search}`;
  if (path === '/' || !isSafePostLoginPath(path)) return;
  try {
    sessionStorage.setItem(POST_LOGIN_PATH_KEY, path);
  } catch {
    // Storage unavailable: sign-in still works and lands on the dashboard.
  }
};

/**
 * Return to the remembered path once, after sign-in landed on the dashboard root.
 * Call before the router mounts so it starts on the restored location.
 */
export const restorePostLoginPath = (): void => {
  let path: string | null = null;
  try {
    path = sessionStorage.getItem(POST_LOGIN_PATH_KEY);
    sessionStorage.removeItem(POST_LOGIN_PATH_KEY);
  } catch {
    return;
  }
  if (path && window.location.pathname === '/' && isSafePostLoginPath(path)) {
    window.history.replaceState(null, '', path);
  }
};
