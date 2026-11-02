/**
 * Sandbox sign-in (OAuth 2.0 Authorization Code + PKCE, public client).
 *
 * Lets an operator sign in with a real delegated identity so the surface
 * sandbox can exercise surfaces that forward the caller's token (e.g. a
 * Microsoft 365 Copilot surface). The whole flow runs in the browser — the
 * dashboard is a **public client**, so there is no client secret. The token is
 * held only in this tab's `sessionStorage` and forwarded to `/execute` as the
 * caller bearer.
 *
 * Config comes from the LLM provider catalog (`llm.json` → provider
 * `sandbox_auth`), so any provider that needs auth follows the same pattern.
 */

/** Provider `sandbox_auth` block from the LLM catalog. Public identifiers only. */
export interface SandboxAuthConfig {
  /** Flow type. Only `oauth2_pkce` is supported today. */
  type: string;
  /** Authority family. `entra` derives the Microsoft login authority. */
  provider?: string;
  /** Entra tenant id (or `common` / `organizations`). */
  tenant_id?: string;
  /** OAuth public-client application (client) id. */
  client_id?: string;
  /** Full authority base URL override (takes precedence over provider/tenant). */
  authority?: string;
  /**
   * Optional origin (scheme + host [+ port]) for the OAuth redirect URI, e.g.
   * `https://gateway.example.com`. The callback **path** is fixed
   * (`/oauth/sandbox-callback`), so only the origin is configurable. When unset,
   * the live dashboard origin (`window.location.origin`) is used — that already
   * matches wherever you loaded the dashboard from, so an override is only needed
   * to pin a specific registered hostname. The chosen origin must also serve this
   * dashboard (the popup handshake is same-origin).
   */
  redirect_origin?: string;
  /** Delegated scopes to request. */
  scopes?: string[];
}

/** An acquired sandbox access token, held in `sessionStorage`. */
export interface SandboxToken {
  accessToken: string;
  /** Epoch milliseconds at which the token expires. */
  expiresAt: number;
  scopes: string[];
}

/** Public redirect path served by {@link SandboxOAuthCallback}. */
export const SANDBOX_CALLBACK_PATH = '/oauth/sandbox-callback';

const PENDING_KEY = 'agentstream.sandboxAuth.pending';
const MESSAGE_TYPE = 'agentstream-sandbox-auth';
const tokenKey = (providerId: string) => `agentstream.sandboxAuth.token.${providerId}`;

// ── PKCE primitives (Web Crypto) ──

function base64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function randomToken(byteLength = 48): string {
  const arr = new Uint8Array(byteLength);
  crypto.getRandomValues(arr);
  return base64Url(arr);
}

async function challengeFromVerifier(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return base64Url(new Uint8Array(digest));
}

// ── Config resolution ──

/** Resolve the OAuth authority base URL, or `null` when not derivable. */
export function authorityFor(cfg: SandboxAuthConfig): string | null {
  if (cfg.authority && cfg.authority.trim()) return cfg.authority.trim().replace(/\/$/, '');
  const provider = cfg.provider || 'entra';
  if (provider === 'entra' && cfg.tenant_id && cfg.tenant_id.trim()) {
    return `https://login.microsoftonline.com/${cfg.tenant_id.trim()}`;
  }
  return null;
}

/** Whether a `sandbox_auth` config is complete enough to attempt sign-in. */
export function sandboxAuthUsable(cfg?: SandboxAuthConfig | null): cfg is SandboxAuthConfig {
  return (
    !!cfg &&
    cfg.type === 'oauth2_pkce' &&
    !!authorityFor(cfg) &&
    !!cfg.client_id &&
    (cfg.scopes?.length ?? 0) > 0
  );
}

/**
 * Extract the Microsoft Entra tenant id from a JWT verification strategy's
 * `expected_issuer` — the v2 issuer `https://login.microsoftonline.com/{tenant}/v2.0`
 * or the legacy `https://sts.windows.net/{tenant}/`. Returns `null` for a
 * non-Entra / unrecognised issuer, or for the multi-tenant placeholders
 * (`common` / `organizations` / `consumers`) that don't name a concrete tenant.
 * Used to auto-match a sandbox sign-in profile (an OAuth Identifier whose tenant
 * issues the tokens the surface's Caller Context accepts) to the surface's
 * inbound verification tenant.
 */
export function tenantFromIssuer(issuer?: string | null): string | null {
  if (!issuer) return null;
  const m =
    issuer.match(/login\.microsoftonline\.com\/([^/?#]+)/i) ??
    issuer.match(/sts\.windows\.net\/([^/?#]+)/i);
  const tenant = m?.[1]?.trim();
  if (!tenant) return null;
  const lower = tenant.toLowerCase();
  return lower === 'common' || lower === 'organizations' || lower === 'consumers' ? null : tenant;
}

/**
 * Full **OAuth Identifier** profile as returned by `GET /oauth-identifiers`
 * (the flattened wire shape: a `provider` tag plus the shape-specific
 * authority fields, `client_id` and `scopes`). Public identifiers only.
 */
export interface SandboxOAuthProfile {
  id: string;
  name: string;
  provider?: string;
  /** Entra shape. */
  tenant_id?: string;
  /** Okta shape. */
  domain?: string;
  authorization_server_id?: string;
  /** Generic OIDC shape. */
  issuer?: string;
  client_id?: string;
  scopes?: string[];
}

/**
 * Map an OAuth Identifier profile to the PKCE {@link SandboxAuthConfig} the
 * Sandbox tab consumes. The profile's shape (`entra` | `okta` | `oidc`) drives
 * the authority: Entra keeps `tenant_id` so `authorityFor` derives the Microsoft
 * login URL; Okta/OIDC resolve to a concrete `authority`. Returns `null` when
 * the profile is missing the fields sign-in needs. This is what lets a surface
 * reference a reusable Credentials profile for sandbox sign-in instead of an
 * inline `sandbox_auth` block (or a provider default in `llm.json`).
 */
export function sandboxAuthFromProfile(
  profile?: SandboxOAuthProfile | null
): SandboxAuthConfig | null {
  if (!profile || !profile.client_id) return null;
  const provider = profile.provider || 'entra';
  const base: SandboxAuthConfig = {
    type: 'oauth2_pkce',
    provider,
    client_id: profile.client_id,
    scopes: profile.scopes ?? [],
  };
  if (provider === 'entra') {
    base.tenant_id = profile.tenant_id;
  } else if (provider === 'okta') {
    const domain = (profile.domain ?? '').trim().replace(/\/$/, '');
    const asid = (profile.authorization_server_id ?? '').trim() || 'default';
    if (domain) base.authority = `https://${domain}/oauth2/${asid}`;
  } else if (provider === 'oidc') {
    const issuer = (profile.issuer ?? '').trim().replace(/\/$/, '');
    if (issuer) base.authority = issuer;
  }
  return sandboxAuthUsable(base) ? base : null;
}

/**
 * Resolve the OAuth redirect URI. Uses the configured `redirect_origin` when set,
 * otherwise the live dashboard origin; the callback path is always fixed.
 */
function redirectUri(cfg: SandboxAuthConfig): string {
  const origin = cfg.redirect_origin?.trim().replace(/\/$/, '') || window.location.origin;
  return `${origin}${SANDBOX_CALLBACK_PATH}`;
}

// ── Token storage (per provider, sessionStorage) ──

/** Read a live (non-expired) token for a provider, or `null`. */
export function readSandboxToken(providerId: string): SandboxToken | null {
  try {
    const raw = sessionStorage.getItem(tokenKey(providerId));
    if (!raw) return null;
    const token = JSON.parse(raw) as SandboxToken;
    if (!token.accessToken || token.expiresAt <= Date.now()) {
      sessionStorage.removeItem(tokenKey(providerId));
      return null;
    }
    return token;
  } catch {
    return null;
  }
}

/** Discard any stored token for a provider (sign out). */
export function clearSandboxToken(providerId: string): void {
  try {
    sessionStorage.removeItem(tokenKey(providerId));
  } catch {
    /* ignore */
  }
}

function storeSandboxToken(providerId: string, token: SandboxToken): void {
  try {
    sessionStorage.setItem(tokenKey(providerId), JSON.stringify(token));
  } catch {
    /* ignore */
  }
}

// ── Interactive sign-in (popup) ──

/**
 * Open a sign-in popup and resolve with the acquired token. The popup lands on
 * {@link SANDBOX_CALLBACK_PATH}, exchanges the code, and posts the result back;
 * the token is stored for the provider before resolving. Rejects when the popup
 * is blocked, closed early, or the flow errors.
 */
export async function signInToTest(
  providerId: string,
  cfg: SandboxAuthConfig
): Promise<SandboxToken> {
  const authority = authorityFor(cfg);
  if (!authority || !cfg.client_id) {
    throw new Error(
      'Sign-in is not fully configured for this provider (missing tenant/client id).'
    );
  }

  const verifier = randomToken(48);
  const challenge = await challengeFromVerifier(verifier);
  const state = randomToken(16);
  const scopes = (cfg.scopes ?? []).join(' ');
  const redirect = redirectUri(cfg);

  sessionStorage.setItem(
    PENDING_KEY,
    JSON.stringify({
      providerId,
      verifier,
      state,
      authority,
      clientId: cfg.client_id,
      scopes,
      redirectUri: redirect,
    })
  );

  const authorizeUrl = new URL(`${authority}/oauth2/v2.0/authorize`);
  authorizeUrl.searchParams.set('client_id', cfg.client_id);
  authorizeUrl.searchParams.set('response_type', 'code');
  authorizeUrl.searchParams.set('redirect_uri', redirect);
  authorizeUrl.searchParams.set('response_mode', 'query');
  authorizeUrl.searchParams.set('scope', scopes);
  authorizeUrl.searchParams.set('state', state);
  authorizeUrl.searchParams.set('code_challenge', challenge);
  authorizeUrl.searchParams.set('code_challenge_method', 'S256');

  const popup = window.open(
    authorizeUrl.toString(),
    'agentstream-sandbox-signin',
    'width=520,height=700'
  );
  if (!popup) {
    throw new Error('Sign-in popup was blocked. Allow popups for this site and try again.');
  }

  return await new Promise<SandboxToken>((resolve, reject) => {
    let settled = false;
    const cleanup = () => {
      window.removeEventListener('message', onMessage);
      clearInterval(closedTimer);
    };
    const onMessage = (event: MessageEvent) => {
      if (event.origin !== window.location.origin) return;
      const data = event.data;
      if (!data || data.type !== MESSAGE_TYPE) return;
      settled = true;
      cleanup();
      if (data.ok && data.accessToken) {
        const token: SandboxToken = {
          accessToken: data.accessToken,
          expiresAt: data.expiresAt,
          scopes: cfg.scopes ?? [],
        };
        storeSandboxToken(providerId, token);
        resolve(token);
      } else {
        reject(new Error(data.error || 'Sign-in failed.'));
      }
    };
    window.addEventListener('message', onMessage);
    const closedTimer = setInterval(() => {
      if (popup.closed && !settled) {
        cleanup();
        reject(new Error('Sign-in window closed before completing.'));
      }
    }, 500);
  });
}

/**
 * Run the authorization-code exchange inside the callback popup and post the
 * result back to the opener. Called by {@link SandboxOAuthCallback}. Always
 * closes the popup when done.
 */
export async function completeSandboxCallbackInPopup(): Promise<void> {
  const params = new URLSearchParams(window.location.search);
  const post = (message: Record<string, unknown>) => {
    try {
      window.opener?.postMessage({ type: MESSAGE_TYPE, ...message }, window.location.origin);
    } catch {
      /* ignore */
    }
  };

  const authError = params.get('error');
  if (authError) {
    post({ ok: false, error: params.get('error_description') || authError });
    window.close();
    return;
  }

  const code = params.get('code');
  const state = params.get('state');
  const pendingRaw = sessionStorage.getItem(PENDING_KEY);
  if (!code || !pendingRaw) {
    post({ ok: false, error: 'Missing authorization code.' });
    window.close();
    return;
  }

  const pending = JSON.parse(pendingRaw) as {
    verifier: string;
    state: string;
    authority: string;
    clientId: string;
    scopes: string;
    redirectUri?: string;
  };
  if (state !== pending.state) {
    post({ ok: false, error: 'State mismatch — sign-in aborted.' });
    sessionStorage.removeItem(PENDING_KEY);
    window.close();
    return;
  }

  try {
    const body = new URLSearchParams({
      client_id: pending.clientId,
      grant_type: 'authorization_code',
      code,
      redirect_uri: pending.redirectUri || `${window.location.origin}${SANDBOX_CALLBACK_PATH}`,
      code_verifier: pending.verifier,
      scope: pending.scopes,
    });
    const response = await fetch(`${pending.authority}/oauth2/v2.0/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
    const data = await response.json();
    if (!response.ok || !data.access_token) {
      post({
        ok: false,
        error:
          data.error_description ||
          data.error ||
          `Token exchange failed (HTTP ${response.status}).`,
      });
    } else {
      const expiresAt = Date.now() + (Number(data.expires_in) || 3600) * 1000;
      post({ ok: true, accessToken: data.access_token, expiresAt });
    }
  } catch (error) {
    post({ ok: false, error: error instanceof Error ? error.message : 'Token exchange error.' });
  } finally {
    sessionStorage.removeItem(PENDING_KEY);
    window.close();
  }
}
