import * as vscode from 'vscode';

import { log } from './log';

/**
 * Microsoft Entra ID (Azure AD) token acquisition via VS Code's built-in
 * `microsoft` authentication provider.
 *
 * The access token is passed as the bearer to the Agent Stream surface, which
 * validates it against a JWT verification strategy and resolves the caller to a
 * Member (for quotas/attribution) and to OPA (`input.source_auth.claims.*`).
 */

export interface EntraConfig {
  tenantId?: string;
  clientId?: string;
  scopes: string[];
}

/** Read the Entra settings from the `agentStream.entra.*` configuration. */
export function readEntraConfig(): EntraConfig {
  const cfg = vscode.workspace.getConfiguration('agentStream');
  const tenantId = cfg.inspect<string>('entra.tenantId')?.globalValue?.trim() || undefined;
  const clientId = cfg.inspect<string>('entra.clientId')?.globalValue?.trim() || undefined;
  const scopes = (cfg.inspect<string[]>('entra.scopes')?.globalValue ?? [])
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  return { tenantId, clientId, scopes };
}

/** Central sign-in identifiers pulled from an IDE Surface bootstrap document. */
export interface BootstrapAuth {
  tenantId?: string;
  clientId?: string;
  scopes?: string[];
}

/**
 * Resolve the effective Entra config used to acquire a token.
 *
 * Manual `agentStream.entra.*` settings are per-user **overrides** and take
 * precedence; any field left unset falls back to the surface's central
 * bootstrap values. This is what lets a client sign in from the Access Point
 * URL alone — change the identifiers once on the surface and every client
 * follows.
 */
export function resolveEntraConfig(bootstrap?: BootstrapAuth): EntraConfig {
  const manual = readEntraConfig();
  const bootstrapScopes = (bootstrap?.scopes ?? [])
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  return {
    tenantId: manual.tenantId ?? (bootstrap?.tenantId?.trim() || undefined),
    clientId: manual.clientId ?? (bootstrap?.clientId?.trim() || undefined),
    scopes: manual.scopes.length > 0 ? manual.scopes : bootstrapScopes,
  };
}

/**
 * Build the scope list for `authentication.getSession`.
 *
 * The built-in Microsoft provider understands two special scope modifiers that
 * must appear *before* the real API scopes:
 *   - `VSCODE_TENANT:<tenant-id>`   — target a specific tenant
 *   - `VSCODE_CLIENT_ID:<client-id>` — use a custom app registration
 */
export function buildScopeList(cfg: EntraConfig): string[] {
  const modifiers: string[] = [];
  if (cfg.tenantId) {
    modifiers.push(`VSCODE_TENANT:${cfg.tenantId}`);
  }
  if (cfg.clientId) {
    modifiers.push(`VSCODE_CLIENT_ID:${cfg.clientId}`);
  }
  return [...modifiers, ...cfg.scopes];
}

/**
 * Acquire an Entra access token.
 *
 * @param interactive when `true`, VS Code may prompt the user to sign in; when
 *   `false`, only an existing cached session is returned (no UI).
 * @param config the effective Entra config to use (manual settings merged with
 *   the surface bootstrap). Defaults to the manual `agentStream.entra.*`
 *   settings when omitted.
 * @returns the session, or `undefined` when not signed in (silent mode) or when
 *   no scopes are available (silent mode).
 * @throws when interactive and no scopes are available.
 */
export async function acquireToken(
  interactive: boolean,
  config?: EntraConfig,
): Promise<vscode.AuthenticationSession | undefined> {
  const cfg = config ?? readEntraConfig();
  if (cfg.scopes.length === 0) {
    log(
      'No Entra scopes available (the IDE Surface published none and ' +
        '"agentStream.entra.scopes" is unset).',
    );
    if (interactive) {
      throw new Error(
        'No sign-in scopes available. Configure Client sign-in on the IDE Surface, ' +
          'or set "agentStream.entra.scopes" (e.g. "api://<api-app-id>/access_as_user").',
      );
    }
    return undefined;
  }
  const scopeList = buildScopeList(cfg);
  log(`Acquiring Entra token (interactive=${interactive}, scopes=[${scopeList.join(', ')}]).`);
  const session = await vscode.authentication.getSession(
    'microsoft',
    scopeList,
    interactive ? { createIfNone: true } : { silent: true },
  );
  log(
    session
      ? `Entra token acquired for ${session.account.label}.`
      : 'No cached Entra session available (not signed in).',
  );
  return session;
}
