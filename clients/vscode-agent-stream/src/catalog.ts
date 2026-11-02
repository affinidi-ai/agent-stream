import * as vscode from 'vscode';

import { log } from './log';
import { resolveEndpointUrl, secureFetch, validateEndpointBase } from './security';

/**
 * Dynamic model discovery against an Agent Stream **IDE Surface** Access Point.
 *
 * The user configures a single Access Point base URL (`agentStream.endpoint`).
 * The extension derives the discovery URL (`agentStream.modelsPath`, default
 * `/v1/models`) and the chat URL (`agentStream.chatPath`,
 * default `/v1/chat/completions`) from it — so pointing the extension at any AP
 * URL "just works" without assuming a fixed path layout. Discovery returns the
 * caller's governed, per-caller-filtered menu; each entry is dispatched back by
 * its `id` in the request `model` field.
 */

/** Routing + presentation extension attached to each published model entry. */
export interface IdeModelEntryExt {
  /** Per-model chat route hint. In v1 this equals the IDE Surface's own route. */
  route: string;
  surface_id: string;
  variant_alias?: string;
  display_name: string;
  group?: string;
  order?: number;
  default?: boolean;
  /** Upstream OpenAI `model` string, when known. */
  model?: string;
  provider?: string;
  max_input_tokens?: number;
  max_output_tokens?: number;
  capabilities?: string[];
  description?: string;
  sunset_at?: string;
  /**
   * Upstream sign-in slot id (see `IdeBootstrap.upstreams`) whose token the
   * client should forward for this model in
   * `X-Agent-Stream-Upstream-Authorization`. Absent ⇒ forward the front-door
   * token (today's behaviour).
   */
  upstream_auth_id?: string;
}

/** A single published model entry (OpenAI base fields + `agent_stream`). */
export interface IdeModelEntry {
  id: string;
  object: string;
  created: number;
  owned_by: string;
  agent_stream: IdeModelEntryExt;
}

/** The `/v1/models` envelope an IDE Surface publishes. */
export interface IdeModelsResponse {
  object: string;
  data: IdeModelEntry[];
  catalog_version?: string;
}

/** Central sign-in identifiers carried by the IDE Surface bootstrap document. */
export interface IdeBootstrapAuth {
  provider: string;
  tenant_id: string;
  client_id: string;
  scopes: string[];
}

/**
 * An **upstream** sign-in slot published in the bootstrap. Describes how the
 * client acquires a *separate* token to forward to a member surface's upstream
 * provider (e.g. a Graph-audience token for Microsoft 365 Copilot), distinct
 * from the front-door token in `auth`. All fields are public OAuth identifiers.
 * A model's `agent_stream.upstream_auth_id` references one of these by `id`.
 */
export interface IdeUpstreamAuth {
  id: string;
  provider: string;
  tenant_id: string;
  client_id: string;
  scopes: string[];
}

/** The **public** IDE Surface bootstrap document (`GET /.well-known/agent-stream`). */
export interface IdeBootstrap {
  auth: IdeBootstrapAuth;
  /** Optional upstream sign-in slots (empty when the surface forwards only the front-door token). */
  upstreams?: IdeUpstreamAuth[];
  models_path: string;
  chat_path: string;
}

/** A discovered model normalized for the VS Code chat provider. */
export interface DiscoveredModel {
  id: string;
  name: string;
  detail?: string;
  maxInputTokens: number;
  maxOutputTokens: number;
  toolCalling: boolean;
  imageInput: boolean;
  /**
   * Upstream sign-in slot id whose token must be forwarded for this model, from
   * the catalogue entry's `agent_stream.upstream_auth_id`. Undefined ⇒ forward
   * only the front-door token.
   */
  upstreamAuthId?: string;
}

const DEFAULT_MAX_INPUT_TOKENS = 128000;
const DEFAULT_MAX_OUTPUT_TOKENS = 8192;
const DISCOVERY_TIMEOUT_MS = 30000;

/** Read the IDE Surface Access Point base URL from user/machine settings only. */
export function accessPoint(): string {
  const cfg = vscode.workspace.getConfiguration('agentStream');
  return (cfg.inspect<string>('endpoint')?.globalValue ?? '').trim().replace(/\/+$/, '');
}

export function allowLocalEndpoints(): boolean {
  const cfg = vscode.workspace.getConfiguration('agentStream');
  return cfg.inspect<boolean>('allowLocalEndpoints')?.globalValue === true;
}

/**
 * Resolve a discovery/dispatch path with the right precedence: an explicit user
 * override in settings wins (per-user escape hatch), otherwise the value the
 * surface published in its bootstrap document, otherwise the built-in default.
 * This is what lets a client need only the Access Point URL.
 */
function resolvePath(key: 'modelsPath' | 'chatPath', bootstrapPath: string | undefined, fallback: string): string {
  const cfg = vscode.workspace.getConfiguration('agentStream');
  const inspected = cfg.inspect<string>(key);
  const explicit = (inspected?.globalValue ?? '').trim();
  if (explicit) {
    return explicit;
  }
  const fromBootstrap = (bootstrapPath ?? '').trim();
  return fromBootstrap || fallback;
}

/**
 * Discovery URL: Access Point base + the model-discovery path. Prefers an
 * explicit `agentStream.modelsPath` override, then the bootstrap `models_path`,
 * then `/v1/models`.
 */
export function modelsUrl(base: string | URL, bootstrapPath?: string): string {
  return resolveEndpointUrl(base, resolvePath('modelsPath', bootstrapPath, '/v1/models'), 'agentStream.modelsPath');
}

/**
 * Chat URL: Access Point base + the dispatch path. Prefers an explicit
 * `agentStream.chatPath` override, then the bootstrap `chat_path`, then
 * `/v1/chat/completions`.
 */
export function chatUrl(base: string | URL, bootstrapPath?: string): string {
  return resolveEndpointUrl(base, resolvePath('chatPath', bootstrapPath, '/v1/chat/completions'), 'agentStream.chatPath');
}

/**
 * Fetch the IDE Surface **public** bootstrap document from its Access Point.
 *
 * This unauthenticated discovery document (`GET {base}/.well-known/agent-stream`)
 * lets the extension configure itself from the Access Point URL alone: it
 * carries the central sign-in identifiers (tenant/client/scopes) and the
 * discovery/dispatch paths. Returns `null` when the surface publishes no
 * bootstrap (404) or on a parse failure, so the caller falls back to manual
 * `agentStream.*` settings. **Throws `EndpointUnreachableError` when the fetch
 * itself fails (DNS failure, connection refused, TLS failure, timeout, …)** —
 * a fundamentally different situation from "server responded 404" that must
 * surface to the user rather than being silently masked as "no bootstrap".
 */
export class EndpointUnreachableError extends Error {
  readonly url: string;
  constructor(url: string, cause: unknown) {
    super(
      `Could not connect to Agent Stream instance at ${url} ` +
        `(${cause instanceof Error ? cause.message : String(cause)})`,
    );
    this.name = 'EndpointUnreachableError';
    this.url = url;
  }
}

export async function fetchBootstrap(base: string): Promise<IdeBootstrap | null> {
  if (!base) {
    return null;
  }
  let url: string;
  let response: Response;
  try {
    const allowLocalDevelopment = allowLocalEndpoints();
    const securityOptions = { allowLocalDevelopment };
    const endpoint = await validateEndpointBase(base, securityOptions);
    url = resolveEndpointUrl(endpoint, '/.well-known/agent-stream', 'bootstrap path');
    log(`Bootstrap → ${url}`);
    response = await secureFetch(
      url,
      { method: 'GET', headers: { Accept: 'application/json' } },
      DISCOVERY_TIMEOUT_MS,
      undefined,
      securityOptions,
    );
  } catch (error) {
    // Network-layer failure — the endpoint is unreachable. This is different
    // from a 404 (which means the server IS up but the surface has no
    // bootstrap): unreachable must surface to the user, 404 is a fallback path.
    log(
      `Bootstrap unreachable at ${base} ` +
        `(${error instanceof Error ? error.message : String(error)}).`,
    );
    throw new EndpointUnreachableError(base, error);
  }
  // 5xx from the ingress/reverse-proxy (typically 502/503/504) means the
  // upstream appliance is unreachable through the proxy — the `fetch()` doesn't
  // throw because the proxy responded, but the appliance behind it is down.
  // Treat that as unreachable too, so the user sees "Could not connect …"
  // instead of the misleading downstream "No sign-in scopes available".
  if (response.status >= 500) {
    log(`Bootstrap ← ${response.status} ${response.statusText} — upstream unreachable at ${base}.`);
    throw new EndpointUnreachableError(
      base,
      new Error(`upstream returned ${response.status} ${response.statusText}`),
    );
  }
  if (!response.ok) {
    log(`Bootstrap ← ${response.status} ${response.statusText} (using manual settings).`);
    return null;
  }
  try {
    const payload = (await response.json()) as IdeBootstrap;
    if (!payload || typeof payload !== 'object' || !payload.auth) {
      log('Bootstrap ← malformed document (using manual settings).');
      return null;
    }
    log(
      `Bootstrap ← provider=${payload.auth.provider}, ` +
        `scopes=${payload.auth.scopes?.length ?? 0}.`,
    );
    return payload;
  } catch (error) {
    log(
      `Bootstrap parse failed (${error instanceof Error ? error.message : String(error)}); ` +
        'using manual settings.',
    );
    return null;
  }
}

function hasCapability(caps: string[] | undefined, pattern: RegExp): boolean {
  return (caps ?? []).some((c) => pattern.test(c));
}

/** Map a published catalogue entry to the provider's normalized model shape. */
export function mapEntry(entry: IdeModelEntry): DiscoveredModel {
  const ext = entry.agent_stream;
  const caps = ext.capabilities ?? [];
  return {
    id: entry.id,
    name: ext.display_name?.trim() || entry.id,
    detail: ext.description ?? ext.group,
    maxInputTokens: ext.max_input_tokens ?? DEFAULT_MAX_INPUT_TOKENS,
    maxOutputTokens: ext.max_output_tokens ?? DEFAULT_MAX_OUTPUT_TOKENS,
    // Absent capability hints mean "unknown" — default tool calling on so
    // agentic Copilot modes keep working; narrow only when hints are present.
    toolCalling: caps.length === 0 ? true : hasCapability(caps, /tool|function/i),
    imageInput: hasCapability(caps, /vision|image/i),
    upstreamAuthId: ext.upstream_auth_id?.trim() || undefined,
  };
}

/**
 * Diagnostic: log only non-secret JWT metadata. The raw token, signature, and
 * PII-bearing claim values are never logged.
 */
function logAccessToken(context: string, token: string): void {
  const parts = token.split('.');
  if (parts.length !== 3) {
    log(`${context}: bearer token is not a JWT (${parts.length} segments).`);
    return;
  }
  const decodeSegment = (seg: string): Record<string, unknown> | null => {
    try {
      const b64 = seg.replace(/-/g, '+').replace(/_/g, '/');
      const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
      const value = JSON.parse(Buffer.from(b64 + pad, 'base64').toString('utf8'));
      return value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
    } catch {
      return null;
    }
  };
  const header = decodeSegment(parts[0]);
  const payload = decodeSegment(parts[1]);
  const groups = Array.isArray(payload?.groups) ? payload.groups.length : 0;
  const roles = Array.isArray(payload?.roles) ? payload.roles.length : 0;
  log(
    `${context}: JWT metadata = ${JSON.stringify({
      alg: header?.alg,
      typ: header?.typ,
      kid: header?.kid,
      iss: payload?.iss,
      aud: payload?.aud,
      ver: payload?.ver,
      tid: payload?.tid,
      appid: payload?.appid,
      azp: payload?.azp,
      groups_count: groups,
      roles_count: roles,
    })}`,
  );
}

/**
 * Fetch the IDE Surface catalogue from its Access Point and return the
 * normalized model list. Throws on network/HTTP/parse failure so the caller can
 * fall back to the static `agentStream.models` list. A **404** is surfaced as a
 * distinct `SurfaceNotFoundError` (URL is wrong / surface deleted — any live
 * surface serves `/v1/models`); a **5xx** as `EndpointUnreachableError` (proxy
 * up, upstream down).
 */
export class SurfaceNotFoundError extends Error {
  readonly url: string;
  constructor(url: string) {
    super(
      `The Agent Stream Access Point at ${url} could not be resolved (HTTP 404 on /v1/models). ` +
        'Check that "agentStream.endpoint" points to a live surface.',
    );
    this.name = 'SurfaceNotFoundError';
    this.url = url;
  }
}

export async function fetchCatalog(
  base: string,
  accessToken?: string,
  bootstrapPath?: string,
): Promise<DiscoveredModel[]> {
  if (!base) {
    throw new Error('Set "agentStream.endpoint" to your IDE Surface Access Point URL.');
  }
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (accessToken) {
    headers.Authorization = `Bearer ${accessToken}`;
    logAccessToken('Discovery', accessToken);
  }
  let url: string;
  let response: Response;
  try {
    const allowLocalDevelopment = allowLocalEndpoints();
    const securityOptions = { allowLocalDevelopment };
    const endpoint = await validateEndpointBase(base, securityOptions);
    url = modelsUrl(endpoint, bootstrapPath);
    log(`Discovery → ${url}`);
    response = await secureFetch(url, { method: 'GET', headers }, DISCOVERY_TIMEOUT_MS, undefined, securityOptions);
  } catch (error) {
    log(
      `Discovery unreachable at ${base} ` +
        `(${error instanceof Error ? error.message : String(error)}).`,
    );
    throw new EndpointUnreachableError(base, error);
  }
  if (response.status === 404) {
    log(`Discovery ← 404 at ${url} — surface not found.`);
    throw new SurfaceNotFoundError(base);
  }
  if (response.status >= 500) {
    log(`Discovery ← ${response.status} ${response.statusText} — upstream unreachable at ${base}.`);
    throw new EndpointUnreachableError(
      base,
      new Error(`upstream returned ${response.status} ${response.statusText}`),
    );
  }
  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(`Discovery failed: ${response.status} ${response.statusText} ${text}`.trim());
  }
  const payload = (await response.json()) as IdeModelsResponse;
  const data = Array.isArray(payload?.data) ? payload.data : [];
  const models = data.filter((e) => e && typeof e.id === 'string' && e.id.length > 0).map(mapEntry);
  log(`Discovery ← ${models.length} model(s) from IDE Surface.`);
  return models;
}
