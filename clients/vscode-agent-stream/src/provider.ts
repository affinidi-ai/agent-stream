import * as vscode from 'vscode';

import { EntraConfig, acquireToken, resolveEntraConfig } from './auth';
import {
  DiscoveredModel,
  EndpointUnreachableError,
  IdeBootstrap,
  SurfaceNotFoundError,
  accessPoint,
  allowLocalEndpoints,
  chatUrl as catalogChatUrl,
  fetchBootstrap,
  fetchCatalog,
} from './catalog';
import { OpenAITool, streamChatCompletion, toOpenAIMessages } from './chat';
import { log, logError, timed } from './log';

interface ModelConfig {
  id: string;
  name?: string;
  /** OpenAI `model` string sent to the surface. Defaults to `id`. */
  model?: string;
  /** Surface variant alias to address (`{endpoint}$alias/...`). Optional. */
  alias?: string;
  /** Per-model endpoint override. Defaults to `agentStream.endpoint`. */
  endpoint?: string;
  maxInputTokens?: number;
  maxOutputTokens?: number;
}

const DEFAULT_MAX_INPUT_TOKENS = 128000;
const DEFAULT_MAX_OUTPUT_TOKENS = 8192;

/**
 * Models discovered from the IDE Surface Access Point on the last successful
 * `provideLanguageModelChatInformation`, keyed by client-facing model id. Used
 * by `provideLanguageModelChatResponse` to dispatch a dynamically-discovered
 * model (one with no matching static `agentStream.models` entry).
 */
let discoveredSnapshot: { base: string; modelsById: ReadonlyMap<string, DiscoveredModel> } | null = null;

/**
 * The IDE Surface bootstrap document from the last discovery, cached so a chat
 * request can reuse the surface's central sign-in identifiers and dispatch path
 * without a second round trip. `null` means the surface published no bootstrap
 * (the extension then relies on manual `agentStream.*` settings).
 */
let lastBootstrap: IdeBootstrap | null = null;

/**
 * The Access Point base URL the cached `lastBootstrap` was fetched from. Used to
 * cache the result **including a negative (`null`) outcome**: when the surface
 * publishes no bootstrap (a 404), we must not re-fetch on every message. A cache
 * entry is valid only while the base URL is unchanged, so editing
 * `agentStream.endpoint` transparently forces a refresh.
 */
let bootstrapBase: string | null = null;

/** Fetch the surface bootstrap, caching the result (including `null`) per base URL. */
async function loadBootstrap(base: string): Promise<IdeBootstrap | null> {
  lastBootstrap = await timed('Bootstrap fetch', () => fetchBootstrap(base));
  bootstrapBase = base;
  return lastBootstrap;
}

/**
 * Return the cached bootstrap for `base`, fetching only when it has not been
 * fetched for this exact base URL yet. This caches a negative (`null`) result so
 * a surface with no bootstrap document does not incur a fresh 404 round trip on
 * every chat message.
 */
async function cachedBootstrap(base: string): Promise<IdeBootstrap | null> {
  return bootstrapBase === base ? lastBootstrap : loadBootstrap(base);
}

/** Map a bootstrap document to the auth override consumed by `resolveEntraConfig`. */
function bootstrapAuth(bootstrap: IdeBootstrap | null) {
  return bootstrap
    ? {
        tenantId: bootstrap.auth.tenant_id,
        clientId: bootstrap.auth.client_id,
        scopes: bootstrap.auth.scopes,
      }
    : undefined;
}

/**
 * Normalise a single OAuth scope string. Tolerates scopes pasted in JSON-array
 * style (wrapping quotes and/or a trailing comma, e.g.
 * `"https://graph.microsoft.com/Sites.Read.All",`) — those literal characters
 * make MSAL request the wrong resource and mint a token for the wrong audience,
 * which Microsoft Graph rejects with "Invalid audience". Strip surrounding
 * whitespace, a leading/trailing comma, and one layer of wrapping quotes.
 */
function sanitizeScope(raw: string): string {
  let s = raw.trim().replace(/^,+/, '').replace(/,+$/, '').trim();
  if (s.length >= 2 && ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'")))) {
    s = s.slice(1, -1).trim();
  }
  return s;
}

/** Replace the discovery cache atomically and scope it to the Access Point that produced it. */
function updateDiscoveredSnapshot(base: string, discovered: DiscoveredModel[]): void {
  discoveredSnapshot = {
    base,
    modelsById: new Map(discovered.map((model) => [model.id, model])),
  };
}

function discoveredModelFor(base: string, modelId: string): DiscoveredModel | undefined {
  return discoveredSnapshot?.base === base ? discoveredSnapshot.modelsById.get(modelId) : undefined;
}

/**
 * Resolve the Entra config for a model's **upstream** sign-in slot, if any.
 *
 * When a discovered model's catalogue entry names an `upstream_auth_id`, the
 * client must forward a *distinct* token (acquired from that slot's
 * tenant/client/scopes) to the surface so it can authenticate to the member's
 * upstream provider (e.g. Microsoft 365 Copilot's Graph API) with a different
 * identity than the front-door token. Returns `undefined` when the model needs
 * no separate upstream token or the slot is missing/blank from the bootstrap.
 */
function upstreamConfigForSlot(
  bootstrap: IdeBootstrap | null,
  modelId: string,
  slotId: string | undefined,
): EntraConfig | undefined {
  const normalizedSlotId = slotId?.trim();
  if (!normalizedSlotId) {
    return undefined;
  }
  const slot = (bootstrap?.upstreams ?? []).find((s) => s.id === normalizedSlotId);
  if (!slot) {
    log(`Model "${modelId}" references upstream slot "${normalizedSlotId}" but the bootstrap declares no such slot.`);
    return undefined;
  }
  const scopes = (slot.scopes ?? []).map(sanitizeScope).filter((s) => s.length > 0);
  if (scopes.length === 0) {
    log(`Upstream slot "${normalizedSlotId}" publishes no scopes; skipping upstream token.`);
    return undefined;
  }
  return {
    tenantId: slot.tenant_id?.trim() || undefined,
    clientId: slot.client_id?.trim() || undefined,
    scopes,
  };
}

/**
 * Resolve the effective Entra sign-in config exactly as model discovery does:
 * fetch the surface's public bootstrap (central tenant/client/scopes) and layer
 * any manual `agentStream.entra.*` overrides on top. The explicit "Sign in"
 * command uses this so it configures itself from the Access Point URL alone,
 * matching the provider path — otherwise it would only see the (usually empty)
 * manual settings and fail with "no scopes available".
 *
 * When the bootstrap publishes no scopes **and** no manual scopes are set, this
 * throws a URL-aware error naming the configured Access Point so the user can
 * either fix the URL or set manual scopes — instead of the generic downstream
 * "No sign-in scopes available" popup that hides which URL was probed.
 */
export async function resolveSignInConfig(): Promise<EntraConfig> {
  const base = accessPoint();
  const bootstrap = await loadBootstrap(base);
  const config = resolveEntraConfig(bootstrapAuth(bootstrap));
  if (config.scopes.length === 0) {
    throw new Error(
      `The Agent Stream Access Point at ${base} did not publish a sign-in bootstrap ` +
        'and no scopes are configured. Check "agentStream.endpoint" points to your IDE Surface, ' +
        'or set "agentStream.entra.scopes" (e.g. "api://<api-app-id>/access_as_user") manually.',
    );
  }
  return config;
}

function configuredModels(): ModelConfig[] {
  const cfg = vscode.workspace.getConfiguration('agentStream');
  const models = cfg.inspect<ModelConfig[]>('models')?.globalValue ?? [];
  return models.filter((m) => m && typeof m.id === 'string' && m.id.trim().length > 0);
}

function readModels(): ModelConfig[] {
  const valid = configuredModels();
  return valid.length > 0 ? valid : [{ id: 'gpt-4o', name: 'Agent Stream (SSO)' }];
}

/**
 * List the required settings that are still unset. Only the Access Point URL is
 * mandatory: the sign-in identifiers (tenant/client/scopes) are pulled from the
 * surface's public bootstrap document, so a client needs only
 * `agentStream.endpoint`. Manual `agentStream.entra.*` settings remain optional
 * per-user overrides.
 */
function missingConfig(model?: ModelConfig): string[] {
  const missing: string[] = [];
  const endpoint = (model?.endpoint ?? accessPoint()).trim();
  if (!endpoint) {
    missing.push('agentStream.endpoint');
  }
  return missing;
}

/**
 * Resolve the chat-completions URL for a statically-configured model. Uses the
 * model's `endpoint` override or the global `agentStream.endpoint`, addresses
 * the surface variant `alias` when set (`{route}$alias/...`), then appends
 * `chatPath`.
 */
function staticBaseUrl(model: ModelConfig): string {
  const base = (model.endpoint ?? accessPoint()).trim().replace(/\/+$/, '');
  if (!base) {
    throw new Error('Set "agentStream.endpoint" to your Agent Stream surface URL.');
  }
  const alias = model.alias?.trim();
  return alias ? `${base}$${alias}` : base;
}

function staticChatUrl(model: ModelConfig): string {
  return catalogChatUrl(staticBaseUrl(model));
}

/** Translate VS Code chat tools into OpenAI function-tool definitions. */
function toOpenAITools(tools: readonly vscode.LanguageModelChatTool[] | undefined): OpenAITool[] {
  return (tools ?? []).map((tool) => ({
    type: 'function',
    function: {
      name: tool.name,
      description: tool.description,
      parameters: tool.inputSchema ?? { type: 'object', properties: {} },
    },
  }));
}

/** Map the VS Code tool mode to an OpenAI `tool_choice`. */
function toToolChoice(mode: vscode.LanguageModelChatToolMode | undefined): 'auto' | 'required' {
  return mode === vscode.LanguageModelChatToolMode.Required ? 'required' : 'auto';
}

/**
 * Drop VS Code's internal bookkeeping fields from `modelOptions` before they
 * reach the request body. VS Code injects underscore-prefixed keys (e.g.
 * `_capturingTokenCorrelationId`) that are not chat-completion parameters;
 * strict providers such as Anthropic reject the whole call with "Extra inputs
 * are not permitted" when they leak through. Real sampling parameters
 * (`temperature`, `max_tokens`, `top_p`, …) are never underscore-prefixed, so
 * they pass through untouched.
 */
function sanitizeModelOptions(
  modelOptions: Record<string, unknown> | undefined,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(modelOptions ?? {})) {
    if (!key.startsWith('_')) {
      out[key] = value;
    }
  }
  return out;
}

/** Build the picker entry for a statically-configured fallback model. */
function staticInfo(
  model: ModelConfig,
  detail: string | undefined,
): vscode.LanguageModelChatInformation {
  return {
    id: model.id,
    name: model.name ?? model.id,
    family: 'agent-stream',
    version: '1.0.0',
    maxInputTokens: model.maxInputTokens ?? DEFAULT_MAX_INPUT_TOKENS,
    maxOutputTokens: model.maxOutputTokens ?? DEFAULT_MAX_OUTPUT_TOKENS,
    capabilities: { toolCalling: true, imageInput: false },
    detail,
  };
}

/**
 * A VS Code language-model provider backed by an Agent Stream LLM surface.
 *
 * Each request acquires the user's Entra ID access token and forwards the chat
 * to the surface over the OpenAI-compatible streaming API, including tool
 * definitions and prior tool results so Copilot's Ask, Edit, Agent, and Plan
 * modes all work. Agent Stream then validates the JWT, enforces OPA/team
 * policy, meters the spend against the resolved Member/Team, and proxies to the
 * upstream model.
 */
export function createProvider(
  onDidChangeLanguageModelChatInformation: vscode.Event<void>,
): vscode.LanguageModelChatProvider {
  return {
    onDidChangeLanguageModelChatInformation,
    async provideLanguageModelChatInformation(options, _token) {
      let detail: string | undefined;
      const missing = missingConfig();
      if (missing.length > 0) {
        detail = `⚠ Not configured — set ${missing.join(' and ')}`;
        log(`Model list: missing configuration (${missing.join(', ')}).`);
        return readModels().map((model) => staticInfo(model, detail));
      }

      // Pull the surface's public bootstrap first: it supplies the central
      // sign-in identifiers (tenant/client/scopes) and discovery/dispatch paths,
      // so the client configures itself from the Access Point URL alone. Manual
      // `agentStream.*` settings still win as per-user overrides. A network-
      // level failure surfaces as a distinct "unreachable" error so the user
      // sees the actual problem (endpoint down) rather than the misleading
      // downstream symptom "No sign-in scopes available".
      const base = accessPoint();
      let bootstrap: IdeBootstrap | null;
      try {
        bootstrap = await loadBootstrap(base);
      } catch (error) {
        if (error instanceof EndpointUnreachableError) {
          detail = `⚠ Could not connect to Agent Stream instance at ${base}`;
          logError('Model list: endpoint unreachable', error);
          return readModels().map((model) => staticInfo(model, detail));
        }
        throw error;
      }
      const entra = resolveEntraConfig(bootstrapAuth(bootstrap));

      let session: Awaited<ReturnType<typeof acquireToken>> | undefined;
      try {
        session = await timed('Entra token acquisition', () =>
          acquireToken(!options.silent, entra),
        );
        detail = session
          ? `Signed in as ${session.account.label}`
          : 'Not signed in — run "Agent Stream: Sign in with Microsoft Entra ID"';
      } catch (error) {
        // Surface stays listed; sign-in happens on first request.
        logError('Model list: sign-in probe failed', error);
      }

      // Dynamic discovery from the IDE Surface Access Point is the primary
      // source; the static `agentStream.models` list is only a fallback when
      // the Access Point is unreachable or returns no usable catalogue.
      try {
        const discovered = await timed('Model discovery', () =>
          fetchCatalog(base, session?.accessToken, bootstrap?.models_path),
        );
        if (discovered.length > 0) {
          updateDiscoveredSnapshot(base, discovered);
          return discovered.map((model) => ({
            id: model.id,
            name: model.name,
            family: 'agent-stream',
            version: '1.0.0',
            maxInputTokens: model.maxInputTokens,
            maxOutputTokens: model.maxOutputTokens,
            capabilities: { toolCalling: model.toolCalling, imageInput: model.imageInput },
            detail: model.detail ? `${detail ?? ''}${detail ? ' · ' : ''}${model.detail}` : detail,
          }));
        }
        updateDiscoveredSnapshot(base, []);
        log('Discovery returned an empty catalogue; falling back to static models.');
      } catch (error) {
        updateDiscoveredSnapshot(base, []);
        logError('Discovery failed; falling back to static models', error);
        if (error instanceof EndpointUnreachableError) {
          detail = `⚠ Could not connect to Agent Stream instance at ${error.url}`;
        } else if (error instanceof SurfaceNotFoundError) {
          detail = `⚠ Agent Stream Access Point not found at ${error.url} — check "agentStream.endpoint"`;
        } else {
          const reason = error instanceof Error ? error.message : String(error);
          detail = detail ? `${detail} · discovery unavailable` : `⚠ Discovery unavailable — ${reason}`;
        }
      }
      return readModels().map((model) => staticInfo(model, detail));
    },

    async provideLanguageModelChatResponse(model, messages, options, progress, token) {
      const staticConfig = configuredModels().find((m) => m.id === model.id);
      // A model with no static entry was discovered dynamically from the IDE
      // Surface Access Point: dispatch to the Access Point's chat URL with the
      // model id in the body (the universal, per-model-string routing path).
      const requestAccessPoint = accessPoint();
      let dynamicModel = staticConfig ? undefined : discoveredModelFor(requestAccessPoint, model.id);
      let resolvedModelId = model.id;
      const config: ModelConfig = staticConfig ?? { id: model.id };

      const missing = missingConfig(config);
      if (missing.length > 0) {
        const message =
          `Agent Stream is not configured: set ${missing.join(' and ')}. ` +
          'If you already edited settings.json, ensure it is in an open workspace-root ".vscode" folder or in your User settings.';
        logError(message);
        throw new Error(message);
      }

      // Reuse the discovery-time bootstrap (or fetch it) so sign-in and dispatch
      // use the surface's central identifiers/paths without extra manual config.
      const bootstrap = await cachedBootstrap(requestAccessPoint);
      const entra = resolveEntraConfig(bootstrapAuth(bootstrap));

      const session = await timed('Entra token acquisition', () => acquireToken(true, entra));
      if (!session) {
        throw new Error('Sign in with Microsoft Entra ID to use the Agent Stream model.');
      }

      // If the first model-list pass ran before sign-in, discovery fails with
      // 403 and VS Code may invoke the fallback static model (`gpt-4o`). Once
      // the interactive request has a token, recover by re-running catalogue
      // discovery and dispatching to the catalogue default instead of sending
      // the stale fallback id to the IDE Surface.
      if (!staticConfig && !dynamicModel && bootstrap) {
        try {
          const discovered = await timed('Authenticated model discovery', () =>
            fetchCatalog(requestAccessPoint, session.accessToken, bootstrap.models_path),
          );
          updateDiscoveredSnapshot(requestAccessPoint, discovered);
          dynamicModel = discoveredModelFor(requestAccessPoint, model.id) ?? discovered[0];
          if (dynamicModel) {
            resolvedModelId = dynamicModel.id;
            if (resolvedModelId !== model.id) {
              log(
                `Selected fallback model '${model.id}' is not in the IDE catalogue; ` +
                  `dispatching to '${resolvedModelId}' from authenticated discovery.`,
              );
            }
          }
        } catch (error) {
          logError('Authenticated discovery failed', error);
          throw new Error(
            'Agent Stream model discovery failed after sign-in; refresh models and try again. ' +
              (error instanceof Error ? error.message : String(error)),
          );
        }
      }
      if (!staticConfig && !dynamicModel && bootstrap) {
        throw new Error('The IDE Surface did not publish any models for this signed-in caller.');
      }
      const dynamic = !staticConfig && Boolean(dynamicModel);

      // When the selected model names an upstream sign-in slot, acquire that
      // slot's distinct token (a different tenant/client/scopes than the front
      // door) and forward it separately so the surface can authenticate to the
      // member's upstream provider (e.g. Copilot Graph) as the caller without
      // the front-door token being reused upstream.
      let upstreamAccessToken: string | undefined;
      const upstreamConfig = dynamic
        ? upstreamConfigForSlot(bootstrap, resolvedModelId, dynamicModel?.upstreamAuthId)
        : undefined;
      if (upstreamConfig) {
        const upstreamSession = await timed('Upstream token acquisition', () =>
          acquireToken(true, upstreamConfig),
        );
        if (!upstreamSession) {
          throw new Error(
            `Sign in to the upstream provider for model "${model.id}" to use it ` +
              '(the model requires a separate upstream credential).',
          );
        }
        upstreamAccessToken = upstreamSession.accessToken;
      }

      const tools = toOpenAITools(options.tools);
      const body: Record<string, unknown> = {
        model: dynamic ? resolvedModelId : (config.model ?? config.id),
        messages: toOpenAIMessages(messages),
        stream: true,
        ...sanitizeModelOptions(options.modelOptions),
      };
      if (tools.length > 0) {
        body.tools = tools;
        body.tool_choice = toToolChoice(options.toolMode);
      }

      const expectedBaseUrl = dynamic ? requestAccessPoint : staticBaseUrl(config);
      const url = dynamic ? catalogChatUrl(expectedBaseUrl, bootstrap?.chat_path) : staticChatUrl(config);
      log(
        `Request → ${url} (model=${String(body.model)}, tools=${tools.length}, ` +
          `source=${dynamic ? 'discovered' : 'static'}).`,
      );

      let textLength = 0;
      let toolCalls = 0;
      const requestStart = Date.now();
      const controller = new AbortController();
      const cancellation = token.onCancellationRequested(() => controller.abort());
      try {
        await streamChatCompletion({
          url,
          expectedBaseUrl,
          allowLocalDevelopment: allowLocalEndpoints(),
          accessToken: session.accessToken,
          upstreamAccessToken,
          body,
          callbacks: {
            onText: (text) => {
              textLength += text.length;
              progress.report(new vscode.LanguageModelTextPart(text));
            },
            onToolCall: (call) => {
              toolCalls += 1;
              progress.report(
                new vscode.LanguageModelToolCallPart(call.callId, call.name, call.input),
              );
            },
          },
          abortSignal: controller.signal,
        });
        log(
          `Response complete (${textLength} chars, ${toolCalls} tool calls) in ` +
            `${Date.now() - requestStart}ms.`,
        );
        if (textLength === 0 && toolCalls === 0) {
          log('WARNING: Agent Stream returned an empty completion (no text, no tool calls).');
        }
      } catch (error) {
        if (controller.signal.aborted) {
          log('Request cancelled by the user.');
        } else {
          logError('Request failed', error);
        }
        throw error;
      } finally {
        cancellation.dispose();
      }
    },

    async provideTokenCount(_model, text) {
      const value = typeof text === 'string' ? text : JSON.stringify(text);
      // Rough heuristic (~4 chars/token); Agent Stream reports authoritative usage.
      return Math.ceil(value.length / 4);
    },
  };
}
