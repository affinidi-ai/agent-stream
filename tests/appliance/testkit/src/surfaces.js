"use strict";

const { config } = require("./config");
const { AUDIENCE } = require("./identities");

// Translate a surface *template* (tests/appliance/config/surfaces/*.json) into the full
// PipeConfig POST body the appliance expects. Templates carry only the
// human-meaningful complexity knobs (identity flavor, model, judge, juror count);
// everything wire-specific (mock endpoints, source auth, team attribution, the
// always-approve judge/jury, cost tracking) is assembled here so the catalog of
// surfaces stays readable.

// An LLMTarget (judge/jury/decider) points at the Mock LLM (the `mock_llm`
// custom-catalog provider) with a FULL endpoint_url. The `mock_llm` provider
// type makes pricing resolve against the "Mock LLM" catalog entry.
function mockLlmTarget(mockInternalUrl, model) {
  return {
    provider_type: "mock_llm",
    model,
    endpoint_url: `${mockInternalUrl}/v1/chat/completions`,
    api_schema: "openai",
  };
}

// Default rejection-taxonomy category id used to name the moderated judge rule.
const DEFAULT_JUDGE_CATEGORY = "prompt_injection";
// Default rejection-taxonomy category ids cycled across moderated jurors.
const DEFAULT_JURY_CATEGORIES = ["toxicity", "hate"];

// A judge LLM stage. When `moderated` is false (default) it always approves but
// still calls the mock (one never-matching regex rule guarantees the judge stage
// runs and meters usage). When `moderated` is true its rule keys on the literal
// BLOCKED that the mock emits for a triggered prompt, so a bad prompt is
// request-side rejected (403) and recorded under the `judge` rejection stage.
//
// The moderated rule's NAME is a canonical rejection-taxonomy category id (e.g.
// `prompt_injection`): the judge's LLM-mode rejection reports the rule name as
// its raw reason, which the appliance's classifier maps to that category — so
// the dashboard rejection breakdown shows a real category instead of
// `uncategorized`.
function buildJudge(mockInternalUrl, moderated, category) {
  const rule = moderated
    ? {
        name: category || DEFAULT_JUDGE_CATEGORY,
        condition: { type: "regex_match", pattern: "BLOCKED" },
        status_code: 403,
        body: "{\"error\":\"blocked by judge\"}",
        content_type: "application/json",
      }
    : {
        name: "never-match",
        condition: { type: "regex_match", pattern: "____TESTKIT_NEVER_MATCH____" },
        status_code: 403,
        body: "{\"error\":\"blocked\"}",
        content_type: "application/json",
      };
  return {
    enabled: true,
    mode: "llm",
    llm: mockLlmTarget(mockInternalUrl, "mock-small"),
    system_prompt: "You are a reviewer for a load test.",
    rules: [rule],
  };
}

// A jury stage. When `moderated` is false (default) every juror approves anything
// (regex approve `.*`). When `moderated` is true each juror approves only when
// the response carries the literal APPROVED, so a triggered (BLOCKED) response is
// response-side rejected (403) and recorded under the `jury` rejection stage.
// (The Rust regex crate has no lookahead, so a positive literal is used rather
// than a negative match.)
//
// In moderated mode each juror's NAME embeds a canonical rejection-taxonomy
// category id (cycled across `categories`): the jury's rejection reason lists
// the rejecting jurors by name, which the appliance's classifier pattern-matches
// to those categories — so the dashboard rejection breakdown shows real
// categories instead of `uncategorized`.
function buildJury(mockInternalUrl, jurorCount, moderated, categories) {
  const approvePattern = moderated ? "APPROVED" : ".*";
  const cats =
    Array.isArray(categories) && categories.length > 0 ? categories : DEFAULT_JURY_CATEGORIES;
  const jurors = [];
  for (let i = 0; i < jurorCount; i += 1) {
    const name = moderated ? `${cats[i % cats.length]}-${i + 1}` : `juror-${i + 1}`;
    jurors.push({
      enabled: true,
      name,
      llm: mockLlmTarget(mockInternalUrl, "mock-small"),
      system_prompt: "You are a reviewer for a load test.",
      decision: { mode: "regex", approve_pattern: approvePattern },
    });
  }
  return { enabled: true, mode: "parallel", jurors };
}

// Identity-flavor specific source auth + caller-email-source + member kind.
function identityWiring(identity, ctx) {
  switch (identity) {
    case "email":
      return {
        sourceAuth: null,
        callerEmailSource: { type: "header", name: "X-Caller-Email" },
        memberKind: "email",
      };
    case "jwt":
      return {
        sourceAuth: {
          type: "jwt_bearer",
          jwt_verification_strategy_id: ctx.jwtStrategyId,
          audiences: [AUDIENCE],
          token_header: "Authorization",
          token_scheme: "Bearer",
        },
        callerEmailSource: { type: "jwt_claim", claim: "sub" },
        memberKind: "subject",
      };
    case "apikey":
      return {
        sourceAuth: {
          type: "api_key_provider",
          extraction: { source: "http_header", field: "X-Api-Key" },
          agent_id: ctx.apiKeyAgentId,
        },
        callerEmailSource: { type: "api_key" },
        memberKind: "api_key",
      };
    case "mtls":
      // Client certs arrive via the forwarded-cert header (the runner is a
      // trusted proxy — see tests/appliance/config/managed.config.toml). Trust is CA-chained to the
      // testkit's throwaway CA (uploaded during setup), and the caller principal
      // is bound to the certificate's subject CN.
      return {
        sourceAuth: {
          type: "mtls",
          trust: { type: "ca", ca_certificate_ids: [ctx.enrolCaCertId] },
          identity_binding: { type: "subject_cn" },
          allow_forwarded: true,
        },
        callerEmailSource: { type: "mtls", binding: "subject_cn" },
        memberKind: "custom",
      };
    default:
      throw new Error(`unknown identity flavor: ${identity}`);
  }
}

// Compose a surface's full data-plane route as `{prefix}/{suffix}`. The
// appliance registers a pipe at its `route` verbatim (matched as an opaque
// string), so invocation works with any route — but the dashboard access-point
// node only renders as configured when the route starts with a known pipe path
// prefix (it decomposes `route` into prefix + custom path). Prepending the
// resolved prefix is therefore purely for a clean dashboard render; it never
// changes how the runner reaches the surface (it always uses the composed route).
function composeRoute(prefix, rawRoute) {
  const suffix = `/${String(rawRoute || "").replace(/^\/+/, "")}`;
  const p = String(prefix || "").replace(/\/+$/, ""); // tolerate a trailing slash / root prefix
  if (!p) return suffix;
  if (suffix === p || suffix.startsWith(`${p}/`)) return suffix;
  return `${p}${suffix}`;
}

// Build the PipeConfig POST body for a template. `ctx` carries the resolved
// mock URL, the JWT strategy id, and the api-key agent id.
function buildPipe(template, ctx) {
  const wiring = identityWiring(template.identity, ctx);
  const pipeId = `tk-${template.key}`;
  const now = new Date().toISOString();
  const route = composeRoute(ctx.pathPrefix, template.route);

  const pipe = {
    id: pipeId,
    name: `Testkit ${template.key}`,
    description: template.description || null,
    pipe_type: {
      type: "llm",
      // The Mock LLM is a custom-catalog provider (`mock_llm`, api_schema
      // openai). An unknown provider_type resolves against the merged catalog
      // and maps to the OpenAI variant, so the model lives in `model` and the
      // base URL in `base_url` (the executor appends the request path suffix).
      // This is a normal catalog provider, so the dashboard renders it fully
      // (provider + model + endpoint selected) instead of the reserved generic
      // "custom" option, which has no catalog models/endpoints.
      provider: {
        provider_type: "mock_llm",
        model: template.model,
        base_url: ctx.mockInternalUrl,
      },
    },
    listen_address: ctx.listenAddress || undefined,
    route,
    cost_tracking: { enabled: true },
    // LLM drift monitoring on every test surface, sampling every interaction so
    // the drift dimensions reliably accumulate (and sessions are captured) during
    // a run. Replay evaluation is enabled with the mock's embeddings endpoint so
    // the drift eval phase can measure semantic distance. A template may pin its
    // own `drift` block to override.
    drift: template.drift || {
      enabled: true,
      sample_rate: 1,
      eval: {
        enabled: true,
        max_sessions: config.driftEvalMaxSessions,
        embeddings: {
          endpoint_url: `${ctx.mockInternalUrl}/v1/embeddings`,
          model: "mock-embed",
        },
      },
    },
    team_attribution: {
      enabled: true,
      caller_email_source: wiring.callerEmailSource,
      // Opt the surface into first-sight member auto-provisioning (enrolment).
      // Off by default so the general surface catalog is unaffected.
      auto_provision: !!template.autoProvision,
      enforce: true,
      allow_individual_overage: false,
      allowed_teams: [],
    },
    enable_metrics: true,
    metrics_enabled: true,
    log_requests: false,
    log_responses: false,
    created_at: now,
    // Tag as an ephemeral test fixture so the debug-only bulk cleanup endpoint
    // (`POST /v1/pipes/test-surfaces/delete`) can find and tombstone it.
    test_surface: true,
  };

  if (template.judge)
    pipe.judge = buildJudge(ctx.mockInternalUrl, !!template.moderated, template.judgeCategory);
  if (template.jurors && template.jurors > 0)
    pipe.jury = buildJury(
      ctx.mockInternalUrl,
      template.jurors,
      !!template.moderated,
      template.juryCategories
    );
  if (wiring.sourceAuth) pipe.source_auth = wiring.sourceAuth;

  return {
    pipeId,
    route,
    identity: template.identity,
    model: template.model,
    memberKind: wiring.memberKind,
    hasJudge: !!template.judge,
    jurors: template.jurors || 0,
    moderated: !!template.moderated,
    drift: !!(pipe.drift && pipe.drift.enabled !== false),
    pipe,
  };
}

// The Surface the testkit's managed API keys hang off. Every api-key Surface
// names it as its `agent_id`, so it is created before them, and it names
// itself. It is never called.
function buildApiKeyHolder(ctx) {
  const { pipe } = buildPipe(
    {
      key: "api-keys",
      description: "Holds the testkit's managed API keys.",
      identity: "apikey",
      route: "/llm/tk-api-keys",
      model: "mock-small",
      drift: { enabled: false },
    },
    ctx,
  );
  pipe.id = ctx.apiKeyAgentId;
  pipe.name = "Testkit API keys";
  return pipe;
}

// Runtime values an author can reference inside a full PipeConfig file, since
// the JWT strategy / api-key agent / mock URL aren't known until setup runs.
// `${JWT_AUDIENCE}` is the audience every testkit token carries.
function substitutePlaceholders(text, ctx) {
  return text
    .replace(/\$\{JWT_STRATEGY_ID\}/g, ctx.jwtStrategyId || "")
    .replace(/\$\{JWT_AUDIENCE\}/g, AUDIENCE)
    .replace(/\$\{APIKEY_AGENT_ID\}/g, ctx.apiKeyAgentId || "")
    .replace(/\$\{MOCK_URL\}/g, ctx.mockInternalUrl || "");
}

const MEMBER_KIND = { email: "email", jwt: "subject", apikey: "api_key" };

// Which of the three identity flavors a full config uses, inferred from its
// source auth (the runner only knows how to mint credentials for these three).
function flavorFromSourceAuth(sourceAuth) {
  if (!sourceAuth) return "email";
  if (sourceAuth.type === "api_key_provider" || sourceAuth.type === "api_key") return "apikey";
  if (sourceAuth.type === "jwt_bearer") return "jwt";
  return "email";
}

// A file authored as a full PipeConfig: substitute runtime placeholders, post it
// verbatim, and derive the routing/identity metadata the simulator needs.
function adoptFullConfig(text, ctx) {
  const pipe = JSON.parse(substitutePlaceholders(text, ctx));
  if (!pipe.route) throw new Error(`full surface config ${pipe.id || "?"} is missing "route"`);
  const provider = pipe.pipe_type && pipe.pipe_type.provider;
  // OpenAI-style / custom-catalog providers (incl. the Mock LLM `mock_llm`)
  // carry the model in `model`; a legacy built-in `custom` provider carries it
  // in `name`.
  const model = provider && (provider.model || provider.name);
  if (!model) throw new Error(`full surface config ${pipe.id || pipe.route} is missing pipe_type.provider model/name`);
  const identity = flavorFromSourceAuth(pipe.source_auth);
  const pipeId = pipe.id || `tk-${pipe.route.replace(/[^a-z0-9]+/gi, "-").replace(/^-+|-+$/g, "")}`;
  pipe.id = pipeId;
  // Compose the route as `{prefix}/{suffix}` (no-op when it already starts with
  // the resolved pipe path prefix) so the dashboard access-point node can
  // decompose it and render as configured instead of showing marching ants.
  pipe.route = composeRoute(ctx.pathPrefix, pipe.route);
  // `created_at` is a required PipeConfig field; default it when a full-config
  // file omits it (the appliance does not synthesize it on POST).
  if (!pipe.created_at) pipe.created_at = new Date().toISOString();
  // Default the host listener so the access-point node renders configured,
  // unless the full-config file pins its own listen address.
  if (!pipe.listen_address && ctx.listenAddress) pipe.listen_address = ctx.listenAddress;
  // Enable LLM drift monitoring unless the full-config file pins its own block,
  // so every test surface feeds the drift dimensions and captures sessions.
  // Replay evaluation points at the mock's embeddings endpoint.
  if (!pipe.drift)
    pipe.drift = {
      enabled: true,
      sample_rate: 1,
      eval: {
        enabled: true,
        max_sessions: config.driftEvalMaxSessions,
        embeddings: {
          endpoint_url: `${ctx.mockInternalUrl}/v1/embeddings`,
          model: "mock-embed",
        },
      },
    };
  // Tag as an ephemeral test fixture so the debug-only bulk cleanup endpoint
  // (`POST /v1/pipes/test-surfaces/delete`) can find and tombstone it.
  pipe.test_surface = true;
  return {
    pipeId,
    route: pipe.route,
    identity,
    model,
    memberKind: MEMBER_KIND[identity],
    hasJudge: !!(pipe.judge && pipe.judge.enabled !== false),
    jurors: pipe.jury && Array.isArray(pipe.jury.jurors) ? pipe.jury.jurors.length : 0,
    moderated: false,
    drift: !!(pipe.drift && pipe.drift.enabled !== false),
    pipe,
  };
}

// Detect the file format and normalize to one shape. A file carrying `pipe_type`
// is a full PipeConfig (posted verbatim); anything else is a compact template.
function buildSurface(text, ctx) {
  const probe = JSON.parse(text);
  if (probe && probe.pipe_type) return adoptFullConfig(text, ctx);
  return buildPipe(probe, ctx);
}

module.exports = { buildApiKeyHolder, buildPipe, buildSurface };
