"use strict";

const { config } = require("./config");

// Thin async client over the appliance admin API + pipe data plane. Both live on
// the same listener (8280): admin under /v1 and /api/v1, pipe invocation under
// the surface's own route. Authentication is the debug-only test-auth bootstrap
// (see README — never enabled in a release build).

class Appliance {
  constructor() {
    this.base = config.applianceUrl;
    this.session = null;
    // The identity/admin router may be served at the root (/v1, /internal) or
    // nested under /api (/api/v1, /api/internal) depending on the appliance's
    // route config. Resolved once by _resolveAdminPrefix() before the first
    // admin call. (Secrets/api-keys are always mounted at /api/v1 independently.)
    this._adminPrefix = "";
  }

  // Prepend the resolved admin prefix to an identity-router path.
  _admin(p) {
    return `${this._adminPrefix}${p}`;
  }

  // Discover whether the admin API is mounted at the root or nested under /api
  // by probing the unauthenticated auth-mode endpoint (returns {"mode":"..."}).
  async _resolveAdminPrefix() {
    for (const prefix of ["", "/api"]) {
      try {
        const res = await this._fetch("GET", `${prefix}/v1/auth/mode`, { raw: true });
        if (res.ok && res.json && typeof res.json.mode === "string") {
          this._adminPrefix = prefix;
          return prefix;
        }
      } catch {
        // try the next candidate prefix
      }
    }
    // Leave the default (root); login() will surface a clear diagnostic.
    return this._adminPrefix;
  }

  async _fetch(method, path, opts = {}) {
    const { body, headers, raw, _retried } = opts;
    const url = path.startsWith("http") ? path : `${this.base}${path}`;
    const h = Object.assign({}, headers);
    if (body !== undefined && !h["content-type"]) h["content-type"] = "application/json";
    if (this.session && !h.Authorization && !h.authorization) {
      h.Authorization = `Bearer ${this.session}`;
    }
    const res = await fetch(url, {
      method,
      headers: h,
      body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
    });
    const text = await res.text();
    let json;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = null;
    }
    if (raw) return { status: res.status, ok: res.ok, json, text };
    if (!res.ok) {
      // Transparent re-auth on session expiry. A long run (coverage waves +
      // drills) can outlive the appliance's session timeout, so an authenticated
      // call late in the run (e.g. reconcile's telemetry fetch) returns 401. When
      // we hold a refreshable test-auth session (not a caller-supplied token) and
      // this isn't the login call itself, re-login once and retry the request.
      if (
        res.status === 401 &&
        this.session &&
        !_retried &&
        !config.applianceSessionToken &&
        !path.includes("/internal/test-support/auth/login")
      ) {
        this.session = null;
        await this.login();
        return this._fetch(method, path, { ...opts, _retried: true });
      }
      const err = new Error(`${method} ${path} -> ${res.status}: ${text.slice(0, 400)}`);
      err.status = res.status;
      err.body = text;
      throw err;
    }
    return json;
  }

  // ---- auth ----
  async login() {
    // If a session/bearer was supplied, use it directly — lets the testkit drive
    // an external appliance that is not in debug test-auth mode.
    if (config.applianceSessionToken) {
      this.session = config.applianceSessionToken;
      return { session_token: this.session, provided: true };
    }
    let out;
    try {
      await this._resolveAdminPrefix();
      out = await this._fetch("POST", this._admin("/internal/test-support/auth/login"), {
        headers: { "X-Test-Token": config.testToken },
        body: { username: config.testUsername },
      });
    } catch (e) {
      throw this._loginHint(e);
    }
    if (!out || !out.session_token) {
      const m = new Error(`test-auth login returned no session_token (got ${JSON.stringify(out)})`);
      m.graceful = true;
      throw m;
    }
    this.session = out.session_token;
    return out;
  }

  // Turn a raw login failure into an actionable, non-fatal diagnostic.
  _loginHint(e) {
    const status = e && e.status;
    let msg;
    if (status === 404 || status === 405) {
      msg =
        `the test-auth bootstrap endpoint is not available at ${this.base} ` +
        `(resolved admin prefix '${this._adminPrefix || "/"}', HTTP ${status}). ` +
        `Most likely APPLIANCE_URL is pointing at the wrong instance, or the appliance was not ` +
        `launched in test mode. It must be a DEBUG build started with AS_TEST_MODE=true and a ` +
        `matching AS_TEST_TOKEN (for example 'make run-debug tk=1'). ` +
        `A different service answering on this port also returns ${status}. ` +
        `Otherwise set APPLIANCE_SESSION_TOKEN=<admin session> to skip test-auth entirely.`;
    } else if (status === 401) {
      msg =
        `the appliance rejected the test token (HTTP 401). The runner's AS_TEST_TOKEN ` +
        `('${config.testToken}') must match the AS_TEST_TOKEN the appliance was launched with.`;
    } else {
      msg =
        `could not reach the test-auth endpoint at ${this.base}: ${e && e.message ? e.message : e}. ` +
        `Is the appliance running and is APPLIANCE_URL correct?`;
    }
    const m = new Error(msg);
    m.graceful = true;
    m.cause = e;
    return m;
  }

  async waitUntilReady(timeoutMs = 60000) {
    const deadline = Date.now() + timeoutMs;
    let lastErr;
    while (Date.now() < deadline) {
      try {
        const res = await this._fetch("GET", "/ping", { raw: true });
        if (res.status < 500) return true;
      } catch (e) {
        lastErr = e;
      }
      await new Promise((r) => setTimeout(r, 1000));
    }
    throw new Error(`appliance not ready: ${lastErr ? lastErr.message : "timeout"}`);
  }

  // ---- members ----
  createMember(member) {
    // Every member the testkit creates is an ephemeral fixture; flag it so the
    // hard-purge endpoint can find and physically delete it (see purgeTestFixtures).
    return this._fetch("POST", this._admin("/v1/members"), { body: { test_fixture: true, ...member } });
  }
  listMembers() {
    return this._fetch("GET", this._admin("/v1/members"));
  }
  deleteMember(id) {
    return this._fetch("DELETE", this._admin(`/v1/members/${encodeURIComponent(id)}`), { raw: true });
  }

  // ---- teams ----
  createTeam(team) {
    // Every team the testkit creates is an ephemeral fixture; flag it so the
    // hard-purge endpoint can find and physically delete it (see purgeTestFixtures).
    return this._fetch("POST", this._admin("/v1/teams"), { body: { test_fixture: true, ...team } });
  }
  listTeams() {
    return this._fetch("GET", this._admin("/v1/teams"));
  }
  deleteTeam(id) {
    return this._fetch("DELETE", this._admin(`/v1/teams/${encodeURIComponent(id)}`), { raw: true });
  }
  addTeamMember(teamId, memberId) {
    return this._fetch("POST", this._admin(`/v1/teams/${encodeURIComponent(teamId)}/members`), {
      body: { member_id: memberId },
    });
  }
  removeTeamMember(teamId, memberId) {
    return this._fetch(
      "DELETE",
      this._admin(`/v1/teams/${encodeURIComponent(teamId)}/members/${encodeURIComponent(memberId)}`),
      { raw: true },
    );
  }

  // ---- pipes (surfaces) ----
  // Create a surface, overwriting any pre-existing surface with the same id. A
  // previous (possibly crashed) run can leave a surface behind that the bulk
  // test-surface cleanup didn't catch — e.g. an appliance build that predates
  // that endpoint, or a surface created before the `test_surface` flag existed.
  // Delete is a soft-delete (the tombstone keeps the id "taken"), so a duplicate
  // id is resolved by overwriting in place via PUT rather than delete+create.
  async createPipe(pipe) {
    try {
      return await this._fetch("POST", this._admin("/v1/pipes"), { body: pipe });
    } catch (e) {
      const conflict = e && e.status === 400 && /already exists/i.test(e.body || e.message || "");
      if (conflict && pipe && pipe.id) {
        return await this.updatePipe(pipe);
      }
      throw e;
    }
  }
  updatePipe(pipe) {
    return this._fetch("PUT", this._admin(`/v1/pipes/${encodeURIComponent(pipe.id)}`), { body: pipe });
  }
  deletePipe(id) {
    return this._fetch("DELETE", this._admin(`/v1/pipes/${encodeURIComponent(id)}`), { raw: true });
  }
  // Bulk-delete every surface flagged `test_surface` (debug/test-mode only).
  // Returns `{ deleted, ids }`. Used to clear surfaces left by a crashed run.
  deleteTestSurfaces() {
    return this._fetch("POST", this._admin("/v1/pipes/test-surfaces/delete"), { body: {} });
  }
  // Hard-purge every test fixture (debug/test-mode only): physically removes
  // (files actually deleted, not tombstoned) every `test_surface` surface plus
  // every non-system `test_fixture` member and team, GC'ing their telemetry.
  // Returns `{ surfaces, members, teams }`, each `{ deleted, ids }`. System
  // records (anonymous/sandbox) are never touched.
  purgeTestFixtures() {
    return this._fetch("POST", this._admin("/v1/test-support/purge"), { body: {} });
  }

  // ---- OPA policy definitions + appliance-wide assignments ----
  createPolicyDefinition(def) {
    return this._fetch("POST", this._admin("/v1/policy-definitions"), { body: def });
  }
  updatePolicyDefinition(def) {
    return this._fetch("PUT", this._admin(`/v1/policy-definitions/${encodeURIComponent(def.id)}`), { body: def });
  }
  deletePolicyDefinition(id) {
    return this._fetch("DELETE", this._admin(`/v1/policy-definitions/${encodeURIComponent(id)}`), { raw: true });
  }
  // Dry-run a policy against a sample input. Body: { input, version?, policy?, policy_type? }.
  // Raw so a bounds rejection (HTTP 400) can be asserted without throwing.
  simulatePolicy(id, body) {
    return this._fetch("POST", this._admin(`/v1/policy-definitions/${encodeURIComponent(id)}/simulate`), {
      body,
      raw: true,
    });
  }
  // Blast radius: how many pipes/surfaces/gateways + global types reference a policy.
  policyImpact(id) {
    return this._fetch("GET", this._admin(`/v1/policy-definitions/${encodeURIComponent(id)}/impact`));
  }
  // Immutable version history, newest-first.
  listPolicyVersions(id) {
    return this._fetch("GET", this._admin(`/v1/policy-definitions/${encodeURIComponent(id)}/versions`));
  }
  // Appliance-wide (global) policy assignments: which reusable policies are
  // enforced on every surface / gateway of a type. Raw so a caller lacking the
  // publish permission (HTTP 403) can degrade to a skip rather than an error.
  getPolicyAssignments() {
    return this._fetch("GET", this._admin("/v1/policy-assignments"), { raw: true });
  }
  setPolicyAssignments(assignments) {
    return this._fetch("PUT", this._admin("/v1/policy-assignments"), { body: assignments, raw: true });
  }

  // ---- routing config ----
  // The surface-routing config drives the dashboard access-point picker:
  // `available_listen_addresses` (host listeners) and `pipe_path_prefix`. The
  // testkit reads the first listener so its surfaces carry a `listen_address`
  // and therefore render as fully configured (no "unconfigured" marching ants).
  surfaceRoutingConfig() {
    return this._fetch("GET", this._admin("/v1/config/surface-routing"));
  }

  // ---- jwt verification strategies ----
  createJwtStrategy(strategy) {
    return this._fetch("POST", this._admin("/v1/jwt-verification-strategies"), { body: strategy });
  }
  deleteJwtStrategy(id) {
    return this._fetch("DELETE", this._admin(`/v1/jwt-verification-strategies/${encodeURIComponent(id)}`), {
      raw: true,
    });
  }

  // ---- certificates (note the /api/v1 prefix, mounted independently) ----
  // Create a certificate (e.g. a CA trust anchor for mTLS source auth). Returns
  // the stored record; its `id` is what a surface's mTLS trust references in
  // `ca_certificate_ids` / `certificate_ids`.
  createCertificate(cert) {
    return this._fetch("POST", "/api/v1/certificates", { body: cert });
  }
  deleteCertificate(id) {
    return this._fetch("DELETE", `/api/v1/certificates/${encodeURIComponent(id)}`, { raw: true });
  }

  // ---- member auto-provisioning (enrolment) ----
  // Read / replace the appliance-level provisioning config, and dry-run the
  // rules against a hand-described identity (write-free preview).
  getProvisioningConfig() {
    return this._fetch("GET", this._admin("/v1/member-provisioning"));
  }
  setProvisioningConfig(config) {
    return this._fetch("PUT", this._admin("/v1/member-provisioning"), { body: config });
  }
  previewProvisioning(body) {
    return this._fetch("POST", this._admin("/v1/member-provisioning/preview"), { body });
  }

  // ---- api keys (note the /api/v1 prefix) ----
  createApiKey(agentId, clientId, labels) {
    return this._fetch("POST", `/api/v1/api-keys/${encodeURIComponent(agentId)}`, {
      body: { client_id: clientId, labels: labels || null },
    });
  }

  // ---- telemetry ----
  async telemetrySeries(keys, from, to, resolution) {
    const params = new URLSearchParams({
      keys: keys.join(","),
      from: String(from),
      to: String(to),
      max_points: "5000",
    });
    if (resolution) params.set("resolution", resolution);
    return this._fetch("GET", this._admin(`/v1/telemetry/series?${params.toString()}`));
  }

  // Per-category rejection counts for one scope over a window. Returns
  // { scope, from, to, total, categories: [{category, label, count}] }.
  async fetchRejections(scope, from, to, resolution) {
    const params = new URLSearchParams({
      scope,
      from: String(from),
      to: String(to),
    });
    if (resolution) params.set("resolution", resolution);
    return this._fetch("GET", this._admin(`/v1/telemetry/rejections?${params.toString()}`));
  }

  // ---- LLM drift (admin-gated `drift.view`) ----
  // Per-dimension drift series for one or more `drift:surface:{id}:{dim}` keys
  // over a window. Read from the dedicated drift store, disjoint from telemetry.
  // Returns [{ key, resolution, step_secs, points: [{t, mean, count}] }].
  async driftSeries(keys, from, to, resolution) {
    const params = new URLSearchParams({
      keys: keys.join(","),
      from: String(from),
      to: String(to),
      max_points: "5000",
    });
    if (resolution) params.set("resolution", resolution);
    return this._fetch("GET", this._admin(`/v1/drift/series?${params.toString()}`));
  }

  // Start replaying a surface's captured "indicative" sessions (`drift.manage`).
  // The replay is asynchronous: this returns immediately with a RUNNING DriftRun
  // ({ id, status, total, progress_done, ... }); poll `getDriftRun(id)` until the
  // status is terminal (completed/failed/cancelled) for the final result.
  runDriftEval(surfaceId) {
    return this._fetch(
      "POST",
      this._admin(`/v1/drift/eval/run?surface_id=${encodeURIComponent(surfaceId)}`),
    );
  }

  // One drift replay-evaluation run (in-flight from the registry, else persisted
  // history) by run id (`drift.view`).
  getDriftRun(runId) {
    return this._fetch("GET", this._admin(`/v1/drift/runs/${encodeURIComponent(runId)}`));
  }

  // Request cancellation of an in-flight drift replay run (`drift.manage`).
  cancelDriftEval(runId) {
    return this._fetch(
      "POST",
      this._admin(`/v1/drift/eval/cancel?run_id=${encodeURIComponent(runId)}`),
    );
  }

  // A surface's captured "indicative" sessions — the prompt/response pairs a
  // replay evaluation re-runs (`drift.view`).
  listDriftSessions(surfaceId) {
    return this._fetch(
      "GET",
      this._admin(`/v1/drift/sessions?surface_id=${encodeURIComponent(surfaceId)}`),
    );
  }

  // Pin a surface's current behaviour (each dimension's mean over the window) as
  // its drift baseline (`drift.manage`). 400s when the window has no drift data,
  // so only baseline a surface that has recorded samples. Returns
  // { surface_id, captured_at, window_secs, dimensions: { dim: mean } }.
  captureDriftBaseline(surfaceId, windowSecs) {
    const params = new URLSearchParams({ surface_id: surfaceId });
    if (windowSecs) params.set("window_secs", String(windowSecs));
    return this._fetch("POST", this._admin(`/v1/drift/baseline?${params.toString()}`));
  }

  // A surface's drift verdict over a window (`drift.view`): each dimension's
  // current mean compared to its pinned baseline, classified stable/warn/drift/
  // unknown. Returns { surface_id, status, baseline_captured_at?, dimensions }.
  driftVerdict(surfaceId, from, to) {
    const params = new URLSearchParams({
      surface_id: surfaceId,
      from: String(from),
      to: String(to),
    });
    return this._fetch("GET", this._admin(`/v1/drift/verdict?${params.toString()}`));
  }

  // ---- pipe invocation (data plane) ----
  async invokePipe(route, payload, headers) {
    const path = `${route}/v1/chat/completions`;
    return this._fetch("POST", path, { body: payload, headers, raw: true });
  }

  // ---- secrets ----
  // Find every stored secret carrying `tag` (metadata only, no value). Used by
  // the conformance suite to resolve the operator's provider keys by their
  // `test-suite-openai` / `test-suite-anthropic` tags. Returns an array.
  findSecretsByTag(tag) {
    return this._fetch("GET", `/api/v1/secrets/tag/${encodeURIComponent(tag)}`);
  }

  // ---- conformance data plane (no admin session injected) ----
  // A raw data-plane request that does NOT attach the admin session, so a
  // surface's own dialect auth (e.g. the Anthropic `x-api-key` header) is
  // exercised exactly as a real client would send it.
  async _dataFetch(method, route, pathSuffix, { body, headers } = {}) {
    const url = `${this.base}${route}${pathSuffix}`;
    const h = Object.assign({}, headers);
    if (body !== undefined && !h["content-type"] && !h["Content-Type"]) {
      h["content-type"] = "application/json";
    }
    const res = await fetch(url, {
      method,
      headers: h,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = null;
    }
    // Surface the gateway's own observability headers so conformance can assert
    // on token/cost/cache/schema signals without parsing the body.
    const agentHeaders = {};
    res.headers.forEach((value, key) => {
      const lower = key.toLowerCase();
      if (lower.startsWith("x-agent-stream-")) agentHeaders[lower] = value;
    });
    return {
      status: res.status,
      ok: res.ok,
      json,
      text,
      contentType: res.headers.get("content-type") || "",
      headers: agentHeaders,
    };
  }

  callSurface(route, pathSuffix, opts) {
    return this._dataFetch("POST", route, pathSuffix, opts);
  }
  getSurface(route, pathSuffix, opts) {
    return this._dataFetch("GET", route, pathSuffix, opts);
  }

  // POST that reads a Server-Sent-Events response body into raw lines, so the
  // caller can parse dialect-specific event/data framing (OpenAI `data:` chunks,
  // Anthropic / Responses `event:`+`data:` pairs). Returns { status, ok, lines,
  // contentType }.
  async streamSurface(route, pathSuffix, { body, headers } = {}) {
    const url = `${this.base}${route}${pathSuffix}`;
    const h = Object.assign({ accept: "text/event-stream" }, headers);
    if (!h["content-type"] && !h["Content-Type"]) h["content-type"] = "application/json";
    const res = await fetch(url, { method: "POST", headers: h, body: JSON.stringify(body) });
    const contentType = res.headers.get("content-type") || "";
    const lines = [];
    if (res.body && typeof res.body[Symbol.asyncIterator] === "function") {
      const decoder = new TextDecoder();
      let buf = "";
      for await (const chunk of res.body) {
        buf += decoder.decode(chunk, { stream: true });
        let nl;
        while ((nl = buf.indexOf("\n")) >= 0) {
          lines.push(buf.slice(0, nl).replace(/\r$/, ""));
          buf = buf.slice(nl + 1);
        }
      }
      if (buf.length) lines.push(buf.replace(/\r$/, ""));
    } else {
      const text = await res.text();
      for (const l of text.split("\n")) lines.push(l.replace(/\r$/, ""));
    }
    return { status: res.status, ok: res.ok, lines, contentType };
  }
}

module.exports = { Appliance };
