"use strict";

const path = require("path");

// Central runtime configuration for the testkit runner, all overridable via env.
// Defaults target an EXTERNAL, already-running appliance on the host (so you can
// watch its UX at http://localhost:8280 while the testkit drives it). The mock
// LLM and the runner run on the host too. The docker-compose ("managed") path
// overrides these with the internal service hostnames.

function intEnv(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const n = Number(raw);
  return Number.isFinite(n) ? Math.trunc(n) : fallback;
}

function strEnv(name, fallback) {
  const raw = process.env[name];
  return raw === undefined || raw === "" ? fallback : raw;
}

// tests/appliance/ root, resolved from this file (tests/appliance/testkit/src/config.js).
const TESTKIT_ROOT = path.resolve(__dirname, "..", "..");

// ---- load profiles ----
// A -load level picks a coherent set of defaults for the traffic knobs below.
// Explicit env overrides (or the matching run.sh flags) always win over the
// profile, so you can pick a level and still tune one knob.
//
//   small   lightweight & short-lived: a tiny population, a few dozen calls,
//           low concurrency. Good for a quick smoke / dashboard sanity check.
//   medium  the historical defaults — omitting -load changes nothing.
//   large   HAMMER the appliance: a big population, thousands of calls, deep
//           concurrency so many connections hit the SAME surface at once, and
//           repeated calls from the SAME member (coverage calls/member up), for
//           maximum sustained throughput.
const LOAD_PROFILES = {
  small: {
    numTeams: 2,
    membersPerTeam: 3,
    numRequests: 30,
    concurrency: 2,
    targetRps: 0,
    durationSeconds: 0,
    capDrillCalls: 6,
    rejectionRequests: 4,
    coverageWaves: 2,
    coverageCallsPerMember: 1,
    enrolmentCalls: 2,
  },
  medium: {
    numTeams: 5,
    membersPerTeam: 10,
    numRequests: 300,
    concurrency: 5,
    targetRps: 0,
    durationSeconds: 0,
    capDrillCalls: 6,
    rejectionRequests: 12,
    coverageWaves: 4,
    coverageCallsPerMember: 1,
    enrolmentCalls: 3,
  },
  large: {
    numTeams: 8,
    membersPerTeam: 15,
    numRequests: 5000,
    concurrency: 250,
    targetRps: 0,
    durationSeconds: 0,
    capDrillCalls: 12,
    rejectionRequests: 40,
    coverageWaves: 4,
    coverageCallsPerMember: 4,
    enrolmentCalls: 6,
  },
};

function resolveLoadProfile() {
  const raw = strEnv("LOAD", "medium").toLowerCase();
  if (LOAD_PROFILES[raw]) return { name: raw, ...LOAD_PROFILES[raw] };
  // Unknown level: warn (to stderr so it never pollutes structured output) and
  // fall back to medium so a typo never silently runs an unexpected intensity.
  process.stderr.write(`[testkit] unknown -load level '${raw}', using 'medium'\n`);
  return { name: "medium", ...LOAD_PROFILES.medium };
}

const loadProfile = resolveLoadProfile();

const config = {
  // Active load profile name (small | medium | large); see LOAD_PROFILES above.
  loadProfile: loadProfile.name,

  // Appliance admin + data plane (same listener: 8280). Defaults to the host
  // appliance you run yourself; compose overrides it to http://as1:8280.
  applianceUrl: strEnv("APPLIANCE_URL", "http://localhost:8280").replace(/\/$/, ""),
  // Debug-only test-auth bootstrap secret (must match AS_TEST_TOKEN on the appliance).
  testToken: strEnv("AS_TEST_TOKEN", "testkit-secret-token"),
  testUsername: strEnv("TESTKIT_ADMIN_USER", "testkit-admin"),
  // Optional: a pre-obtained admin session/bearer token. When set, the runner
  // uses it directly and skips the debug test-login — lets you drive an external
  // appliance that is NOT in test-auth mode.
  applianceSessionToken: strEnv("APPLIANCE_SESSION_TOKEN", ""),

  // How the *appliance* reaches the mock LLM (goes into surface base_url).
  // Host appliance => host-reachable localhost; compose overrides to the service.
  mockInternalUrl: strEnv("MOCK_INTERNAL_URL", "http://localhost:9000").replace(/\/$/, ""),
  // How the *runner* reaches the mock control plane (call log).
  mockControlUrl: strEnv("MOCK_CONTROL_URL", "http://localhost:9000").replace(/\/$/, ""),

  // Fixed agent id used for the ApiKeyProvider source-auth surfaces.
  apiKeyAgentId: strEnv("TESTKIT_AGENT_ID", "testkit-agent"),

  // Scale of the synthetic population.
  numTeams: intEnv("NUM_TEAMS", loadProfile.numTeams),
  membersPerTeam: intEnv("MEMBERS_PER_TEAM", loadProfile.membersPerTeam),
  // How many member->surface calls to drive in the load phase of each round.
  numRequests: intEnv("NUM_REQUESTS", loadProfile.numRequests),

  // ---- load shaping (the general-traffic "load phase" of each round) ----
  // Maximum number of in-flight requests dispatched at once. 1 = serial (the
  // legacy behaviour). Reconciliation stays exact at any concurrency because
  // each request carries a unique correlation nonce the mock records per call.
  concurrency: Math.max(1, intEnv("CONCURRENCY", loadProfile.concurrency)),
  // Target dispatch rate (requests/second). 0 = unlimited (dispatch as fast as
  // `concurrency` allows). When > 0 the dispatcher paces new requests so the
  // start rate approaches this many per second.
  targetRps: Math.max(0, Number(strEnv("RPS", String(loadProfile.targetRps))) || 0),
  // Wall-clock budget for the load phase, in seconds. 0 = run exactly
  // `numRequests` calls; > 0 = keep dispatching until the budget elapses
  // (then `numRequests` is ignored as the stop condition).
  durationSeconds: Math.max(0, intEnv("DURATION", loadProfile.durationSeconds)),

  // ---- cap drill (deterministic member/team quota enforcement check) ----
  // Whether the round runs the cap-enforcement drill (serial, deterministic).
  capDrill: strEnv("CAP_DRILL", "true").toLowerCase() !== "false",
  // How many calls to drive at each cap-drill target before asserting it tripped.
  capDrillCalls: intEnv("CAP_DRILL_CALLS", loadProfile.capDrillCalls),
  // ---- rejection drill (judge/jury content rejection check) ----
  // Whether the round drives "bad" prompts at moderated surfaces and verifies
  // the appliance reports judge/jury rejections.
  rejectionDrill: strEnv("REJECTION_DRILL", "true").toLowerCase() !== "false",
  // How many bad-prompt requests to send per moderated surface in the drill.
  rejectionRequests: intEnv("REJECTION_REQUESTS", loadProfile.rejectionRequests),

  // ---- policy drill (OPA enforcement) ----
  // Whether each round runs the OPA policy drill: per-surface allow/deny, multi-
  // policy deny-overrides, fail-closed eviction, appliance-wide global +
  // monitor-only enforcement, and the dry-run / impact / version-history APIs.
  policyDrill: strEnv("POLICY_DRILL", "true").toLowerCase() !== "false",
  // Calls per policy scenario before asserting the expected status (200 / 403).
  policyRequests: Math.max(1, intEnv("POLICY_REQUESTS", 3)),

  // ---- enrolment drill (member auto-provisioning across JWT/API-key/mTLS) ----
  // Whether each round exercises first-sight member provisioning: novel VERIFIED
  // identities are presented at auto-provisioning surfaces, the minted members +
  // team assignments are asserted, and real priced LLM traffic is driven through
  // them so their cost/tokens reconcile. Additive to the rest of the run.
  enrolmentDrill: strEnv("ENROLMENT_DRILL", "true").toLowerCase() !== "false",
  // Priced calls to drive per enrolled member per round (>=1; call 1 provisions).
  enrolmentCalls: Math.max(1, intEnv("ENROLMENT_CALLS", loadProfile.enrolmentCalls)),
  // Whether the round-1 guardrail sub-scenario runs (asserts
  // max_auto_provisioned_members refuses a further mint).
  enrolmentGuardrail: strEnv("ENROLMENT_GUARDRAIL", "true").toLowerCase() !== "false",
  // mTLS is mandatory when the enrolment drill runs: if it cannot be exercised
  // (no openssl, or the appliance doesn't trust the runner as a forwarded-cert
  // proxy) the run FAILS. Set ENROLMENT_MTLS=optional to downgrade to a skip.
  enrolmentMtlsOptional: strEnv("ENROLMENT_MTLS", "required").toLowerCase() === "optional",
  // Header the runner sends the url-encoded client cert PEM in. Must match the
  // appliance's [tls.client_auth].forwarded_header.header_name.
  enrolmentForwardedHeader: strEnv("ENROLMENT_FORWARDED_HEADER", "x-forwarded-client-cert"),

  // ---- coverage sweep (every-member attention + multi-bucket time series) ----
  // Whether each round runs a coverage sweep that drives calls through EVERY
  // (non-drill) callable member — not just the uncapped load members — so no
  // member is left with zero usage, spread across several telemetry buckets so
  // each member shows a real multi-point usage series instead of a single point.
  // Runs last in the round so any quota pollution cannot disturb the cap-drill
  // or load phases. Capped members that 429 mid-sweep are recorded as `blocked`
  // (expected), never anomalies.
  coverage: strEnv("COVERAGE", "true").toLowerCase() !== "false",
  // Number of waves. Each wave drives one batch of calls per member; waves are
  // spaced > one telemetry bucket apart so each lands in its own bucket — the
  // source of the multi-point time series (≥3 for a visible line/area chart).
  coverageWaves: Math.max(1, intEnv("COVERAGE_WAVES", loadProfile.coverageWaves)),
  // Seconds between waves. Must exceed the finest telemetry bucket (30s) so two
  // consecutive waves can never share a bucket.
  coverageWaveGapSeconds: Math.max(0, intEnv("COVERAGE_WAVE_GAP", 35)),
  // Calls per member per wave.
  coverageCallsPerMember: Math.max(1, intEnv("COVERAGE_CALLS", loadProfile.coverageCallsPerMember)),

  // Whether each round runs a drift evaluation sweep: create + run a small
  // evaluation suite against every drift-enabled surface so the graded drift
  // dimensions (quality, self-consistency, semantic distance) get data. Suite
  // runs bypass the request handler (attributed to the drift-runner identity),
  // so they never disturb the exact usage reconciliation.
  driftEval: strEnv("DRIFT_EVAL", "true").toLowerCase() !== "false",
  // Max concurrent suite runs during the drift eval sweep.
  driftEvalConcurrency: Math.max(1, intEnv("DRIFT_EVAL_CONCURRENCY", 4)),
  // Number of eval waves per round, spaced > one telemetry bucket apart (reusing
  // COVERAGE_WAVE_GAP) so the graded drift dimensions (quality, self-consistency,
  // semantic distance) form a multi-point line instead of a single point.
  driftEvalWaves: Math.max(1, intEnv("DRIFT_EVAL_WAVES", 3)),
  // Cap the captured sessions each drift-eval run replays. The replay is
  // synchronous and sequential — every session re-runs the surface's full
  // pipeline (main + judge + jury LLM calls) — so an uncapped run (backend
  // default 50) can exceed a reverse-proxy gateway timeout (→ HTML 504) for a
  // judge/jury surface reached through a proxy. Keep it small; raise it when
  // hitting the appliance directly.
  driftEvalMaxSessions: Math.max(1, intEnv("DRIFT_EVAL_MAX_SESSIONS", 5)),

  // Seconds to wait after the last call so fire-and-forget telemetry settles
  // before reconciliation reads the series.
  settleSeconds: intEnv("SETTLE_SECONDS", 4),

  // Forced telemetry resolution tier for reconciliation queries.
  reconResolution: strEnv("RECON_RESOLUTION", "30s"),

  // Reconciliation tolerances.
  costAbsTolerance: Number(strEnv("COST_ABS_TOLERANCE", "0.0000005")),
  costRelTolerance: Number(strEnv("COST_REL_TOLERANCE", "0.005")),

  // Whether teardown runs at the end (stats are reconciled + written first).
  teardown: strEnv("TEARDOWN", "true").toLowerCase() !== "false",

  // Interactive mode: after each round, show the result and prompt for the next
  // action (run again / clean up / quit) instead of tearing down automatically.
  // Defaults to on when stdin is a TTY; force with INTERACTIVE=true|false.
  interactive: (() => {
    const raw = (process.env.INTERACTIVE || "").toLowerCase();
    if (raw === "true") return true;
    if (raw === "false") return false;
    return Boolean(process.stdin && process.stdin.isTTY);
  })(),

  // Where the retained run report is written.
  resultsDir: strEnv("RESULTS_DIR", path.join(TESTKIT_ROOT, "results")),

  // Surface templates (the varying-complexity surface catalog) + the shared
  // managed.llm.json the appliance uses (single pricing source of truth).
  surfacesDir: strEnv("SURFACES_DIR", path.join(TESTKIT_ROOT, "config", "surfaces")),
  llmCatalogPath: strEnv("LLM_CATALOG_PATH", path.join(TESTKIT_ROOT, "config", "managed.llm.json")),

  // Optional RNG seed for reproducibility of the population (not the mock usage).
  seed: intEnv("SEED", 0),
};

module.exports = { config };
