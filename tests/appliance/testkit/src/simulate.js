"use strict";

const { config } = require("./config");
const { info, warn, sleep, pick } = require("./log");
const { runPool } = require("./pool");
const { spinner, isStopRequested } = require("./progress");
const { enrolmentPhase } = require("./enrolment");
const { policyPhase } = require("./policy");
const { driftEvalPhase } = require("./drift-eval");

// Drive synthetic member -> surface traffic against the appliance and record the
// local ground truth into the ledger. Each round has up to five phases:
//
//   1. cap drill   — serial, deterministic: drive tiny-capped members/teams past
//                    their quota and assert the appliance enforces it (HTTP 429),
//                    while an uncapped control is never blocked.
//   2. enrolment   — present novel VERIFIED identities (JWT claims / API key /
//                    mTLS client cert) at auto-provisioning surfaces and assert
//                    the appliance mints members + assigns teams on first sight,
//                    then drives real priced LLM traffic through the newly
//                    enrolled members so their cost/tokens reconcile too.
//   3. rejection   — drive "bad" prompts at moderated judge/jury surfaces and
//                    assert the appliance rejects them (HTTP 403) and reports the
//                    rejection telemetry under the right stage.
//   4. load        — concurrent general traffic from uncapped members, paced by
//                    the concurrency/rps/duration knobs.
//   5. coverage    — a full-population sweep that drives a few calls through
//                    EVERY (non-drill) callable member, spread over several
//                    time-spaced waves so no member is left at zero usage and
//                    each shows a real multi-bucket time series.
//
// Correlation is by nonce, not by serial call-count delta: each request embeds a
// unique `[[tkid:<nonce>]]` marker the mock records on every upstream call it
// serves (main LLM + judge + each juror). After a 200 the runner reads
// `GET /__mock/by-nonce` to get exactly that execution's upstream calls and
// tokens — accurate even under heavy concurrency.

const PROMPTS = [
  "Summarise the quarterly results in two sentences.",
  "Explain how a hash map works to a five year old.",
  "Translate 'good morning' into three languages.",
  "Draft a short polite decline to a meeting invite.",
  "List three benefits of unit testing.",
  "What is the capital of an imaginary country named Zedonia?",
];

// Must match the mock server's REJECT_TRIGGER. A prompt carrying this makes the
// mock emit BLOCKED content, which the moderated judge/jury surfaces reject.
const REJECT_TRIGGER = "[[reject]]";

// A permissive structured-output request. Sent on a fraction of coverage traffic
// so the drift **schema-validity** dimension gets samples: the mock returns a
// JSON object for it, which the gateway validates against this schema (a real
// caller opting into structured output is what fills that graph in production).
const SCHEMA_RESPONSE_FORMAT = {
  type: "json_schema",
  json_schema: {
    name: "testkit_result",
    strict: false,
    schema: {
      type: "object",
      properties: { result: { type: "string" } },
      required: ["result"],
      additionalProperties: true,
    },
  },
};

let NONCE_SEQ = 0;
function newNonce(roundIdx) {
  NONCE_SEQ += 1;
  return `r${roundIdx}-${NONCE_SEQ}-${Math.random().toString(36).slice(2, 10)}`;
}

function buildHeaders(member) {
  if (member.flavor === "email") return { "X-Caller-Email": member.cred.email };
  if (member.flavor === "jwt") {
    // A token carrying claims drives claim-based provisioning/team rules on
    // first sight; a bare-subject token still resolves an existing member.
    const tok = member.cred.claims
      ? member.signer.signWithClaims(member.cred.subject, member.cred.claims)
      : member.signer.sign(member.cred.subject);
    return { Authorization: `Bearer ${tok}` };
  }
  if (member.flavor === "apikey") return { "X-Api-Key": member.cred.secret };
  if (member.flavor === "mtls") {
    // Present the client cert through the forwarded-cert header (url-encoded
    // PEM). The appliance trusts the runner as a forwarded proxy — see
    // tests/appliance/config/managed.config.toml [tls.client_auth].
    return {
      [config.enrolmentForwardedHeader]: encodeURIComponent(
        member.cred.clientCertPem,
      ),
    };
  }
  throw new Error(`unknown flavor ${member.flavor}`);
}

async function resetMock() {
  try {
    await fetch(`${config.mockControlUrl}/__mock/reset`, { method: "POST" });
  } catch (e) {
    warn(`mock reset failed: ${e.message}`);
  }
}

async function callsForNonce(nonce) {
  const res = await fetch(
    `${config.mockControlUrl}/__mock/by-nonce?nonce=${encodeURIComponent(nonce)}`,
  );
  const j = await res.json();
  return j.calls || [];
}

// Execute one request and, on a 200, PRICE its full per-stage usage from the
// mock's per-nonce call log — WITHOUT recording it into the ledger. Splitting
// execution from recording lets the enrolment drill discover the freshly-minted
// member id (only known after the first call succeeds) before attributing the
// spend. Returns { status, member, surface, nonce } plus { grand, llm } on 200.
async function executeOnce(appliance, pricer, member, surface, opts) {
  const roundIdx = opts.roundIdx;
  const reject = !!opts.reject;
  const nonce = newNonce(roundIdx);
  const base = pick(opts.rng, PROMPTS);
  const content = `[[tkid:${nonce}]] ${reject ? `${REJECT_TRIGGER} ` : ""}${base}`;
  const payload = {
    model: surface.model,
    messages: [{ role: "user", content }],
  };
  // Opt this request into structured output when asked, so the surface records a
  // schema-validity drift sample (production sampling only fills that dimension
  // for callers that request a json_schema).
  if (opts.responseFormat) payload.response_format = opts.responseFormat;
  const headers = { ...buildHeaders(member), ...(opts.headers || {}) };

  let res;
  try {
    res = await appliance.invokePipe(surface.route, payload, headers);
  } catch (e) {
    return { status: 0, error: String(e), member, surface, nonce };
  }

  if (res.status === 200) {
    const calls = await callsForNonce(nonce);
    const usage = (res.json && res.json.usage) || {
      prompt_tokens: 0,
      completion_tokens: 0,
      total_tokens: 0,
    };
    let grandCost = 0;
    let grandTokens = 0;
    for (const c of calls) {
      grandCost += pricer.cost(c.model, c.prompt_tokens, c.completion_tokens);
      grandTokens += c.total_tokens;
    }
    const llmCost = pricer.cost(
      surface.model,
      usage.prompt_tokens,
      usage.completion_tokens,
    );
    const llmTokens = usage.total_tokens;
    return {
      status: 200,
      member,
      surface,
      nonce,
      grand: { cost: grandCost, tokens: grandTokens },
      llm: { cost: llmCost, tokens: llmTokens },
    };
  }
  return {
    status: res.status,
    member,
    surface,
    nonce,
    body: res.text ? res.text.slice(0, 300) : null,
  };
}

// Record a priced execution into the ledger under the given attribution. A
// member may belong to several teams (auto-provisioned members in particular),
// so the full team set is recorded.
function recordExecution(ledger, { surfaceId, memberId, teamIds, grand, llm }) {
  ledger.recordSuccess({
    surfaceId,
    memberId,
    teamIds,
    grand,
    llm,
    stages: null,
  });
}

// Record a Judge/Jury content rejection (HTTP 403) into the ledger's rejection
// scopes under the same attribution the appliance uses. ANY phase can produce
// one: the rejection drill drives them deliberately, but a fail-closed juror
// error (e.g. an upstream timeout under concurrent load) also rejects otherwise
// benign traffic — and the appliance records both — so the ledger must mirror
// both or the appliance-wide + per-team rejection totals over-count during
// reconciliation. Jury stage when the surface has jurors (juror decisions are
// response-side), else judge. Full team set, matching the success path.
function recordExecutionRejection(ledger, member, surface) {
  ledger.recordRejection({
    surfaceId: surface.pipeId,
    stage: surface.jurors > 0 ? "jury" : "judge",
    memberId: member.id,
    teamIds: member.teamIds || [member.teamId],
  });
}

// Execute one request and record it into the ledger: full per-stage usage on a
// 200, or a rejection on a Judge/Jury 403 (the appliance records rejection
// telemetry for those, so the ledger must too — see recordExecutionRejection).
// Returns { status, member, surface } plus the priced usage on success.
async function executeAndRecord(
  appliance,
  ledger,
  pricer,
  member,
  surface,
  opts,
) {
  const r = await executeOnce(appliance, pricer, member, surface, opts);
  if (r.status === 200) {
    recordExecution(ledger, {
      surfaceId: surface.pipeId,
      memberId: member.id,
      teamIds: member.teamIds || [member.teamId],
      grand: r.grand,
      llm: r.llm,
    });
  } else if (r.status === 403 && (surface.hasJudge || surface.jurors > 0)) {
    recordExecutionRejection(ledger, member, surface);
  }
  return r;
}

// ---- phase 1: deterministic cap-enforcement drill ----
async function capDrillPhase(
  appliance,
  world,
  ledger,
  pricer,
  rng,
  roundIdx,
  stats,
) {
  const cd = world.capDrill;
  const out = { enabled: !!cd, control: null, targets: [], pass: true };
  if (!cd) return out;

  const sp = spinner("cap drill");
  let driven = 0;
  const drive = async (member, n, tag) => {
    const r = {
      calls: 0,
      ok200: 0,
      blocked429: 0,
      anomalies: 0,
      firstBlockAt: null,
    };
    for (let i = 0; i < n; i += 1) {
      if (isStopRequested()) break;
      const res = await executeAndRecord(
        appliance,
        ledger,
        pricer,
        member,
        cd.surface,
        { roundIdx, rng },
      );
      r.calls += 1;
      driven += 1;
      if (res.status === 200) r.ok200 += 1;
      else if (res.status === 429) {
        r.blocked429 += 1;
        if (r.firstBlockAt == null) r.firstBlockAt = i;
      } else {
        r.anomalies += 1;
        stats.anomalies.push({
          phase: "cap-drill",
          member: member.id,
          status: res.status,
          body: res.body,
          error: res.error,
        });
      }
      sp.set({ at: tag, calls: driven, blocked: r.blocked429 });
    }
    return r;
  };

  // The uncapped control must never be blocked.
  const control = await drive(
    cd.control,
    Math.max(2, Math.floor(config.capDrillCalls / 2)),
    "control",
  );
  out.control = { memberId: cd.control.id, ...control };
  if (control.blocked429 > 0) {
    out.pass = false;
    stats.capFailures.push({
      kind: "control",
      member: cd.control.id,
      reason: "uncapped control was blocked (429)",
    });
  }

  // Each capped target must trip enforcement within the call budget.
  for (const target of cd.targets) {
    if (isStopRequested()) break;
    const r = await drive(target.member, config.capDrillCalls, target.scope);
    const targetPass = r.blocked429 > 0;
    if (!targetPass) {
      out.pass = false;
      stats.capFailures.push({
        kind: target.kind,
        scope: target.scope,
        member: target.member.id,
        reason: `capped ${target.scope} never enforced (no 429 in ${r.calls} calls)`,
      });
    }
    out.targets.push({
      kind: target.kind,
      scope: target.scope,
      memberId: target.member.id,
      ...r,
      pass: targetPass,
    });
  }

  info(
    `cap drill: control 429s=${out.control.blocked429} (want 0); ${
      out.targets.filter((t) => t.pass).length
    }/${out.targets.length} capped targets enforced`,
  );
  sp.stop();
  return out;
}

// ---- phase 2: judge/jury rejection drill ----
async function rejectionPhase(
  appliance,
  world,
  ledger,
  pricer,
  rng,
  roundIdx,
  stats,
) {
  const out = { enabled: false, surfaces: [], pass: true };
  const moderated = world.moderatedSurfaces || [];
  if (!config.rejectionDrill || moderated.length === 0) return out;
  out.enabled = true;

  for (const surface of moderated) {
    if (isStopRequested()) break;
    const stage = surface.hasJudge ? "judge" : "jury";
    const callers = (world.loadMembers || []).filter(
      (m) => m.flavor === surface.identity,
    );
    if (callers.length === 0) {
      warn(
        `rejection drill: no ${surface.identity} load members for ${surface.pipeId}`,
      );
      continue;
    }
    const rec = {
      pipeId: surface.pipeId,
      stage,
      sent: 0,
      blocked: 0,
      allowed: 0,
      anomalies: 0,
    };
    const sp = spinner(`rejection drill ${surface.pipeId}`);
    for (let i = 0; i < config.rejectionRequests; i += 1) {
      if (isStopRequested()) break;
      const member = pick(rng, callers);
      const res = await executeAndRecord(
        appliance,
        ledger,
        pricer,
        member,
        surface,
        { roundIdx, rng, reject: true },
      );
      rec.sent += 1;
      if (res.status === 403) {
        // executeAndRecord already mirrored the rejection into the ledger.
        rec.blocked += 1;
      } else if (res.status === 200) {
        rec.allowed += 1; // a bad prompt slipped through — moderation failure
      } else {
        rec.anomalies += 1;
        stats.anomalies.push({
          phase: "rejection",
          member: member.id,
          surface: surface.pipeId,
          status: res.status,
          body: res.body,
          error: res.error,
        });
      }
      sp.set({
        stage,
        sent: rec.sent,
        blocked: rec.blocked,
        allowed: rec.allowed,
      });
    }
    sp.stop();
    rec.pass = rec.blocked === rec.sent && rec.allowed === 0;
    if (!rec.pass) out.pass = false;
    out.surfaces.push(rec);
  }

  info(
    `rejection drill: ${out.surfaces.filter((s) => s.pass).length}/${out.surfaces.length} moderated surfaces rejected all bad prompts`,
  );
  return out;
}

// ---- phase 3: concurrent general load ----
async function loadPhase(
  appliance,
  world,
  ledger,
  pricer,
  rng,
  roundIdx,
  stats,
) {
  const out = { sent: 0, ok: 0, blocked: 0, anomalies: 0 };
  const members = world.loadMembers || [];
  if (members.length === 0) {
    warn("load phase skipped: no uncapped load members");
    return out;
  }

  const durationMs =
    config.durationSeconds > 0 ? config.durationSeconds * 1000 : 0;
  const total = durationMs > 0 ? Number.MAX_SAFE_INTEGER : config.numRequests;
  const startedAt = Date.now();
  const sp = spinner("load phase");

  await runPool(
    {
      concurrency: config.concurrency,
      total,
      durationMs,
      rps: config.targetRps,
      shouldStop: isStopRequested,
      onError: (e) =>
        stats.anomalies.push({ phase: "load", kind: "pool", error: String(e) }),
    },
    async () => {
      const member = pick(rng, members);
      const surface = pick(rng, member.surfaces);
      const res = await executeAndRecord(
        appliance,
        ledger,
        pricer,
        member,
        surface,
        { roundIdx, rng },
      );
      out.sent += 1;
      if (res.status === 200) out.ok += 1;
      else if (res.status === 429) {
        out.blocked += 1;
        // Load members are uncapped, so a 429 here is unexpected.
        stats.capFailures.push({
          kind: "load",
          member: member.id,
          surface: surface.pipeId,
          reason: "uncapped load member blocked (429)",
        });
      } else {
        out.anomalies += 1;
        stats.anomalies.push({
          phase: "load",
          member: member.id,
          surface: surface.pipeId,
          status: res.status,
          body: res.body,
          error: res.error,
        });
      }
      const secs = (Date.now() - startedAt) / 1000;
      const rps = secs > 0 ? (out.sent / secs).toFixed(1) : "0.0";
      sp.set(
        durationMs > 0
          ? {
              sent: out.sent,
              ok: out.ok,
              blocked: out.blocked,
              rps,
              left: `${Math.max(0, Math.ceil((durationMs - (Date.now() - startedAt)) / 1000))}s`,
            }
          : {
              progress: `${out.sent}/${total}`,
              ok: out.ok,
              blocked: out.blocked,
              rps,
            },
      );
    },
  );
  sp.stop();

  info(
    `load phase: sent=${out.sent} ok=${out.ok} blocked=${out.blocked} anomalies=${out.anomalies} (concurrency=${config.concurrency}, rps=${config.targetRps || "unlimited"}, duration=${config.durationSeconds || "n/a"}s)`,
  );
  return out;
}

// ---- phase 4: full-population coverage sweep ----
// Drive a few calls through EVERY (non-drill) callable member so no member is
// left with zero usage, and spread the calls across several telemetry buckets
// (waves spaced > one bucket apart) so each member shows a real multi-point time
// series rather than a single point. Capped members may exhaust their quota and
// return 429 mid-sweep — that is expected and recorded as `blocked`, never an
// anomaly. Runs last so any quota pollution cannot disturb the cap-drill or
// load phases (whose members are uncapped by construction).
async function coveragePhase(
  appliance,
  world,
  ledger,
  pricer,
  rng,
  roundIdx,
  stats,
) {
  const out = {
    enabled: false,
    waves: 0,
    members: 0,
    sent: 0,
    ok: 0,
    blocked: 0,
    anomalies: 0,
  };
  if (!config.coverage) return out;
  // Exclude the deliberately tiny-capped cap-drill fixtures: their whole purpose
  // is to stay blocked, so they cannot (and should not) accrue usage here.
  const members = (world.callableMembers || []).filter((m) => !m.drill);
  if (members.length === 0) {
    warn("coverage sweep skipped: no callable members");
    return out;
  }
  out.enabled = true;
  out.members = members.length;

  const sp = spinner("coverage sweep");
  for (let wave = 0; wave < config.coverageWaves; wave += 1) {
    if (isStopRequested()) break;
    for (const member of members) {
      if (isStopRequested()) break;
      const surface = pick(rng, member.surfaces);
      for (let c = 0; c < config.coverageCallsPerMember; c += 1) {
        // Alternate structured-output requests so every swept surface accrues
        // schema-validity drift samples alongside plain chat.
        const responseFormat = c % 2 === 0 ? SCHEMA_RESPONSE_FORMAT : null;
        const res = await executeAndRecord(
          appliance,
          ledger,
          pricer,
          member,
          surface,
          {
            roundIdx,
            rng,
            responseFormat,
          },
        );
        out.sent += 1;
        if (res.status === 200) out.ok += 1;
        else if (res.status === 429)
          out.blocked += 1; // capped member hit quota — expected
        else {
          out.anomalies += 1;
          stats.anomalies.push({
            phase: "coverage",
            member: member.id,
            surface: surface.pipeId,
            status: res.status,
            body: res.body,
            error: res.error,
          });
        }
        sp.set({
          wave: `${wave + 1}/${config.coverageWaves}`,
          sent: out.sent,
          ok: out.ok,
          blocked: out.blocked,
        });
      }
    }
    out.waves += 1;
    // Space waves > one telemetry bucket apart so each wave lands in its own
    // bucket — the source of the multi-point time series.
    if (
      wave < config.coverageWaves - 1 &&
      config.coverageWaveGapSeconds > 0 &&
      !isStopRequested()
    ) {
      const gapEnd = Date.now() + config.coverageWaveGapSeconds * 1000;
      while (Date.now() < gapEnd && !isStopRequested()) {
        const remaining = Math.max(0, Math.ceil((gapEnd - Date.now()) / 1000));
        sp.set({
          wave: `${wave + 1}/${config.coverageWaves}`,
          status: "waiting for next bucket",
          next_in: `${remaining}s`,
        });
        await sleep(Math.min(250, gapEnd - Date.now()));
      }
    }
  }
  sp.stop();

  info(
    `coverage sweep: ${out.members} members \u00d7 ${out.waves} wave(s) -> sent=${out.sent} ok=${out.ok} blocked=${out.blocked} anomalies=${out.anomalies}`,
  );
  return out;
}

function sumDrillCalls(cd) {
  let n = cd.control ? cd.control.calls : 0;
  for (const t of cd.targets) n += t.calls;
  return n;
}
function sumRejectionSent(rej) {
  let n = 0;
  for (const s of rej.surfaces) n += s.sent;
  return n;
}

async function timedPhase(stats, name, run) {
  const startedAt = Date.now();
  try {
    return await run();
  } finally {
    stats.timingsMs[name] = Date.now() - startedAt;
    info(`${name} duration: ${(stats.timingsMs[name] / 1000).toFixed(1)}s`);
  }
}

// Run one full round (cap drill -> rejection -> load) against the world, adding
// to the cumulative ledger. Returns the per-round stats.
async function runRound(appliance, world, ledger, pricer, rng, roundIdx) {
  // Reset the mock call log so nonce lookups stay cheap; rounds are sequential.
  await resetMock();

  const stats = {
    round: roundIdx,
    startTs: Math.floor(Date.now() / 1000),
    endTs: 0,
    anomalies: [],
    capFailures: [],
    enrolmentFailures: [],
    policyFailures: [],
    timingsMs: {},
  };

  stats.capDrill = await timedPhase(stats, "capDrill", () =>
    capDrillPhase(appliance, world, ledger, pricer, rng, roundIdx, stats),
  );
  stats.enrolment = await timedPhase(stats, "enrolment", () =>
    enrolmentPhase(
      { executeOnce, recordExecution },
      appliance,
      world,
      ledger,
      pricer,
      rng,
      roundIdx,
      stats,
    ),
  );
  stats.rejection = await timedPhase(stats, "rejection", () =>
    rejectionPhase(appliance, world, ledger, pricer, rng, roundIdx, stats),
  );
  stats.load = await timedPhase(stats, "load", () =>
    loadPhase(appliance, world, ledger, pricer, rng, roundIdx, stats),
  );
  stats.coverage = await timedPhase(stats, "coverage", () =>
    coveragePhase(appliance, world, ledger, pricer, rng, roundIdx, stats),
  );

  // Policy enforcement drill runs LAST: it briefly sets an appliance-wide global
  // deny (always restored in a finally), so keeping it after all reconciled
  // traffic guarantees that window can never affect another phase's requests.
  stats.policy = await timedPhase(stats, "policy", () =>
    policyPhase(
      { executeOnce, recordExecution },
      appliance,
      world,
      ledger,
      pricer,
      rng,
      roundIdx,
      stats,
    ),
  );

  // Drift evaluation sweep: create + run a small suite against every
  // drift-enabled surface so the graded drift dimensions (quality,
  // self-consistency, semantic distance) get data. Bypasses the handler, so it
  // records no surface telemetry and can't disturb reconciliation.
  stats.driftEval = await timedPhase(stats, "driftEval", () =>
    driftEvalPhase(appliance, world),
  );

  stats.endTs = Math.floor(Date.now() / 1000);
  stats.sent =
    stats.load.sent +
    (stats.capDrill.enabled ? sumDrillCalls(stats.capDrill) : 0) +
    (stats.enrolment.enabled ? stats.enrolment.sent : 0) +
    sumRejectionSent(stats.rejection) +
    stats.coverage.sent;
  stats.ok = stats.load.ok;
  stats.blocked = stats.load.blocked;

  info(
    `round ${roundIdx} done: load ok=${stats.load.ok}, enrolment ${
      stats.enrolment.enabled
        ? `${stats.enrolment.kinds.filter((k) => k.pass).length}/${stats.enrolment.kinds.length} kinds`
        : "off"
    }, coverage ok=${stats.coverage.ok}/${stats.coverage.sent} over ${stats.coverage.members} members, cap pass=${stats.capDrill.pass}, rejection pass=${stats.rejection.pass}, anomalies=${stats.anomalies.length}`,
  );
  // A tiny settle so any straggling fire-and-forget telemetry has a head start.
  await sleep(50);
  return stats;
}

module.exports = { runRound };
