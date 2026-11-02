"use strict";

const { config } = require("./config");
const { info } = require("./log");

// Sum a telemetry series' points across the whole queried window.
function sumSeries(series) {
  let cost = 0;
  let tokens = 0;
  let requests = 0;
  for (const p of series.points || []) {
    cost += p.cost || 0;
    tokens += p.tokens || 0;
    requests += p.requests || 0;
  }
  return { cost, tokens, requests };
}

function chunk(arr, size) {
  const out = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

async function fetchActuals(appliance, keys, from, to) {
  const actual = new Map();
  for (const batch of chunk(keys, 200)) {
    const series = await appliance.telemetrySeries(batch, from, to, config.reconResolution);
    for (const s of series) actual.set(s.key, sumSeries(s));
  }
  return actual;
}

function costClose(expected, actual) {
  const abs = Math.abs(expected - actual);
  if (abs <= config.costAbsTolerance) return true;
  const rel = expected === 0 ? abs : abs / Math.abs(expected);
  return rel <= config.costRelTolerance;
}

async function reconcile(appliance, world, ledger, window, capFailures, enrolmentFailures, policyFailures) {
  const from = window.from;
  const to = window.to;

  // Every ledger key, plus judge/jury stage keys for the internal consistency check.
  const ledgerKeys = ledger.keys();
  const stageKeys = [];
  for (const s of world.surfaces) {
    if (s.hasJudge) stageKeys.push(`surface:${s.pipeId}:stage:judge`);
    if (s.jurors > 0) stageKeys.push(`surface:${s.pipeId}:stage:jury`);
  }
  const allKeys = Array.from(new Set([...ledgerKeys, ...stageKeys]));
  const actual = await fetchActuals(appliance, allKeys, from, to);

  const results = [];
  let pass = true;
  for (const key of ledgerKeys) {
    const exp = ledger.get(key);
    const act = actual.get(key) || { cost: 0, tokens: 0, requests: 0 };
    const tokensOk = exp.tokens === act.tokens;
    const requestsOk = exp.requests === act.requests;
    const costOk = costClose(exp.cost, act.cost);
    const ok = tokensOk && requestsOk && costOk;
    if (!ok) pass = false;
    results.push({ key, expected: exp, actual: act, ok, tokensOk, requestsOk, costOk });
  }

  // Per-surface stage consistency: llm + judge + jury == surface grand total,
  // and judge/jury buckets are non-zero where configured.
  const stageChecks = [];
  for (const s of world.surfaces) {
    const surf = actual.get(`surface:${s.pipeId}`) || { cost: 0, tokens: 0, requests: 0 };
    const llm = actual.get(`surface:${s.pipeId}:stage:llm`) || { cost: 0, tokens: 0 };
    const judge = actual.get(`surface:${s.pipeId}:stage:judge`) || { cost: 0, tokens: 0 };
    const jury = actual.get(`surface:${s.pipeId}:stage:jury`) || { cost: 0, tokens: 0 };
    const stageTokens = llm.tokens + judge.tokens + jury.tokens;
    const stageCost = llm.cost + judge.cost + jury.cost;
    const tokensOk = stageTokens === surf.tokens;
    const costOk = costClose(surf.cost, stageCost);
    const judgeOk = !s.hasJudge || judge.tokens > 0;
    const juryOk = s.jurors === 0 || jury.tokens > 0;
    const ok = tokensOk && costOk && judgeOk && juryOk;
    if (surf.requests > 0 && !ok) pass = false; // only assert for surfaces that saw traffic
    stageChecks.push({
      surface: s.pipeId,
      surfaceTotal: surf,
      llm,
      judge,
      jury,
      tokensOk,
      costOk,
      judgeOk,
      juryOk,
      ok,
    });
  }

  // LLM drift verification: every drift-enabled surface that saw successful
  // traffic must have recorded drift samples (latency + response length are
  // emitted on every buffered success). Reads the dedicated, admin-gated drift
  // store, disjoint from the usage telemetry above.
  const driftChecks = [];
  const driftSurfaces = world.surfaces.filter((s) => s.drift);
  if (driftSurfaces.length > 0) {
    const driftKeys = [];
    for (const s of driftSurfaces) {
      driftKeys.push(`drift:surface:${s.pipeId}:latency_ms`);
      driftKeys.push(`drift:surface:${s.pipeId}:response_length`);
    }
    const driftCounts = new Map();
    let driftError = null;
    try {
      for (const batch of chunk(driftKeys, 200)) {
        const series = await appliance.driftSeries(batch, from, to, config.reconResolution);
        for (const ds of series) {
          const count = (ds.points || []).reduce((a, p) => a + (p.count || 0), 0);
          driftCounts.set(ds.key, count);
        }
      }
    } catch (e) {
      driftError = e && e.message ? e.message : String(e);
    }
    for (const s of driftSurfaces) {
      const surf = actual.get(`surface:${s.pipeId}`) || { requests: 0 };
      const latencyCount = driftCounts.get(`drift:surface:${s.pipeId}:latency_ms`) || 0;
      const lengthCount = driftCounts.get(`drift:surface:${s.pipeId}:response_length`) || 0;
      // Drift samples land only on the success path, so only assert for surfaces
      // that saw successful (cost-bearing) traffic.
      const expectSamples = surf.requests > 0;
      const seriesOk = driftError == null && (!expectSamples || latencyCount > 0);

      // Baseline confirmation: a surface that recorded samples must be able to
      // pin its current behaviour as a baseline (`POST /v1/drift/baseline`) and
      // then read a verdict (`GET /v1/drift/verdict`). Pinned from the
      // accumulated traffic and read over the same window, the surface has not
      // drifted, so the verdict must carry a baseline timestamp and a status
      // other than `drift`. Keep capture and verdict on the same short window so
      // the RRD tier cannot aggregate their samples differently. Only a surface
      // with data can be baselined (the pin 400s on an empty window), so skip
      // surfaces that recorded no samples.
      let baselinePinned = false;
      let verdictStatus = null;
      let baselineError = null;
      if (seriesOk && expectSamples && latencyCount > 0) {
        try {
          const baselineWindowSecs = Math.max(300, to - from);
          const b = await appliance.captureDriftBaseline(s.pipeId, baselineWindowSecs);
          baselinePinned = !!(b && b.captured_at);
          const v = await appliance.driftVerdict(s.pipeId, from, to);
          verdictStatus = v && v.status ? v.status : null;
          if (!baselinePinned || !v || !v.baseline_captured_at) {
            baselineError = "baseline not pinned or not reflected in the verdict";
          } else if (verdictStatus === "drift") {
            baselineError = `unexpected drift verdict for a freshly-pinned baseline (status=${verdictStatus})`;
          }
        } catch (e) {
          baselineError = e && e.message ? e.message : String(e);
        }
      }

      const ok = seriesOk && baselineError == null;
      if (expectSamples && !ok) pass = false;
      driftChecks.push({
        surface: s.pipeId,
        requests: surf.requests,
        latencyCount,
        lengthCount,
        expectSamples,
        baselinePinned,
        verdictStatus,
        baselineError,
        ok,
        error: driftError,
      });
    }
  }

  // Rejection reconciliation: every rejection scope the runner recorded must
  // match the appliance's `total` for that scope over the window.
  const rejectionChecks = [];
  for (const scope of ledger.rejectionScopes()) {
    const expected = ledger.rejectionCount(scope);
    let actualTotal = null;
    let error = null;
    try {
      const r = await appliance.fetchRejections(scope, from, to, config.reconResolution);
      actualTotal = r && typeof r.total === "number" ? r.total : 0;
    } catch (e) {
      error = e && e.message ? e.message : String(e);
    }
    const ok = error == null && actualTotal === expected;
    if (!ok) pass = false;
    rejectionChecks.push({ scope, expected, actual: actualTotal, ok, error });
  }

  // Cap-enforcement drill failures (uncapped control blocked, or a capped target
  // never enforced) fail the whole reconciliation.
  const caps = capFailures || [];
  if (caps.length > 0) pass = false;

  // Enrolment drill failures (a novel identity not provisioned, a missing
  // identifier/team, a broken idempotency/guardrail, or mTLS not exercisable)
  // fail the whole reconciliation too.
  const enrol = enrolmentFailures || [];
  if (enrol.length > 0) pass = false;

  // Policy-enforcement drill failures (an allow/deny mismatch, a fail-closed or
  // deny-overrides gap, a leaked global, or a broken management endpoint) fail
  // the whole reconciliation too.
  const policy = policyFailures || [];
  if (policy.length > 0) pass = false;

  info(
    `reconciliation: ${results.filter((r) => r.ok).length}/${results.length} series matched; ${
      rejectionChecks.filter((r) => r.ok).length
    }/${rejectionChecks.length} rejection scopes matched; ${
      driftChecks.filter((d) => d.ok).length
    }/${driftChecks.length} drift surfaces recorded (${
      driftChecks.filter((d) => d.baselinePinned).length
    } baselines confirmed); capFailures=${caps.length}; enrolmentFailures=${enrol.length}; policyFailures=${policy.length}; pass=${pass}`,
  );
  return {
    from,
    to,
    results,
    stageChecks,
    driftChecks,
    rejectionChecks,
    capFailures: caps,
    enrolmentFailures: enrol,
    policyFailures: policy,
    pass,
  };
}

module.exports = { reconcile };
