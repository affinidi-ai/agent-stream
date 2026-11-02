"use strict";

const { config } = require("./config");
const { info, warn, sleep } = require("./log");
const { isStopRequested } = require("./progress");

// Replay-evaluate every drift-enabled surface so the graded drift dimensions
// (semantic distance, plus re-measured latency / length / refusal / safety /
// schema validity) have data on the LLM Drift page. Each surface's captured
// "indicative" sessions — the real prompt/response pairs recorded automatically
// during the load/coverage traffic phases — are re-run through the surface and
// each new answer compared to the originally-captured one.
//
// Runs several waves spaced > one telemetry bucket apart so each graded
// dimension shows a multi-point line (a single run is one point). Runs go
// through the surface's executor attributed to the internal drift-runner
// identity, which BYPASSES the request handler — so they record NO surface usage
// telemetry and never disturb the exact token/cost reconciliation. Bounded
// concurrency keeps mock load sane; failures are logged, not fatal.
async function driftEvalPhase(appliance, world) {
  const out = { enabled: false, surfaces: 0, ran: 0, failed: 0, waves: 0, sessions: 0 };
  if (!config.driftEval) return out;
  const surfaces = (world.surfaces || []).filter((s) => s.drift);
  if (surfaces.length === 0) return out;
  out.enabled = true;
  out.surfaces = surfaces.length;

  const waves = Math.max(1, config.driftEvalWaves);
  const gapMs = Math.max(0, config.coverageWaveGapSeconds) * 1000;
  for (let w = 0; w < waves && !isStopRequested(); w += 1) {
    await runEvalWave(appliance, surfaces, out);
    out.waves += 1;
    // Space waves so each lands in its own telemetry bucket (a multi-point line).
    if (w < waves - 1 && gapMs > 0 && !isStopRequested()) await sleep(gapMs);
  }
  info(
    `drift eval: ${out.ran} run(s) across ${out.surfaces} surface(s) over ${out.waves} wave(s), ${out.sessions} session(s) replayed (${out.failed} failed)`,
  );
  return out;
}

// One wave: replay every drift surface's captured sessions, with bounded
// concurrency.
async function runEvalWave(appliance, surfaces, out) {
  const limit = Math.max(1, Math.min(config.driftEvalConcurrency, surfaces.length));
  let idx = 0;
  async function worker() {
    while (idx < surfaces.length && !isStopRequested()) {
      const s = surfaces[idx];
      idx += 1;
      try {
        const result = await runAndAwaitEval(appliance, s.pipeId);
        out.ran += 1;
        out.sessions += (result && result.total) || 0;
      } catch (e) {
        out.failed += 1;
        warn(`drift eval failed for ${s.pipeId}: ${e && e.message ? e.message : e}`);
      }
    }
  }
  await Promise.all(Array.from({ length: limit }, worker));
}

// Start a replay evaluation and poll until it reaches a terminal status. The
// eval endpoint is now asynchronous (returns a running record immediately), so
// the testkit polls the run by id for the final counts. Bounded by a wall-clock
// deadline so a wedged run can't hang the phase.
const EVAL_POLL_INTERVAL_MS = 1000;
const EVAL_POLL_TIMEOUT_MS = 5 * 60 * 1000;
const TERMINAL = new Set(["completed", "failed", "cancelled"]);

async function runAndAwaitEval(appliance, surfaceId) {
  const started = await appliance.runDriftEval(surfaceId);
  const runId = started && started.id;
  if (!runId) return started;
  if (TERMINAL.has(started.status)) return started;
  const deadline = Date.now() + EVAL_POLL_TIMEOUT_MS;
  let last = started;
  while (Date.now() < deadline && !isStopRequested()) {
    await sleep(EVAL_POLL_INTERVAL_MS);
    try {
      last = await appliance.getDriftRun(runId);
    } catch (e) {
      warn(`drift eval poll failed for ${runId}: ${e && e.message ? e.message : e}`);
      continue;
    }
    if (last && TERMINAL.has(last.status)) return last;
  }
  return last;
}

module.exports = { driftEvalPhase };
