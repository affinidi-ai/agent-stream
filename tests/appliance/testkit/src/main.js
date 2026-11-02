"use strict";

const fs = require("fs");
const path = require("path");

const { config } = require("./config");
const { info, warn, error, makeRng } = require("./log");
const { Appliance } = require("./appliance");
const { makePricer } = require("./pricing");
const { Ledger } = require("./ledger");
const { setup } = require("./setup");
const { runRound } = require("./simulate");
const { reconcile } = require("./reconcile");
const { teardown } = require("./teardown");
const { ask } = require("./prompt");
const {
  waitWithCountdown,
  startStopListener,
  stopStopListener,
  isStopRequested,
  resetStop,
} = require("./progress");

function writeReport(report) {
  try {
    fs.mkdirSync(config.resultsDir, { recursive: true });
  } catch (e) {
    warn(`could not create results dir: ${e}`);
  }
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const file = path.join(config.resultsDir, `testkit-report-${stamp}.json`);
  fs.writeFileSync(file, JSON.stringify(report, null, 2));
  info(`report written to ${file}`);
  return file;
}

// Build a cumulative summary across every round run so far plus the latest
// (cumulative) reconciliation.
function summarise(recon, rounds) {
  const failedSeries = recon.results.filter((r) => !r.ok);
  const failedStages = recon.stageChecks.filter(
    (s) => s.surfaceTotal.requests > 0 && !s.ok,
  );
  const failedRejections = recon.rejectionChecks.filter((r) => !r.ok);
  const driftChecks = recon.driftChecks || [];
  const driftExpected = driftChecks.filter((d) => d.expectSamples);
  const failedDrift = driftExpected.filter((d) => !d.ok);
  const driftBaselinesConfirmed = driftExpected.filter(
    (d) => d.baselinePinned,
  ).length;

  let loadSent = 0;
  let loadOk = 0;
  let loadBlocked = 0;
  let anomalies = 0;
  let rejectionBlocked = 0;
  let rejectionAllowed = 0;
  let capTargetsEnforced = 0;
  let capTargetsTotal = 0;
  let enrolmentSent = 0;
  let enrolmentKindsPassed = 0;
  let enrolmentKindsTotal = 0;
  let enrolmentGuardrailPass = null;
  let policyChecksPassed = 0;
  let policyChecksTotal = 0;
  let driftEvalSurfaces = 0;
  let driftEvalGraded = 0;
  let driftEvalFailed = 0;
  for (const rs of rounds) {
    loadSent += rs.load.sent;
    loadOk += rs.load.ok;
    loadBlocked += rs.load.blocked;
    anomalies += rs.anomalies.length;
    if (rs.rejection) {
      for (const s of rs.rejection.surfaces) {
        rejectionBlocked += s.blocked;
        rejectionAllowed += s.allowed;
      }
    }
    if (rs.capDrill && rs.capDrill.enabled) {
      capTargetsTotal += rs.capDrill.targets.length;
      capTargetsEnforced += rs.capDrill.targets.filter((t) => t.pass).length;
    }
    if (rs.enrolment && rs.enrolment.enabled) {
      enrolmentSent += rs.enrolment.sent;
      enrolmentKindsTotal += rs.enrolment.kinds.length;
      enrolmentKindsPassed += rs.enrolment.kinds.filter(
        (k) => k.pass && !k.skipped,
      ).length;
      if (rs.enrolment.guardrail && rs.enrolment.guardrail.ran) {
        enrolmentGuardrailPass =
          enrolmentGuardrailPass !== false && rs.enrolment.guardrail.pass;
      }
    }
    if (rs.policy && rs.policy.enabled) {
      policyChecksTotal += rs.policy.checks.length;
      policyChecksPassed += rs.policy.checks.filter((c) => c.ok).length;
    }
    if (rs.driftEval && rs.driftEval.enabled) {
      driftEvalSurfaces += rs.driftEval.surfaces;
      driftEvalGraded += rs.driftEval.ran;
      driftEvalFailed += rs.driftEval.failed;
    }
  }

  return {
    pass: recon.pass,
    rounds: rounds.length,
    seriesTotal: recon.results.length,
    seriesMatched: recon.results.length - failedSeries.length,
    seriesFailed: failedSeries.length,
    stageChecksFailed: failedStages.length,
    driftSurfacesTotal: driftExpected.length,
    driftSurfacesRecorded: driftExpected.length - failedDrift.length,
    driftSurfacesFailed: failedDrift.length,
    driftBaselinesConfirmed,
    driftEvalSurfaces,
    driftEvalGraded,
    driftEvalFailed,
    rejectionScopesTotal: recon.rejectionChecks.length,
    rejectionScopesFailed: failedRejections.length,
    capFailures: recon.capFailures.length,
    capTargetsEnforced,
    capTargetsTotal,
    policyFailures: recon.policyFailures.length,
    policyChecksPassed,
    policyChecksTotal,
    enrolmentFailures: recon.enrolmentFailures.length,
    enrolmentSent,
    enrolmentKindsPassed,
    enrolmentKindsTotal,
    enrolmentGuardrailPass,
    rejectionBlocked,
    rejectionAllowed,
    loadSent,
    loadOk,
    loadBlocked,
    anomalies,
  };
}

function buildReport(summary, recon, rounds, world) {
  return {
    generatedAt: new Date().toISOString(),
    config: {
      loadProfile: config.loadProfile,
      numTeams: config.numTeams,
      membersPerTeam: config.membersPerTeam,
      numRequests: config.numRequests,
      concurrency: config.concurrency,
      targetRps: config.targetRps,
      durationSeconds: config.durationSeconds,
      capDrill: config.capDrill,
      rejectionDrill: config.rejectionDrill,
      enrolmentDrill: config.enrolmentDrill,
      enrolmentCalls: config.enrolmentCalls,
      enrolmentGuardrail: config.enrolmentGuardrail,
      enrolmentMtlsOptional: config.enrolmentMtlsOptional,
      coverage: config.coverage,
      coverageWaves: config.coverageWaves,
      coverageWaveGapSeconds: config.coverageWaveGapSeconds,
      reconResolution: config.reconResolution,
      costAbsTolerance: config.costAbsTolerance,
      costRelTolerance: config.costRelTolerance,
      seed: config.seed,
    },
    summary,
    rounds: rounds.map((r) => ({
      round: r.round,
      window: { from: r.startTs, to: r.endTs },
      load: r.load,
      capDrill: r.capDrill,
      enrolment: r.enrolment,
      rejection: r.rejection,
      coverage: r.coverage,
      capFailures: r.capFailures,
      enrolmentFailures: r.enrolmentFailures,
      policy: r.policy,
      policyFailures: r.policyFailures,
      timingsMs: r.timingsMs,
      anomalies: r.anomalies,
    })),
    reconciliation: recon,
    surfaces: world.surfaces.map((s) => ({
      pipeId: s.pipeId,
      route: s.route,
      identity: s.identity,
      model: s.model,
      hasJudge: s.hasJudge,
      jurors: s.jurors,
      moderated: s.moderated,
    })),
  };
}

async function nextAction() {
  const ans = (
    await ask(
      "\n[r] run another round (cumulative)  [c] clean up & exit  [p] hard-purge fixtures & exit  [q] quit (leave population)  > ",
    )
  ).toLowerCase();
  if (ans === "r" || ans === "run" || ans === "") return "run";
  if (ans === "c" || ans === "clean" || ans === "cleanup") return "clean";
  if (ans === "p" || ans === "purge") return "purge";
  if (ans === "q" || ans === "quit" || ans === "exit") return "quit";
  info(`unrecognised choice '${ans}'; please pick r, c, p, or q`);
  return nextAction();
}

async function main() {
  const rng = makeRng(config.seed);
  const appliance = new Appliance(config.applianceUrl);
  const pricer = makePricer(config.llmCatalogPath);
  const ledger = new Ledger();

  let world;
  try {
    info(
      `load level: ${config.loadProfile} (teams=${config.numTeams}, members/team=${config.membersPerTeam}, requests=${config.numRequests}, concurrency=${config.concurrency})`,
    );
    info("waiting for appliance readiness...");
    await appliance.waitUntilReady();
    const auth = await appliance.login();
    info(
      auth.provided
        ? "using provided appliance session token"
        : "logged in to appliance admin API (test-auth)",
    );

    world = await setup(appliance, rng);
    info(
      `population ready: ${world.teams.length} teams, ${world.members.length} members, ${world.surfaces.length} surfaces`,
    );

    const rounds = [];
    const capFailures = [];
    const enrolmentFailures = [];
    const policyFailures = [];
    let firstStartTs = null;
    let lastRecon = null;
    let cleanedUp = false;

    let roundIdx = 0;
    if (config.interactive && process.stdin.isTTY) {
      info(
        "tip: press q during a round to wrap up after it finishes (telemetry is retained)",
      );
    }
    // Run at least one round, then either loop interactively or stop.
    // eslint-disable-next-line no-constant-condition
    while (true) {
      roundIdx += 1;
      info(`==== ROUND ${roundIdx} ====`);
      resetStop();
      startStopListener();
      let stats;
      try {
        stats = await runRound(appliance, world, ledger, pricer, rng, roundIdx);
      } finally {
        stopStopListener();
      }
      if (isStopRequested())
        info("stop requested — wrapping up this round (telemetry retained).");
      rounds.push(stats);
      capFailures.push(...stats.capFailures);
      enrolmentFailures.push(...stats.enrolmentFailures);
      policyFailures.push(...stats.policyFailures);
      if (firstStartTs == null) firstStartTs = stats.startTs;

      const settleStartedAt = Date.now();
      await waitWithCountdown(
        "settling for telemetry to flush",
        config.settleSeconds,
      );
      stats.timingsMs.telemetrySettle = Date.now() - settleStartedAt;

      // Cumulative reconciliation: window spans the first round to now. The
      // `from` margin must exceed one telemetry bucket step (reconResolution,
      // 30s by default) so a bucket aligned just below firstStartTs is not
      // excluded by the half-open range query.
      const window = {
        from: firstStartTs - 120,
        to: Math.floor(Date.now() / 1000) + 10,
      };
      const reconciliationStartedAt = Date.now();
      lastRecon = await reconcile(
        appliance,
        world,
        ledger,
        window,
        capFailures,
        enrolmentFailures,
        policyFailures,
      );
      stats.timingsMs.reconciliation = Date.now() - reconciliationStartedAt;
      info(
        `reconciliation duration: ${(stats.timingsMs.reconciliation / 1000).toFixed(1)}s`,
      );
      const summary = summarise(lastRecon, rounds);
      const reportFile = writeReport(
        buildReport(summary, lastRecon, rounds, world),
      );

      info("==== CUMULATIVE SUMMARY ====");
      info(JSON.stringify(summary, null, 2));
      info(`report: ${reportFile}`);
      info(summary.pass ? "ROUND RESULT: PASS" : "ROUND RESULT: FAIL");

      if (!config.interactive) {
        info("non-interactive mode: single round complete");
        if (config.teardown) {
          info("tearing down population (statistics retained in report)...");
          await teardown(appliance, world);
          cleanedUp = true;
        } else {
          info("teardown disabled; leaving population in place");
        }
        break;
      }

      const action = await nextAction();
      if (action === "run") continue;
      if (action === "clean") {
        info("cleaning up population...");
        await teardown(appliance, world);
        cleanedUp = true;
        break;
      }
      if (action === "purge") {
        info("hard-purging all test fixtures (files actually removed)...");
        const purged = await appliance.purgeTestFixtures();
        info(
          `purged: ${purged.surfaces.deleted} surface(s), ${purged.members.deleted} member(s), ${purged.teams.deleted} team(s)`,
        );
        cleanedUp = true;
        break;
      }
      // quit: leave the population in place for further manual inspection.
      info(
        "leaving population in place (re-run with the same config to add more).",
      );
      break;
    }

    const pass = lastRecon && lastRecon.pass;
    info("==== TESTKIT DONE ====");
    info(
      `rounds run: ${rounds.length}; population ${cleanedUp ? "cleaned up" : "left in place"}`,
    );
    if (!pass) {
      error(
        "TESTKIT FAILED: appliance statistics did not match locally tracked statistics",
      );
      process.exitCode = 1;
    } else {
      info(
        "TESTKIT PASSED: appliance statistics matched locally tracked statistics",
      );
      process.exitCode = 0;
    }
  } catch (e) {
    if (e && e.graceful) {
      error(`testkit run aborted: ${e.message}`);
    } else {
      error(`testkit run errored: ${e && e.stack ? e.stack : e}`);
    }
    // Best-effort teardown so a crashed run does not leave residue.
    if (world && config.teardown) {
      try {
        await teardown(appliance, world);
      } catch (te) {
        warn(`cleanup after error failed: ${te}`);
      }
    }
    process.exitCode = 2;
  }
}

main().catch((e) => {
  // Last-resort safety net: never exit with an unhandled promise rejection.
  error(`fatal: ${e && e.stack ? e.stack : e}`);
  process.exitCode = 2;
});
