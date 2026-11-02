"use strict";

// Entry point for the real-API conformance suite (see conformance.js).
//
//   node src/conformance-main.js
//
// Drives the appliance at APPLIANCE_URL, resolving the operator's provider keys
// by tag (default `test-suite-openai` / `test-suite-anthropic`), creating one
// OpenAI-backed and one Anthropic-backed surface, and asserting every supported
// client dialect (OpenAI Chat, Anthropic Messages, OpenAI Responses) plus
// /v1/models and /v1/embeddings conforms — regardless of the upstream model.
//
// Auth to the admin API is the same as the main testkit: a debug test-auth
// session (AS_TEST_MODE) or a supplied APPLIANCE_SESSION_TOKEN. It never runs
// the mock LLM and never touches the load/quota reconciliation harness.

const fs = require("fs");
const path = require("path");

const { config } = require("./config");
const { info, warn, error } = require("./log");
const { Appliance } = require("./appliance");
const { runConformance } = require("./conformance");

function env(name, fallback) {
  const v = process.env[name];
  return v === undefined || v === "" ? fallback : v;
}

function writeReport(report) {
  try {
    fs.mkdirSync(config.resultsDir, { recursive: true });
  } catch (e) {
    warn(`could not create results dir: ${e}`);
  }
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const file = path.join(config.resultsDir, `conformance-report-${stamp}.json`);
  fs.writeFileSync(file, JSON.stringify(report, null, 2));
  return file;
}

function summarize(results) {
  const total = results.length;
  const skipped = results.filter((r) => r.skipped).length;
  const soft = results.filter((r) => r.soft).length;
  const failed = results.filter((r) => r.ok === false && !r.skipped);
  const passed = total - skipped - failed.length;
  return { total, passed, failed: failed.length, skipped, soft, failures: failed };
}

// Wait for a single keypress. Resolves true to proceed (clean up), false to
// leave things in place (Ctrl-C, which in raw mode arrives as byte 0x03).
function waitForKeypress(promptText) {
  return new Promise((resolve) => {
    const stdin = process.stdin;
    process.stdout.write(promptText);
    const wasRaw = !!stdin.isRaw;
    if (stdin.setRawMode) stdin.setRawMode(true);
    stdin.resume();
    stdin.once("data", (buf) => {
      if (stdin.setRawMode) stdin.setRawMode(wasRaw);
      stdin.pause();
      process.stdout.write("\n");
      resolve(!(buf && buf.length && buf[0] === 3));
    });
  });
}

// Keep the created surfaces (and their traffic) reviewable, then clean up on a
// keypress. A non-interactive run (CI, piped) tears down immediately.
async function reviewAndCleanup(created, teardown) {
  if (!created || created.length === 0) return;
  if (!process.stdin.isTTY) {
    await teardown();
    return;
  }
  info("");
  info(`${created.length} conformance surface(s) are live for review: ${created.join(", ")}`);
  info("Inspect their access points and Monitoring (traffic) in the dashboard now.");
  const doClean = await waitForKeypress(
    "Press any key to clean up all conformance test surfaces (Ctrl-C to leave them)… ",
  );
  if (doClean) {
    await teardown();
    info("cleaned up conformance test surfaces.");
  } else {
    info(`left ${created.length} conformance surface(s) in place for review: ${created.join(", ")}`);
    info("Re-run to overwrite them, or hard-purge test fixtures from the dashboard.");
  }
}

async function main() {
  const opts = {
    openaiTag: env("CONF_OPENAI_TAG", "test-suite-openai"),
    anthropicTag: env("CONF_ANTHROPIC_TAG", "test-suite-anthropic"),
    openaiModel: env("CONF_OPENAI_MODEL", "gpt-4o-mini"),
    anthropicModel: env("CONF_ANTHROPIC_MODEL", "claude-haiku-4-5"),
    embeddingsModel: env("CONF_EMBEDDINGS_MODEL", "text-embedding-3-small"),
    listenAddress: "",
    pathPrefix: "",
  };

  const appliance = new Appliance(config.applianceUrl);
  try {
    info(`conformance target: ${config.applianceUrl}`);
    info(
      `models: openai='${opts.openaiModel}' anthropic='${opts.anthropicModel}' embeddings='${opts.embeddingsModel}'`,
    );
    info("waiting for appliance readiness...");
    await appliance.waitUntilReady();
    const auth = await appliance.login();
    info(auth.provided ? "using provided appliance session token" : "logged in to appliance admin API (test-auth)");

    // Resolve the data-plane path prefix (e.g. `/llm`) so surface routes are
    // matched by the pipe router, and scope the surfaces to the listener we
    // invoke through so their access point renders configured in the dashboard
    // (no "unconfigured" marching ants). If no advertised listener matches the
    // target URL, leave the surface unscoped (it still routes on any listener).
    try {
      const routing = await appliance.surfaceRoutingConfig();
      const prefixes = (routing && routing.pipe_path_prefix) || [];
      opts.pathPrefix = prefixes.length ? prefixes[0].prefix || "/llm" : "/llm";
      const addrs = (routing && routing.available_listen_addresses) || [];
      opts.listenAddress = addrs.find((a) => config.applianceUrl.startsWith(a)) || "";
    } catch (e) {
      opts.pathPrefix = "/llm";
      warn(`could not resolve surface routing (using '${opts.pathPrefix}'): ${e.message || e}`);
    }
    info(`data-plane path prefix: ${opts.pathPrefix}${opts.listenAddress ? ` (listener ${opts.listenAddress})` : ""}`);

    info("==== CONFORMANCE RUN ====");
    const { pass, results, created, teardown } = await runConformance(appliance, opts, info);

    const summary = summarize(results);
    const reportFile = writeReport({ generatedAt: new Date().toISOString(), target: config.applianceUrl, opts, summary, results });

    info("==== CONFORMANCE SUMMARY ====");
    info(`total=${summary.total} passed=${summary.passed} failed=${summary.failed} skipped=${summary.skipped} soft=${summary.soft}`);
    for (const f of summary.failures) {
      error(`  FAIL [${f.surface}/${f.dialect}] ${f.name}: ${f.error}`);
    }
    info(`report: ${reportFile}`);

    if (!pass) {
      error("CONFORMANCE FAILED: one or more dialect/endpoint checks did not conform");
      process.exitCode = 1;
    } else {
      info("CONFORMANCE PASSED: all supported APIs conform on both OpenAI- and Anthropic-backed surfaces");
      process.exitCode = 0;
    }

    // Leave the surfaces up for review, then tear down on a keypress.
    await reviewAndCleanup(created, teardown);
  } catch (e) {
    if (e && e.graceful) {
      error(`conformance run aborted: ${e.message}`);
    } else {
      error(`conformance run errored: ${e && e.stack ? e.stack : e}`);
    }
    process.exitCode = 2;
  }
}

main().catch((e) => {
  error(`fatal: ${e && e.stack ? e.stack : e}`);
  process.exitCode = 2;
});
