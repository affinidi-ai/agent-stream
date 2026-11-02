"use strict";

const fs = require("fs");

// Mirrors the appliance's catalog pricing math so the runner can independently
// compute the cost of every mock upstream call and reconcile it against the
// appliance's telemetry. The appliance resolves per-model `cost_per_1k_input` /
// `cost_per_1k_output` (USD per 1,000 tokens); cost = tokens * rate / 1000.
//
// Reads the SAME llm.json the appliance loads, so there is one source of truth.

function loadPricing(catalogPath) {
  const raw = fs.readFileSync(catalogPath, "utf8");
  const catalog = JSON.parse(raw);
  const prices = new Map(); // model value -> { input, output }
  for (const provider of catalog.providers || []) {
    for (const model of provider.models || []) {
      if (typeof model.value !== "string") continue;
      if (typeof model.cost_per_1k_input === "number" && typeof model.cost_per_1k_output === "number") {
        prices.set(model.value, {
          input: model.cost_per_1k_input,
          output: model.cost_per_1k_output,
        });
      }
    }
  }
  return prices;
}

function makePricer(catalogPath) {
  const prices = loadPricing(catalogPath);
  return {
    has(model) {
      return prices.has(model);
    },
    // Cost in USD for a single call's token usage.
    cost(model, inputTokens, outputTokens) {
      const p = prices.get(model);
      if (!p) return 0;
      return (inputTokens * p.input) / 1000 + (outputTokens * p.output) / 1000;
    },
  };
}

module.exports = { makePricer };
