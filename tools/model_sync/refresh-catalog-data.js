#!/usr/bin/env node

/**
 * Refresh the built-in LLM catalog data by visiting each provider.
 *
 * Deterministic, review-first pipeline (NOT an LLM agent — pricing feeds cost
 * accounting/budgets, so it must be authoritative and reproducible):
 *
 *   1. Load a curated base catalog (default: config/examples/llm.example.json).
 *      Curated fields — endpoints, icon, description, hero, request_profile,
 *      api_key_validation, api_key_label, filter_tag — are always preserved.
 *   2. DISCOVER models: for each provider that has an API key in the
 *      environment, call its own `/models` endpoint (OpenAI-, Anthropic-, and
 *      Gemini-schema, plus Ollama tags). Providers without a key keep their
 *      existing models. Azure/Bedrock/Copilot have no listable model API and are
 *      skipped.
 *   3. ENRICH pricing + context windows from LiteLLM's public, structured
 *      `model_prices_and_context_window.json` (no scraping, no keys). Models
 *      with no pricing match are kept but reported as unpriced (meter at $0).
 *   4. Emit a candidate catalog + a human-review diff report (added/removed
 *      models, price changes).
 *   5. VALIDATE the candidate through tools/model_sync/publish-builtin-catalog.js so a
 *      broken catalog can never be produced.
 *
 * Usage:
 *   node tools/model_sync/refresh-catalog-data.js [options]
 *     --source <path>       Base catalog (default: config/examples/llm.example.json)
 *     --out <path>          Candidate output (default: dist/llm.json)
 *     --pricing-file <path> Local LiteLLM pricing JSON (offline; skips the download)
 *     --pricing-url <url>   Override the LiteLLM pricing URL
 *     --no-discovery        Skip live provider /models calls (enrich pricing only)
 *     --prune               Drop existing models no longer returned by discovery
 *     --timeout <ms>        Per-request timeout (default: 20000)
 *
 * API keys are read from `${ENUM_VALUE}_API_KEY` env vars (e.g. OPENAI_API_KEY,
 * ANTHROPIC_API_KEY, GROQ_API_KEY). Keys are never printed.
 *
 * Requires Node 18+ (global fetch).
 */

const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const REPO_ROOT = path.resolve(__dirname, "..", "..");
const DEFAULT_SOURCE = path.join(REPO_ROOT, "config/examples/llm.example.json");
const DEFAULT_OUT = path.join(REPO_ROOT, "dist/llm.json");
const PUBLISH_SCRIPT = path.join(__dirname, "publish-builtin-catalog.js");
const DEFAULT_PRICING_URL =
  "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json";

function parseArgs(argv) {
  const args = {
    source: DEFAULT_SOURCE,
    out: DEFAULT_OUT,
    pricingFile: null,
    pricingUrl: DEFAULT_PRICING_URL,
    discovery: true,
    prune: false,
    timeout: 20000,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--no-discovery") args.discovery = false;
    else if (a === "--prune") args.prune = true;
    else if (a === "--source") args.source = path.resolve(argv[++i]);
    else if (a === "--out") args.out = path.resolve(argv[++i]);
    else if (a === "--pricing-file") args.pricingFile = path.resolve(argv[++i]);
    else if (a === "--pricing-url") args.pricingUrl = argv[++i];
    else if (a === "--timeout") args.timeout = parseInt(argv[++i], 10) || 20000;
    else {
      console.error(`Unknown argument: ${a}`);
      process.exit(2);
    }
  }
  return args;
}

const keyEnvFor = (enumValue) =>
  `${enumValue.toUpperCase().replace(/[^A-Z0-9]/g, "_")}_API_KEY`;

const titleCase = (id) =>
  id
    .replace(/[-_/]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (c) => c.toUpperCase());

async function fetchJson(url, { headers = {}, timeout }) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(url, { headers, signal: controller.signal });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status} ${res.statusText}`);
    }
    return await res.json();
  } finally {
    clearTimeout(t);
  }
}

/**
 * Resolve how to list a provider's models from its catalog entry. Returns
 * `{ kind, url, headers }` or `{ kind: "skip", reason }`.
 */
function discoveryPlan(provider, apiKey) {
  const schema = (provider.api_schema || "openai").toLowerCase();
  const enumValue = (provider.enum_value || "").toLowerCase();
  const base = (provider.default_base_url || "").replace(/\/+$/, "");
  const prefix = provider.api_version_prefix || "/v1";

  if (enumValue === "ollama") {
    return { kind: "ollama", url: `${base || "http://localhost:11434"}/api/tags`, headers: {} };
  }
  if (schema === "copilot" || enumValue.includes("azure") || enumValue.includes("bedrock")) {
    return { kind: "skip", reason: "no listable model API for this provider" };
  }
  if (!apiKey) {
    return { kind: "skip", reason: `no ${keyEnvFor(provider.enum_value)} in environment` };
  }
  if (schema === "anthropic") {
    return {
      kind: "anthropic",
      url: `${base}/v1/models`,
      headers: { "x-api-key": apiKey, "anthropic-version": "2023-06-01" },
    };
  }
  if (schema === "gemini") {
    return {
      kind: "gemini",
      url: `${base}/v1beta/models?key=${encodeURIComponent(apiKey)}&pageSize=1000`,
      headers: {},
    };
  }
  // OpenAI-compatible (openai and all the presets).
  return {
    kind: "openai",
    url: `${base}${prefix}/models`,
    headers: { Authorization: `Bearer ${apiKey}` },
  };
}

/** Extract the discovered model id list from a provider's /models response. */
function extractModelIds(kind, body) {
  if (!body) return [];
  if (kind === "gemini") {
    return (body.models || [])
      .filter((m) => (m.supportedGenerationMethods || []).includes("generateContent"))
      .map((m) => String(m.name || "").replace(/^models\//, ""))
      .filter(Boolean);
  }
  if (kind === "ollama") {
    return (body.models || []).map((m) => m.name).filter(Boolean);
  }
  // openai / anthropic share `{ data: [{ id }] }`.
  return (body.data || []).map((m) => m.id).filter(Boolean);
}

/** Build a pricing lookup from the LiteLLM JSON keyed by several id forms. */
function pricingLookup(litellm, provider, modelId) {
  if (!litellm) return null;
  const p = (provider.enum_value || "").toLowerCase();
  const bare = modelId.includes("/") ? modelId.split("/").pop() : modelId;
  const candidates = [modelId, `${p}/${modelId}`, bare, `${p}/${bare}`];
  for (const c of candidates) {
    const entry = litellm[c];
    if (entry && (entry.input_cost_per_token != null || entry.output_cost_per_token != null)) {
      return entry;
    }
  }
  return null;
}

const per1k = (perToken) =>
  perToken == null ? null : Number((perToken * 1000).toPrecision(6));

async function loadPricing(args) {
  if (args.pricingFile) {
    if (!fs.existsSync(args.pricingFile)) {
      console.warn(`⚠ pricing file not found: ${args.pricingFile} — continuing without pricing enrichment`);
      return null;
    }
    try {
      return JSON.parse(fs.readFileSync(args.pricingFile, "utf8"));
    } catch (e) {
      console.warn(`⚠ pricing file is not valid JSON: ${e.message} — continuing without enrichment`);
      return null;
    }
  }
  try {
    console.log(`• Downloading pricing/metadata from ${args.pricingUrl}`);
    return await fetchJson(args.pricingUrl, { timeout: args.timeout });
  } catch (e) {
    console.warn(`⚠ could not download pricing (${e.message}) — continuing without enrichment`);
    return null;
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (!fs.existsSync(args.source)) {
    console.error(`Base catalog not found: ${args.source}`);
    process.exit(2);
  }
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(args.source, "utf8"));
  } catch (e) {
    console.error(`Base catalog is not valid JSON: ${e.message}`);
    process.exit(1);
  }
  if (doc && doc.llm && Array.isArray(doc.llm.providers) && !doc.providers) {
    doc = { providers: doc.llm.providers };
  }
  if (!doc || !Array.isArray(doc.providers)) {
    console.error("Base catalog has no 'providers' array.");
    process.exit(1);
  }

  const litellm = await loadPricing(args);
  const report = [];

  for (const provider of doc.providers) {
    const name = provider.name || provider.enum_value;
    const existing = Array.isArray(provider.models) ? provider.models : [];
    const existingById = new Map(existing.map((m) => [m.value, m]));
    report.push(`\n  ${name} (${provider.enum_value})`);

    // ── 1. Discover live model ids (best-effort per provider) ──────────────
    let discoveredIds = null; // null = discovery not performed
    if (args.discovery) {
      const apiKey = process.env[keyEnvFor(provider.enum_value)];
      const plan = discoveryPlan(provider, apiKey);
      if (plan.kind === "skip") {
        report.push(`      discovery skipped (${plan.reason})`);
      } else {
        try {
          const body = await fetchJson(plan.url, { headers: plan.headers, timeout: args.timeout });
          discoveredIds = extractModelIds(plan.kind, body);
          report.push(`      discovered ${discoveredIds.length} models via ${plan.kind} API`);
        } catch (e) {
          report.push(`      discovery FAILED (${e.message}) — keeping existing models`);
        }
      }
    }

    // ── 2. Build the merged model set (union unless --prune) ───────────────
    const targetIds = new Set(existing.map((m) => m.value));
    const added = [];
    if (discoveredIds) {
      for (const id of discoveredIds) {
        if (!targetIds.has(id)) {
          targetIds.add(id);
          added.push(id);
        }
      }
      if (args.prune) {
        for (const m of existing) {
          if (!discoveredIds.includes(m.value)) targetIds.delete(m.value);
        }
      }
    }

    // ── 3. Enrich pricing + context and preserve curated model fields ──────
    const removed = [];
    let priced = 0;
    const unpriced = [];
    const models = [];
    for (const id of targetIds) {
      const base = existingById.get(id) || { name: titleCase(id), value: id };
      const model = { ...base };
      const pricing = pricingLookup(litellm, provider, id);
      if (pricing) {
        const ci = per1k(pricing.input_cost_per_token);
        const co = per1k(pricing.output_cost_per_token);
        if (ci != null) model.cost_per_1k_input = ci;
        if (co != null) model.cost_per_1k_output = co;
        if (pricing.max_input_tokens != null) model.max_input_tokens = pricing.max_input_tokens;
        if (pricing.max_output_tokens != null) model.max_output_tokens = pricing.max_output_tokens;
        priced++;
      } else if (model.cost_per_1k_input == null && model.cost_per_1k_output == null) {
        unpriced.push(id);
      }
      models.push(model);
    }
    if (args.prune && discoveredIds) {
      for (const m of existing) {
        if (!discoveredIds.includes(m.value)) removed.push(m.value);
      }
    }
    provider.models = models;

    if (added.length) report.push(`      + added: ${added.join(", ")}`);
    if (removed.length) report.push(`      - pruned: ${removed.join(", ")}`);
    report.push(`      priced ${priced}/${models.length}${unpriced.length ? `, unpriced: ${unpriced.join(", ")}` : ""}`);
  }

  // ── 4. Write candidate + report ──────────────────────────────────────────
  const normalized = JSON.stringify({ providers: doc.providers }, null, 2) + "\n";
  fs.mkdirSync(path.dirname(args.out), { recursive: true });
  fs.writeFileSync(args.out, normalized);

  console.log("\n── Refresh report ─────────────────────────────────────────");
  for (const line of report) console.log(line);
  console.log(`\n✔ Wrote candidate catalog → ${path.relative(REPO_ROOT, args.out)}`);
  if (!litellm) {
    console.log("⚠ Pricing was NOT enriched (no LiteLLM data). Review costs before publishing.");
  }

  // ── 5. Validate through the publish gate ─────────────────────────────────
  console.log("\n• Validating candidate…");
  try {
    execFileSync("node", [PUBLISH_SCRIPT, "--check", "--source", args.out], { stdio: "inherit" });
  } catch {
    console.error("\n✖ Candidate catalog failed validation — do NOT publish.");
    process.exit(1);
  }
  console.log(
    "\nReview the diff, then publish the file to the location referenced by `llm_catalog.refresh_url` in agent-stream.json."
  );
}

main().catch((e) => {
  console.error(`Unexpected error: ${e && e.stack ? e.stack : e}`);
  process.exit(1);
});
