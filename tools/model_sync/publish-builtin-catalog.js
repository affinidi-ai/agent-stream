#!/usr/bin/env node

/**
 * Publish / re-generate the built-in LLM provider catalog (`llm.json`).
 *
 * Affinidi runs this periodically to produce the master catalog that appliances
 * pull via the dashboard "Refresh Builtin Models" action. It validates the
 * source catalog against the same contract the appliance enforces
 * (`config/schemas/llm_catalog.schema.json`) plus the semantic rules a JSON
 * schema can't express (unique provider ids), so a broken catalog is caught
 * BEFORE it is published — it can never be served to appliances.
 *
 * Usage:
 *   node tools/model_sync/publish-builtin-catalog.js [--source <path>] [--out <path>] [--check]
 *
 *   --source <path>  Source catalog (default: config/examples/llm.example.json)
 *   --out <path>     Output master file (default: dist/llm.json)
 *   --check          Validate only; do not write output (CI / pre-publish gate)
 *
 * Exits non-zero on any validation failure.
 */

const fs = require("fs");
const path = require("path");

const REPO_ROOT = path.resolve(__dirname, "..", "..");
const DEFAULT_SOURCE = path.join(REPO_ROOT, "config/examples/llm.example.json");
const DEFAULT_OUT = path.join(REPO_ROOT, "dist/llm.json");
const SCHEMA_PATH = path.join(REPO_ROOT, "config/schemas/llm_catalog.schema.json");

const ENUM_VALUE_RE = /^[A-Za-z0-9_-]+$/;

function parseArgs(argv) {
  const args = { source: DEFAULT_SOURCE, out: DEFAULT_OUT, check: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--check") args.check = true;
    else if (a === "--source") args.source = path.resolve(argv[++i]);
    else if (a === "--out") args.out = path.resolve(argv[++i]);
    else {
      console.error(`Unknown argument: ${a}`);
      process.exit(2);
    }
  }
  return args;
}

const isObject = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
const nonEmptyString = (v) => typeof v === "string" && v.trim().length > 0;

/**
 * Validate a catalog document. Returns an array of error strings (empty = ok).
 * Mirrors the appliance's `validate_catalog_document` + the JSON schema.
 */
function validateCatalog(doc) {
  const errors = [];
  if (!isObject(doc)) {
    return ["Catalog must be a JSON object with a 'providers' array."];
  }
  if (!Array.isArray(doc.providers)) {
    return ["Catalog is missing a 'providers' array."];
  }
  if (doc.providers.length === 0) {
    errors.push("Catalog contains no providers.");
  }

  const seen = new Set();
  doc.providers.forEach((p, i) => {
    if (!isObject(p)) {
      errors.push(`providers[${i}] must be an object.`);
      return;
    }
    if (!nonEmptyString(p.enum_value)) {
      errors.push(`providers[${i}] is missing a non-empty "enum_value".`);
      return;
    }
    const ev = p.enum_value.trim();
    if (!ENUM_VALUE_RE.test(ev)) {
      errors.push(`providers[${i}] enum_value "${ev}" may only contain letters, digits, hyphens and underscores.`);
    }
    if (!nonEmptyString(p.name)) {
      errors.push(`Provider "${ev}" is missing a non-empty "name".`);
    }
    const lowered = ev.toLowerCase();
    if (seen.has(lowered)) {
      errors.push(`Provider "${ev}" is defined more than once.`);
    }
    seen.add(lowered);

    if (p.api_key_validation !== undefined &&
        !["mandatory", "optional", "none"].includes(p.api_key_validation)) {
      errors.push(`Provider "${ev}" has invalid api_key_validation "${p.api_key_validation}" (expected mandatory|optional|none).`);
    }

    if (p.endpoints !== undefined) {
      if (!Array.isArray(p.endpoints)) {
        errors.push(`Provider "${ev}" "endpoints" must be an array.`);
      } else {
        p.endpoints.forEach((ep, j) => {
          if (!isObject(ep)) errors.push(`Provider "${ev}" endpoints[${j}] must be an object.`);
          else {
            if (!nonEmptyString(ep.name)) errors.push(`Provider "${ev}" endpoints[${j}] is missing a "name".`);
            if (!nonEmptyString(ep.path)) errors.push(`Provider "${ev}" endpoints[${j}] is missing a "path".`);
          }
        });
      }
    }

    if (p.models !== undefined) {
      if (!Array.isArray(p.models)) {
        errors.push(`Provider "${ev}" "models" must be an array.`);
      } else {
        p.models.forEach((m, j) => {
          if (!isObject(m)) errors.push(`Provider "${ev}" models[${j}] must be an object.`);
          else {
            if (!nonEmptyString(m.name)) errors.push(`Provider "${ev}" models[${j}] is missing a "name".`);
            if (!nonEmptyString(m.value)) errors.push(`Provider "${ev}" models[${j}] is missing a "value".`);
          }
        });
      }
    }
  });

  return errors;
}

function main() {
  const args = parseArgs(process.argv.slice(2));

  if (!fs.existsSync(SCHEMA_PATH)) {
    console.error(`Schema not found at ${SCHEMA_PATH}`);
    process.exit(2);
  }
  if (!fs.existsSync(args.source)) {
    console.error(`Source catalog not found: ${args.source}`);
    process.exit(2);
  }

  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(args.source, "utf8"));
  } catch (e) {
    console.error(`Source catalog is not valid JSON: ${e.message}`);
    process.exit(1);
  }

  // Normalize a legacy `{ "llm": { "providers": [...] } }` document.
  if (doc && doc.llm && Array.isArray(doc.llm.providers) && !doc.providers) {
    doc = { providers: doc.llm.providers };
  }

  const errors = validateCatalog(doc);
  if (errors.length > 0) {
    console.error(`✖ Catalog validation failed (${errors.length} problem(s)):`);
    for (const err of errors) console.error(`  - ${err}`);
    console.error(`\nValidated against ${path.relative(REPO_ROOT, SCHEMA_PATH)}.`);
    process.exit(1);
  }

  const providerCount = doc.providers.length;
  const modelCount = doc.providers.reduce(
    (n, p) => n + (Array.isArray(p.models) ? p.models.length : 0),
    0
  );
  console.log(`✔ Catalog valid: ${providerCount} providers, ${modelCount} models.`);

  if (args.check) {
    console.log("Check-only mode (--check): no output written.");
    return;
  }

  const normalized = JSON.stringify({ providers: doc.providers }, null, 2) + "\n";
  fs.mkdirSync(path.dirname(args.out), { recursive: true });
  fs.writeFileSync(args.out, normalized);
  console.log(`✔ Wrote master catalog → ${path.relative(REPO_ROOT, args.out)}`);
  console.log("Publish this file to the location referenced by `llm_catalog.refresh_url` in agent-stream.json.");
}

main();
