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
 * Appliances read the manifest at `llm_catalog.refresh_url`, not the catalog
 * itself. With `--catalogue-url`, `--sequence` and `--version`, the script also
 * writes that manifest, carrying the SHA-256 and size of the written catalog.
 *
 * Usage:
 *   node tools/model_sync/publish-builtin-catalog.js [--source <path>] [--out <path>] [--check]
 *     [--catalogue-url <url> --sequence <n> --version <v> [--version-id <id>] [--manifest-out <path>]]
 *
 *   --source <path>        Source catalog (default: config/examples/llm.example.json)
 *   --out <path>           Output master file (default: dist/llm.json)
 *   --check                Validate only; do not write output (CI / pre-publish gate)
 *   --catalogue-url <url>  https URL the catalog will be served from, on the refresh_url host
 *   --sequence <n>         publication_sequence, higher than the last published one
 *   --version <v>          Release the catalog comes from, shown to administrators
 *   --version-id <id>      Unique publication id (default: <version>:<sequence>)
 *   --manifest-out <path>  Manifest output (default: current.json next to --out)
 *
 * Exits non-zero on any validation failure.
 */

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const REPO_ROOT = path.resolve(__dirname, "..", "..");
const DEFAULT_SOURCE = path.join(REPO_ROOT, "config/examples/llm.example.json");
const DEFAULT_OUT = path.join(REPO_ROOT, "dist/llm.json");
const SCHEMA_PATH = path.join(REPO_ROOT, "config/schemas/llm_catalog.schema.json");

const ENUM_VALUE_RE = /^[A-Za-z0-9_-]+$/;
const MANIFEST_SCHEMA_VERSION = 1;
const MAX_CATALOG_BYTES = 8 * 1024 * 1024;
const MAX_FIRST_SEQUENCE = 2 ** 32;

function parseArgs(argv) {
  const args = { source: DEFAULT_SOURCE, out: DEFAULT_OUT, check: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--check") args.check = true;
    else if (a === "--source") args.source = path.resolve(argv[++i]);
    else if (a === "--out") args.out = path.resolve(argv[++i]);
    else if (a === "--catalogue-url") args.catalogueUrl = argv[++i];
    else if (a === "--sequence") args.sequence = argv[++i];
    else if (a === "--version") args.version = argv[++i];
    else if (a === "--version-id") args.versionId = argv[++i];
    else if (a === "--manifest-out") args.manifestOut = path.resolve(argv[++i]);
    else {
      console.error(`Unknown argument: ${a}`);
      process.exit(2);
    }
  }
  return args;
}

/**
 * Check the manifest arguments. Returns an array of error strings (empty = ok,
 * or no manifest requested). Mirrors the appliance's `validate_manifest`.
 */
function validateManifestArgs(args) {
  const requested = ["catalogueUrl", "sequence", "version", "versionId", "manifestOut"].some(
    (k) => args[k] !== undefined
  );
  if (!requested) return [];
  const errors = [];
  let url;
  try {
    url = new URL(args.catalogueUrl);
  } catch {
    errors.push("--catalogue-url must be a valid URL.");
  }
  if (url && url.protocol !== "https:") errors.push("--catalogue-url must be https.");
  if (url && (url.username || url.password)) errors.push("--catalogue-url must not carry credentials.");
  if (!/^[1-9][0-9]*$/.test(args.sequence || "") || !Number.isSafeInteger(Number(args.sequence))) {
    errors.push("--sequence must be a positive integer.");
  } else if (Number(args.sequence) > MAX_FIRST_SEQUENCE) {
    console.warn(`⚠ --sequence is above 2^32; an appliance with no accepted publication refuses it.`);
  }
  if (!nonEmptyString(args.version)) errors.push("--version must not be empty.");
  if (args.versionId !== undefined && !nonEmptyString(args.versionId)) {
    errors.push("--version-id must not be empty.");
  }
  return errors;
}

/** The manifest describing `catalogBytes` as published at `args.catalogueUrl`. */
function buildManifest(args, catalogBytes) {
  return {
    schema_version: MANIFEST_SCHEMA_VERSION,
    publication_sequence: Number(args.sequence),
    version_id: args.versionId || `${args.version}:${args.sequence}`,
    version: args.version,
    catalogue_url: args.catalogueUrl,
    sha256: crypto.createHash("sha256").update(catalogBytes).digest("hex"),
    size_bytes: catalogBytes.length,
    published_at: new Date().toISOString(),
  };
}

const isObject = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
const nonEmptyString = (v) => typeof v === "string" && v.trim().length > 0;
const isRelativePath = (p) => p.startsWith("/") && !p.startsWith("//") && !p.startsWith("/\\");

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
            else if (!isRelativePath(ep.path)) {
              errors.push(`Provider "${ev}" endpoints[${j}] path must start with a single '/'.`);
            }
          }
        });
      }
    }

    if (p.models === undefined) {
      errors.push(`Provider "${ev}" is missing a "models" array.`);
    } else {
      if (!Array.isArray(p.models)) {
        errors.push(`Provider "${ev}" "models" must be an array.`);
      } else {
        if (p.models.length === 0) {
          console.warn(`⚠ Provider "${ev}" lists no models; an appliance that does not have it yet refuses the refresh.`);
        }
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

  const manifestErrors = validateManifestArgs(args);
  if (manifestErrors.length > 0) {
    for (const err of manifestErrors) console.error(`✖ ${err}`);
    process.exit(2);
  }

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

  const normalized = Buffer.from(JSON.stringify({ providers: doc.providers }, null, 2) + "\n");
  if (normalized.length > MAX_CATALOG_BYTES) {
    console.error(`✖ Catalog is ${normalized.length} bytes; appliances accept at most ${MAX_CATALOG_BYTES}.`);
    process.exit(1);
  }
  fs.mkdirSync(path.dirname(args.out), { recursive: true });
  fs.writeFileSync(args.out, normalized);
  console.log(`✔ Wrote master catalog → ${path.relative(REPO_ROOT, args.out)}`);

  if (args.catalogueUrl === undefined) {
    console.log(
      "No manifest written. Rerun with --catalogue-url, --sequence and --version to write the manifest " +
        "appliances read at `llm_catalog.refresh_url`."
    );
    return;
  }
  const manifestOut = args.manifestOut || path.join(path.dirname(args.out), "current.json");
  fs.writeFileSync(manifestOut, JSON.stringify(buildManifest(args, normalized), null, 2) + "\n");
  console.log(`✔ Wrote manifest → ${path.relative(REPO_ROOT, manifestOut)}`);
  console.log(
    `Upload ${path.relative(REPO_ROOT, args.out)} to ${args.catalogueUrl} first, then the manifest to ` +
      "`llm_catalog.refresh_url`, on the same host and port."
  );
}

main();
