# Model Sync — built-in LLM catalog tooling

Tools Affinidi uses to (re)generate and publish the **master built-in LLM
catalog** (`llm.json`) that appliances pull via the dashboard **Models → Refresh
Builtin Models** button.

Both scripts are plain Node (**Node 18+**, for global `fetch`), have **no
dependencies**, and validate against the shared schema
`config/schemas/llm_catalog.schema.json` — the same contract the appliance
enforces, so a catalog that would break appliances is caught before it is
published.

| Script | Purpose |
| ------ | ------- |
| `refresh-catalog-data.js` | Rebuild catalog **data** — visit each provider, discover models, enrich pricing/context, emit a candidate + review diff. |
| `publish-builtin-catalog.js` | **Validate + normalize** a catalog into the publishable master file (also usable as a pre-publish check). |

The two are coupled: `refresh-catalog-data.js` runs `publish-builtin-catalog.js`
as its final validation step, so keep them in the same folder.

---

## 1. Refresh the catalog data

Deterministic, review-first pipeline (intentionally **not** an LLM agent —
pricing feeds cost accounting, so it uses authoritative sources and flags
anything it can't price for human review):

1. Loads a curated base catalog (default `config/examples/llm.example.json`).
   Curated fields — `endpoints`, `icon`, `description`, `hero`,
   `request_profile`, `api_key_validation` — are always preserved.
2. **Discovers** live model ids from each provider's own `/models` API
   (OpenAI-, Anthropic-, and Gemini-schema, plus Ollama tags). Providers with no
   API key keep their existing models. Azure / Bedrock / Copilot have no listable
   model API and are skipped.
3. **Enriches** pricing + context windows from LiteLLM's public
   `model_prices_and_context_window.json` (per-token → per-1k). Models with no
   pricing match are kept but reported as unpriced (they meter at $0).
4. Writes a candidate catalog + prints a per-provider diff report.
5. Validates the candidate through `publish-builtin-catalog.js --check`.

### Run it

```bash
# From the repo root. Discovers models for every provider whose API key is in
# the environment, enriches pricing from LiteLLM, writes dist/llm.json.
node tools/model_sync/refresh-catalog-data.js

# Enrich pricing only, no live provider calls (no keys needed):
node tools/model_sync/refresh-catalog-data.js --no-discovery

# Use a local LiteLLM pricing file (offline / air-gapped):
node tools/model_sync/refresh-catalog-data.js --pricing-file ./model_prices.json
```

### API keys (for model discovery)

Discovery reads each provider's key from an environment variable named
`${ENUM_VALUE}_API_KEY` (the provider's `enum_value`, upper-cased, non-alnum → `_`):

```bash
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
export GROQ_API_KEY=gsk_...
export GEMINI_API_KEY=...
node tools/model_sync/refresh-catalog-data.js
```

Providers without a key are simply skipped (their existing models are kept).
Keys are only used for the `/models` request and are never written or logged.

### Flags

| Flag | Default | Meaning |
| ---- | ------- | ------- |
| `--source <path>` | `config/examples/llm.example.json` | Curated base catalog to refresh. |
| `--out <path>` | `dist/llm.json` | Candidate output file. |
| `--pricing-file <path>` | — | Local LiteLLM pricing JSON (skips the download). |
| `--pricing-url <url>` | LiteLLM `main` | Override the pricing source URL. |
| `--no-discovery` | off | Skip live `/models` calls; enrich pricing only. |
| `--prune` | off | Drop existing models no longer returned by discovery (default keeps the union). |
| `--timeout <ms>` | `20000` | Per-request timeout. |

**Always review the diff report and the unpriced list before publishing** —
pricing drives billing.

---

## 2. Validate / publish the master catalog

```bash
# Validate only (pre-publish check). Exits non-zero on any problem.
node tools/model_sync/publish-builtin-catalog.js --check

# Validate and write the normalized master file.
node tools/model_sync/publish-builtin-catalog.js --source dist/llm.json --out dist/llm.json
```

| Flag | Default | Meaning |
| ---- | ------- | ------- |
| `--source <path>` | `config/examples/llm.example.json` | Catalog to validate. |
| `--out <path>` | `dist/llm.json` | Normalized output (ignored with `--check`). |
| `--check` | off | Validate only; write nothing. |

Validation enforces the JSON schema **plus** the semantic rules a schema can't
express: at least one provider, each provider has a unique `enum_value` and a
`name`, each model has a `name` + `value`, each endpoint a `name` + `path`.

---

## 3. Publish + how appliances consume it

1. Publish the resulting `llm.json` to a URL (e.g. a CDN / object store).
2. Point each appliance at it by setting `llm_catalog.refresh_url` in
   `agent-stream.json`:

   ```json
   "llm_catalog": { "refresh_url": "https://models.example.com/llm.json" }
   ```

3. On the appliance's **Models** page, click **Refresh Builtin Models**. The
   backend downloads the file, re-validates it against the same schema, moves the
   current `llm.json` aside to `llm.json.bak`, installs the new one, and
   hot-reloads — with automatic rollback if anything fails. (The button is hidden
   when `refresh_url` is unset.)

---

## Typical workflow

```bash
export OPENAI_API_KEY=... ANTHROPIC_API_KEY=... GROQ_API_KEY=...

# 1. Rebuild + validate the data.
node tools/model_sync/refresh-catalog-data.js

# 2. Review dist/llm.json and the printed diff (added / pruned / unpriced).

# 3. Publish dist/llm.json to the location referenced by llm_catalog.refresh_url.
```
