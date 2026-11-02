# agent-stream end-to-end testkit

A self-contained, Docker-based harness that exercises the **whole appliance**
(surfaces, source auth, teams/members, cap enforcement, per-stage metering and
usage telemetry) **without caring about a real LLM**. A mock OpenAI-protocol
server stands in for the model; the testkit knows the exact token usage of every
upstream call it provokes and reconciles the appliance's recorded statistics
against an independently computed ground-truth ledger.

> [!CAUTION]
> **Debug-only / never production.** The runner authenticates to the admin API
> through the appliance's test-auth bootstrap endpoint
> (`POST /internal/test-support/auth/login`). That endpoint is compiled in
> **only** under `debug_assertions` and is mounted **only** in `passkey` auth
> mode, and even then it stays disabled unless **both** `AS_TEST_MODE=true` and
> a non-empty `AS_TEST_TOKEN` are set (it fails closed otherwise). The testkit
> therefore builds and runs a **DEBUG** `agent-stream` binary with those env vars
> set. **Never** run a release build with `AS_TEST_MODE`, and never ship this
> image. A release binary physically cannot expose the endpoint.

## What it does

1. **Mock LLM** (`mock-llm/server.js`) — an OpenAI `/v1/chat/completions` server
   with random latency (a realistic 400-2500ms think time per call, tunable via
   `MOCK_LLM_MIN_MS` / `MOCK_LLM_MAX_MS`) and a **variable `usage` block** (prompt
   tokens derived
   from the request size, completion tokens random). Each request carries a
   unique `[[tkid:<nonce>]]` marker in its prompt, which the mock records against
   every upstream call it serves for that execution (main LLM **and** judge **and**
   each juror). To make this work for **jurors** — which review the *serialized
   main response*, not the user prompt — the mock **echoes the nonce back into
   every response's content** (and the `[[reject]]` trigger into a `BLOCKED`
   response). That way the nonce reaches juror upstream calls (so their tokens are
   counted) and a triggered response carries the reject signal forward so a
   moderated jury rejects. It returns `BLOCKED` content when the prompt carries
   `[[reject]]` (otherwise `APPROVED`), so moderated surfaces can be made to reject
   deterministically. The control plane exposes
   `GET /__mock/by-nonce?nonce=` (the per-execution calls, concurrency-safe) plus
   the legacy `/__mock/calls`, `/__mock/count`, `/__mock/reset`.
2. **Appliance** (`as1`) — a fresh, isolated `agent-stream` whose catalog carries
   a standalone **Mock LLM** provider (`config/managed.llm.json`, `enum_value: "mock_llm"`,
   `api_schema: "openai"`) exposing `mock-small` / `mock-large` with fixed prices.
   Surfaces address it with `provider_type: "mock_llm"` (model in `model`, base URL
   in `base_url`). It uses a **distinct** enum — not the reserved `custom`, which
   the dashboard treats as the generic manual-endpoint provider (no catalog
   models/endpoints), so a surface built on `custom` renders with a blank
   provider/model and empty endpoints.
3. **Surfaces** — a catalog of varying complexity loaded from
   `config/surfaces/*.json`: plain LLM, LLM + judge, LLM + jury, and
   LLM + judge + jury, across three caller-identity flavors (email header, RS256
   JWT, and ApiKey). Most judges and juries are wired to **always approve** while
   still calling the mock, so every stage meters usage without ever blocking on
   content. A few **moderated** surfaces (`*-moderated.json`) instead reject the
   mock's `BLOCKED` output, so the rejection drill can exercise judge/jury
   `403`s. Moderated surfaces name their judge rule and jurors after canonical
   rejection-taxonomy category ids (e.g. `prompt_injection`, `toxicity`, `hate`),
   so the appliance classifies the blocks into real dashboard categories instead
   of `uncategorized` (override per template with `judgeCategory` /
   `juryCategories`). Each surface is also stamped with the appliance's first
   host listener as its `listen_address`, so its access point renders fully
   configured in the dashboard (no "unconfigured" marching ants). Each file may
   be authored in either of two formats (detected per
   file) — see **Authoring surfaces** below. Every surface the runner creates is
   tagged `test_surface: true`; at the **start** of setup the runner calls the
   debug-only `POST /v1/pipes/test-surfaces/delete` to clear any test surfaces
   left behind by a previous (e.g. crashed) run. Before the catalog, the runner
   creates the Surface the run's managed API keys are issued for
   (`TESTKIT_AGENT_ID`, never called); every ApiKey surface names it as its
   `agent_id`. Every JWT surface accepts the audience the testkit's tokens carry,
   `https://testkit.local/agent-stream`.
4. **Population** — `NUM_TEAMS` × `MEMBERS_PER_TEAM` members (default 5 × 10),
   identified by a **mix** of ApiKey / email / JWT, invented per run. Roughly a
   third of members and teams get a random tiny cap. On top of that, when the
   **cap drill** is enabled the runner mints **deterministic** fixtures: an
   uncapped control member, a token-capped member (`monthly_token_cap: 50`), a
   budget-capped member (`monthly_budget_usd: 0.0005`), and a tiny-budget team
   (`monthly_budget_usd: 0.0008`) with two uncapped members — so cap enforcement
   is exercised by construction rather than by luck.
5. **Rounds (cap drill → enrolment → rejection → load → coverage → policy).** A *round* drives up to
   six phases against the population, recording the local ground truth as it
   goes. Correlation is by **nonce**, not serial call-count delta: every request
   embeds a unique `[[tkid:<nonce>]]` marker, and after a `200` the runner reads
   `GET /__mock/by-nonce` to get exactly that execution's upstream calls and
   tokens — accurate under heavy concurrency.
   - **Cap drill** (serial, deterministic) drives each tiny-capped fixture past
     its quota and asserts the appliance enforces it (`429`), while the uncapped
     control is never blocked.
   - **Enrolment drill** exercises **member auto-provisioning** across all three
     **verified** identity kinds — **JWT claims**, **API key**, and **mTLS client
     certificate**. The testkit is its own tiny identity provider: it mints an
     RS256 JWT (with `email`/`name`/`groups`/`tid` claims) against a self-published
     static-JWK strategy, an API key, and — via a throwaway `openssl` CA — a client
     certificate presented through the forwarded-client-cert header. It sets the
     appliance provisioning config (`PUT /v1/member-provisioning`), previews the
     rules (`POST …/preview`), then presents each **novel** identity at an
     auto-provisioning surface and asserts a member is minted on first sight with
     the expected identifiers and team memberships (a shared "enrolled" team, an
     "engineering" team from a JWT group, and a per-tenant team created on demand
     via `ensure_team`). It then drives several **priced** LLM calls through each
     enrolled member so their cost/tokens reconcile exactly like the rest of the
     population, asserts idempotency (a repeat identity mints no duplicate), and —
     once, in round 1 — asserts `max_auto_provisioned_members` refuses a further
     mint. **mTLS is mandatory when the drill runs:** if it can't be exercised
     (no `openssl`, or the appliance doesn't trust the runner as a forwarded-cert
     proxy) the run **fails** with a diagnostic — set `ENROLMENT_MTLS=optional`
     (or `-enrolment-mtls-optional`) to downgrade that to a logged skip.
   - **Rejection drill** drives `[[reject]]` prompts at **moderated** judge/jury
     surfaces and asserts the appliance rejects them (`403`) and reports the
     rejection telemetry under the right stage. A guaranteed-uncapped caller is
     minted if the random population lacks one.
   - **Load** drives concurrent general traffic from **uncapped** members only
     (so token/cost reconciliation stays exact), paced by the
     concurrency / RPS / duration knobs.
   - **Coverage sweep** drives a few calls through **every** (non-drill) callable
     member — not just the uncapped load members — so no member is left with zero
     usage. It runs as several time-spaced **waves** (`COVERAGE_WAVES`, spaced
     `COVERAGE_WAVE_GAP` seconds apart, which must exceed the finest 30s
     telemetry bucket) so each member's calls land in **distinct buckets**,
     producing a real multi-point usage time series instead of a single point
     that line/area charts cannot draw. It runs **last** so any quota pollution
     cannot disturb the cap-drill or load phases; capped members that hit their
     quota mid-sweep return `429` (recorded as `blocked`, expected — never an
     anomaly), so only successes accrue and reconciliation stays exact. Half of
     coverage calls request **structured output** (`response_format: json_schema`,
     which the mock answers with a JSON object) so the drift **schema-validity**
     dimension gets samples. Disable with `COVERAGE=false` to keep CI rounds fast.
   - **Policy drill** exercises the **OPA policy engine** end to end. It creates
     reusable `llm.policy` definitions plus three policy-bound surfaces, then
     drives a dedicated uncapped caller to assert: a header-gated policy
     **allows** with the pass header and **denies** (`403`) without it; a
     two-policy surface is **deny-overridden** (one deny blocks even when the
     other allows); deleting a referenced definition **fail-closes** the surface
     live (`200` → `403`); an appliance-wide **global** deny blocks every LLM
     surface while **monitor-only** records without blocking; and the **dry-run**
     (`…/simulate`, incl. a draft body + a bounds rejection), **blast-radius**
     (`…/impact`), and **version-history** (`…/versions`) management APIs behave.
     A policy `403` accrues no usage and no rejection telemetry (only a
     governance record), so the drill reconciles exactly; the global-deny window
     is always restored, and the phase runs **last** so it can never affect
     another phase. Disable with `POLICY_DRILL=false` (or `-no-policy-drill`).
   - **Drift eval sweep** replays every drift-enabled surface's captured
     **indicative surface data** (the real prompt/response pairs recorded
     automatically during the load/coverage traffic) via
     `POST /v1/drift/eval/run`, filling the *replay* drift dimensions —
     **Quality** (answer-stability rate) and **Semantic distance** (against the
     mock's `/v1/embeddings`), plus the re-measured latency / length / refusal /
     safety / schema. It runs in several **waves** (`DRIFT_EVAL_WAVES`, spaced
     `COVERAGE_WAVE_GAP` apart) so each dimension shows a **multi-point line**
     rather than a single point. Replays go through the surface executor under
     the internal drift-runner identity, which **bypasses the request handler**,
     so they record no usage telemetry and never disturb reconciliation. (The
     production-sampled dimensions fill automatically from the load/coverage
     traffic as it is captured.) Disable with `DRIFT_EVAL=false`.
6. **Local tally** — every successful call is recorded in a ledger keyed by the
   **same** telemetry series keys the appliance uses (`surfaces:all`,
   `surface:{id}`, `surface:{id}:stage:{llm|judge|jury}`, `member:{id}`,
   `member:{id}:surface:{id}`, `team:{id}`). Every rejection is recorded into a
   separate rejection ledger (`rejection:all`, `rejection:surface:{id}`,
   `rejection:surface:{id}:stage:{judge|jury}`, `rejection:member:{id}`,
   `rejection:team:{id}`) — rejections record **only** rejection telemetry, never
   usage, matching the appliance. A Judge/Jury `403` is recorded from **any**
   phase, not just the rejection drill: a fail-closed juror error (e.g. an
   upstream timeout under concurrent load) rejects otherwise-benign traffic and
   the appliance records it, so the ledger mirrors those too or the
   appliance-wide / per-team rejection totals would over-count at reconciliation.
7. **Stop & compare** — after a short settle, the runner queries
   `GET /v1/telemetry/series` for every tracked key over the run window and
   compares the appliance's window sums to the local ledger: **tokens and request
   counts exact, cost within tolerance**. It also checks per-surface stage
   consistency (`stage:llm + stage:judge + stage:jury == surface total`, with
   judge/jury buckets non-zero where configured), reconciles every rejection
   scope against `GET /v1/telemetry/rejections`, verifies each drift-monitored
   surface recorded LLM-drift samples (`GET /v1/drift/series`) after its traffic,
   and fails if any cap drill did not enforce or any policy check mismatched.
8. **Review & repeat (interactive).** Reconciliation runs **before** any
   teardown and the report is written to `results/`. In interactive mode the
   runner then prompts **run again** (cumulative — the next round adds to the
   same population and ledger, and reconciliation spans the whole run), **clean
   up & exit**, or **quit** (leave the population in place). In non-interactive
   mode it runs exactly one round, then tears down (unless `TEARDOWN=false`). The
   appliance-wide `surfaces:all` aggregate is never deleted, so statistics
   survive teardown.

While a round is working, every phase shows a **live progress line** (spinner,
running counts, throughput, and a countdown during the telemetry-settle and
inter-wave gaps) so it is obvious the run is moving rather than stuck; when the
output is piped (CI / docker), the same progress degrades to a throttled plain
log line. On a TTY you can **press `q` during a round to wrap up** — the runner
stops dispatching new work, lets in-flight calls drain, then finishes the round
normally (reconcile + report) and returns to the interactive prompt. Telemetry
is retained either way.

## Running

The testkit has two modes. **External is the default** so you can watch the
appliance UX while the testkit drives it.

### External (default) — drive an appliance you run yourself

You start the appliance (e.g. a debug build with `make run-debug tk=1`) and the testkit runs only the
mock LLM + the runner on the host, pointing at it. The appliance URL is
**required** via `-host` — there is no default, so it is never ambiguous which
appliance is being driven:

```bash
cd tests/appliance
./run.sh -host http://localhost:8280            # external is the default mode
./run.sh external -host http://localhost:8280   # same, explicit
```

Flags: `-load` (overall intensity: `small` | `medium` | `large`);
`-concurrency`, `-rps`, `-duration`, `-requests` (load shaping);
`-no-cap-drill`, `-no-rejection-drill`, `-no-policy-drill`, `-no-enrolment-drill` (skip a drill
phase); `-enrolment-mtls-optional` (downgrade the mandatory mTLS enrolment check
to a skip on appliances not configured to trust the runner as a forwarded-cert
proxy); `-no-interactive` (one round then teardown). Each accepts `-flag val` or
`-flag=val`. Every flag also has an env equivalent — see **Configuration**.

> **External mode + mTLS enrolment.** The mTLS enrolment sub-drill presents the
> client cert through the forwarded-client-cert header, so the appliance must
> trust the runner as a forwarded proxy. The **managed** appliance config does
> this out of the box. For an **external** appliance you drive yourself, add this
> to its bootstrap config (then restart — it is startup-only):
>
> ```toml
> [tls.client_auth]
> trusted_proxies = ["127.0.0.1/32"]   # or your runner's source CIDR
>
> [tls.client_auth.forwarded_header]
> header_name = "x-forwarded-client-cert"
> format = "url_encoded_pem"
> ```
>
> Without it, the mTLS sub-drill fails the run (by design) unless you pass
> `-enrolment-mtls-optional`. JWT-claims and API-key enrolment need no extra
> config.

#### Load levels (`-load`)

`-load` picks a coherent set of population/traffic defaults in one switch.
Individual flags/env (e.g. `-concurrency`, `-requests`) still override the level
they belong to, so you can pick a level and tune one knob.

| Level | Population | Load calls / round | Concurrency | Coverage calls/member | Intent |
| ----- | --------- | ------------------ | ----------- | --------------------- | ------ |
| `small` | 2 teams × 3 = 6 members | 30 | 2 | 1 | Lightweight & short-lived — a quick smoke / dashboard sanity check. |
| `medium` *(default)* | 5 teams × 10 = 50 members | 300 | 5 | 1 | The historical behaviour — omitting `-load` changes nothing. |
| `large` | 8 teams × 15 = 120 members | 5000 | 250 | 4 | **Hammer** the appliance — deep concurrency so many connections hit the **same** surface at once, repeated calls from the **same** member, maximum sustained throughput. |

```bash
./run.sh -host http://localhost:8280 -load small    # fast smoke
./run.sh -host http://localhost:8280 -load large    # stress
```


#### Setups (recipes)

All of these target a host appliance at `http://localhost:8280`; swap the
`-host` URL for your own. `-duration` is in **seconds** and bounds the *load
phase* of each round (the cap + rejection drills run first and are short), so in
interactive mode a round = short drills + the timed load phase + the coverage
sweep, then the run-again/clean-up prompt. The coverage sweep adds roughly
`COVERAGE_WAVES × COVERAGE_WAVE_GAP` seconds of wall-clock per round (defaults
≈ `4 × 35s`); set `COVERAGE=false` to skip it when you want fast rounds.

| Setup | Command | What you get |
| ----- | ------- | ------------ |
| **Smoke (default)** | `./run.sh -host http://localhost:8280` | One light round (300 load calls, serial), interactive prompt after. |
| **Quick small smoke** | `./run.sh -host http://localhost:8280 -load small -no-interactive` | Tiny population, ~30 calls, one round, auto-teardown — the fastest end-to-end check. |
| **Hammer (large)** | `./run.sh -host http://localhost:8280 -load large` | Big population, 5000 calls at concurrency 250 — many connections to the same surface, repeated calls per member, max throughput. |
| **Watch it work** | `./run.sh -host http://localhost:8280 -concurrency 8 -rps 30` | Moderate concurrent traffic you can watch in the dashboard; interactive. |
| **Heavy 30-min soak (interactive)** | `NUM_TEAMS=10 MEMBERS_PER_TEAM=20 ./run.sh -host http://localhost:8280 -concurrency 32 -rps 100 -duration 1800` | 200 members; each round drives **30 minutes** of concurrent load (~100 req/s), then prompts you to run another round (cumulative) or clean up. Leave it running and watch the live stats. |
| **Max pressure** | `NUM_TEAMS=20 MEMBERS_PER_TEAM=25 ./run.sh -host http://localhost:8280 -concurrency 64 -rps 0 -duration 1800` | `-rps 0` = dispatch as fast as 64 workers allow (unthrottled), for 30 min. Stress test. |
| **Fixed big run, keep population** | `NUM_REQUESTS=2000 SEED=42 TEARDOWN=false ./run.sh -host http://localhost:8280` | Reproducible 2000-call round, population left in place for inspection. |
| **Load only (no drills)** | `./run.sh -host http://localhost:8280 -concurrency 16 -rps 50 -duration 300 -no-cap-drill -no-rejection-drill` | Pure load, 5 min — skips the cap/rejection drills. |
| **CI / one-shot** | `./run.sh -host http://localhost:8280 -requests 500 -no-interactive` | Single round, auto-teardown, exits with pass/fail code. |
| **Self-contained** | `./run.sh managed` | Throwaway appliance + mock + runner in docker-compose; no `-host`. |

> **The heavy 30-minute interactive run** — copy/paste this to drive a sustained
> ~100 req/s for half an hour while you watch the appliance dashboard, then
> decide round-by-round whether to keep going:
>
> ```bash
> cd tests/appliance
> NUM_TEAMS=10 MEMBERS_PER_TEAM=20 \
>   ./run.sh -host http://localhost:8280 -concurrency 32 -rps 100 -duration 1800
> ```
>
> Interactivity auto-enables on a TTY; if you launch it from a pipe/script and
> still want the prompt, add `INTERACTIVE=true`. To go even harder, raise
> `-concurrency` and set `-rps 0` (unthrottled). Use `[r]` at the prompt to add
> another 30-minute round onto the same cumulative ledger.

When run from a terminal the runner is **interactive**: after each round it
prints the cumulative summary and prompts **[r]** run another round (adds to the
same population/ledger), **[c]** clean up & exit, or **[q]** quit and leave the
population in place. Piped/CI invocations auto-detect non-TTY and run a single
round.

Requirements: local Node (for the mock + runner) and a running appliance that:

- is reachable at the `-host` URL;
- has the **Mock LLM** provider (`enum_value: "mock_llm"`, `api_schema: "openai"`,
  models `mock-small` / `mock-large`) in its catalog. It should live in the
  **custom** catalog (`_storage/llm_configuration/custom_llm.json`) so the mock
  never ships as a built-in. It must
  carry `"api_key_validation": "none"` (the mock takes no key). Use a **distinct**
  enum, never the reserved `custom`: the dashboard treats `custom` as the generic
  manual-endpoint provider, so a surface built on it renders with a blank
  provider/model and empty endpoints (and marching ants). If that field is missing
  or set to `mandatory`, the dashboard draws **marching ants** on every testkit
  LLM node because it thinks an API-key secret is required;
- can reach the host mock at `MOCK_INTERNAL_URL` (default `http://localhost:9000`);
- is either in debug test-auth mode (`AS_TEST_MODE=true` + `AS_TEST_TOKEN` +
  passkey auth) **or** you pass `APPLIANCE_SESSION_TOKEN=<admin session>` so the
  runner skips the test-login.

This way the surfaces, teams, members, traffic, caps, and stats all appear in
**your** appliance's dashboard as the run proceeds (use `TEARDOWN=false` to keep
them afterwards).

### Managed — self-host a throwaway appliance via docker-compose

No external instance needed; everything (mock + a fresh DEBUG appliance + runner)
runs in containers. Requirements: Docker (with Compose v2) only.

```bash
cd tests/appliance
./run.sh managed
```

Both modes exit with the runner's exit code:

- **0** — appliance statistics matched the locally tracked statistics.
- **non-zero** — a reconciliation mismatch, a cap-enforcement anomaly, or an
  error.

The run report (per-series expected vs actual, stage checks, cap failures,
anomalies, and per-phase durations) is written to
`results/testkit-report-<timestamp>.json`. Managed runs also retain
`results/containers.log` for failure diagnosis.

## Conformance suite (real provider APIs)

Separate from the mock-LLM load/reconciliation harness above, the **conformance
suite** proves that an LLM Surface conforms to every **client API dialect** it
accepts — **OpenAI Chat Completions** (`/v1/chat/completions`), **Anthropic
Messages** (`/v1/messages`), and **OpenAI Responses** (`/v1/responses`) — plus
`/v1/models` and `/v1/embeddings`. It uses the **real** OpenAI and Anthropic APIs
(not the mock), because the whole point of the feature is that the client dialect
is independent of the upstream model. Every chat dialect is driven against **both**
an OpenAI-backed and an Anthropic-backed surface (a cross-product), so a bug in
either transform direction is caught.

It is a **conformance** test, not load: one call per case, tiny token budgets.

**Provider keys are resolved by tag.** Create a provider API key in the appliance
and tag it — `test-suite-openai` for the OpenAI key, `test-suite-anthropic` for
the Anthropic key. Optionally tag a web-search engine key `test-suite-tavily` to
enable the `web_search` server-tool case (the `web_fetch` case needs no key and
always runs). The suite looks them up via `GET /api/v1/secrets/tag/{tag}`,
creates its own `test_surface`-tagged surfaces (`tk-conf-openai`,
`tk-conf-anthropic`, `tk-conf-embeddings`, `tk-conf-routing`, `tk-conf-web-tools`,
`tk-conf-context`), runs the matrix, and deletes them.

```bash
# From the tests/appliance/ dir — runs ONLY conformance (no mock, no load), -host passed through:
./run.sh -conformance -host http://localhost:8280

# Or run it directly:
cd tests/appliance/testkit
# Point at your appliance (debug test-auth mode, or supply APPLIANCE_SESSION_TOKEN).
APPLIANCE_URL=http://localhost:8280 npm run conformance
```

Overridable via env: `CONF_OPENAI_TAG`, `CONF_ANTHROPIC_TAG`, `CONF_OPENAI_MODEL`
(default `gpt-4o-mini`), `CONF_ANTHROPIC_MODEL` (default `claude-haiku-4-5`),
`CONF_EMBEDDINGS_MODEL` (default `text-embedding-3-small`).

Exit code **0** = every dialect/endpoint conformed on both surfaces; **1** = a
hard failure (a check that did not conform); **2** = a run error (e.g. a missing
tagged key). Capability-dependent cases (vision, tools, reasoning) are gated per
surface, and behaviours that depend on the upstream (e.g. usage inside a streamed
response) are recorded as **soft** — reported but never failing the suite. The
report is written to `results/conformance-report-<timestamp>.json`.

The surfaces are created with a matching `listen_address`, so their access point
renders **configured** in the dashboard (no "unconfigured" marching ants). When
run **interactively** (a TTY), the suite **pauses after the run** so you can
inspect the surfaces and their Monitoring (traffic) — **press any key to tear
them down**, or **Ctrl-C to leave them in place** for further review. A
non-interactive run (CI, piped) tears them down immediately.

The suite covers the same cases as the third-party `llm-api-compat-test-suite`
(basic chat, system/multi-turn, content parts, streaming chunks/events, tool
calling + result round-trips + forced tool choice, vision) and adds the OpenAI
**Responses** dialect the third-party kit does not test — so we do not need to run
the external kit. It also exercises the advanced inference controls end-to-end:

- **Unified reasoning** (reasoning-capable / Anthropic-backed surface): an
  Anthropic `thinking` request round-trips to a native thinking block, and an
  OpenAI-dialect `reasoning` object surfaces `message.reasoning` +
  `reasoning_details` and the `x-agent-stream-reasoning-tokens` header — proving
  reasoning normalizes across dialects and upstreams.
- **Structured outputs**: a `json_schema` request returns JSON and the gateway
  reports conformance on the `x-agent-stream-schema-valid` header (validated on
  every provider; a shape miss on a steered provider is soft).
- **Prompt caching**: a `cache_control` breakpoint on a large system prefix is
  accepted (proving passthrough) on both the OpenAI and native Anthropic dialects;
  cache read/write tokens (`x-agent-stream-cache-write-tokens` and the Anthropic
  usage block) are asserted, soft when the provider cache is cold.
- **Per-request routing**: a dedicated routing surface (OpenAI primary + Anthropic
  failover target) proves `provider.only` and `models[]` steer to the expected
  pool member — asserted via the `x-agent-stream-provider` response header — and
  that a preference matching no pool member is rejected.
- **Governed server tools**: a dedicated server-tools surface (OpenAI-backed)
  proves the gateway executes `web_fetch` — the agentic loop completes (200) and
  cites the fetched URL (soft, model-dependent), while a link-local metadata
  target is refused by the SSRF guard (hard: no metadata citation may leak).
  `web_search` runs when a Tavily key is tagged `test-suite-tavily` (capability
  off otherwise) and cites its results (soft).
- **Context-window guard**: a dedicated surface (tiny configured window) proves
  `transforms: ["middle-out"]` compresses an over-window prompt — asserted
  deterministically via the `x-agent-stream-context-transform` header (with
  `elided>=1`) — and that `transforms: []` opts out (no header).

The suite reads the gateway's own `x-agent-stream-*` response headers to assert
these token/cache/schema signals.

It also runs an **auth-enforcement** check on a bearer-protected surface
(`jwt_bearer` source auth): every dialect — `/v1/chat/completions`,
`/v1/messages`, `/v1/responses` — must reject a missing bearer with **401** and
accept a valid JWT with **200**. The Anthropic `x-api-key` path is included
(it maps to Bearer at the front door) and must still 401 on an invalid value, so
the mapping can never bypass authentication.

## Cleaning up the junk (soft-delete vs. hard purge)

> [!IMPORTANT]
> **Every ordinary appliance `DELETE` is a soft-delete.** Members, teams, and
> surfaces deleted via the normal endpoints flip the record's `status` to
> `deleted` and **keep the JSON file on disk** as a tombstone (the tombstone
> reserves the identifier and lets telemetry be GC'd cleanly). The teardown
> phase, the `[c]` clean-up choice, and the debug-only bulk endpoint
> `POST /v1/pipes/test-surfaces/delete` are all soft-deletes — they make the junk
> disappear from the dashboard and the list endpoints, but the files remain. This
> keeps historical usage attribution intact.

This is by design and is **not a problem for re-runs**: each run mints
**per-run-unique** member emails / JWT subjects / api-key client ids, so leftover
tombstones never collide with a fresh population. You can run the testkit as many
times as you like without ever hard-deleting anything.

### The one-call hard-purge (the "button")

When you genuinely want the fixtures **physically gone** (files removed, not
tombstoned), the testkit's interactive menu offers a hard-purge:

```text
[r] run another round  [c] clean up & exit  [p] hard-purge fixtures & exit  [q] quit
```

Pressing **`[p]`** calls the debug-only endpoint `POST /v1/test-support/purge`,
which in one shot **physically deletes**:

- every surface flagged `test_surface` (**including existing tombstones**),
- every non-system member flagged `test_fixture`,
- every non-system team flagged `test_fixture`,

and GC's each one's telemetry series. The testkit stamps `test_fixture: true` on
every member and team it creates (and `test_surface: true` on every surface), so
the purge finds exactly the testkit's own population. **The built-in system
records (anonymous / sandbox) are never touched.** It responds with
`{ surfaces, members, teams }`, each `{ deleted, ids }`.

Gating mirrors `test-surfaces/delete`: the endpoint returns `404` unless the
appliance is a **debug** build with test-auth enabled (`AS_TEST_MODE` +
`AS_TEST_TOKEN`), so it is invisible in release/production. Normal teardown
still soft-deletes (to retain attribution) — purge is the opt-in destructive
path. You can also call it directly:

```bash
curl -sS -X POST http://localhost:8280/internal/test-support/auth/login \
  -H 'content-type: application/json' -d '{"token":"testkit-secret-token"}' >/dev/null
curl -sS -X POST http://localhost:8280/v1/test-support/purge \
  -H 'authorization: Bearer testkit-secret-token'
```

### Wiping the store on disk

If you want a **total clean slate** (e.g. lots of accumulated tombstones from
real dashboard work, not just testkit fixtures), wipe the throwaway env's
storage and restart:

```bash
# Stop the appliance first (`make run-debug tk=1`), then from
# the repo root remove the data dirs you want gone. This is the testkit's
# THROWAWAY env — do NOT do this on an appliance holding real surfaces.
# (Paths follow envs/local/config/config.toml [storage_paths]; surfaces live
# under surfaces, and telemetry/usage live under _volatile/.)
rm -f envs/local/_storage/members/*.json \
      envs/local/_storage/teams/*.json \
      envs/local/_storage/surfaces/*.json \
      envs/local/_storage/apikeys/*.json

# Optional: also drop the accumulated usage/telemetry so stats reset too.
rm -rf envs/local/_volatile/usage/team_usage/* \
       envs/local/_volatile/usage/surface_usage/* \
       envs/local/_volatile/timeseries/telemetry/* \
       envs/local/_volatile/timeseries/ops_telemetry/*

# Restart the appliance. The built-in system records (anonymous / sandbox) and
# the LLM catalog re-seed themselves on boot, so a wiped store comes back clean.
```

For the **managed** (docker-compose) mode there is nothing to clean — each
`./run.sh managed` removes and recreates its disposable storage volumes, so the
junk never persists between runs.

## Configuration

All knobs are environment variables (see `testkit/src/config.js`), overridable on
the `run.sh` invocation or in your shell:

| Var                       | Default                 | Meaning                                                 |
| ------------------------- | ----------------------- | ------------------------------------------------------- |
| `APPLIANCE_URL`           | _(set by `-host`)_      | Appliance to drive (external mode). Pass via `-host`; no default. |
| `APPLIANCE_SESSION_TOKEN` | _(unset)_               | Admin session/bearer; set it to skip the test-login.    |
| `MOCK_INTERNAL_URL`       | `http://localhost:9000` | How the **appliance** reaches the mock (surface base URL).|
| `MOCK_CONTROL_URL`        | `http://localhost:9000` | How the **runner** reaches the mock control plane.       |
| `AS_IMAGE_TARGET`         | `local`                 | Managed image target: `local` builds from source; `ci` packages `tests/appliance/bin/agent-stream`. |
| `TESTKIT_RUNTIME_IMAGE`   | `debian:bookworm-slim`  | Managed runtime base image; CI may override it with a registry mirror. |
| `TESTKIT_NODE_IMAGE`      | `node:20-alpine`        | Mock and runner image; CI may override it with a registry mirror. |
| `LOAD`                    | `medium`                | Load level (`small`\|`medium`\|`large`) seeding the population/traffic defaults below. Per-knob env/flags still override it. |
| `NUM_TEAMS`               | _(load level)_          | Number of teams.                                        |
| `MEMBERS_PER_TEAM`        | _(load level)_          | Members per team.                                       |
| `NUM_REQUESTS`            | _(load level)_          | Load-phase calls per round (ignored when `DURATION>0`). |
| `CONCURRENCY`             | _(load level)_          | Max in-flight load-phase requests.                      |
| `RPS`                     | _(load level)_          | Target load-phase requests/sec (`0` = unbounded).       |
| `DURATION`                | _(load level)_          | Load-phase run time in seconds (`>0` overrides `NUM_REQUESTS`). |
| `CAP_DRILL`               | `true`                  | Run the deterministic cap-enforcement drill.            |
| `CAP_DRILL_CALLS`         | _(load level)_          | Calls per capped target in the cap drill.               |
| `REJECTION_DRILL`         | `true`                  | Run the judge/jury rejection drill.                     |
| `REJECTION_REQUESTS`      | _(load level)_          | Bad prompts per moderated surface in the rejection drill.|
| `POLICY_DRILL`            | `true`                  | Run the OPA policy enforcement drill.                   |
| `POLICY_REQUESTS`         | `3`                     | Calls per policy scenario before asserting 200/403.     |
| `COVERAGE`                | `true`                  | Run the every-member coverage sweep (set `false` to skip).|
| `COVERAGE_WAVES`          | _(load level)_          | Coverage waves; ≥3 gives a visible line/area time series.|
| `COVERAGE_WAVE_GAP`       | `35`                    | Seconds between coverage waves (must exceed the 30s bucket).|
| `COVERAGE_CALLS`          | _(load level)_          | Calls per member per coverage wave.                     |
| `DRIFT_EVAL`              | `true`                  | Replay each drift surface's captured sessions (`POST /v1/drift/eval/run`) to fill quality / semantic-distance. |
| `DRIFT_EVAL_CONCURRENCY`  | `4`                     | Max concurrent replay evaluations in the drift eval sweep. |
| `DRIFT_EVAL_WAVES`        | `3`                     | Drift eval waves (spaced `COVERAGE_WAVE_GAP` apart) so replay dims show a multi-point line. |
| `DRIFT_EVAL_MAX_SESSIONS` | `5`                     | Captured sessions each replay run re-runs. The replay is sequential through the full pipeline, so a high value can exceed a reverse-proxy gateway timeout (`504`) for judge/jury surfaces; raise it when hitting the appliance directly. |
| `INTERACTIVE`             | _(auto: TTY)_           | Prompt run-again/clean-up after each round.             |
| `SETTLE_SECONDS`          | `4`                     | Wait before reconciling (telemetry flush).              |
| `RECON_RESOLUTION`        | `30s`                   | Forced telemetry tier for reconciliation.               |
| `TEARDOWN`                | `true`                  | Delete the population at the end (`false` keeps it).    |
| `SEED`                    | `0`                     | RNG seed for the population (`0` = random).             |
| `AS_TEST_TOKEN`           | `testkit-secret-token`  | Test-auth bootstrap secret (appliance + runner).        |
| `TESTKIT_AGENT_ID`        | `testkit-agent`         | Id of the Surface the runner creates to hold its managed API keys. |

> In external mode the runner prices calls from `config/managed.llm.json`, so
> those prices must match the Mock LLM custom catalog of the appliance you
> target.

Example: a bigger, reproducible run that leaves the population in place for
inspection:

```bash
NUM_REQUESTS=2000 SEED=42 TEARDOWN=false ./run.sh -host http://localhost:8280
```

## How reconciliation stays exact

- **One source of pricing.** The managed appliance and runner read the **same**
  `config/managed.llm.json`; cost is `tokens * cost_per_1k / 1000`. To avoid endpoint
  vs model pricing ambiguity, prices live only on the models.
- **`cost_tracking.enabled = true`** on every surface so the main-LLM cost
  reaches `metrics.cost` (it is gated otherwise).
- **LLM drift monitoring is on for every surface** (`drift.enabled = true`,
  `sample_rate = 1`), so every buffered success feeds the surface's drift
  dimensions; reconciliation then asserts each drift-monitored surface that saw
  traffic recorded samples in the dedicated drift store, **pins a baseline**
  (`POST /v1/drift/baseline`) from that accumulated behaviour, and confirms the
  surface's **verdict** (`GET /v1/drift/verdict`) carries the baseline timestamp
  and is not `drift` (it was just pinned from the same traffic, so it has not
  moved). The count of confirmed baselines is reported as
  `driftBaselinesConfirmed`.
- **Nonce correlation, not call-count delta.** Every request embeds a unique
  `[[tkid:<nonce>]]` marker the mock stamps onto every upstream call it serves
  for that execution. After a `200` the runner reads `GET /__mock/by-nonce` to
  attribute the precise usage of the main call (the response `usage`) and of each
  judge/juror call (priced at its own model) — matching how the appliance meters
  per stage, and correct even when many requests run concurrently.
- **Load uses only uncapped members.** The concurrent load phase draws from
  members that are uncapped both individually and on their team, so it never
  trips a `429` mid-flight and token/cost sums stay exact. Caps are exercised
  separately by the deterministic **cap drill**.
- **Blocked calls record no usage.** A judge/jury `403` consumes upstream tokens
  but the appliance bills none of it (only rejection telemetry); the runner
  mirrors that — the rejection ledger never touches the usage series.
- **Always-approve vs moderated guards.** Plain judge/jury surfaces carry a
  never-matching judge rule and a `.*` juror approve pattern, so every stage runs
  and meters without blocking. Moderated surfaces invert this (judge rule
  `BLOCKED`, juror pattern `APPROVED`) so a `[[reject]]` prompt is rejected
  deterministically.

## Authoring surfaces

Each file in `config/surfaces/` is loaded and its format detected **per file**:

- **Compact template** — the small files (`email-plain.json`, `jwt-judge.json`,
  …). They carry only the complexity knobs and the runner expands them into the
  full `POST /v1/pipes` body, wiring the mock endpoints, the right source auth
  for the identity flavor, the always-approve judge/jury, team attribution and
  cost tracking. Shape:

  ```json
  { "key": "jwt-judge", "identity": "jwt", "route": "/llm/jwt-judge",
    "model": "mock-small", "judge": true, "jurors": 0 }
  ```

  `identity` is one of `email | jwt | apikey`; `judge` is a bool; `jurors` is a
  count. Add `moderated: true` to make the judge/jury reject the mock's
  `BLOCKED` output. Optional `judgeCategory` (string) and `juryCategories`
  (string array, cycled across jurors) override the rejection-taxonomy category
  ids the moderated judge rule / jurors are named after (defaults
  `prompt_injection` and `["toxicity", "hate"]`).

- **Full PipeConfig** — any file containing a `pipe_type` key (e.g.
  `full-email-plain.json`). The runner posts it to `/v1/pipes` **verbatim**, so
  you have full control over every field. Because the JWT strategy, the API-key
  agent, and the mock URL aren't known until the run starts, these placeholders
  are substituted before posting:

  | Placeholder           | Replaced with                                  |
  | --------------------- | ---------------------------------------------- |
  | `${MOCK_URL}`         | the mock base URL — append the chat path for the `custom` provider `endpoint`/`endpoint_url` (`${MOCK_URL}/v1/chat/completions`) |
  | `${JWT_STRATEGY_ID}`  | the runtime `jwt_verification_strategy_id`     |
  | `${JWT_AUDIENCE}`     | the audience every testkit token carries; list it in `audiences` |
  | `${APIKEY_AGENT_ID}`  | the api-key provider `agent_id`: the Surface holding the run's managed API keys |

  The runner infers the identity flavor from `source_auth` (none ⇒ email,
  `jwt_bearer` ⇒ jwt, `api_key_provider` ⇒ apikey) so the right member
  credentials are minted and presented. Keep `caller_email_source` consistent
  with that flavor (`header` `X-Caller-Email` for email, `jwt_claim` `sub` for
  jwt, `api_key` for apikey). See `full-email-plain.json` for a worked example.

To add your own surface, drop either form into `config/surfaces/` — no code
change needed. `llm.json` stays the model **catalog** (validation + pricing); it
is not per-surface config, and the surface's own `pipe_type.provider` is what
selects the upstream.

## Layout

```
tests/appliance/
  mock-llm/          mock OpenAI server + control plane
  testkit/src/       config, identities (RS256 JWT, email, ApiKey),
                     appliance client, pricing, surface builder, ledger,
                     setup, simulate (rounds/phases), pool (concurrency),
                     reconcile, teardown, prompt (interactive), main (load test),
                     conformance + conformance-main (real-API conformance suite)
  config/
    managed.config.toml passkey-mode managed appliance bootstrap
    managed.limits.json high test-only appliance limits
    managed.llm.json mock-small / mock-large catalog and pricing source
    surfaces/        the surface catalog (compact templates and/or full configs)
  results/           run reports (git-ignored)
  Dockerfile         DEBUG agent-stream build
  docker-compose.yml mock-llm + as1 + runner
  run.sh             build + run + exit code
```

Managed mode is self-contained: the image derives non-secret runtime fixtures
from `config/examples/`, mounts the managed bootstrap/catalog fixtures, and uses
disposable Docker volumes for appliance state. Only JSON run reports persist in
`tests/appliance/results/`. The `managed.config.toml` and `managed.llm.json` names are
intentional: the root `.gitignore` excludes files named exactly `config.toml` and
`llm.json`, which would silently omit fixtures using those names.
