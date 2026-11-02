# Agent Stream BDD Guide

Use this guide with the BDD/Gherkin harness skill. It captures Agent Stream-specific file locations, terminology, and harness rules.

## Read first

- `CONTEXT.md`
- `AGENTS.md`
- `docs/CAPABILITIES.md`
- `tests/appliance/README.md` for the existing appliance testkit product-loop model
- `src/pipes/config.rs` for Surface/Pipe configuration shape
- `src/pipes/executor.rs` before changing runtime pipeline behavior
- `src/pipes/policy_manager.rs` before changing LLM Surface or IDE Surface policy behavior
- `src/pipes/handlers/http_handlers.rs` before changing surface HTTP routing or IDE catalog dispatch
- `src/telemetry/` and `src/pipes/metrics_store.rs` before asserting usage or rejection telemetry
- `tests/features/surface/*.feature`
- `tests/surface_bdd.rs`, `tests/surface_bdd/**/*.rs`, and `tests/bdd_support/**/*.rs`
- `Cargo.toml` test target entries

## Runner profile

| Runner | Feature directory | Purpose | Execution model |
| --- | --- | --- | --- |
| `surface_bdd` | `tests/features/surface` | Product workflows for LLM Surfaces, IDE Surfaces, callers, members, teams, policies, guardrails, metering, and telemetry | Concurrent scenarios capped by `BDD_MAX_CONCURRENT_SCENARIOS`; one temporary config/storage tree, mock provider set, and `agent-stream` process per scenario |

Start with `surface_bdd`. Do not add Docker or fabric-style topology unless a scenario requires behavior that cannot be exercised through a local real-process appliance and HTTP collaborators.

## Test-layer scope

Prioritize core product workflows. Use BDD for user journeys and visible orchestration through the real process; keep algorithmic, parsing, and configuration matrices in component or unit tests.

## Terminology reminders

- `CONTEXT.md` is the source of truth.
- Use `Surface`, `LLM Surface`, `IDE Surface`, `Provider`, `Member`, `Team`, and `Caller` as defined there; write Surface, never Pipe.
- Use `operator` for the human/external system configuring the appliance through the Admin API or dashboard.
- Use `caller` for the runtime client invoking a surface.
- Use `provider` for an LLM vendor adapter or test stand-in reached by an LLM Surface.
- Use `member` and `team` for attribution, quotas, and access control.
- Use `source authentication` for caller credential checks at the surface route.
- Use `guardrail`, `Judge`, `Jury`, `Decider`, `Prompt Guard`, `budget`, `rate limit`, `telemetry`, and `rejection` consistently with the reference guide.
- Do not use internal routing-unit names in Gherkin or customer-visible docs.
- Do not expose harness mechanics such as `mock`, `fixture`, or temp storage in feature text unless the scenario is about harness behavior.

## Harness rules

- Start the real `agent-stream` binary and exercise it over real HTTP. Run the suite against a debug build (the default `cargo test`): the harness reaches its loopback collaborators through `AS_TEST_MODE` and `AS_TEST_SERVICE_ENDPOINT_ALLOWLIST`, which a release build ignores, so under `cargo test --release` the appliance refuses those loopback provider URLs.
- Redirect each child process's stdout and stderr to its per-scenario `agent-stream.log`; never inherit the Cucumber runner's terminal. Include a bounded log tail when startup fails. The full log follows the scenario directory's lifecycle.
- Use isolated per-scenario state: temp config, temp storage, dynamic ports, per-scenario collaborators, and no shared mutable process env across `.await` points.
- Prefer the existing appliance testkit model for product-loop fidelity, but keep BDD support minimal and Rust-native.
- Reuse and extend existing mock LLM infrastructure before creating BDD-specific alternatives.
- Shared runtime harness support belongs under `tests/bdd_support/`. Runtime support may start processes/collaborators, send HTTP, sign tokens, record observations, or assert behavior.
- Static config and storage fixtures belong in `tests/bdd_support/config.rs`. Code there should model or write files consumed by `agent-stream`; it should not start processes, send requests, sign tokens, or assert runtime behavior.
- Suite-specific worlds and step bindings stay under `tests/surface_bdd/`.
- Organize bindings under `tests/surface_bdd/steps/` by product domain, keeping related `Given`, `When`, and `Then` bindings together. Do not aggregate bindings into keyword-based `given.rs`, `when.rs`, or `then.rs` files.
- Reusable suite-specific mechanics belong in nested `tests/surface_bdd/steps/support/` modules. These modules contain no Cucumber attributes; domain step modules may depend on support modules, never on another step module.
- Cross-suite runtime support belongs under `tests/bdd_support/`. Register it in `tests/bdd_support/mod.rs` and cover harness-only behavior with module unit tests or support tests.
- Keep admin API response assertions, caller traffic assertions, provider observation assertions, and telemetry assertions explicit.
- Capture created surface ids and use them for later update, disable, delete, and readback assertions.
- Seed prerequisite state in `Given`; reserve `When` for the one operator/caller action being tested.
- Scenario temp directories honour `BDD_TEMP_DIR_ROOT` and `BDD_TEMP_DIR_PREFIX`.
- For debug runs, support `DEBUG=1` to run serially and include only `@debug` scenarios.

## Terms authentication and routes

Terms scenarios use the test-only authentication route to create real persisted users and sessions through the shared Terms-aware session finalizer. A per-scenario Affinidi Well collaborator serves mutable current metadata; the harness uses a one-second refresh interval and may seed the durable cache before startup. This covers consent-pending session, central update, and last-known-good behavior without claiming to exercise a WebAuthn ceremony or SAML assertion. Passkey registration version validation remains covered by manager unit tests around the Terms registration contract; full passkey and SAML protocol journeys require dedicated authenticator and identity-provider harnesses.

The identity and Terms endpoints are mounted at the appliance root in the BDD configuration. Management access tokens (`/api/v1/access-tokens`) and secrets (`/api/v1/secrets`) are the exceptions.

## BDD Gherkin inventory and lint

Use `scripts/bdd-gherkin.py` as the required inventory and validation tool.

Required authoring loop:

```bash
scripts/bdd-gherkin.py --inventory
# read .bdd-gherkin/context.md completely before adding or renaming DSL

scripts/bdd-gherkin.py --lint
# run after changing .feature files or step bindings
```

`--inventory` writes an AI-oriented catalog of Cucumber step bindings, usage counts, and implementation references. Read the bound Rust function before reusing any non-trivial step.

`--lint` exits non-zero for hard errors such as unmatched required steps, ambiguous matches, unused bindings, invalid scenario shape, and invalid `Scenario Outline` examples. Warnings cover draft/stale tags, duplicate or unknown tags, terminology issues, broad regexes, and near-duplicate wording.

## DSL ownership

- Exact step expressions, bindings, and usage counts belong only in the generated `.bdd-gherkin/context.md` inventory.
- Read the generated inventory and bound Rust functions before adding or renaming expressions.
- Reuse or parameterize existing expressions when they describe the same product behavior.
- Keep this guide limited to durable terminology, scenario-shape, harness, and assertion rules.
- Prefer typed product outcomes over generic HTTP-status wording.
- Name providers and other observable collaborators when asserting effects or no-call behavior.

## Assertion guidance

- Always assert caller/operator-visible status separately.
- For success, assert both the response body semantics and the provider/collaborator observation.
- For source-authentication failures, assert `401` with `source_authentication_failed`, plus provider no-call proof.
- For denials after a caller is authenticated, assert the rejection status/body and explicit provider no-call proof where the provider must not be reached.
- For provider errors, assert `502` with `provider_error`, machine-readable upstream status when present, and collaborator observations proving the provider was reached.
- For telemetry, poll with a bounded settle timeout and assert behavior-level totals or buckets. Avoid brittle full-object equality.
- For LLM protocol behavior, assert behavior-defining fields such as model, messages, usage, request id, selected model, or stage bucket. Do not assert only that a JSON object exists.

## Scenario tags

Use only tags that change runner behavior, currently `@wip`, `@known-bug`, and `@debug`. Do not add inert grouping or descriptive tags.

Scenarios or features tagged `@wip` are skipped by default. Use `@wip` for drafted Gherkin that is not ready to execute.

Scenarios tagged `@known-bug` are executable but skipped by default. Use `@known-bug` for accepted current product defects. Provide an opt-in env var such as:

```bash
BDD_INCLUDE_KNOWN_BUGS=1 cargo test --test surface_bdd
```

## Commands

For BDD wording/tooling:

```bash
scripts/bdd-gherkin.py --inventory
scripts/bdd-gherkin.py --lint
```

For surface feature or step changes:

```bash
cargo test --test surface_bdd --no-run
cargo test --test surface_bdd
BDD_FEATURE_PATH=tests/features/surface/<feature>.feature cargo test --test surface_bdd
```

Before ready for review after harness/code changes:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --test surface_bdd
scripts/bdd-gherkin.py --lint
```

## Changelog

BDD scenarios, harness support, Gherkin tooling, and BDD docs are test changes. Record them in `.changelog/wip/<branch>.yaml` under the public category that best matches their user-visible effect, or leave every category list empty when there is none. Do not edit `CHANGELOG.md` directly.
