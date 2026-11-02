# Making Changes

Recipes for the changes that come up repeatedly, organised by what you want to do rather
than by the subsystem it lands in.

Each recipe lists the files to touch, the document to update, and the test layer, and names
code to read first. Read that code: it is more reliable than this page, which describes the
shape rather than the detail.

Before starting, read [`ARCHITECTURE.md`](../../ARCHITECTURE.md) for the request path and its
invariants, and [`CONTEXT.md`](../../CONTEXT.md) for the vocabulary. Every change needs a
changelog fragment and tests; see [`CONTRIBUTING.md`](../../CONTRIBUTING.md) and
[`TESTING.md`](TESTING.md).

## Add a provider

A Provider is a vendor or endpoint family an LLM Surface can call upstream.

**Read first:** `LLMProvider` in [`src/pipes/types/llm.rs`](../../src/pipes/types/llm.rs) and
`resolve_provider_headers` in [`src/pipes/executor.rs`](../../src/pipes/executor.rs).

| Order | File | Change |
| --- | --- | --- |
| 1 | `src/pipes/types/llm.rs`, `src/pipes/types/llm_provider_ext.rs` | Add the provider's variant and its `LLMProviderExt` accessors, including its `api_schema`. |
| 2 | `config/examples/llm.example.json` | Add the catalog entry: base URL, endpoints, models, and prices. |
| 3 | `src/pipes/request_shaping.rs`, `src/pipes/executor.rs` | Add the request wire transform and the response transform back to OpenAI Chat, if the provider does not speak OpenAI Chat. |
| 4 | `src/pipes/executor.rs` | Make sure `resolve_provider_headers` covers the provider's authentication header. |
| 5 | `src/pipes/streaming.rs` | Add the schema to `passthrough_eligible` only if `spawn_metered_stream` can translate its event stream. |
| 6 | `docs/PROVIDERS_AND_CREDENTIALS.md` | Document the provider, its key source behaviour, and its limitations. |

**Tests:** unit tests for both transforms and the usage parser; a behaviour scenario in
`tests/features/surface/` using the mock provider set.

**Watch for:**

- The provider clients never follow redirects. Keep it that way: a redirect would carry
  upstream headers and keys to the redirect target.
- The caller's own key is offered only to the default upstream's main call. Every other
  call (Judge, Jurors, Decider, failover, load-balancing members) resolves its key with
  `CallerKey::NotOffered` ([`src/pipes/key_source.rs`](../../src/pipes/key_source.rs)).
- Every platform-key call goes through `admit_call` immediately before it is sent, so
  budgets hold. A call path that skips it is unmetered spend.

## Add a client API dialect

A Client API dialect is a request format callers may use, such as OpenAI Chat, Anthropic
Messages, or OpenAI Responses.

**Read first:** [`src/pipes/ingress.rs`](../../src/pipes/ingress.rs).

| Order | File | Change |
| --- | --- | --- |
| 1 | `src/pipes/ingress.rs` | Add the `IngressSchema` variant, its path detection in `detect_ingress_schema`, and decide whether `default_accepted_ingress_schemas` includes it. |
| 2 | `src/pipes/handlers/http_handlers.rs` | Normalise the request to OpenAI Chat at the front door, before any gate. |
| 3 | `src/pipes/handlers/http_handlers.rs`, `src/pipes/streaming_skin.rs` | Re-skin success bodies, errors, and streamed events to the dialect at the edge. |
| 4 | `www/default/src/` | Let the Surface's accepted dialects include it. |
| 5 | `docs/CLIENT_API_DIALECTS.md` | Document the dialect, its paths, and what does not translate. |

**Tests:** unit tests for normalisation and re-skinning, both directions; a behaviour scenario
calling a Surface in the new dialect.

**Watch for:** every stage between the front door and the edge sees OpenAI Chat. Do not
branch on the dialect inside the pipeline.

## Add a pipeline stage or inference control

**Read first:** [the full order](../../ARCHITECTURE.md#full-order) in `ARCHITECTURE.md`, then
`handle_chat_completions` in
[`src/pipes/handlers/http_handlers.rs`](../../src/pipes/handlers/http_handlers.rs).

| Order | File | Change |
| --- | --- | --- |
| 1 | `src/pipes/config.rs` | Add the Surface configuration, if the stage is configurable. See [Add a Surface configuration field](#add-a-surface-configuration-field). |
| 2 | `src/pipes/handlers/http_handlers.rs` | Place a request-shaping stage once, in the handler, before the split into the streaming and buffered executors, so both paths run it. Document ingestion runs before the context-window guard; a stage that changes the prompt's size belongs before the guard too. |
| 3 | `src/surface_context/mod.rs` | If a policy should see the stage's input, expose it under `input.resource` (`ResourceContext`). |
| 4 | `src/pipes/metering.rs` | If the stage makes a billable call, meter it and admit it against the budget. |
| 5 | `src/pipes/streaming.rs` | If the stage acts on the response, make `passthrough_eligible` return `false` when it is configured. |
| 6 | `docs/INFERENCE_CONTROLS.md`, `ARCHITECTURE.md` | Document the control, and add the stage to the request path and full order. |

**Tests:** a unit test for the stage's logic; a behaviour scenario proving it runs in the
right place and refuses with the right status.

**Watch for:** a response-side stage that streaming does not know about is silently skipped
on streamed answers.

## Add a field to policy input

Anything a Rego policy can read lives in `PolicyInput`.

**Read first:** [`src/surface_context/mod.rs`](../../src/surface_context/mod.rs).

| Order | File | Change |
| --- | --- | --- |
| 1 | `src/surface_context/mod.rs` | Add the field to the relevant context struct, or a new context to `PolicyInput`. Raise `POLICY_INPUT_SCHEMA_VERSION` if the change is not purely additive. |
| 2 | Every `PolicyInput::new` caller | Populate it: the LLM and IDE Surface paths in `src/pipes/handlers/http_handlers.rs`, realtime in `src/pipes/realtime.rs`, and the Fabric receive path in `src/gateways/connection_points/message_processor.rs`. |
| 3 | `docs/POLICY.md` | Document the field and its possible values. |

**Tests:** unit tests for the context; a behaviour scenario with a policy that reads the field.

**Watch for:** a policy reading a missing value gets `undefined` in Rego rather than an error.
A field populated on only some paths is a silent gap.

## Add a request-attribute routing rule

**Read first:** `resolve_route_decision` in
[`src/pipes/handlers/http_handlers.rs`](../../src/pipes/handlers/http_handlers.rs).

| Order | File | Change |
| --- | --- | --- |
| 1 | `src/pipes/config.rs` | Add the rule's match condition. |
| 2 | `src/pipes/handlers/http_handlers.rs` | Evaluate it in `resolve_route_decision`, which applies explicit `$alias`, then routing rules, then the canary split, then the base. |
| 3 | `docs/ROUTING.md` | Document the condition and its precedence. |

**Tests:** `resolve_route_decision` is pure over its inputs, so unit-test it directly; a
behaviour scenario for the routed request.

**Watch for:** a rule that matches on request attributes belongs in the Router, not the
Decider. The Decider is an LLM that picks a Candidate and costs a model call.

## Add a secret reference

Any Surface field that names a stored secret.

**Read first:** `resolve_reference` and `SurfaceSecrets` in
[`src/secrets/mod.rs`](../../src/secrets/mod.rs).

| Order | File | Change |
| --- | --- | --- |
| 1 | `src/identity/handlers/pipe_secret_bindings.rs` | Add the field to `secret_bindings`, paired with the destination that actually receives it. That one walk feeds both the save-time tenancy check in `validate_pipe_references` and the `secrets.view` check on where a stored secret is sent. |
| 2 | The request-time code | Resolve it through a `SurfaceSecrets` built with the Surface's tenant, never by reading the store directly. |
| 3 | `docs/PROVIDERS_AND_CREDENTIALS.md` | Document the field. |

**Tests:** unit tests for a reference the Surface's tenant may use and one it may not, and a
row in `every_secret_site_is_paired_and_held` proving that moving the field's destination
is refused without `secrets.view`.

**Watch for:** `resolve_reference` is the single lookup both the save-time check and the
request path use. A second lookup order would let the checked secret and the sent secret
differ. A secret pushed straight into the tenancy collection instead of `secret_bindings`
is tenancy-checked but has no destination check, so any editor could send it to their own
host.

## Add a Surface configuration field

**Read first:** `PipeConfig` in [`src/pipes/config.rs`](../../src/pipes/config.rs) and
`PipeVariantOverrides` in [`src/pipes/pipe_variants.rs`](../../src/pipes/pipe_variants.rs).

| Order | File | Change |
| --- | --- | --- |
| 1 | `src/pipes/config.rs` | Add the field with `#[serde(default)]`, so Surfaces saved before it existed still load. |
| 2 | `src/pipes/handlers/llm_handler.rs` | Validate it in `LLMHandler::validate_config`. |
| 3 | `src/identity/handlers/pipe_tenancy.rs` | If it references a price or other tenant-owned record, check it in `validate_pipe_references`. A secret goes in `secret_bindings` instead (see [Add a secret reference](#add-a-secret-reference)). Both checks run on create, update, the Variant API, and promote-to-default in `src/identity/handlers/pipes.rs`. |
| 4 | `src/pipes/pipe_variants.rs` | If a Variant may override it, add it to `PipeVariantOverrides` and to the merge in `resolve_variant`. |
| 5 | `www/default/src/pages/EditPipePage/pipeMappingHelpers.ts` | Map it between the API shape and the form, and in `www/default/src/components/builder/pipe-variants/pipeVariantMapping.ts` if Variants override it. |
| 6 | The owning doc | Document it in the feature's reference doc. |

**Tests:** unit tests for validation, positive and negative; a wire-shape test pinning the
JSON the dashboard mirrors, like `usage_alert_wire_shape_keys_match_frontend` in
`src/pipes/config.rs`.

**Watch for:** `PipeVariantOverrides` denies unknown fields, so a Variant setting a field it
does not declare is rejected rather than ignored.

## Add a stored-object provider field

A request field that names an object stored at the provider, such as a file, a vector store,
or a stored response.

**Read first:** [`src/pipes/shared_credential.rs`](../../src/pipes/shared_credential.rs).

| Order | File | Change |
| --- | --- | --- |
| 1 | `src/pipes/shared_credential.rs` | Add the key to `STORED_OBJECT_KEYS`, or the part or tool type to `STORED_OBJECT_TYPES`. |
| 2 | `docs/PROVIDERS_AND_CREDENTIALS.md` | Note the field among those refused on a key the tenant does not own. |

**Tests:** unit tests that a body naming the object is detected, and that the same name
inside a JSON Schema is not.

**Watch for:** the list is a denylist. A provider field that names a stored object and is not
listed passes the check.

## Change a Governance Record

**Read first:** `GovernanceRecord` in
[`src/governance/record.rs`](../../src/governance/record.rs) and `capture_with_id` in
[`src/governance/capture.rs`](../../src/governance/capture.rs).

| Order | File | Change |
| --- | --- | --- |
| 1 | `src/governance/record.rs` | Add the field as an `Option` with `#[serde(default, skip_serializing_if = "Option::is_none")]`. |
| 2 | The capture site | Populate it through `capture_with_id`, which applies the Surface's `CapturePolicy` (body capture, recorded outcomes, retention). |
| 3 | `docs/GOVERNANCE_RECORDS.md` | Document the field. |

**Tests:** a unit test that a record without the field still verifies; a behaviour scenario
for the captured value.

**Watch for:** each record's hash is computed over its canonical JSON and chained to the
previous record. A field that serialises on records written before it existed would break
their verification. Never embed raw media bytes; record a digest.

## Add a drift dimension or replay path

**Read first:** `DriftDimension` in [`src/drift/dimension.rs`](../../src/drift/dimension.rs)
and `meter_replay` in [`src/drift/runner.rs`](../../src/drift/runner.rs).

| Order | File | Change |
| --- | --- | --- |
| 1 | `src/drift/dimension.rs` | Add the dimension. Its series key is `drift:surface:{id}:{dimension}`; `is_valid_drift_key` in `src/identity/handlers/drift.rs` accepts only that shape. |
| 2 | `src/drift/runner.rs` | Meter any replay spend through `record_surface_llm_usage` and the quota tracker, charged to the owning Member, or to the built-in `drift-runner` Member when there is none. |
| 3 | `docs/LLM_DRIFT.md` | Document the dimension and how it is computed. |

**Tests:** unit tests for the computation and the key; a behaviour scenario if replays change.

## Add a management API endpoint

**Read first:** an existing route registration in
[`src/identity/router.rs`](../../src/identity/router.rs).

| Order | File | Change |
| --- | --- | --- |
| 1 | `src/rbac/mod.rs` | Add a `Feature` variant and its key in `Feature::as_str`, following the `<area>.view` / `<area>.edit` / `<area>.delete` naming. |
| 2 | `src/rbac/mod.rs` | Give the key its minimum role in `RbacConfig::default()`. A key missing from the map is denied to every role, administrators included. |
| 3 | `config/examples/rbac.example.json` | Add the key with the same role. |
| 4 | `src/identity/handlers/` | Write the handler. If it reads or changes a tenant-ownable record, scope it to the caller's tenant ([`src/tenancy/`](../../src/tenancy/)). |
| 5 | `src/identity/router.rs` | Register the route through the RBAC guard: `.route(path, gate.gate(post(handler), Feature::YourFeature))`. A route registered without it is unprotected. Secret routes are registered in `src/secrets/router.rs`. |
| 6 | `src/auth_manager/permissions.rs` | If the dashboard uses the feature, add its key to `get_permissions`. |
| 7 | `www/default/src/api.ts` | Add the client call. |
| 8 | `docs/RBAC.md`, `docs/ACCESS_TOKENS.md` | Describe the permission, and the resource kind if Management PATs can be scoped to it. |

**Tests:** a unit test for the handler; tests that a role without the permission and a caller
from another tenant are refused.

**Watch for:** the dashboard hides controls based on the permissions endpoint, so a feature
missing there is invisible rather than refused.

## Add a stored record type

State is a cache over JSON files. There is no migration system; a new field must deserialize
from records written before it existed.

**Read first:** `StorableEntity` and `StorageBackend` in
[`src/storage/filesystem.rs`](../../src/storage/filesystem.rs).

| Order | File | Change |
| --- | --- | --- |
| 1 | your module | Define the type and implement `StorableEntity`; `id()` becomes the filename. |
| 2 | your module | Define the store and back it with one of the filesystem storages. |
| 3 | `src/config/types.rs`, `src/config/bootstrap.rs` | Add the path to `StoragePaths` with a default, resolved relative to the configuration directory like the others. |
| 4 | `config/examples/config.example.toml` | Add it under `[storage_paths]`. |
| 5 | your type | Encrypt sensitive fields with `#[serde(with = "crate::encryption::serde_encrypted::string")]` or its `option_string` variant. |
| 6 | `src/server/orchestrator.rs` | Open the store at startup, and if running components cache the records, subscribe to its events (`subscribe()`) so edits apply without a restart. |
| 7 | `docs/CONFIGURATION_REFERENCE.md` | Document the storage path. |

**Tests:** unit tests for load, save, and a record written without the newest field.

**Watch for:**

- Give every new field `#[serde(default)]`, or loading an existing record fails.
- `StorableEntity::migrate_raw_json` is the hook for renaming or removing a field. It runs
  on the raw JSON before deserialization. `on_load` normalises after deserialization.
- If `id()` is itself a credential, as a session token is, set
  `StorableEntity::ID_IS_SECRET`. Storage then logs only the id's first characters,
  including in file paths. Use `loggable_id` for any log line of your own that names the id.
- A record that should be tenant-ownable needs an optional tenant id; absent means
  appliance-wide.
- Decide whether the storage export ([`src/export/redact.rs`](../../src/export/redact.rs))
  should exclude or redact the new directory. A directory holding credentials, their
  hashes, key material, people or captured traffic goes in `EXCLUDED_DIRS`. Otherwise check
  that every credential field's name contains one of the `SECRET_KEY_MARKERS`, that any
  field holding user content is in `CONTENT_KEYS`, and that personal fields match
  `PII_KEYS` or `PII_KEY_MARKERS`. Only JSON and JSON Lines files are ever exported.

## Add a dashboard page

**Read first:** an existing page folder under `www/default/src/pages/`, and
[`www/default/AGENTS.md`](../../www/default/AGENTS.md).

| Order | File | Change |
| --- | --- | --- |
| 1 | `www/default/src/api.ts` | Add the API calls. Pages do not call `fetch` directly. |
| 2 | `www/default/src/pages/<Name>/` | Add the page. Keep the entry file orchestration-focused, with sections, hooks, and helpers beside it. |
| 3 | `www/default/src/routes.ts` | Register the route. |
| 4 | the page | Give every interactive element a `data-testid` following the [convention](../../ui-tests/README.md). |
| 5 | `ui-tests/specs/` | Add a spec. |
| 6 | `www/default/AGENTS.md` | Record any page requirement a future change must preserve. |

**Tests:** Jest for helpers and hooks; a Playwright spec for the page.

**Watch for:** gate controls on the permissions from `PermissionsContext`. A view-only user
should see the data and not the mutating controls.

## Add an outbound call

Any new call Agent Stream makes to an address an operator or a payload can influence.

| Order | File | Change |
| --- | --- | --- |
| 1 | `src/url_validation.rs` | Validate the configured URL at save time with the matching `validate_*_url` function. |
| 2 | `src/http_client.rs`, `src/outbound_fetch.rs` | Send through a builder that checks every resolved address at connect time and follows no redirects: `with_strict_validating_resolver` for a user-supplied endpoint that must never reach an internal network (strict policy: no loopback, private, link-local or metadata address; for example Langfuse and the LLM connection test), or `with_service_endpoint_resolver` for an operator-configured service that may sit on a private network (no loopback, unspecified, link-local or metadata address; for example Judge, Jury and the response-cache embedder). Or fetch through `fetch_public_bounded`. The builder table at the top of `src/http_client.rs` lists every builder's check and proxy behaviour. |
| 3 | The owning doc | Document the destination and what it receives. |

**Tests:** unit tests that private, loopback, link-local, and cloud-metadata addresses are
refused.

**Watch for:** do not build a `reqwest::Client` directly for a target that is not a fixed
constant. A hostname that passes a check at save time can resolve to an internal address on
the next lookup, which is why validation happens in the resolver. A connect-time check
ignores `HTTP_PROXY` and `HTTPS_PROXY`, because a proxy would resolve the host itself, so
the new destination needs direct egress from the appliance. reqwest does not call the
resolver for an IP-literal URL, so validate IP literals before sending.

## Related

- [`ARCHITECTURE.md`](../../ARCHITECTURE.md): the map this page assumes.
- [`TESTING.md`](TESTING.md): which test layer each change belongs in.
- [`DEVELOPMENT.md`](DEVELOPMENT.md): running and debugging locally.
- [`CONTRIBUTING.md`](../../CONTRIBUTING.md): what a contribution has to include.
