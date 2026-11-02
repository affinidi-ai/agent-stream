# Prompts

How Agent Stream stores versioned Prompt templates, how a request references
one instead of sending the text, how a template is rendered, and the
management API that maintains them.

For the product concepts, see the hosted
[Prompt management](https://docs.affinidi.com/products/affinidi-trust-fabric/agent-stream/concepts/prompt-management/)
page. This page documents the implementation in
[`src/prompts/`](../src/prompts/), the prompt-reference stage in
[`src/pipes/handlers/http_handlers.rs`](../src/pipes/handlers/http_handlers.rs)
and the management handlers in
[`src/identity/handlers/prompts.rs`](../src/identity/handlers/prompts.rs).

## Moving parts

| Part | What it is |
| --- | --- |
| Prompt | A named record with one or more versions (`Prompt` in [`src/prompts/types.rs`](../src/prompts/types.rs)). |
| Version | A numbered list of chat messages whose `content` may hold `{{variable}}` placeholders (`PromptVersion`). |
| Prompt reference | A `prompt` block in a request body naming a Prompt, optionally a version, and variable values (`PromptReference` in [`src/prompts/expand.rs`](../src/prompts/expand.rs)). |
| Prompt store | `FileSystemPromptStore` ([`src/prompts/store.rs`](../src/prompts/store.rs)), one process-wide instance. |

## The Prompt record

```json
{
  "id": "greeter",
  "name": "Greeter",
  "description": "Support greeting",
  "tenant_id": "tenant-a",
  "default_version": 2,
  "versions": [
    { "version": 1, "messages": [{ "role": "system", "content": "You are helpful." }] },
    {
      "version": 2,
      "label": "prod",
      "messages": [
        { "role": "system", "content": "You are {{persona}}." },
        { "role": "user", "content": "Hello, I am {{name}}." }
      ]
    }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `id` | Caller-chosen slug: 1 to 128 characters of letters, digits, `_` and `-` (`is_valid_prompt_id`). It is also the storage file name. |
| `name` | Required, non-blank. |
| `description` | Optional. |
| `status` | `enabled` (default), `disabled` or `deleted`. A disabled Prompt is left out of the list and is not resolved by a request. A deleted Prompt is a tombstone: kept on disk, hidden from every read. |
| `tenant_id` | The owning tenant; absent for an appliance-wide Prompt. A tenant token always creates in its own tenant, a dashboard session may name a tenant, and an appliance-wide token cannot. |
| `versions[]` | Each with `version` (a number unique within the Prompt), `messages` (`role` and `content`), an optional `label`, and `created_at`. |
| `default_version` | The version used when a reference names none. Must exist when set. |
| `test_fixture` | Marks an ephemeral test Prompt. |
| `created_at`, `updated_at` | Set by the server. |

`Prompt::validate` refuses a blank `id` or `name`, a duplicate version number,
a version with no messages, a message with a blank `role`, and a
`default_version` that names no version.

### Storage

Prompts are stored by `FileSystemPromptStore` as one `{id}.json` per Prompt in
the directory `[storage_paths] prompts` names (default `../_storage/prompts`,
relative to `config.toml`). The in-memory cache is authoritative and every
change is written to disk at once, like the other stores; see
[ARCHITECTURE.md](../ARCHITECTURE.md#state-and-storage). The store is opened at
startup and registered globally (`set_global_prompt_store`) so the data-plane
handler can resolve a reference.

## Referencing a Prompt in a request

A chat request can carry a `prompt` block instead of, or as well as,
`messages`:

```json
{
  "model": "gpt-4o",
  "prompt": { "id": "greeter", "version": 2, "variables": { "persona": "a support agent", "name": "Ada" } },
  "messages": [{ "role": "user", "content": "Where is my order?" }]
}
```

| Field | Meaning |
| --- | --- |
| `id` | The Prompt id. Required; checked against `is_valid_prompt_id` before any lookup. |
| `version` | Optional version number. |
| `variables` | Optional object of values. A string is inserted verbatim; any other JSON value is inserted as its JSON text. |

### Where it runs

The prompt-reference stage runs in `handle_chat_completions` after the team
gate, usage limits and model allow-list, and before document ingestion, the
guards and the response-cache lookup (see
[ARCHITECTURE.md](../ARCHITECTURE.md#front-door-and-gates)):

1. `take_prompt_reference` removes the `prompt` block from the body, so it
   never reaches the provider.
2. The store returns the Prompt only if it is not deleted (`get_active`).
3. The Prompt must be one the Surface may reference
   (`tenancy::can_reference(surface tenant, prompt tenant)`): a tenant's Surface
   may use its own tenant's Prompts and appliance-wide ones; an appliance-wide
   Surface may use appliance-wide Prompts only.
4. The selected version is rendered with the supplied variables.
5. `inject_messages` puts the rendered messages **before** any `messages` the
   client sent, so a client can append turns to a templated system prompt.

Every later stage, including Prompt Guard, the Judge and the cache key, sees the
rendered messages. Identical references with identical variables therefore
share a cache entry.

On a request an IDE Surface dispatched, the stage runs on the member LLM
Surface, so the member's tenant decides which Prompts are visible.

### Refusals

| Status | Message | Cause |
| --- | --- | --- |
| 400 | `invalid prompt reference: …` | The block is not an object with a string `id`, or a field has the wrong type |
| 400 | `prompt reference id must be 1–128 chars of [A-Za-z0-9_-]` | The id fails `is_valid_prompt_id` |
| 400 | `unknown prompt '{id}'` | No such Prompt, it is deleted, **or it belongs to another tenant** |
| 400 | `prompt has no versions` | The Prompt has no versions |
| 400 | `prompt has no version {n}` | The requested (or default) version does not exist |
| 400 | `missing prompt variables: a, b` | Placeholders with no value, all listed at once |
| 500 | `prompt store not configured` | The store was not opened |

All 400s use `type: invalid_request_error`. Another tenant's Prompt gets exactly
the same `unknown prompt` answer as a missing one, so a reference cannot be used
to discover which ids exist.

## Rendering

`Prompt::render` ([`src/prompts/types.rs`](../src/prompts/types.rs)) picks the
version, then renders each message's `content` with `render_template`:

- **Version choice** (`resolve_version`): the requested version, else
  `default_version`, else the highest version number.
- **Placeholders** are `{{name}}`; whitespace inside the braces is trimmed, so
  `{{ name }}` is the same variable.
- **Values** are substituted in one left-to-right pass. A value that itself
  contains `{{` is not expanded again.
- **Missing variables** are collected across every message and reported
  together. Unused variables are ignored.
- **An unclosed `{{`** is left in the text literally, along with everything
  after it.
- Each rendered message is `{ "role", "content" }`, with `content` a string.

`PromptVersion::variables` lists the distinct placeholder names of a version in
first-seen order; the render endpoint returns it so a playground can show the
expected inputs.

## Management API

The routes are registered in
[`src/identity/router.rs`](../src/identity/router.rs) under the management API
(`/api/v1`), behind session or Management PAT authentication. Each handler loads
the caller and checks its role against the RBAC feature.

| Method and path | Feature | Behaviour |
| --- | --- | --- |
| `GET /api/v1/prompts` | `prompts.view` | Every non-deleted Prompt the caller may see |
| `GET /api/v1/prompts/{id}` | `prompts.view` | One Prompt; 404 when missing, deleted or not visible |
| `POST /api/v1/prompts` | `prompts.edit` | Create with the body's `id` |
| `PUT /api/v1/prompts/{id}` | `prompts.edit` | Replace the whole record |
| `DELETE /api/v1/prompts/{id}` | `prompts.delete` | Tombstone; 204 |
| `POST /api/v1/prompts/{id}/render` | `prompts.view` | Render with `{ version?, variables }`; returns `{ messages, variables }` |

Default roles ([`src/rbac/`](../src/rbac/)): `prompts.view` is **user**;
`prompts.edit` and `prompts.delete` are **administrator**. See
[RBAC.md](RBAC.md).

### Create

`create_prompt` validates the id (400), resolves `tenant_id` with
`tenant_for_create` (a tenant token creates in its own tenant and is refused
(403) if the body names another; an appliance-wide token may not set one (403);
a session may set it), checks
the id is inside the token's resource scope (403), refuses an id held by a
non-deleted Prompt (409), applies the appliance's `prompts` count limit (403),
validates the record (400) and stamps `created_at` and `updated_at`. An id
whose Prompt was deleted can be created again; the new record replaces the
tombstone.

### Update

`update_prompt` loads the existing, non-deleted Prompt (404), checks the caller
may change it (403, see _Visibility_), then saves the body with the path's `id`, the stored
`tenant_id` and `created_at`, and a new `updated_at`, after `validate`. The body
replaces the record, versions included: a client adds a version by sending the
full list with the new one appended.

### Visibility

`prompt_allowed` decides what a caller may read or render:

- an appliance-wide Prompt (no `tenant_id`) is visible to every caller;
- a tenant's Prompt is visible to callers with no tenant context, and to a
  tenant token of the same tenant whose resource scope admits
  `prompts:{id}` (`scope_allows_resource` with `ResourceKind::Prompts`).

`prompt_writable` decides what a caller may update or delete. It applies the
same tenant and scope rules through `tenancy::can_mutate`, without the
appliance-wide exception: an appliance-wide Prompt is rendered for every tenant,
so only a caller with no tenant context may change or delete it, and a tenant
token gets 403. An appliance-wide token narrowed to listed resources also gets
403 on every update or delete, because a resource scope without a tenant admits
no Prompt id.

See [ACCESS_TOKENS.md](ACCESS_TOKENS.md) for tenant context and scope patterns.

## Known limitations

- **Versions are not immutable.** `PUT` replaces the record, so a client can
  change or remove an existing version's messages. Version numbers identify
  entries; they do not preserve history.
- **No per-request version pinning by label.** A reference selects a version by
  number only; `label` is descriptive.
- **Text-only messages.** A version's `content` is a string; content-part arrays
  (images, files) cannot be templated.
- **One message shape.** Rendered messages carry only `role` and `content`, so
  a template cannot hold tool calls or names.

## Related

- [ARCHITECTURE.md](../ARCHITECTURE.md#front-door-and-gates): where the
  prompt-reference stage sits.
- [RESILIENCE_AND_CACHING.md](RESILIENCE_AND_CACHING.md): the response cache
  that keys on the rendered messages.
- [GUARDRAILS.md](GUARDRAILS.md) and [PROMPT_GUARD.md](PROMPT_GUARD.md): the
  stages that inspect the rendered messages.
- [RBAC.md](RBAC.md): `prompts.view`, `prompts.edit`, `prompts.delete`.
- [ACCESS_TOKENS.md](ACCESS_TOKENS.md): Management PATs, tenants and resource
  scopes.
- [IDE_SURFACES.md](IDE_SURFACES.md): dispatched requests and the member's
  tenant.
