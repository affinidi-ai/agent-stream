# Surface Templates

Each `*.json` file here is a builtin **Surface template**, seeded at startup into the
Surface template store (`[storage_paths] surface_templates`, default
`../_storage/surface_templates`). A template is a portable snapshot of a Surface
configuration; the dashboard applies one to start a new Surface on the canvas or to add
elements to the Surface being edited.

The store is served by the Management API under `/v1/pipe-templates` (list, create,
import, read, update, delete, export). The code calls these "pipe templates"
([`src/pipe_templates/`](../../../src/pipe_templates/)).

## File shape

```jsonc
{
  "$schema": "https://fabric.affinidi.io/schemas/pipe-template/v1.json",
  "id": "builtin-...",          // stable id; also the on-disk filename
  "name": "Human name",
  "kind": "full",               // "full" or "partial" (default "partial")
  "description": "one-liner",
  "details": "longer markdown shown when expanded",
  "starter_hint": "callout text shown on the canvas after applying",
  "icon": "bolt",               // FontAwesome name, no `fa-` prefix
  "tags": ["llm", "starter"],   // see Tags below
  "author": "system",
  "builtin": true,
  "sort_priority": 10,          // lower sorts first
  "pipe": { /* opaque Surface snapshot, see below */ }
}
```

`$schema` is a schema identifier (`pipe-template/v1`) recorded with the template. It is
not a URL to fetch, and Agent Stream does not validate against it.

### Tags

| Tag | Effect in the dashboard |
| --- | --- |
| `starter` | Lists the template in the new-Surface starter picker, unless its `kind` is `partial` |
| `ide` | Offers the template on the IDE Surface editor; LLM Surface editors hide it |

Other tags (`llm`, `blank`, `governed`, provider names) are descriptive.

## `pipe` snapshot

The `pipe` object is the dashboard's Surface form payload. Agent Stream stores it as
opaque JSON; only the dashboard knows its shape. For an LLM Surface it is the flat form
(`provider`, `model`, `endpoint_url`, `route`, rate-limit, cost-tracking, policy,
Prompt Guard, Judge and Jury fields, optionally `variants`). For an IDE Surface it holds
`pipe_type: { "type": "ide_catalog", "config": { "members": [] } }` plus any front-door
blocks such as `opa_policy` and `rate_limit`.

The snapshot may contain placeholder tokens the dashboard fills in when the template is
applied:

| Token | Filled with |
| --- | --- |
| `$SURFACE_NAME` | the new Surface name |
| `$SURFACE_ROUTE` | the chosen route |
| `$SURFACE_ENDPOINT` | the Upstream URL |

## Template kind: `full` vs `partial`

| `kind` | Behaviour on apply |
| --- | --- |
| `full` | Replaces the whole Surface from the `pipe` snapshot. A `full` template may also carry a `canvas` blob and Upstream `variants` inside `pipe` (alias-addressed provider, model and endpoint overrides). |
| `partial` | Does not replace the Surface. Merges the `items[]` bundle onto the current Surface (additive, no overwrite prompt). Partial templates never appear in the starter picker. |

### `items[]` (partial templates)

Each item is one canvas element placed onto the current Surface:

```jsonc
{
  "scope": "middleware",        // pipe | source | upstream | middleware
  "kind": "pipe-rate-limit",    // element kind the dashboard maps to form fields
  "address": "…",               // optional alias/anchor address
  "config": { /* partial element config, merged onto the element's defaults */ }
}
```

Recognised `kind`s: `pipe-body`, `pipe-source`, `pipe-upstream`, `pipe-rate-limit`,
`pipe-cost-tracking`, `pipe-override-policy`, `pipe-prompt-guard`, `pipe-judge`,
`pipe-jury`. Unknown kinds are skipped on apply.

## Seeding rules

- At startup every `*.json` in this directory (copied to `<config_dir>/surface_templates/`)
  is stamped `builtin: true` and written to the store as `<id>.json`. A file whose `id` is
  empty or cannot be a single file name in the store (it is `.` or contains `/`, `\`, `..`
  or NUL) is skipped with a warning; the other files still seed.
- A stored copy that still has `builtin: true` is rewritten from the seed at startup when
  its content differs, so corrected builtins ship without a migration. With encryption at
  rest enabled, a builtin already in the store is not rewritten; delete its stored file to
  re-seed it. Set `builtin: false` on a stored
  copy to adopt it: the seeder then leaves it alone, and it becomes editable and deletable.
- Builtins cannot be changed or removed through `PUT` or `DELETE /v1/pipe-templates/{template_id}`
  (`403`). Templates created, imported or updated through the API are always stored with
  `builtin: false`.
- Reading and exporting templates requires `pipes.view`; creating, importing and updating
  requires `pipes.edit`; deleting requires `pipes.delete`.
- An imported template keeps its `id` only when it uses letters, digits, `-` and `_` (at most
  128 characters); any other non-empty id is rejected.

## Files

| File | Surface | Kind | Notes |
| --- | --- | --- | --- |
| `blank_llm_pipe.json` | LLM | not set (`partial`) | Empty LLM Surface starter |
| `openai_chat_pipe.json` | LLM | not set (`partial`) | OpenAI chat completions starter (GPT-4o) |
| `anthropic_claude_pipe.json` | LLM | not set (`partial`) | Anthropic Claude messages starter |
| `multi_provider_llm_pipe.json` | LLM | full | Base OpenAI Upstream plus OpenAI and Anthropic Upstream variants |
| `guardrails_pack_partial.json` | LLM | partial | Adds rate limit, cost tracking and Prompt Guard |
| `blank_ide_surface.json` | IDE | full | Empty IDE model catalogue; add LLM Surfaces as members on the canvas |
| `governed_ide_surface.json` | IDE | full | IDE catalogue with front-door OPA policy (policy left to pick) and rate limiting (60 requests and 100,000 tokens per minute) |

## Related

- [`config/examples/README.md`](../README.md): the other example configuration files
- [IDE Surfaces](../../../docs/IDE_SURFACES.md)
- [Configuration reference](../../../docs/CONFIGURATION_REFERENCE.md)
