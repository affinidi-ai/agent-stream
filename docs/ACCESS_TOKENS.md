# Access Tokens

Management access tokens (personal access tokens, PATs) let a service call the management
API without an interactive passkey, SAML or OIDC sign-in. This page covers the token contract,
expiry, delegation and rotation, resource patterns, and tenant ownership of management
records. For concepts, use the hosted
[security and access control](https://docs.affinidi.com/products/affinidi-trust-fabric/agent-stream/concepts/security-and-access-control/)
page.

Implemented in [`src/access_tokens/`](../src/access_tokens/), with authentication and
resource-scope enforcement in
[`src/auth_manager/middleware.rs`](../src/auth_manager/middleware.rs),
[`src/auth_manager/pat.rs`](../src/auth_manager/pat.rs), and
[`src/auth_manager/resource_scope.rs`](../src/auth_manager/resource_scope.rs), and tenancy
in [`src/tenancy/`](../src/tenancy/).

Management access tokens are distinct from data-plane API keys, which authenticate
callers on a Surface (see [`SOURCE_AUTH.md`](SOURCE_AUTH.md)).

## Token contract

| Property | Value |
| --- | --- |
| Secret | `aspat_` followed by 32 random bytes, base64url without padding. Returned once, at create or rotate. Secrets issued with the earlier `atgpat_` prefix are still accepted, so secret scanners should match both prefixes. |
| Record id | `asat_` followed by a UUID. Tokens created before the rename keep their `atgat_` id. |
| At rest | SHA-256 hash of the full secret only. |
| Bound user | `user_id`: the user the token acts as. That user's current role is the token's ceiling. |
| Scopes | `scopes`: an allow-list of RBAC permission names. Empty means the bound user's full role. |
| Resource restriction | Optional `resource_pattern` and `required_headers`; see [Resource patterns](#resource-patterns). |
| Expiry | Optional `expires_at`, fixed at creation. |
| `last_used_at` | Updated on use; writes are coalesced to at most one per 60 seconds. Using a token on a Standby never writes it back, and only the ready Active instance records the use, so a Standby cannot overwrite a revocation. Tokens are re-read on promotion ([what promotion does](CONFIGURATION_RELOAD.md#what-promotion-does)), so a revocation is guaranteed once `GET /api/v1/health` returns `200`, not for a request that reaches the instance directly while it is activating. A management write made through a Standby (update, rotate) still goes to shared storage from the Standby's copy; see [server mode](CONFIGURATION_RELOAD.md#server-mode). |

The caller sends the secret as `Authorization: Bearer aspat_...`. When no valid session
matches the bearer, `require_session_auth` tries it as an access token. Authentication
fails (`401`) when the token is unknown, revoked, or expired, when any ancestor in its
delegation chain is inactive, or when its bound user is no longer approved. Deleting a user
revokes every token bound to them, with the tokens delegated from those, so approving a kept
OIDC or SAML record again does not bring them back. A stored
resource scope that no longer compiles makes the token unusable rather than unscoped.

Effective permissions on a feature-gated route are the bound user's role intersected with
the token's scopes; see [`RBAC.md`](RBAC.md#access-tokens-and-roles). When Terms are
enabled, the bound user must have accepted the current Terms, or every call answers `403`
`TERMS_ACCEPTANCE_REQUIRED` (see [`TERMS_AND_CONSENT.md`](TERMS_AND_CONSENT.md)).

## Management API

| Method | Path | Permission | Purpose |
| --- | --- | --- | --- |
| `GET` | `/api/v1/access-tokens` | `access_tokens.view` | List token metadata, newest first |
| `POST` | `/api/v1/access-tokens` | `access_tokens.edit` | Create; returns the secret once, `201` |
| `GET` | `/api/v1/access-tokens/{id}` | `access_tokens.view` | Read one token's metadata |
| `PUT` | `/api/v1/access-tokens/{id}` | `access_tokens.edit` | Replace name, description, scopes, and resource restriction |
| `POST` | `/api/v1/access-tokens/{id}/rotate` | `access_tokens.edit` | Replace the secret; returns the new secret once, `200` |
| `DELETE` | `/api/v1/access-tokens/{id}` | `access_tokens.delete` | Revoke, with every descendant; `204` |

All three permissions default to `administrator`. Metadata never includes the hash or the
secret. Create, update, rotate, and revoke are logged at `info` with the actor and token
id, never the secret.

### Create

```http
POST /api/v1/access-tokens
Content-Type: application/json

{
  "name": "metrics-reader",
  "subject_user_id": "svc-metrics",
  "scopes": ["metrics.view"],
  "expires_at": "2027-06-30T00:00:00Z"
}
```

| Field | Required | Meaning |
| --- | --- | --- |
| `name` | Yes | Non-blank display name. |
| `description` | No | Free text. |
| `scopes` | No | Permission names. Each must be a key in the RBAC configuration, or the request is refused with `400` `unknown scope`. |
| `resource_pattern`, `required_headers` | No | See [Resource patterns](#resource-patterns). |
| `expires_at` | No | Exact RFC 3339 timestamp. Omit for a token that never expires. |
| `subject_user_id` | No | Bind the token to another existing user, such as a dedicated service account. Omit to bind it to the caller. |

The request rejects unknown fields, so a relative expiry such as a day count is refused.

Create resolves the issuer (the caller) and the subject from the user store and requires
both to be approved: a subject that is not approved answers `403`, an unknown subject
`400`. Every requested scope must be held by both the issuer's and the subject's current
role. With no scopes, the subject's role must not rank above the issuer's. `created_by`
always records the issuer.

### Least privilege

To give a service read-only metrics access, provision a dedicated, approved service user
with the lowest role that covers the job (`user` holds `metrics.view` by default), then
create a token bound to it and scoped to `["metrics.view"]`, as in the example above. The
token reads `GET /v1/pipes-metrics` (under the management API prefix, `/api` in the
example configuration) and is refused with `403` on feature-gated routes that
need another permission. Binding to a service account rather than a person means the token
survives staff changes; demoting or disabling the service account takes effect on the next
request.

### Expiry

`expires_at` must be in the future and at most 3650 days after creation; otherwise `400`.
It cannot be changed after creation. An expired token fails authentication and reports
`active: false`.

### Update

`PUT` replaces `name`, `description`, `scopes`, `resource_pattern`, and `required_headers`.
The bound user and expiry cannot change. Scopes are checked against both roles again. A
revoked token answers `409`.

### Rotate

Rotate replaces the secret on the same record. The id, subject, scopes, expiry, resource
restriction, and delegation lineage are unchanged, so descendants keep working.
`rotation_generation` increments and `rotated_at` and `rotated_by` are stamped. The old
secret stops authenticating immediately on the instance that rotated it. A Standby keeps
authenticating the old secret from its own copy until it is promoted
([server mode](CONFIGURATION_RELOAD.md#server-mode)). A revoked or expired token, an inactive
lineage, or a rotation that lost a concurrent race answers `409`.

Rotation is not a zero-downtime roll. To roll without an outage, create a second token,
deploy and verify it, then revoke the first. On a suspected leak, revoke rather than
rotate: revocation cascades to descendants, rotation does not touch them.

## Delegation

A token that holds `access_tokens.edit` can create a child token:

- The child is bound to the same user; naming another `subject_user_id` is refused with
  `403`.
- When the parent has explicit scopes, the child's scopes must be a non-empty subset of
  them.
- `parent_token_id` and `delegation_depth` record the chain, at most three hops below a
  root.
- A token with a `resource_pattern` or `required_headers` cannot create or modify tokens.
- A token can read and manage only itself and its descendants. On rotate, update, and
  revoke, any other id, including one that does not exist, answers `403`; `GET` answers
  `404`.
- Authentication walks the whole chain and fails if any ancestor is inactive, missing,
  cyclic, or inconsistent in subject, scope, or depth.
- Revoking a token revokes every transitive descendant.

Only an interactive session can create a root token or bind a token to another user.
Records without lineage fields are roots (`delegation_depth` 0).

## Resource patterns

A token can be confined to named management records of one tenant. A non-empty
`resource_pattern` uses this grammar:

```text
TENANT:${header-name}:<resource-kind>:<resource-id-pattern>
```

Several kinds share one non-capturing group:

```text
TENANT:${x-external-account}:(?:pipes:prod-.*|secrets:.*)
```

`required_headers` lists the headers the token must present on every call, each with a
validation pattern:

```json
{
  "resource_pattern": "TENANT:${x-external-account}:(?:pipes:prod-.*|secrets:.*)",
  "required_headers": [ { "name": "x-external-account", "pattern": "tenant-a" } ]
}
```

With `x-external-account: tenant-a`, the token can reach `TENANT:tenant-a:pipes:prod-chat`.
Resource ids stay their ordinary ids; the tenant comes from the validated header.

The resource kinds are `secrets`, `certificates`, `api-keys`, `pipes`, `surfaces`,
`gateways`, `connection-points`, `mediators`, `integrations`, `policy-definitions`,
`pipe-templates`, `credential-providers`, `jwt-verification-strategies`,
`oauth-identifiers`, `prompts`, `members`, and `teams`.

API key ids start with `askey_`, and keys created before the rename keep their `atgk_` id.
An `api-keys` pattern written for the `atgk_` prefix also matches a newer key: a generated
key id `askey_<uuid>` (32 lowercase hex characters) is checked as `atgk_<uuid>` as well, while
any other id, such as a Surface id referenced by API-key source authentication, is checked
only as written, so `TENANT:${h}:api-keys:atgk_.*` keeps
covering keys created after the rename. The alias only runs that way: `api-keys:askey_.*` does
not match a key with an `atgk_` id, so a token scoped that way leaves earlier keys out of
lists and is denied on them. To cover every key, use `api-keys:.*` or
`api-keys:(?:askey|atgk)_.*`. API key secrets now start with `assec_` instead of
`atgs_`; secrets issued earlier keep working.

### Validation

Create and update refuse with `400` unless:

1. Header names are valid (1 to 64 characters) and unique, case-insensitively; at most 8
   headers.
2. Header patterns compile, are at most 256 characters, and are matched fully anchored.
   A pattern that constrains nothing, such as `.*` or `.+`, is refused.
3. The resource pattern is at most 512 characters, holds exactly one `${header}`
   placeholder, and every selector starts with a resource kind above; several selectors
   sit in one non-capturing group.
4. The interpolated pattern compiles within the size limits.

A header-only token (`required_headers` without a pattern) gates requests on the header
but gains no tenant authority.

### Trusted edge for broad selectors

The token holder chooses the header value, so a header pattern that admits more than one
tenant is accepted only when an authenticated edge owns that header. Declare it in the
bootstrap config:

```toml
[tenancy.trusted_tenant_header]
header = "x-external-account"
edge_strips_client_values = true
```

This asserts that the edge removes every caller-supplied value of the header and writes
the authoritative tenant. It is read at startup. Without it, or with a different header
name or `edge_strips_client_values = false`, creating a broad-selector token is refused
with `400`, and a stored broad-selector token is refused with `403` on every request. An
exact selector, such as `tenant-a` or `tenant\.a`, needs no edge.

### Request enforcement

On each call made with a resource-restricted token, `require_session_auth`:

1. Requires every required header exactly once, matching its pattern; otherwise `403`.
2. Validates the tenant id (1 to 128 characters of `A-Z a-z 0-9 . _ : -`), escapes it, and
   substitutes it into the pattern.
3. Matches by-id routes against `TENANT:<tenant>:<kind>:<id>`. A miss answers `404` on a
   read and `403` on a write.
4. Leaves collection routes and routes whose path id is not the record id to the handler,
   which checks the caller-supplied id or filters the listing.
5. Refuses unsupported scoped routes (`404` read, `403` write) and any mutation outside the
   scoped families (`403`).

Raw header values and secrets are never logged.

## Tenant ownership

A tenant id from an access token is a management authorisation namespace. Top-level
records carry an optional `tenant_id`; absent means appliance-global:

- Surfaces (pipes) and internal surface records;
- Gateways and Mediators;
- Secrets, Certificates, Integrations, policy definitions, and Prompts;
- Credential Providers, JWT verification strategies, and OAuth Identifiers;
- Members, Teams, and operator-created Surface templates.

A tenant token reaches same-tenant and global records. Changing or deleting a Surface also
needs its owner, an administrator, or a token of the Surface's own tenant, so tenant tokens
bound to different users manage each other's same-tenant Surfaces but not global ones (see
[Surface ownership](RBAC.md#surface-ownership)). An interactive session is
appliance-wide. A record created through a tenant token is stamped with its tenant, and the
request cannot override it.

Child records take their owner's tenant and are still checked against the pattern by their
own id: Variants from their Surface, API keys from their Surface, Connection Points from
their Gateway, policy and Prompt versions from their definition, integration assignments
from their owner. Team membership requires compatible Team and Member ownership. This
appliance's own Gateway, built-in templates, and system Members and Teams stay global.

Policy definitions and Prompts are special cases: a tenant token can read global ones and
reference them, but can change or delete only its own tenant's (see
[`PROMPTS.md`](PROMPTS.md#visibility)). Policy definitions additionally cannot change
appliance-wide assignments (see [`POLICY.md`](POLICY.md#tenancy)).

### References

Before a reference is saved, the referenced record must pass both ownership and the
token's pattern:

| Owner | May reference |
| --- | --- |
| Tenant-owned | Same tenant or global |
| Global | Global only |

The check covers every Variant (including disabled ones), Gateways, Connection Points,
Credential Providers, Teams, appliance-wide policy assignments, and Integration mappings.

### Reassigning ownership

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/v1/tenant-ownership/{kind}/{id}/impact` | Incoming and outgoing references |
| `PUT` | `/v1/tenant-ownership/{kind}/{id}` | Set `{ "tenant_id": "<id>" }` or `null` |

Both require `tenant_ownership.manage` (`administrator`). Reassignment answers `409` when a
reference would become incompatible. A resource-restricted token cannot reassign
ownership. Child records move only with their parent, and system records cannot be moved.

Tenancy partitions management records, not the data plane: runtime stores, listeners,
policy compilation, and hot reload are shared.

## Operational notes

- Present tokens only over TLS.
- Keep `access_tokens.edit` administrator-only.
- After upgrading from a release that did not re-read tokens on promotion, list the access
  tokens and revoke again any that were revoked before a failover and now show as active. The
  upgrade reads token records as they are stored and does not change records written earlier.
- The test-support login (`AS_TEST_MODE` with a non-empty `AS_TEST_TOKEN`) exists for
  test rigs only; services use access tokens.

## Related

- [`RBAC.md`](RBAC.md): roles, permission keys, and how scopes intersect with roles.
- [`POLICY.md`](POLICY.md): policy definitions and appliance-wide assignments.
- [`TERMS_AND_CONSENT.md`](TERMS_AND_CONSENT.md): Terms acceptance for a token's bound
  user.
- [`SOURCE_AUTH.md`](SOURCE_AUTH.md): data-plane caller authentication.
- [`CONFIGURATION_REFERENCE.md`](CONFIGURATION_REFERENCE.md): the `[tenancy]` bootstrap
  settings.
- [`../CONTEXT.md`](../CONTEXT.md): the glossary, including Management PAT.
