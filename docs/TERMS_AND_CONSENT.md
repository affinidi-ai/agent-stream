# Terms and Consent

How Agent Stream requires dashboard users to accept Terms before they use the management
API, and how it keeps evidence that they did. For the operator task, use the hosted
[require Terms before dashboard access](https://docs.affinidi.com/products/affinidi-trust-fabric/agent-stream/how-to-guides/security/require-terms-before-dashboard-access/)
guide.

Implemented in [`src/terms/`](../src/terms/), with session gating in
[`src/auth_manager/middleware.rs`](../src/auth_manager/middleware.rs). The vocabulary
(Terms version, Terms version ID, Acceptance Record, last-known-good metadata) is defined
in [`../CONTEXT.md`](../CONTEXT.md#terms-and-consent).

## Turning it on

Terms are enforced when `terms` is `true` in `agent-stream.json`. The default is `false`:
no user is asked to accept anything, every status check reports no consent required, and
management access tokens behave as without Terms.

```json
{
  "terms": true,
  "affinidi_terms_url": "https://well.affinidi.io/terms/v1/current.json"
}
```

`affinidi_terms_url` is where the current Affinidi Terms metadata is fetched from, and is
required when `terms` is `true`. It must be an absolute HTTPS URL with a host and no
embedded credentials; debug builds also accept loopback HTTP for local testing. Both
settings are read at startup, so changing them needs a restart. See
[`CONFIGURATION_REFERENCE.md`](CONFIGURATION_REFERENCE.md).

## Two documents

| Document | Published by | Document id |
| --- | --- | --- |
| Affinidi Terms | Affinidi, fetched from `affinidi_terms_url` | `affinidi-terms` |
| Customer Terms | The appliance operator, from the dashboard | `customer-terms` |

Either, both, or neither may be current. A user accepts at most two versions at once, one
of each.

## Versions

A Terms version is immutable. Its `version_id` is the opaque identity used for every
acceptance and staleness check; its `version` is the label people read.

**Customer Terms** have one mutable draft. Publishing makes the draft an immutable
version with a new `version_id`, records who published it and when, and makes it current.
A `version` label that has already been published is rejected, so changed content or a
changed URL needs a new label. Deactivating stops Customer Terms from being required
without deleting published versions or Acceptance Records; requiring them again means
publishing a new version. The appliance does not detect changes to content hosted at an
unchanged URL.

**Affinidi Terms** arrive as metadata from `affinidi_terms_url`, at most 64 KiB, with
redirects refused. The provider rejects an update that would rewrite history:

| Rejected update | Why |
| --- | --- |
| A lower `publication_sequence` than the current one | A rollback |
| A non-positive sequence | Invalid |
| A new sequence that reuses the current `version_id` | A changed document under an old identity |
| A `version_id` seen earlier brought back | A reused identity |

Affinidi Terms metadata is read-only in the appliance.

## Refresh and outage behaviour

The Affinidi metadata is refreshed right after startup and then on a background task, at a
random point between 3,300 and 3,600 seconds so appliances do not refresh in step. Metadata
becomes active only after it is validated and written durably under
`_storage/terms/affinidi/`.

`AFFINIDI_TERMS_REFRESH_INTERVAL_SECONDS` sets a fixed delay between refresh attempts, for
tests and diagnostics. Release builds clamp it to 60 to 3,600 seconds; debug builds allow 1
to 3,600. A missing, invalid, or zero value uses the random interval.

A failed refresh keeps the last-known-good metadata, without expiry, and reports the
provider as degraded. The appliance starts without waiting for the first refresh.

| Endpoint or metric | Reports |
| --- | --- |
| `GET /v1/terms/provider-health` | Provider state and last successful refresh. Does not affect readiness. |
| `agent_stream_affinidi_terms_refresh_total` | Refresh outcomes |
| `agent_stream_affinidi_terms_refresh_duration_seconds` | Refresh duration |
| `agent_stream_affinidi_terms_cache_age_seconds` | Age of the cached metadata |
| `agent_stream_affinidi_terms_publication_sequence` | Active publication sequence |

## Who has to accept what

| Context | A current version is required when |
| --- | --- |
| Passkey registration | The user has not accepted that exact version |
| Login, version flagged `requires_reconsent` | The user has not accepted that exact version |
| Login, any other version | The user has never accepted any version of that document |

An ordinary new version therefore does not interrupt existing users; one flagged
`requires_reconsent` is enforced at their next login. Sessions already allowed are not
interrupted.

## Accepting

`POST /v1/terms/acceptances` takes the versions the user is accepting:

- Every submitted version must be marked accepted.
- At most two versions may be submitted.
- The submitted set must equal the required set exactly.

If the requirement changed while the user was reading, the request fails with `409`
`TERMS_VERSION_STALE` rather than recording an outdated version. Acceptance unblocks every
pending session of that user.

Each accepted version produces an immutable **Acceptance Record**: the user, the appliance
(`appliance_id`, the appliance's issuer DID), the document, the exact `version_id`, its
label, title, and URL, the server-recorded time, and whether it happened at registration or
login. Registration records acceptance before the passkey user is saved; if saving the
user then fails, the log carries the user id so the retained record can be correlated.

## Gating the session

A user who logs in with Terms outstanding gets a **consent-pending session**. It is
authenticated, but reaches only:

- `/v1/terms/applicable`, `/v1/terms/status`, and `/v1/terms/acceptances`;
- `/auth/check`, `/auth/logout`, and `/saml/logout`;

each also under the `/api` prefix. Any other protected route answers `403`
`TERMS_ACCEPTANCE_REQUIRED`. Public endpoints stay reachable. Once the required versions are
accepted, the same session reaches everything its role allows.

A management access token is gated on behalf of its bound user. While that user has Terms
outstanding, every call made with the token answers `403` `TERMS_ACCEPTANCE_REQUIRED` with
the message "Sign in to Agent Stream as this access token's owner, accept the required
Terms and Conditions, then retry." Access resumes after the user accepts; no new token is
needed. Enabling `terms`, or publishing a version that requires re-consent, can therefore
block automation until each bound user signs in and accepts.

When Terms state cannot be verified, new authentication, consent-pending sessions, and
access tokens fail closed with `503` `TERMS_OPERATIONAL_FAILURE`. Sessions already allowed
keep working.

## Errors

| Status | Code | Meaning |
| --- | --- | --- |
| `403` | `TERMS_ACCEPTANCE_REQUIRED` | Acceptance is outstanding |
| `409` | `TERMS_VERSION_STALE` | A submitted version is no longer current |
| `503` | `TERMS_OPERATIONAL_FAILURE` | Status cannot be verified |
| `400` | `TERMS_INVALID` | Invalid input; `message` describes the validation failure |
| `409` | `TERMS_DRAFT_REQUIRED` | Publish was requested with no Customer Terms draft saved |
| `404` | `TERMS_DISABLED` | Terms are off (`terms` is `false`); returned by the Terms definition, provider-health, draft, publish and deactivate routes |

Operational errors do not expose internal detail.

## Management API

| Route | Permission | Purpose |
| --- | --- | --- |
| `GET /v1/terms/applicable` | None (public) | Current versions, for the registration page |
| `GET /v1/terms/provider-health` | None (public) | Affinidi provider state (`404` `TERMS_DISABLED` while `terms` is `false`) |
| `GET /v1/terms/status` | Any session, including consent-pending | Whether this user must accept, and what |
| `POST /v1/terms/acceptances` | Any session, including consent-pending | Accept the required versions |
| `GET /v1/terms` | `terms.view` | Both documents, the draft, and version history |
| `PUT /v1/terms/customer/draft` | `terms.edit` | Save the Customer Terms draft |
| `POST /v1/terms/customer/publish` | `terms.edit` | Publish the draft as a new version |
| `POST /v1/terms/customer/deactivate` | `terms.edit` | Stop requiring Customer Terms |

`terms.view` and `terms.edit` default to `administrator` (see [`RBAC.md`](RBAC.md)).

## Storage and backup

Terms state is stored under `storage_paths.terms` (default `_storage/terms/`), resolved
relative to the bootstrap config directory:

| Directory | Holds |
| --- | --- |
| `affinidi/` | Last-known-good Affinidi Terms metadata, with rollback protection and seen version ids |
| `customer/` | The draft and the immutable published history |
| `acceptances/` | Acceptance Records |

Back up and restore the whole directory with the rest of the appliance state. Acceptance
Records are bound to the appliance's issuer DID: preserve it when restoring. A changed DID
means retained records no longer satisfy acceptance, so users accept again at their next
login and access tokens need their bound user to accept for the new identity. Acceptance
Records survive user deletion.

Loading is strict: an unreadable, malformed, or undecryptable file blocks Terms
verification rather than replacing a valid cache with a partial one. Validation also checks
publication invariants, immutable URLs, and every Customer Terms acceptance against its
published version. After initialisation, Customer Terms and Acceptance Records are served
from validated memory; writes persist atomically before the cache changes. Manual edits to
healthy Terms storage need a restart or a promotion to load; `config.reload` does not reload
these stores. Promotion to Active re-opens and validates them on their next use.
A store that failed to initialise retries on later Terms operations.

To recover an invalid Affinidi cache, restore a known-good copy from backup or repair it
while preserving the publication sequence and seen version ids. Deleting
`affinidi/current.json` resets rollback protection, so do it only after verifying the
authoritative upstream publication. Never delete Acceptance Records to recover the
provider.

## Related

- [`../CONTEXT.md`](../CONTEXT.md#terms-and-consent): the Terms vocabulary.
- [`RBAC.md`](RBAC.md): `terms.view`, `terms.edit`, and the roles that apply after
  consent.
- [`ACCESS_TOKENS.md`](ACCESS_TOKENS.md): access tokens gated on their bound user's
  acceptance.
- [`CONFIGURATION_REFERENCE.md`](CONFIGURATION_REFERENCE.md): `terms`,
  `affinidi_terms_url`, and `storage_paths.terms`.
- [`ENCRYPTION_AT_REST.md`](ENCRYPTION_AT_REST.md): backups that carry Terms state.
