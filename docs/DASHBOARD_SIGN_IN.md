# Dashboard Sign-In

How a person signs into the Agent Stream dashboard with a passkey or through SAML single
sign-on, how the resulting session is carried and expires, and the routes a signed-in user
calls for their own profile, avatar and dashboard preferences. Services that call the
management API without signing in use access tokens instead (see
[`ACCESS_TOKENS.md`](ACCESS_TOKENS.md)).

Implemented in [`src/auth/`](../src/auth/), with the session gate in
[`src/auth_manager/middleware.rs`](../src/auth_manager/middleware.rs), the profile handlers
in [`src/auth_manager/handlers.rs`](../src/auth_manager/handlers.rs), settings in
[`src/identity/handlers/settings.rs`](../src/identity/handlers/settings.rs) and
[`src/identity/handlers/user_settings.rs`](../src/identity/handlers/user_settings.rs), and
image uploads in [`src/uploads/mod.rs`](../src/uploads/mod.rs). Routes are mounted in
[`src/identity/router.rs`](../src/identity/router.rs).

Every route on this page belongs to the management API, so it is reached under that API's
route prefix (`routes` entry of type `identity_api`, normally `/api`): `/auth/login/start`
is called as `/api/auth/login/start`. See
[`CONFIGURATION_REFERENCE.md`](CONFIGURATION_REFERENCE.md).

## Sign-in mode

An appliance uses one sign-in mode, set by `auth_mode` in `config.toml` at startup:
`passkey` (the default) or `saml`. Only the routes of the active mode are mounted.
`saml` reads `saml.json` and fails startup if it cannot be read.

| Route | Permission | Purpose |
| --- | --- | --- |
| `GET /v1/auth/mode` | None (public) | `{"mode": "passkey"}` or `{"mode": "saml"}`, so the dashboard shows the matching sign-in page |

## Passkey sign-in

Passkeys use WebAuthn ([`src/auth/handlers.rs`](../src/auth/handlers.rs)). The relying
party comes from `agent-stream.json` `webauthn` (`rp_id`, `external_origin`). Each start
step returns a `challenge_id` and the WebAuthn options; the matching finish step must
present that `challenge_id` within 5 minutes, and a challenge is used once. At most 10,000
challenges are outstanding at once; past that, expired challenges are dropped first, then the
oldest.

| Route | Permission | Purpose |
| --- | --- | --- |
| `POST /auth/register/start` | None (public) | Start registering a passkey for a new username |
| `POST /auth/register/finish` | None (public) | Store the new user and passkey |
| `POST /auth/login/start` | None (public) | Start signing in a username |
| `POST /auth/login/finish` | None (public) | Verify the passkey and open a session |

Registration:

- The first user registered on an appliance becomes the primary `administrator`, approved
  at once. Every later user starts as `user` with status `New` and cannot sign in until an
  administrator approves them (see [`RBAC.md`](RBAC.md)).
- Registering an existing username returns a challenge that cannot be finished, so the
  response does not reveal whether the name is taken.
- `register/start` answers `403` once the appliance user limit is reached.
- When Terms are on, the registration request carries the accepted versions, and they are
  recorded before the user is saved (see [`TERMS_AND_CONSENT.md`](TERMS_AND_CONSENT.md)).
- Registration does not open a session; the user signs in afterwards.

Sign-in:

- `login/start` for an unknown username, or for a user who is not approved, returns a
  challenge that allows no credentials, so the response does not reveal which case applies.
- `login/finish` answers `401` when the passkey does not verify. On success it records the
  user's last sign-in and returns `session_token` and `consent_required`, and sets the
  session cookie.

## SAML sign-in

SAML mode uses SP-initiated sign-in against the identity provider configured in
`saml.json` ([`src/auth/saml/`](../src/auth/saml/)); its fields are in
[`CONFIGURATION_REFERENCE.md`](CONFIGURATION_REFERENCE.md#samljson).

| Route | Permission | Purpose |
| --- | --- | --- |
| `GET /saml/login` | None (public) | Redirect the browser to the identity provider with a new AuthnRequest |
| `POST /saml/acs` | None (public) | Assertion consumer service: validate the response and open a session |
| `GET /saml/metadata` | None (public) | The service provider metadata, as XML, for registering the appliance with the identity provider |
| `POST /saml/logout` | None (public) | End the session (the same as `POST /auth/logout`) |

- `saml/login` sets a `__Host-saml_authn_id` correlation cookie (`Secure`, `HttpOnly`,
  `SameSite=None`, 5 minutes). The ACS checks the response against the request that cookie
  names, so a response cannot be completed in a different browser, and clears it after a
  successful sign-in.
- A response that does not validate answers `401`.
- The first SAML sign-in provisions the user. SAML users are approved at once; the very
  first user on the appliance is the primary `administrator`, and anyone else takes the role
  `role_mapping` maps their role value to, or `user` when it has no entry. Every later
  sign-in sets the username, email, name, department and job title again from the identity
  provider, and the role too for everyone but the primary administrator, who stays
  `administrator`. See [`CONFIGURATION_REFERENCE.md`](CONFIGURATION_REFERENCE.md#samljson).
- When provisioning a new user would pass the appliance user limit, the ACS answers `403`
  with a readable page instead of opening a session.
- On success the ACS sets the session cookie and returns a page that keeps the session token
  for the dashboard and redirects to `/`. The page's one inline script carries a fresh nonce,
  and its `Content-Security-Policy` runs only that script (see
  [Security headers](OBSERVABILITY.md#security-headers)).
- Signing out ends the appliance session only; it does not sign out of the identity
  provider.

## Sign-in throttling

The registration, passkey sign-in, SAML login and ACS routes, and `/auth/check`, are
throttled per client ([`src/auth/throttle.rs`](../src/auth/throttle.rs)). A client is its
connecting address, with an IPv6 address grouped by its /64 prefix. Behind a reverse proxy
listed in `tls.client_auth.trusted_proxies`, the client is the rightmost `X-Forwarded-For`
hop that is not a listed proxy; from any other peer the header is ignored.

| Limit | Value | Over the limit |
| --- | --- | --- |
| Sign-in requests (registration, passkey sign-in, SAML login and ACS) | 10 per client per minute | `429` with `Retry-After` |
| `/auth/check` requests | 120 per client per minute | `429` with `Retry-After`, unless the request carries a valid session, which is always answered |
| Failed sign-ins | 10 per client | The client is locked out of the sign-in routes for 15 minutes after its last failure |

Only a `login/finish` or ACS response of `401` (a passkey or SAML response that did not
verify) counts as a failed sign-in. Any successful finish step, registration included, clears
the count. A registration whose passkey does not verify answers `400` and does not count, and
neither does a malformed request, an unknown or expired challenge, or a refusal for another
reason.

## Sessions

A successful sign-in creates a session ([`src/auth/session.rs`](../src/auth/session.rs))
identified by a random token. The client presents it either way:

- `Authorization: Bearer <token>`, which takes precedence; or
- the `session_token` cookie, set as `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`.

A token is never read from the query string.

Sessions last `session_timeout_minutes` (default 20) from their last use. Each request that
passes the session gate, and each `/auth/check`, pushes the expiry out again, and the gate
re-sends the cookie with a matching `Max-Age`. Sessions are written to
`[storage_paths] sessions` (default `../_storage/sessions`), so they survive a restart;
expired sessions are removed at startup and, in SAML mode, every 5 minutes on the Active
instance.

A session whose user is no longer approved (status `New` or `Disabled`, or removed) is
refused with `401` on every protected route.

| Route | Permission | Purpose |
| --- | --- | --- |
| `GET /auth/check` | None (public) | Whether the presented session is valid, with `username`, `consent_required` and `terms_enabled` |
| `POST /auth/logout` | None (public) | Delete the presented session and clear the cookie |

In passkey mode `/auth/check` answers `200` with `authenticated: false` when there is no
valid session; in SAML mode it answers `401`, and a valid response also carries `user_id`.

When Terms are on and the user has outstanding versions at sign-in, the session is
consent-pending: it reaches only the Terms routes, `/auth/check` and the logout routes until
the user accepts. [`TERMS_AND_CONSENT.md`](TERMS_AND_CONSENT.md#gating-the-session) covers
this.

Debug builds also offer a test-support login for UI tests, disabled unless its environment
variables are set; see [`development/TESTING.md`](development/TESTING.md).

## Profile and avatar

These routes act on the caller's own user record, taken from the session (or, for an access
token, its bound user). They need no permission beyond an approved user.

| Route | Permission | Purpose |
| --- | --- | --- |
| `GET /v1/profile` | Any signed-in user | The caller's username, role, status, profile fields, avatar path and last sign-in |
| `PUT /v1/profile` | Any signed-in user | Update `first_name`, `last_name`, `email`, `department` and `job_title`; omitted fields are kept |
| `POST /v1/profile/avatar` | Any signed-in user | Upload an avatar as multipart field `avatar`; returns the updated profile |
| `GET /v1/permissions` | Any signed-in user | The caller's permissions (see [`RBAC.md`](RBAC.md#permissions-response)) |

In SAML mode the identity provider overwrites the profile fields at each sign-in.

The avatar is stored as `<user_id>.<ext>` under `[storage_paths] avatars` (default
`../_storage/avatars`), and the profile points to the new file (an earlier avatar with a
different extension is left on disk). It is served at `avatars/<file>` under the
API prefix without a session.

## Image uploads

| Route | Permission | Purpose |
| --- | --- | --- |
| `POST /v1/uploads/image` | Any signed-in user | Store a dashboard image, such as an LLM provider logo, sent as multipart field `file`; returns `{"path": "uploads/<id>.<ext>"}` |

Avatars and uploads share the same checks:

| Check | Refusal |
| --- | --- |
| The part's content type is JPEG, PNG, GIF or WebP (SVG is refused) | `415` |
| The bytes start with the signature of that format | `415` |
| The image is at most 5 MiB | `413` (`400` when the whole request exceeds 6 MiB) |
| The named field is present | `400` |

Uploads are written under `[storage_paths] uploads` (default `../_storage/uploads`) with a
random name and served at `uploads/<file>` under the API prefix without a session, with
`Content-Security-Policy: default-src 'none'; sandbox` and `X-Content-Type-Options: nosniff`.

## Dashboard settings

System settings hold appliance-wide dashboard and operational values: dashboard windows and
refresh, feature flags, Prometheus endpoint authentication (see
[`OBSERVABILITY.md`](OBSERVABILITY.md)), audit recording, and the appliance id. They are
stored in `settings.json` under `[storage_paths] settings`.

| Route | Permission | Purpose |
| --- | --- | --- |
| `GET /v1/settings` | `settings.view` | The system settings, with the Prometheus password hash blanked |
| `POST /v1/settings` | `settings.edit` | Update the fields supplied; the Prometheus password is sent in plain text and stored as a bcrypt hash |
| `DELETE /v1/settings` | `settings.edit` | Reset every system setting to its default |

A save is validated before it is stored: the badge threshold must be at least 1 minute,
metrics retention between 1 and 10,080 minutes, and enabling Prometheus authentication for
the first time needs a username and password, and the appliance id must be at most 256
printable characters without spaces, quotes, backslashes, braces or `$`. `feature_flags`
replaces the whole system flag map. Changing the audit settings is itself
recorded. Both permissions default to `administrator` (see [`RBAC.md`](RBAC.md)).

User settings let each signed-in user override display preferences for themselves. They are
stored per user under `[storage_paths] settings` in `users/<user_id>.json`.

| Route | Permission | Purpose |
| --- | --- | --- |
| `GET /v1/user-settings` | Any signed-in user | The effective settings: the caller's overrides applied over the system settings |
| `POST /v1/user-settings` | Any signed-in user | Set overrides for the fields supplied; returns the effective settings |
| `DELETE /v1/user-settings` | Any signed-in user | Remove all the caller's overrides |
| `GET /v1/user-settings/overrides` | Any signed-in user | Only the caller's overrides |

A user can override `refresh_interval_seconds` (1 to 300), `log_timestamp_format` (`utc`,
`local`, `relative` or `compact`), `bucket_seconds`, `badge_threshold_minutes` (at least 1),
`payments_min_display`, and `feature_flags` (the map sent replaces the caller's earlier flag
overrides; each flag is applied over the system value). Every other field always comes from
the system settings.

Every system-settings and user-settings response sends `prometheus_auth_password_hash` empty.

## Related

- [`ACCESS_TOKENS.md`](ACCESS_TOKENS.md): management access without signing in.
- [`RBAC.md`](RBAC.md): roles, approval, and permission keys.
- [`TERMS_AND_CONSENT.md`](TERMS_AND_CONSENT.md): Terms acceptance at registration and
  sign-in.
- [`CONFIGURATION_REFERENCE.md`](CONFIGURATION_REFERENCE.md): `auth_mode`,
  `session_timeout_minutes`, `webauthn`, `saml.json`, and `[storage_paths]`.
- [`../CONTEXT.md`](../CONTEXT.md): the glossary.
