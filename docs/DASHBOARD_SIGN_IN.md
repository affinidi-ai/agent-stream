# Dashboard Sign-In

How a person signs into the Agent Stream dashboard with a passkey, or through SAML or OpenID
Connect (OIDC) single sign-on, how the resulting session is carried and expires, and the routes a signed-in user
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
`passkey` (the default), `saml` or `oidc`. Only the routes of the active mode are mounted.
`saml` reads `saml.json` and fails startup if it cannot be read; `oidc` reads `oidc.json` and
fails startup if it cannot be read or any of its settings is refused.

| Route | Permission | Purpose |
| --- | --- | --- |
| `GET /v1/auth/mode` | None (public) | `{"mode": "passkey", "label": null}`, `"saml"` or `"oidc"`, so the dashboard shows the matching sign-in page; in OIDC mode `label` is the provider name for the sign-in button |

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
- `login/finish` answers `401` when the passkey does not verify, and when the user was
  deleted or disabled after `login/start`; a failure to store the
  sign-in answers `500`. On success it records the
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
- A user who is not approved (for example an administrator disabled or deleted them) is
  refused with `403` and a readable page that does not say why, and no session opens.
  Deleting a SAML user keeps their record, as
  [Deleting an OIDC or SAML user](#deleting-an-oidc-or-saml-user) describes.
- When the username the IdP asserts is already held by another user, the user gets their SAML
  user ID as username instead, and only when that is held too is the sign-in refused with the
  same page, with nothing created or changed. A user whose stored username already is the
  asserted one signs in as before, so users who already share a username keep signing in. To
  clear a refusal, change the asserted attribute at the identity provider, or delete the
  other user if they are not an administrator.
- On success the ACS sets the session cookie and returns a page that keeps the session token
  for the dashboard and redirects to `/`. The page's one inline script carries a fresh nonce,
  and its `Content-Security-Policy` runs only that script (see
  [Security headers](OBSERVABILITY.md#security-headers)).
- Signing out ends the appliance session only; it does not sign out of the identity
  provider.

## OIDC sign-in

OIDC mode signs people in with one OpenID provider, configured in `oidc.json`
([`src/auth/oidc/`](../src/auth/oidc/)), using the authorization code flow with PKCE. Its
fields are in [`CONFIGURATION_REFERENCE.md`](CONFIGURATION_REFERENCE.md#oidcjson). The file
must bind sign-in to a tenant at the provider: startup stops unless `required_claims` has an
entry on a claim other than `iss`, `aud` or `azp`, or `allow_any_account` is `true` with
`role_mapping.unmapped` left at `deny`. A role for `unmapped` also needs an entry that lists only exact values.

| Route | Permission | Purpose |
| --- | --- | --- |
| `GET /oidc/login` | None (public) | Redirect the browser to the provider to sign in |
| `GET /oidc/callback` | None (public) | Where the provider sends the browser back (`redirect_uri`): verify the sign-in and open a session |
| `GET`, `POST /oidc/initiate` | None (public) | Third-party-initiated login: start a sign-in at the provider's request (the provider's `initiate_login_uri`) |
| `POST /oidc/logout` | None (public) | Sign out of the dashboard, and give the provider's sign-out address (the same as `POST /auth/logout` in OIDC mode) |
| `POST /oidc/backchannel-logout` | None (public; a signed logout token) | Back-channel logout: end the sessions of a sign-out at the provider (the provider's `backchannel_logout_uri`) |

The provider:

- Its discovery document, `{issuer}/.well-known/openid-configuration` (one trailing `/` of
  the issuer dropped), is fetched when sign-in first needs it and kept for 24 hours. Startup
  tries once and logs the result, but a provider that cannot be reached does not stop
  startup: only sign-in waits, and `oidc/login` answers `503` with a readable page. Until a
  document has been fetched, one request fetches it while the others wait, and after a
  failed fetch the next attempt is a minute later; requests meanwhile get the same failure.
- Once a document has been fetched, a refresh that fails logs a warning and sign-in keeps
  using the cached document, trying again after a minute. One sign-in refreshes at a time;
  the others use the cached document meanwhile. A token endpoint that cannot be reached,
  answers `404` or fails with a `5xx` has the document fetched again at the next sign-in; an
  OAuth error such as `invalid_grant` does not.
- The document must name the configured `issuer` exactly, and every endpoint in it must be
  `https`. When it lists `code_challenge_methods_supported` that list must include `S256`,
  and when it lists `token_endpoint_auth_methods_supported` that list must include the
  configured `token_endpoint_auth_method`.

The flow:

- `oidc/login` sends a fresh `state`, `nonce` and PKCE `S256` challenge, and sets a
  `__Host-oidc_state` cookie (`Secure`, `HttpOnly`, `SameSite=Lax`, 10 minutes) holding the
  `state`. The callback is refused unless the browser presents that cookie for the same
  `state`, so a callback URL cannot be completed in a different browser. A callback without
  that cookie is refused before its `state` is used, so the browser that started the sign-in
  can still finish it. A browser has one such cookie, so when several sign-ins are started in
  it only the most recently started one can finish. Each `state` works once, within 10 minutes; at most 10,000 sign-ins wait at once, and past that the oldest is
  dropped.
- The callback exchanges the code at the provider's token endpoint, authenticating with
  `client_secret_basic` or `client_secret_post`, and verifies the ID token:
  - its signature, against the provider's published keys (JWKS), with an algorithm listed in
    `id_token_signing_algs`. A key id the cached keys lack makes one fresh fetch, so key
    rotation works.
  - `iss` equals the configured issuer, and `aud` includes `client_id`. A token for several
    audiences needs `azp` equal to `client_id`.
  - `exp` has not passed and `iat` is not more than 60 seconds ahead (60 seconds of leeway each).
  - `nonce` is the one this sign-in sent, and `sub` is 1 to 255 characters.
- Each `required_claims` entry must be met: the claim, or an element of it when it is an
  array, equals one of the listed strings or booleans, with the type matching too, or matches
  one of its `regex:` patterns. Then `role_mapping` gives the role: each value of
  the role claim (a string, or each string in an array) takes the role of its exact entry, or
  else the highest role among the `regex:` patterns it matches, and the highest role across
  the values wins. When no value maps, the account gets `role_mapping.unmapped`, which by
  default refuses it.

Users:

- A user is identified by their provider account, the issuer and `sub` together, never by
  email. The first sign-in creates the user, approved at once and never the primary
  administrator: in OIDC mode the first user is not made `administrator`, and every role comes
  from the mapping.
- The username is the `claims.username` claim, else the email, else `sub`. When another user
  has it, the username is `sub`; when another user has that too, the sign-in is refused.
- Every sign-in sets the username, email, first and last name, and role again from the ID
  token, so an administrator's role change for an OIDC user lasts until that user next signs
  in.
- When a sign-in changes the user's role, their other sessions end, so other tabs and devices
  sign in again with the new role. When `required_claims` or `role_mapping` refuses an
  existing user, all their sessions end; the user record is kept.
- A user who is not approved (an administrator disabled them) is refused even with a valid ID
  token, and all their sessions end. When creating a user would pass the appliance user limit, the callback answers `403`
  with a readable page.
- Deleting an OIDC user keeps their record, so the next sign-in is refused; see
  [Deleting an OIDC or SAML user](#deleting-an-oidc-or-saml-user).

Outcomes:

- A refused sign-in shows a readable page that does not say why; the log records a reason
  code: `issuer_mismatch`, `state_unknown`, `binding_mismatch`, `code_missing`,
  `access_denied`, `exchange_failed`, `id_token_invalid`, `claim_not_allowed`, `role_unmapped`,
  `user_disabled`, `user_limit`, `op_unavailable` or `server_error`. No token, code, secret or
  claim value is logged.
- Only a code the provider refuses (`invalid_grant`) answers `401`, because the code is the
  only thing a caller sends that could be a guess. The ID token comes from the token endpoint,
  never from the caller.
- A callback with an unknown or expired `state`, without this browser's binding cookie, or
  with neither a code nor an error answers `400`. An ID token that does not verify answers
  `502`. A token endpoint or key set that cannot be reached, answers `404` or fails with a
  `5xx` answers `503`; any other token endpoint error, such as `invalid_client`, answers
  `500`. An account the settings refuse, a disabled user, or a sign-in the provider declined
  answers `403`.
- On success the callback sets the session cookie and returns the same page as SAML sign-in,
  also sent with `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.
- Signing out of the dashboard also signs the person out of the provider (RP-initiated logout,
  [OpenID Connect RP-Initiated Logout
  1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)). `POST /auth/logout`
  ends the session and clears the cookie as in the other modes, and when the session came
  from an OIDC sign-in, `logout.rp_initiated` is on and the provider publishes an
  `end_session_endpoint`, it answers `{"end_session_url": "..."}`: that endpoint with
  `id_token_hint` (the session's ID token, accepted even once expired), `client_id`,
  `post_logout_redirect_uri` when configured, and a random `state`. Otherwise it answers
  `{}`, and the sign-out stays local. The dashboard opens that address when the person signs
  out; a session that expires never does, so a timed-out dashboard does not sign the person
  out of the provider. The provider then sends the browser to `post_logout_redirect_uri`,
  and the login page shows "You have signed out." when that address carries `signed_out=1`.
- Each OIDC session records the provider sign-in it came from: the issuer, `sub`, and the
  provider's session id (`sid`) when the ID token carries one, and the ID token itself, used
  only as the `id_token_hint` above. The session is created with it, so back-channel logout
  can always find the session.

Back-channel logout ([OpenID Connect Back-Channel Logout
1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)) lets a sign-out at the
provider end the matching dashboard sessions. The provider posts a form with a
`logout_token` to `/oidc/backchannel-logout`, server to server and without cookies:

- The token is checked like an ID token: its signature against the provider's keys with an
  algorithm in `id_token_signing_algs`, `iss`, `aud`, `exp` (required, as Back-Channel
  Logout 1.0 requires it), and `azp`, which when present must be the `client_id` and must be
  present when `aud` names several audiences. Then a `typ` header, when present, must be
  `logout+jwt`, and `iat` must not be more than 60 seconds ahead. It must have an `events`
  claim holding the back-channel logout event, no `nonce` (so an ID token is never taken as
  a logout token), `sub` or `sid`, and a `jti` not seen before.
- Replay protection is best effort. Each `jti` is remembered until its token would expire
  plus the 60 seconds of clock skew allowed, in this process's memory only: a restart or a
  promotion of another instance forgets them, and at 10,000 the one closest to expiry is
  dropped. A replay needs a logout token the provider signed, and only ends sessions again.
- A token with `sid` ends the sessions signed in with that provider session (and that `sub`,
  when it also has one). A token with only `sub` ends every session of that account. A
  session whose ID token had no `sid` cannot be told apart from the account's other provider
  sessions, so a token with `sid` and `sub` ends it when `sub` names its account. A session
  created by OIDC sign-in before sessions recorded the provider sign-in is ended by any token
  whose `sub` names its account. Personal access tokens are not touched.
- Every answer has `Cache-Control: no-store`. It is `200` whether or not a session matched,
  since the provider may retry. A request that is not a form with a token that verifies gets
  `400` with `{"error":"invalid_request"}`. A logout that could not end every session it
  names gets `400` with `{"error":"logout_failed"}`, and its `jti` is forgotten so the
  provider can send it again. `503` asks the provider to retry: the provider or its keys
  could not be reached; the token names a key not in the keys fetched within the last minute
  (a key rotated in that minute is seen after it); or this instance is not the ready Active
  instance, whose sessions are the live ones.
- The provider's back-channel logout URI must reach the Active instance through readiness
  routing, like dashboard traffic; see
  [Server mode](CONFIGURATION_RELOAD.md#server-mode).
- An open dashboard tab loses access within about 30 seconds, when its connection next
  checks the session.
- The route is not throttled, because a provider may send many logouts at once; a request
  body is at most 16 KiB. `logout.backchannel: false` in `oidc.json` removes the route.

Third-party-initiated login ([OpenID Connect Core 1.0 section
4](https://openid.net/specs/openid-connect-core-1_0.html#ThirdPartyInitiatedLogin)) lets the
provider, or a portal it controls, link people straight into the dashboard.
`/oidc/initiate` takes its parameters from the query (`GET`) or a form body (`POST`, which
arrives cross-site by design, so it is not behind any same-origin check):

| Parameter | Handling |
| --- | --- |
| `iss` | Required, and must equal the configured `issuer` exactly; otherwise the answer is `400` with a readable page (`issuer_mismatch`). It is never used to choose or fetch anything. |
| `login_hint` | Optional. Passed on to the provider when it is at most 256 characters with no control characters; otherwise dropped. |
| `target_link_uri` | Optional. Where the dashboard opens after signing in, when it is an absolute URL on the dashboard's own origin (the origin of `redirect_uri`), without user info, whose path and query still resolve on that origin, with no encoded slash or backslash in the path, within 1,024 characters. Its path and query are kept; anything else opens `/`, so the endpoint never sends the browser to another site. The sign-in page itself always loads `/` and leaves the path for the dashboard, which opens it as it restores any deep link after sign-in, so it only ever opens a dashboard page, never an `/api/` address. |

Every request starts a fresh sign-in, as `oidc/login` does, even when the browser already has a
session: the provider's own session usually makes the round trip silent, and it guarantees the
new session belongs to the person the provider just sent. A sign-in started at `oidc/login`
leaves no path, so the dashboard opens `/`, or the page it remembered before sending the person
to sign in.

To register Agent Stream at the provider:

| Provider setting | Value |
| --- | --- |
| Client type | Confidential (a web application with a client secret) |
| Redirect URI | The `redirect_uri` in `oidc.json`, for example `https://stream.example.com/api/oidc/callback` |
| Grant | Authorization code, with PKCE `S256` |
| Client authentication | `client_secret_basic` (the default) or `client_secret_post`, as `token_endpoint_auth_method` says |
| ID token signing | An algorithm in `id_token_signing_algs` (`ES256` by default) |
| Claims in the ID token | The role claim, every claim in `required_claims`, and the profile claims |
| Post-logout redirect URI | The `logout.post_logout_redirect_uri` in `oidc.json`, for example `https://stream.example.com/?signed_out=1` |
| Back-channel logout URI | `/oidc/backchannel-logout` on the same origin, for example `https://stream.example.com/api/oidc/backchannel-logout`; the provider must be able to reach it, through the same readiness routing as dashboard traffic. Either setting of "session required" works: a logout with `sid` ends that provider session, one with only `sub` ends all of the account's sessions |
| Initiate login URI (optional) | `/oidc/initiate` on the same origin, for example `https://stream.example.com/api/oidc/initiate`, when the provider links people into the dashboard |

## Deleting an OIDC or SAML user

`DELETE /v1/users/{user_id}` removes a user who signs in with a passkey. A user who signs in
with an OIDC or SAML account is not removed: with no record, the next sign-in would create a
new approved user with the mapped role. The record is kept `Disabled` and marked deleted, so
that sign-in is refused like any disabled user's (`403`, no reason shown; `user_disabled` in
the OIDC log).

- **Cleared:** first and last name, email, department, job title, avatar link and passkeys.
  The username becomes the user id and the role goes back to `user`.
- **Kept:** the user id, the created and last login times, the user's notifications and
  personal settings (both are stored by user id, so an approved-again user gets them back),
  and the provider account the sign-in matches on: the OIDC issuer and `sub`, or the SAML
  user ID. The Users and Edit User pages show the account on a kept record, and keep showing
  it after approval until the user's next sign-in gives the record a username again, so an
  administrator knows whose sign-in approving it allows.
- **Every delete:** the user's sessions end, the access tokens bound to the user and the
  tokens whose secret the user last received are revoked (see
  [`ACCESS_TOKENS.md`](ACCESS_TOKENS.md)), and the uploaded avatar image files are removed
  (the shared default avatar never is). A file that cannot be removed is logged and does not
  stop the delete. The `user.deleted` integration event fires once, and the delete is logged
  on the `audit` target as `user.deleted` with the number of tokens revoked; deleting a kept
  record again changes nothing.
- **User limit:** a kept record does not count toward the `users` limit. Approving it again
  gives it a seat, so that approval answers `403` when the limit is reached.
- **Signing in again:** an administrator sets the status back to `approved`. The next
  sign-in is the same user, with the role set from the claim or attribute mapping again. A
  role in the kept record is not used. Approving fires `user.approved` (without the welcome
  notification) as well as `user.updated`, so an integration that offboarded the person on
  `user.deleted` sees them return, and ends any session and revokes any access token still
  bound to the user.
- Terms Acceptance Records survive user deletion; see
  [`TERMS_AND_CONSENT.md`](TERMS_AND_CONSENT.md).

## Sign-in throttling

The registration, passkey sign-in, SAML login and ACS, and OIDC login, initiate and callback
routes, and `/auth/check`, are throttled per client ([`src/auth/throttle.rs`](../src/auth/throttle.rs)). A client is its
connecting address, with an IPv6 address grouped by its /64 prefix. Behind a reverse proxy
listed in `tls.client_auth.trusted_proxies`, the client is the rightmost `X-Forwarded-For`
hop that is not a listed proxy; from any other peer the header is ignored.

| Limit | Value | Over the limit |
| --- | --- | --- |
| Sign-in requests (registration, passkey sign-in, SAML login and ACS, OIDC login, initiate and callback) | 10 per client per minute | `429` with `Retry-After` |
| `/auth/check` requests | 120 per client per minute | `429` with `Retry-After`, unless the request carries a valid session, which is always answered |
| Failed sign-ins | 10 per client | The client is locked out of the sign-in routes for 15 minutes after its last failure |

Only a `login/finish`, ACS or OIDC callback response of `401` (a passkey or SAML response that
did not verify, or an OIDC code the provider refused) counts as a failed sign-in. Any successful finish step, registration included, clears
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
expired sessions are removed at startup and, in SAML and OIDC modes, every 5 minutes on the
Active instance.

A session whose user is no longer approved (status `New` or `Disabled`, or removed) is
refused with `401` on every protected route.

| Route | Permission | Purpose |
| --- | --- | --- |
| `GET /auth/check` | None (public) | Whether the presented session is valid, with `username`, `consent_required` and `terms_enabled` |
| `POST /auth/logout` | None (public) | Delete the presented session and clear the cookie |

In passkey mode `/auth/check` answers `200` with `authenticated: false` when there is no
valid session; in SAML and OIDC modes it answers `401`, and a valid response also carries
`user_id`.

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

In SAML mode the identity provider overwrites the profile fields at each sign-in; in OIDC
mode it overwrites the username, email, and first and last name.

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

## Known limitations

- A user whose record was removed has no record left, so their next sign-in creates a new
  approved user: this is the case for a user deleted before delete kept OIDC and SAML
  records. Disable such a user to keep them out.
- A kept record is matched by its exact OIDC issuer and `sub`, or by its SAML user ID. After
  you change the issuer, the SAML `user_id` mapping, or the sign-in mode, a deleted person's
  next sign-in finds no record and creates a new approved user. Disable deleted users by hand
  before the change.
- No action removes a kept record, because removing it lets the account sign in again. To
  answer an erasure request, delete the record's file from `_storage/`; the account's next
  sign-in then creates a new approved user, so disable the account at the provider first.

## Related

- [`ACCESS_TOKENS.md`](ACCESS_TOKENS.md): management access without signing in.
- [`RBAC.md`](RBAC.md): roles, approval, and permission keys.
- [`TERMS_AND_CONSENT.md`](TERMS_AND_CONSENT.md): Terms acceptance at registration and
  sign-in.
- [`CONFIGURATION_REFERENCE.md`](CONFIGURATION_REFERENCE.md): `auth_mode`,
  `session_timeout_minutes`, `webauthn`, `saml.json`, `oidc.json`, and `[storage_paths]`.
- [`../CONTEXT.md`](../CONTEXT.md): the glossary.
