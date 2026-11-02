# Agent Stream Connector for VS Code

Use an **Affinidi Agent Stream** LLM surface as a model in **GitHub Copilot Chat**
— in **Ask, Edit, Agent, and Plan** modes — authenticated **per user** with your
corporate **Microsoft Entra ID (Azure AD)** sign-in. Every request carries the
developer's Entra access token, so the Agent Stream administrator can identify
each user, attribute spend to a Member/Team, enforce budgets and quotas, and apply
**OPA policies** such as _"user must be in group X"_ — all centrally, with nothing
sensitive stored in the editor.

```
 VS Code (Copilot Chat)
   │  picks the "Agent Stream" model provider
   ▼
 This extension
   │  getSession('microsoft', …)  ── Entra ID access token (auto-refreshed by VS Code)
   ▼
 POST {endpoint}/v1/chat/completions   Authorization: Bearer <entra-jwt>
   ▼
 Agent Stream LLM surface
   ├─ jwt_bearer source auth   → validate iss + JWKS + aud + exp
   ├─ OPA policy               → input.source_auth.claims.groups / roles
   ├─ team gate                → resolve Member by claim → budget / quota / RPM-TPM
   └─ forward                  → upstream model (OpenAI / Azure / Anthropic / …)
```

The extension is a thin, dependency-free client. **All governance is server-side
in Agent Stream** — the gateway already supports JWT validation, claim-based
attribution, and OPA group checks; this extension only delivers the token and
streams the response.

---

## Which model do I pick? (client vs. gateway)

**Copilot is the *client*, not a model, and there is no "Copilot" model to
configure in Agent Stream.** Two things are easy to confuse:

- **Today, without this extension:** when you pick a model like "Claude Opus" in
  Copilot with "no API key, just my SSO," **GitHub Copilot's backend is itself a
  gateway.** Your SSO signs you in to GitHub (a Copilot-seat *entitlement*), and
  GitHub calls the provider with **GitHub's own key**, billed to your Copilot
  subscription. Your token is never sent to the provider as the API key.
  ⚠️ **That entitlement is GitHub's and cannot be re-brokered through Agent
  Stream** — there is no upstream URL where Agent Stream can present your token
  and get Copilot's Claude back. To use Agent Stream you need an upstream it can
  call (Azure OpenAI/Foundry, AWS Bedrock, Anthropic, an internal gateway, …).
- **With this extension:** you pick the **"Agent Stream (SSO)"** entry in the
  model picker (added by this extension — *not* GitHub's built-in model). That
  routes the chat to your surface with your Entra token.

### What the surface serves, and the `model` field

The real model is whatever the surface's **upstream provider** is (set in the
dashboard). How the `model` you send is resolved depends on the surface's
**model override policy** (`override_policy.model`):

| Policy | Behaviour |
|---|---|
| `GatewayWins` | The surface's configured model **always** wins. Pin one model (e.g. Claude) here; the picker `id` is cosmetic. |
| `InjectIfMissing` (default) / `ClientWins` | The picker entry's `model` is **forwarded** to the upstream (must be a real id the provider accepts). |

### Where the credits come from

- **Stored key (default):** the surface holds a **company** provider key (a
  secret). Your SSO **identifies and limits** you; the company key **pays**.
- **Identity pass-through (`forward_caller_token`):** the surface forwards **your
  token** as the outbound credential (see Part A step 6). Use this when the
  upstream accepts the caller's bearer token itself — e.g. **Azure OpenAI /
  Azure AI Foundry with Entra ID auth**, where your SSO token literally *is* the
  key. Agent Stream still adds team/OPA/budgets on top.

  - **Dual-token (separate front-door and upstream identities):** by default the
    forwarded token is the same one you signed in to the surface with. When the
    front door and the upstream need **different** tokens — e.g. a custom
    app-scoped token gates OPA on the IDE Surface while **Microsoft 365 Copilot**
    needs a Graph-audience token — the IDE Surface can publish one or more
    **upstream sign-in slots** in its bootstrap. A model that names a slot makes
    the extension acquire that slot's token separately (its own
    tenant/client/scopes) and forward it in the
    `X-Agent-Stream-Upstream-Authorization` header, while your front-door token
    still rides `Authorization`. This is fully surface-driven: you only ever set
    `agentStream.endpoint`. VS Code may prompt a second Microsoft sign-in the
    first time you use such a model (once per distinct scope set).

---

## Part A — Configure the Agent Stream surface

Do this once in the Agent Stream dashboard (or admin API). Terminology and
mechanisms are described in [`docs/SOURCE_AUTH.md`](../../docs/SOURCE_AUTH.md), [`docs/USAGE_LIMITS_AND_ATTRIBUTION.md`](../../docs/USAGE_LIMITS_AND_ATTRIBUTION.md), and [`docs/POLICY.md`](../../docs/POLICY.md).

### 1. Register a JWT verification strategy (your Entra tenant)

Create a strategy that trusts tokens from your tenant:

- **Issuer** (`expected_issuer`): `https://login.microsoftonline.com/<tenant-id>/v2.0`
- **JWKS**: Remote — `https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys`

> The `/v2.0` issuer only works when your resource app is configured to **issue
> v2 tokens** (Part B step 5). Without that, tokens carry the v1 issuer
> `https://sts.windows.net/<tenant-id>/` and every request fails with
> `InvalidIssuer`.

Admin API: `POST /v1/jwt-strategies`.

### 2. Turn on `jwt_bearer` source auth on the surface

On the LLM surface, set **Source auth = JWT bearer**:

- **Strategy**: the one from step 1.
- **Audiences**: the API app's audience, e.g. `api://<api-app-id>` (must match the
  token's `aud` — see Part B). Leave empty only if your tokens have no `aud`.

### 3. Register Members and Teams (quotas & attribution)

- Create a **Member** per developer (or let the built-in anonymous member cover
  unlisted callers). Match the member by the claim you'll key on:
  - `Subject { sub }` → matches the token `sub` (Entra object id of the user), or
  - `Email { email }` → matches the token `email`/`preferred_username`.
- Set each member's **monthly budget / token caps** and optional **per-minute
  RPM/TPM**, and an optional **model allow-list**.
- Group members into **Teams** with their own budgets.

### 4. Enable team attribution on the surface

- **Caller match source** = `jwt_claim` with the claim you keyed members on
  (`email`, `preferred_username`, `sub`, or `oid`).
- Turn on **enforce** to make quotas blocking, and optionally **restrict to
  teams**.

### 5. Add an OPA policy for group/role checks (optional)

The whole decoded token is available to Rego as `input.source_auth.claims`.
Example — allow only members of an `engineering` group:

```rego
package channel.policy

default allow = false

allow {
    input.source_auth.method == "jwt_bearer"
    input.source_auth.claims.groups[_] == "<engineering-group-object-id>"
}
```

If you use **App Roles** instead of raw groups (recommended, see Part B), check
`input.source_auth.claims.roles[_] == "gateway.user"`.

### 6. (Optional) Forward the caller's token to the provider

If your upstream accepts the caller's **own** bearer token (e.g. **Azure OpenAI /
Azure AI Foundry with Entra ID auth**), enable **"Forward caller's token to the
provider (identity pass-through)"** on the surface property panel. Agent Stream
then sends `Authorization: Bearer <caller token>` to the upstream instead of the
stored key — the user's SSO token *is* the credential, while attribution, budgets,
and OPA still apply. Requires `jwt_bearer` source auth (step 2). Variant-
overridable. Leave it **off** to use a stored company key (step is not needed for
Anthropic/Bedrock/OpenAI, which don't accept Entra tokens).

---

## Part B — Configure Microsoft Entra ID

The goal: an app registration whose **API scope** is the audience Agent Stream
trusts, that **VS Code is allowed to request a token for**, and whose token
carries a **group/role claim** for OPA. VS Code's built-in Microsoft provider
acts as your app via the `VSCODE_CLIENT_ID:` scope modifier.

> **Two roles are involved:** the **API** (the resource/audience — `api://…`) and
> the **client** (the app VS Code signs in as). The confusing part of most guides
> is that these can be the **same** app registration or **two** separate ones.
> Below, Option 1 uses a single app (simplest); Option 2 splits them.

### Option 1 — One app registration (recommended, simplest)

The app is both the API and the client, so no cross-app authorization is needed.

1. **Register an app** — "Agent Stream API".
2. **Expose an API** → set the **Application ID URI** to `api://<app-id>` and add
   a **delegated scope** named `access_as_user`.
3. **Authentication** → **Add a platform → Mobile and desktop applications**, add
   **both** redirect URIs **`https://vscode.dev/redirect`** and
   **`http://localhost`** (no port), and set **Allow public client flows = Yes**.
   VS Code's Microsoft provider signs you in either through its protocol handler
   (`https://vscode.dev/redirect`) or — when you use a **custom `clientId`** — via
   a **loopback** redirect `http://localhost:<random-port>`. Entra matches
   `http://localhost` for a public-client app **ignoring the port**, so the single
   port-less entry covers every dynamic port. Do **not** register a fixed
   `http://localhost:PORT` — the port changes each sign-in (this is the cause of
   `AADSTS50011` redirect-URI-mismatch errors).
4. **Emit a group/role claim** for OPA (pick one):
   - **App Roles (recommended):** **App roles → Create** a role with value
     `gateway.user`, then under **Enterprise applications → Users and groups**
     assign the allowed groups to it. Tokens carry `roles: ["gateway.user"]` —
     no group-overage issues.
   - **Or raw groups:** **Token configuration → Add groups claim** (Access token).
     Large group counts trigger `hasgroups` overage; prefer App Roles at scale.
5. **Issue v2 access tokens.** Open the app's **Manifest** and set the API
   token version to `2`:
   ```json
   "api": {
     "requestedAccessTokenVersion": 2
   }
   ```
   New tenants use the Microsoft Graph manifest (nested `api.requestedAccessTokenVersion`
   shown above); older tenants have a top-level `accessTokenAcceptedVersion: 2`
   instead — set whichever your Portal shows. Without this the app issues **v1**
   tokens whose `iss` is `https://sts.windows.net/<tenant-id>/`, while the JWT
   strategy in Part A step 1 expects the **v2** issuer
   `https://login.microsoftonline.com/<tenant-id>/v2.0`, and every sign-in
   fails with `InvalidIssuer`. VS Code caches the previously-issued token, so
   after flipping this you must **sign out from the Accounts menu** (bottom-left)
   and reload the window before the fix takes effect (see Troubleshooting →
   *InvalidIssuer*).
6. **Extension settings:** `clientId` **and** the app id in the scope are the
   **same** app: `clientId = <app-id>`, `scopes = ["api://<app-id>/access_as_user"]`.

Because the app is requesting its own exposed scope, no "Authorized client
applications" entry or admin-consent step is required.

### Option 2 — Two app registrations (API + separate editor client)

Use this only if your org keeps API and client registrations separate. Here the
"pre-authorize" **and** "delegated permission" steps are **both** required (they
are not alternatives):

1. **API app** — expose `api://<api-app-id>/access_as_user` (as in Option 1
   steps 1–2), emit the group/role claim (Option 1 step 4), **and set the API
   manifest `api.requestedAccessTokenVersion: 2`** (Option 1 step 5 — required
   on the **API app**, not the editor client, because the resource app's
   manifest is what decides the token's issuer/version).
2. **Editor client app** — a separate app registered as a **public client** with
   redirect URIs `https://vscode.dev/redirect` **and** `http://localhost` (no
   port) under **Mobile and desktop applications**, and **Allow public client
   flows = Yes**. (The port-less `http://localhost` covers VS Code's dynamic
   loopback port — see Option 1 step 3.)
   - **API permissions → Add a permission → My APIs →** the API app **→ Delegated
     →** `access_as_user`, then **Grant admin consent**.
   - In the **API app → Expose an API → Authorized client applications**,
     **pre-authorize** the editor client's id (removes the per-user consent
     prompt).
3. **Extension settings:** `clientId = <editor-client-app-id>`,
   `scopes = ["api://<api-app-id>/access_as_user"]`.

### Result

Either option gives you a **tenant id**, a **client id**, and a **scope**
`api://<api-app-id>/access_as_user` for the extension settings in Part C.

---

## Part C — Install & configure the extension

### Build

```bash
cd clients/vscode-agent-stream
npm install
npm run compile
```

Package a `.vsix` (optional, for distribution):

```bash
npx @vscode/vsce package
```

Install the `.vsix` via **Extensions view → … → Install from VSIX**, or press
`F5` in this folder to launch an Extension Development Host.

### Settings

> **Pointing at an IDE Surface?** You need **only** `agentStream.endpoint` — the
> extension pulls the Entra sign-in identifiers and paths from the surface's
> public bootstrap. See [_Dynamic discovery from an IDE Surface_](#dynamic-discovery-from-an-ide-surface-recommended--only-the-endpoint-is-needed)
> below. The full settings below are for a plain LLM surface or manual overrides.
>
> In the VS Code **Settings** UI the required `agentStream.endpoint` field is
> shown on its own, and everything else (paths, fallback model list, manual
> `agentStream.entra.*`) is grouped under a separate **"Optional overrides"**
> section you can ignore unless you deliberately need to override a value the
> surface already publishes.

Add to your User/Machine `settings.json` (workspace settings are ignored for these trust-boundary keys):

```jsonc
{
  "agentStream.endpoint": "https://gateway.example.com/vscode",
  "agentStream.models": [
    { "id": "gpt-4o", "name": "Agent Stream (SSO)" }
  ],
  "agentStream.entra.tenantId": "<tenant-id>",
  "agentStream.entra.clientId": "<editor-public-client-id>",
  "agentStream.entra.scopes": ["api://<api-app-id>/access_as_user"]
}
```

- `agentStream.endpoint` is the **Access Point base URL**; the extension appends
  `agentStream.modelsPath` (default `/v1/models`) for discovery and
  `agentStream.chatPath` (default `/v1/chat/completions`) for chat. Change those
  paths only if your surface exposes a non-standard layout — otherwise any
  Access Point URL just works. The endpoint and optional overrides are read only
  from User/Machine settings so a repository's `.vscode/settings.json` cannot
  redirect bootstrap, model discovery, chat, or token forwarding.
- `agentStream.models[].model` is sent as the OpenAI `model` field (defaults to
  `id`) and must be a model the surface/provider accepts (unless the surface pins
  it with override policy `GatewayWins`).

#### Dynamic discovery from an IDE Surface (recommended — only the endpoint is needed)

Point `agentStream.endpoint` at an **IDE Surface** Access Point and that URL is
**all you need** — the extension configures everything else from the surface:

```jsonc
{
  "agentStream.endpoint": "https://gateway.example.com/ide"
}
```

On first use the extension fetches the surface's **public** discovery document
(`GET {endpoint}/.well-known/agent-stream`, unauthenticated — it carries only
public OAuth identifiers, never secrets) and reads:

- the **Microsoft Entra sign-in** identifiers — tenant id, editor client id and
  scopes — so it can sign you in without any local `agentStream.entra.*` setting;
- the discovery/dispatch **paths** (`models_path` / `chat_path`).

It then **discovers the model list automatically** — fetching the surface's
published `GET /v1/models` catalogue and showing exactly those models in the
Copilot Chat picker, so you don't hand-maintain `agentStream.models` at all.
Picking one of those models sends the chat back to the same Access Point with the
published model id, and the IDE Surface dispatches it to the right member LLM
surface (each with its own governance). Run **"Agent Stream: Refresh Models"** to
re-fetch on demand.

**Central management.** Because the sign-in identifiers live on the surface, an
administrator changes the tenant / client / scopes **once** on the IDE Surface's
**Client sign-in** panel and every developer's editor picks it up — there are no
per-machine `agentStream.entra.*` settings to roll out to a thousand employees.
The **Client sign-in** section on the surface is optional; if it is not
configured (the surface serves no bootstrap, or you point at a plain LLM
surface), the extension falls back to the manual settings below.

Any `agentStream.*` setting you *do* set in User/Machine settings is treated as an
**override** and wins over the bootstrap value — useful for testing a different
tenant or a non-standard path:

```jsonc
{
  "agentStream.endpoint": "https://gateway.example.com/ide",
  // optional overrides — normally pulled from the surface bootstrap:
  "agentStream.entra.tenantId": "<tenant-id>",
  "agentStream.entra.clientId": "<editor-public-client-id>",
  "agentStream.entra.scopes": ["api://<api-app-id>/access_as_user"]
}
```

#### Multiple models via surface variants (static fallback)

To offer several company models in the picker (e.g. Claude *and* GPT), give each
entry a unique `id` and route it to a surface **variant** with `alias` (and/or a
different `endpoint`). The extension addresses the variant as `{endpoint}$alias/…`:

```jsonc
"agentStream.models": [
  { "id": "claude", "name": "Claude (Company · SSO)", "alias": "claude" },
  { "id": "gpt4o",  "name": "GPT-4o (Company · SSO)", "alias": "gpt4o" }
]
```

Each `alias` must match a variant on the surface (each variant has its own
provider/model/credentials). Omit `alias` to hit the base surface. Several models
that share one provider (e.g. two Claude tiers on one Anthropic surface) need no
variants — just set each entry's `model` to a real provider id.

### Use it

1. Run **"Agent Stream: Sign in with Microsoft Entra ID"** from the Command
   Palette (or just start a chat — you'll be prompted).
2. Open **Copilot Chat**, click the **model picker**, and choose
   **Agent Stream (SSO)**.
3. Use it in **Ask**, **Edit**, **Agent**, and **Plan** modes. The provider
   advertises tool calling, so Copilot's agentic modes (read/edit files, run
   terminal, multi-step planning) work — provided the **upstream model behind the
   surface supports function calling** (e.g. GPT-4o, Claude 3.5+, Gemini 1.5+).
   Requests flow through Agent Stream with your Entra identity, so the
   administrator sees usage, spend, and policy decisions per user/team.

---

## How identity flows (why this works)

| Concern | Where it's enforced |
|---|---|
| User identity | Entra access token bearer → Agent Stream `jwt_bearer` source auth validates it |
| "Who is this user?" | `team_attribution.caller_email_source = jwt_claim{…}` resolves a **Member** |
| Budgets / quotas / rate limits | Agent Stream **team gate** on the resolved Member/Team |
| "Must be in group X" | **OPA** reads `input.source_auth.claims.groups` / `.roles` |
| Cost & usage reporting | Agent Stream dashboards + `GET /v1/spend-report` |

The extension never sees or stores a long-lived secret — VS Code's Microsoft
account manages token acquisition and refresh.

---

## Troubleshooting

> **See what's happening.** Run **Agent Stream: Show Logs** (Command Palette) to
> open the **"Agent Stream"** output channel. It logs configuration problems,
> the request URL and HTTP status, the completion summary, and empty responses —
> the first place to look when "nothing happens".

- **Nothing happens / no request reaches the gateway** — almost always
  misconfiguration. In the model picker the entry shows **"⚠ Not configured — set
  agentStream.endpoint"** and a chat request fails with the same message. Put
  your `agentStream.*` keys in User/Machine settings; repository workspace
  settings are deliberately ignored so a checked-out project cannot redirect
  Agent Stream traffic or token forwarding.
- **Sign-in seems to do nothing** — run **Agent Stream: Sign in with Microsoft
  Entra ID** (Command Palette, or the **Manage** gear on the provider in the
  model picker). You'll now see a progress notification and a success/error toast
  (each with a **Show Logs** button). If `agentStream.entra.scopes` is empty the
  sign-in reports it instead of failing silently.
- **"Could not connect to Agent Stream instance at `<url>`"** — the extension
  couldn't reach `agentStream.endpoint`: either the fetch failed at the network
  layer (DNS failure, connection refused, TLS handshake failure, timeout) or the
  ingress/reverse-proxy in front of the appliance returned a **5xx** (typically
  `502`/`503`/`504` — the proxy is up but the appliance behind it is down). This
  is distinct from the two cases below, which fire when the endpoint responds
  cleanly. Production endpoints must be HTTPS and resolve to public addresses;
  localhost, private/link-local ranges, cloud metadata endpoints, embedded
  credentials, unsafe bootstrap paths, and cross-origin chat targets fail closed.
  For local development only, enable `agentStream.allowLocalEndpoints` in
  User/Machine settings to permit `http://localhost`/private lab addresses.
- **"Agent Stream Access Point not found at `<url>` — check `agentStream.endpoint`"**
  (model picker) or **"The Agent Stream Access Point at `<url>` did not publish
  a sign-in bootstrap and no scopes are configured"** (sign-in) — the endpoint
  responds but `/v1/models` and/or `/.well-known/agent-stream` returned **404**.
  The URL is almost certainly wrong or points to a deleted/renamed surface.
  Compare the URL against the route shown on your **IDE Surface** in the
  dashboard (e.g. `…/llm/my-ide-catalogue`); the sign-in variant of the message
  also fires on a plain LLM Surface (`…/llm/toy/meter`) that legitimately has no
  sign-in bootstrap — for that case set the manual `agentStream.entra.*`
  overrides instead of relying on central sign-in.
- **"No sign-in scopes available. Configure Client sign-in on the IDE Surface, or
  set `agentStream.entra.scopes`"** — a legacy variant of the message above,
  emitted only when a bootstrap **was** received but its `scopes` array was
  empty. Fix by populating the IDE Surface's **Client sign-in → Scopes** field,
  or set `agentStream.entra.scopes` manually.
- **Sign-in fails with a garbled/invalid scope** — in the IDE Surface **Access
  Point → Client sign-in → Scopes** field, each scope must be on **its own line,
  whole**. A single scope such as `api://<api-app-id>/access_as_user` split across
  two lines becomes two invalid scopes (`api://<api-app-id>` and `/access_as_user`)
  and Entra rejects the sign-in. Keep the entire scope on one line.
- **401 / `InvalidAudience`** — the token `aud` doesn't match the surface's
  configured audiences. Ensure `agentStream.entra.scopes` targets the API app
  (`api://<api-app-id>/…`) and the surface audience is `api://<api-app-id>`.
- **401 / `InvalidIssuer`** — the strategy issuer must be
  `https://login.microsoftonline.com/<tenant-id>/v2.0` (v2.0 tokens). If your
  token's `iss` is `https://sts.windows.net/<tenant-id>/` (**v1**) instead of
  `.../v2.0` (**v2**), the **resource app registration hasn't opted into v2
  tokens** — set `api.requestedAccessTokenVersion: 2` in the app Manifest
  (Part B Option 1 step 5, or Option 2 on the API app). After changing the
  manifest, **VS Code's Microsoft account provider caches the previously-issued
  v1 token**, so nothing changes until you sign out: click your account (bottom
  left) → the Microsoft account → **Sign Out**, then **Developer: Reload Window**
  and retry. Confirm on the next attempt by inspecting the token in the extension
  output — the log line `Discovery: JWT payload = …` shows the token's `iss`.
- **403 `policy_denied`** — OPA rejected the request; the user's token lacks the
  required group/role claim. Verify the App Role assignment or the optional
  `groups` claim is being emitted.
- **403 `member_not_permitted` / `team_required`** — the caller didn't resolve to
  a permitted Member/Team, or the anonymous member/team is disabled. Register the
  user, or adjust the surface's team restrictions.
- **Sign-in loop / no token** — confirm `tenantId`, `clientId`, and the scope are
  correct and that the client app is authorized for the API scope (Part B step 3).
- **`AADSTS50011` — redirect URI `http://localhost:<port>` doesn't match** — when
  you sign in with a **custom `clientId`**, VS Code uses a **loopback** redirect
  with a **dynamic port** (`http://localhost:63431`, different each time). Register
  the port-less loopback URI so it matches every port: in the app registration
  **Authentication → Mobile and desktop applications**, add **`http://localhost`**
  (no port) and set **Allow public client flows = Yes**. Entra ignores the port
  for public-client loopback redirects, so one entry covers all ports — registering
  a specific `http://localhost:63431` will **not** work because the port rotates.
- **Model not in the picker** — the model list now refreshes automatically when
  you change `agentStream.models`, `agentStream.endpoint`, or
  `agentStream.chatPath`, so your configured entries should appear within a
  moment (no reload needed). If the picker still shows a stale entry — e.g. the
  default **Agent Stream (SSO)** name, which means the extension fell back to its
  built-in default because it read no valid `agentStream.models` — check that
  your `settings.json` is valid JSON and each entry has a non-empty string `id`,
  then reload the window (**Developer: Reload Window**). Ensure
  `agentStream.endpoint` and at least one model are configured.
- **"No utility model is configured for 'copilot-utility-small' … main agent
  model is BYOK"** — this is a **GitHub Copilot** message, not an Agent Stream
  error. Copilot uses small internal *utility* models (`copilot-utility`,
  `copilot-utility-small`) for background chores — chat titles, commit messages,
  intent detection, tool-risk checks, the todo list, etc. It has these built in
  for its own models, but when the **main** model is a third-party/BYOK provider
  like Agent Stream it has none unless you say which to use, so any feature that
  needs one throws this. Fix it either way:
  - **Reuse Agent Stream for utility work** (simplest): set
    `"chat.byokUtilityModelDefault": "mainAgent"`. No other config, and the
    background traffic stays governed by your gateway.
  - **Pin a specific (cheap) model**: set `"chat.utilitySmallModel"` and
    `"chat.utilityModel"` to `"<vendor>/<id>"` — e.g. `"agent-stream/gpt-4o-mini"`
    (the vendor is `agent-stream`; the id is your model's `id`). These take
    precedence over `chat.byokUtilityModelDefault`.

  The third option, `"chat.byokUtilityModelDefault": "copilot"`, needs an active
  GitHub Copilot sign-in (a Copilot token), which a BYOK-only setup doesn't have
  — that missing token is the usual reason the error appears at all. Utility
  requests you route to Agent Stream count against your budget/quota and are
  attributed to your Member/Team like any other call.

  This was a VS Code regression (the setting defaulted to `none` in 1.128–1.129);
  **VS Code 1.130+** ships it defaulting to `copilot`, so updating VS Code also
  clears the error for anyone signed into Copilot. A BYOK-only setup should still
  prefer `mainAgent` per the first option above.

---

## Limitations (v1)

- Text + tool calling (function calling) are supported, which covers Ask, Edit,
  Agent, and Plan modes. Agentic modes require the **upstream** model to support
  function calling; a non-tool model still works for plain Ask chat.
- Tool results include only text-valued parts and are sent in an explicit
  untrusted-data envelope so embedded content cannot redefine its provenance.
- Image input is advertised as off.
- Streaming path only (matches Agent Stream's SSE passthrough).
- No programmatic sign-out for the built-in Microsoft provider — use the
  **Accounts** menu.
