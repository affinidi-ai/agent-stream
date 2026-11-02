# Microsoft 365 Copilot

How an LLM Surface fronts the Microsoft 365 Copilot Chat API: the `m365_copilot`
provider, the request and response translation, identity pass-through and the
dual-token channel, buffered and streamed calls, and the limitations.

For the product concepts, see the hosted
[Providers and models](https://docs.affinidi.com/products/affinidi-trust-fabric/agent-stream/concepts/providers-and-models/)
page. This page documents the implementation, mainly in
[`src/pipes/executor.rs`](../src/pipes/executor.rs),
[`src/pipes/request_shaping.rs`](../src/pipes/request_shaping.rs),
[`src/pipes/streaming.rs`](../src/pipes/streaming.rs) and
[`src/pipes/handlers/llm_handler.rs`](../src/pipes/handlers/llm_handler.rs).

## What it does

A caller sends an ordinary OpenAI chat-completions request to the Surface.
Agent Stream turns it into a Copilot Chat API call made **as the signed-in
user**, with the caller's own delegated Entra token. Copilot grounds the answer
on that user's OneDrive, SharePoint, Teams, mail and calendar content, under
the user's Entra permissions and sensitivity labels, and returns only the
answer text.

Retrieval happens inside Microsoft 365: Copilot returns an answer, not the
source files, and Agent Stream does not fetch or store document contents.
Because each call carries the user's own token, a different user's token is
answered from that user's content.

![A user and app holding a delegated Entra token call an Agent Stream Surface, whose Copilot provider translates the OpenAI chat call into a Copilot call made as the signed-in user, under OPA policy and per-stage metering, with a 403 when denied; inside the Microsoft 365 boundary, under the user's Entra permissions, Copilot grounds on OneDrive, SharePoint, mail, and calendar, and returns the synthesised answer to the user, not the source files](assets/diagrams/m365-copilot-translation.png)

The rest of the Surface's governance still applies: source auth, inbound
policy, rate limit, team gate and attribution, and request-side guards.

## The provider

| Property | Value |
| --- | --- |
| `provider_type` | `m365_copilot` (`LLMProvider::M365Copilot`) |
| Wire schema | `copilot` (`api_schema()`) |
| Default base URL | `https://graph.microsoft.com` (`DEFAULT_M365_COPILOT_BASE_URL`); override with `base_url`, for example a national cloud |
| Caller's path appended | No: the executor builds the conversation endpoints itself |
| API key | None; `api_key_secret` is left empty |
| Model billed | The configured model |
| Key source | `client`: the signed-in user's licence pays |

The shipped catalog has an `m365_copilot` entry. A custom catalog provider with
`api_schema: "copilot"` is held to the same rules, because they key on the
schema (`LLMProviderExt::requires_forward_caller_token`).

### Save-time rules

`LLMHandler::validate_config` refuses a Copilot Surface:

- without `forward_caller_token: true` (the Chat API needs a delegated user
  token; without one there is no per-user grounding);
- whose `forward_caller_token` Surface does not use `jwt_bearer` source auth,
  so a forwarded token has always been verified first (a rule for every
  Surface that forwards the caller's token).

```json
{
  "id": "copilot",
  "name": "Microsoft 365 Copilot",
  "route": "/llm/copilot",
  "pipe_type": {
    "type": "llm",
    "provider": { "provider_type": "m365_copilot", "model": "copilot" }
  },
  "forward_caller_token": true,
  "streaming": { "enabled": true },
  "source_auth": {
    "type": "jwt_bearer",
    "jwt_verification_strategy_id": "entra-tenant",
    "audiences": ["<api-app-client-id>"]
  }
}
```

The JWT verification strategy (`expected_issuer`, `jwks_source`) is a separate
stored record; see [SOURCE_AUTH.md](SOURCE_AUTH.md).

## Request and response translation

The Chat API is stateful: a conversation must exist before a turn is posted.
For each execution the executor:

1. creates a conversation with `POST {base}/beta/copilot/conversations`
   (`create_copilot_conversation`), sending the forwarded token;
2. posts the turn to `{base}/beta/copilot/conversations/{id}/chat`, or to
   `.../chatOverStream` when streaming.

`transform_to_copilot_format` maps the normalised OpenAI body:

| OpenAI request | Copilot request |
| --- | --- |
| The last `role: "user"` message | `message.text` |
| Every other message (system, prior turns), as `"{role}: {text}"` | `additionalContext[].text`; omitted when empty |
| — | `locationHint.timeZone`, always `UTC` |
| Sampling parameters, tools and anything else | Dropped |

Only text content parts are kept. `transform_from_copilot_format` maps the
response back:

| Copilot response | OpenAI response |
| --- | --- |
| The last `messages[].text` | `choices[0].message.content`, `finish_reason: "stop"` |
| No usage reported | `usage` with zero prompt, completion and total tokens |
| — | `model: "m365-copilot"` |

Each data-plane request opens a new conversation and replays the thread as
`additionalContext`. The management sandbox execute API
(`POST /api/v1/pipes/{pipe_id}/execute` and `/execute/stream`) also accepts a
`conversation_id`: the executor then reuses that conversation and sends only the
new user message, and returns the id it used (`conversation_id` in the buffered
response, the `x-agent-stream-conversation-id` header on a stream).

## Identity pass-through

With `forward_caller_token`, `resolve_provider_headers` sends the caller's
bearer token as the upstream `Authorization` on the main call:

- `X-Agent-Stream-Upstream-Authorization` when the caller sent it;
- otherwise the `Authorization` token the front door verified.

The forwarded token must carry the Chat API's delegated Microsoft Graph
permissions; an application-only token is not supported by the API.

### Dual token behind an IDE Surface

An IDE Surface's front door usually verifies a token issued for the
organisation's own API, so policies can read its claims, while the Chat API
needs a token issued for Microsoft Graph. One token cannot serve both
audiences, so the Copilot member carries an `upstream_oauth_identifier_id`:

- the IDE Surface publishes that OAuth Identifier as an upstream slot in its
  bootstrap and stamps the slot id on the member's model entry;
- the client signs in to the front door and sends that token in
  `Authorization`;
- for this model it also acquires the slot's Graph token and sends it in
  `X-Agent-Stream-Upstream-Authorization`;
- the Copilot member forwards the Graph token, never the front-door token.

A request an IDE Surface dispatched never offers either header to a member's
provider as a caller provider key, so a client that sends the Graph token on
every request does not leak it to another member. An `ide.policy` can require
the second token for a model through `input.request.forwarded_upstream_auth`.
See [IDE_SURFACES.md](IDE_SURFACES.md).

## Buffered and streamed calls

The Surface's `streaming.enabled` switch, the same one every LLM Surface has,
chooses. `passthrough_eligible` admits the `copilot` schema.

| `streaming.enabled` | Client sends `"stream": true` | Copilot endpoint | Client receives |
| --- | --- | --- | --- |
| `true` (default) | Yes | `chatOverStream` | `chat.completion.chunk` server-sent events |
| `true` (default) | No | `chat` | One `chat.completion` |
| `false` | Either | `chat` | One `chat.completion` |

Streaming is always the client's choice; the switch only decides whether it is
honoured. A Surface with any response-side stage (Jury, Comparer or
Summariser, response Prompt Guard rules or Expert Witnesses, or active server
tools) always buffers; see [ARCHITECTURE.md](../ARCHITECTURE.md#streaming).

`chatOverStream` events are full conversation snapshots, not deltas. The
stream translator in [`src/pipes/streaming.rs`](../src/pipes/streaming.rs)
diffs each snapshot's last message against the text already forwarded, emits
only the appended text as a `content` delta, and closes with a
`finish_reason: "stop"` chunk and `data: [DONE]`. It accepts single-line,
multi-line and pretty-printed `data:` JSON.

## Metering

Copilot reports no token usage, so buffered and streamed calls record zero
tokens and zero cost. The call is labelled `client`, so it bills nothing to the
member budget and is never refused by a platform-key budget or metering check.
Request counts, team attribution and rate limits still apply.

## Known limitations

- **Text answers only.** The Chat API returns text. Tools and function calling
  are not passed through, and the API cannot act (send mail, create files,
  schedule meetings).
- **No token metering.** Usage and cost record as zero.
- **Judge, Jury and Decider do not fit.** They assume OpenAI message editing,
  which does not round-trip through the Copilot conversation contract, and a
  response-side stage forces buffering.
- **Fixed `locationHint`.** The time zone is always `UTC`.
- **No conversation memory on the data plane.** Each request opens a new
  conversation; only the sandbox execute API reuses one.
- **Preview API.** The Chat API is a Microsoft Graph `/beta` API and needs a
  Microsoft 365 Copilot licence per user.

## Related

- [IDE_SURFACES.md](IDE_SURFACES.md): Catalogue members, upstream slots and the
  bootstrap.
- [PROVIDERS_AND_CREDENTIALS.md](PROVIDERS_AND_CREDENTIALS.md): identity
  pass-through, key sources and the dual-token header.
- [SOURCE_AUTH.md](SOURCE_AUTH.md): `jwt_bearer` and JWT verification
  strategies.
- [POLICY.md](POLICY.md): `input.request.forwarded_upstream_auth`.
- [`clients/vscode-agent-stream/README.md`](../clients/vscode-agent-stream/README.md):
  the editor client that acquires the upstream token per model.
