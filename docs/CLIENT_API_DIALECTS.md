# Client API Dialects

How an LLM Surface answers callers in three request formats (OpenAI Chat Completions,
Anthropic Messages, and OpenAI Responses), whichever provider it calls. This page covers
path negotiation, the request and response translations, the streaming encoders,
authentication header mapping, error envelopes, and the per-Surface
`accepted_ingress_schemas` control. For the operator view, see the hosted
[Surface reference](https://docs.affinidi.com/products/affinidi-trust-fabric/agent-stream/reference/surfaces/surface-reference/).

In code a Client API dialect is called a _skin_ (`IngressSchema`).

## The model

The dialect is chosen for each request by its path. It is not a property of the Surface,
the provider, or the model. A caller using the Anthropic SDK can reach a Surface backed
by an OpenAI model, and an OpenAI SDK can reach a Surface backed by Claude.

The pipeline works on one internal shape, the OpenAI Chat Completions body. The handler
translates the request into that shape at the front door and translates the response
back on the way out:

```text
caller (OpenAI Chat | Anthropic Messages | OpenAI Responses)
   │  normalise at the front door
   ▼
OpenAI Chat body ──► gates, guards, routing, provider call ──► OpenAI Chat result
                                                                   │  convert back at the edge
                                                                   ▼
                                                  response in the caller's dialect
```

Everything between the two edges sees the OpenAI Chat shape: Prompt Guard and NER IDs,
the Judge, Decider, Comparer and Summariser, the Jury, the response cache, budgets,
usage accounting, and Governance Records. Adding a dialect changes none of them.
Provider-specific wire shaping (Anthropic, Gemini, and others) happens later, just before
the provider call, and is independent of the caller's dialect.

## Path negotiation

`detect_ingress_schema` in [`src/pipes/ingress.rs`](../src/pipes/ingress.rs) reads the
final path segment, ignoring a query string and a trailing slash.

| Path suffix | Dialect | `IngressSchema` value |
| --- | --- | --- |
| `…/v1/chat/completions` | OpenAI Chat Completions | `openai_chat` |
| `…/v1/messages` | Anthropic Messages | `anthropic_messages` |
| `…/v1/responses` | OpenAI Responses | `openai_responses` |

Any other path, including `/v1/messages/count_tokens` and `/v1/embeddings`, is treated as
OpenAI Chat, which is the identity translation. Only LLM Surfaces and IDE Surfaces
translate dialects; on any other Surface type the handler forces `openai_chat` so the body
is never rewritten.

After a non-OpenAI dialect is normalised, the request is dispatched to the provider's
chat endpoint (`/v1/chat/completions` as the path suffix), not to the caller's path.

The LLM data plane accepts request bodies up to 32 MiB
(`LLM_MAX_REQUEST_BODY_BYTES` in [`src/proxy/server.rs`](../src/proxy/server.rs)).

## Controlling which dialects a Surface accepts

`accepted_ingress_schemas` on `PipeConfig`
([`src/pipes/config.rs`](../src/pipes/config.rs)) lists the dialects a Surface answers.
The default (`default_accepted_ingress_schemas`) is all three. The dashboard shows it as
the **Client API formats** control.

A request in a dialect the Surface does not accept is refused before anything else on the
Surface runs, as if the route did not exist for that format:

```json
{ "error": { "message": "This surface does not accept the anthropic_messages API format",
             "type": "invalid_request_error", "code": "ingress_format_not_accepted" } }
```

The status is `404`. On an Anthropic Messages request the envelope is converted to the Anthropic dialect (see
[Errors](#errors)).

The check runs at the dialect gate, after the Surface is loaded and before IDE dispatch,
the Router, and source authentication. See the
[full order](../ARCHITECTURE.md#full-order).

## Request translation

### Anthropic Messages to OpenAI Chat

`transform_from_anthropic_request` in
[`src/pipes/request_shaping.rs`](../src/pipes/request_shaping.rs):

| Anthropic | OpenAI Chat |
| --- | --- |
| Top-level `system` (string or text blocks) | A leading `system` message. Blocks that carry `cache_control` stay as content parts so the breakpoint survives; otherwise the text is flattened. |
| `messages[]` with string content | Passed through. |
| `text` block | Text part, keeping `cache_control`. |
| `image` block (`source.type` `base64` or `url`) | `image_url` part, keeping `cache_control`. An image with a `file` source is dropped. |
| `document` block, `source.type: "base64"` | `{ "type": "file", "file": { "file_data": "data:<media_type>;base64,…", "filename" } }`, using `title` as the filename and keeping `cache_control`. |
| `document` block, `source.type: "file"` (Files API) | `{ "type": "file", "file": { "file_id", "filename" } }`, using `title` as the filename. |
| `document` block, `source.type: "text"` | Text part. A `url` or `content` source is dropped. |
| Assistant `tool_use` block | Assistant `tool_calls[]` entry (`id`, `type: "function"`, `function.name`, `function.arguments` as a JSON string). |
| User `tool_result` block | A separate `{ "role": "tool", "tool_call_id", "content" }` message, in order. Text content is flattened to a string; content with an `image` or `document` block becomes a parts array, mapped as above. |
| `tools[]` (`name`, `description`, `input_schema`) | `{ "type": "function", "function": { name, description, parameters } }`. |
| `tool_choice` `auto` / `any` / `none` / `tool` + `name` | `auto` / `required` / `none` / `{ "type": "function", "function": { "name" } }`. |
| `max_tokens` | `max_tokens`. |
| `stop_sequences` | `stop`. |
| `metadata.user_id` | `user`. |
| `temperature`, `top_p`, `stream` | Passed through. |
| `thinking` | Canonical `reasoning` (see [`INFERENCE_CONTROLS.md`](INFERENCE_CONTROLS.md#reasoning)). |

`top_k` and any field not listed are dropped. The `anthropic-version` and
`anthropic-beta` headers do not affect routing.

### OpenAI Chat to an Anthropic upstream

When the Surface calls an Anthropic provider, `transform_to_anthropic_format` in
[`src/pipes/request_shaping.rs`](../src/pipes/request_shaping.rs) shapes the OpenAI Chat
body just before the call, buffered or streamed, whichever dialect the caller used. It
reverses the content mapping, so Anthropic `image` and `document` blocks reach Claude
unchanged; the full part mapping is in
[`MODALITIES.md`](MODALITIES.md#what-reaches-an-anthropic-upstream). Anthropic rejects
unknown top-level fields, so:

- A string `user` becomes `metadata.user_id`, or `safety_identifier` when there is no
  `user`. A `metadata.user_id` already present is kept, and every other `metadata` key is
  dropped. A non-string `user` or `safety_identifier` is dropped.
- Legacy function calling runs as tools: `functions` becomes `tools` and `function_call`
  becomes `tool_choice` (when the request has no `tools` or `tool_choice` of its own), an
  assistant `function_call` becomes a `tool_use` block, and a `role: "function"` message
  becomes the `tool_result` for the latest call of that name. The answer comes back as
  `tool_calls`, not `function_call`.
- `service_tier` `auto` stays `auto` and `default` becomes `standard_only`, the only tiers
  Anthropic accepts. Any other tier (`flex`, `priority`) is dropped.
- `n`, `seed`, `logprobs`, `top_logprobs`, `logit_bias`, `frequency_penalty`,
  `presence_penalty`, `store`, `modalities`, `audio`, `prediction`, `web_search_options`,
  `prompt_cache_key`, `verbosity`, `response_format`,
  `max_completion_tokens` (after it fills `max_tokens`), `stream_options`, and
  `parallel_tool_calls` are dropped. A caller's `web_search_options` does not turn on web
  search; the Surface's own server tools do (see
  [`INFERENCE_CONTROLS.md`](INFERENCE_CONTROLS.md#server-tools)).
- `stop` becomes `stop_sequences`.

A Claude model on Bedrock gets the same body through `transform_to_bedrock_anthropic_format`,
which also drops `metadata` and `service_tier` (Bedrock rejects both), removes `model`, and
adds `anthropic_version`. Bedrock reads images and documents only inline, so an image URL
or a `file_id` is refused with `400 unsupported_content`. See
[`PROVIDERS_AND_CREDENTIALS.md`](PROVIDERS_AND_CREDENTIALS.md#provider-types).

### OpenAI Responses to OpenAI Chat

`transform_from_responses_request` in
[`src/pipes/request_shaping.rs`](../src/pipes/request_shaping.rs):

| Responses | OpenAI Chat |
| --- | --- |
| `instructions` | A leading `system` message. |
| `input` as a string | One `user` message. |
| `input[]` `message` item | A message with that role. Parts `input_text`, `output_text`, and `text` become text; `input_image` becomes `image_url`; `input_audio` becomes `input_audio`; `input_file` becomes a `file` part (`filename`, `file_data`, `file_id`). |
| `function_call` item | Assistant `tool_calls[]` entry. |
| `function_call_output` item | A `tool` message. |
| `reasoning` item | Dropped. |
| `tools[]` (flat `{ type: "function", name, description, parameters }`) | Nested OpenAI function tool. |
| `tool_choice` | Mapped to the OpenAI form. |
| `max_output_tokens` | `max_tokens`. |
| `temperature`, `top_p`, `stream`, `parallel_tool_calls` | Passed through. |
| `text.format` | `response_format`. |
| `reasoning` (`effort`, `summary`) | Canonical `reasoning`; `summary` is dropped. |
| `user` (a string), else `metadata.user_id` (a string) | `user`. |

`store`, `previous_response_id`, the rest of `metadata`, and other fields not listed are
dropped. Agent Stream
keeps no conversation state, so a caller must send the whole conversation each turn.

## Response translation (buffered)

`skin_success_body` in
[`src/pipes/handlers/http_handlers.rs`](../src/pipes/handlers/http_handlers.rs) re-skins
the final OpenAI Chat body, after every response-side stage has run.

### OpenAI Chat to Anthropic Messages

`transform_to_anthropic_response` builds:

```jsonc
{
  "id": "msg_…",
  "type": "message",
  "role": "assistant",
  "model": "<resolved model>",
  "content": [
    { "type": "thinking", "thinking": "…" },          // when reasoning is present
    { "type": "text", "text": "…" },
    { "type": "tool_use", "id": "call_…", "name": "…", "input": { } }
  ],
  "stop_reason": "end_turn",
  "stop_sequence": null,
  "usage": { "input_tokens": 0, "output_tokens": 0,
             "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0 }
}
```

Thinking blocks are rebuilt from `reasoning_details` when present, which keeps their
signatures, otherwise from `reasoning` text. Tool-call arguments, a JSON string in OpenAI
Chat, are parsed into the `input` object. The cache counters appear only when the provider
reported them.

| `finish_reason` | `stop_reason` |
| --- | --- |
| `stop` | `end_turn` |
| `length` | `max_tokens` |
| `tool_calls` | `tool_use` |
| `content_filter` | `end_turn` |
| absent, with tool calls | `tool_use` |

### OpenAI Chat to OpenAI Responses

`transform_to_responses_response` builds:

```jsonc
{
  "id": "resp_…", "object": "response", "status": "completed",
  "model": "<resolved model>",
  "output": [
    { "type": "reasoning", "id": "rs_…", "summary": [ { "type": "summary_text", "text": "…" } ] },
    { "type": "message", "id": "msg_…", "role": "assistant", "status": "completed",
      "content": [ { "type": "output_text", "text": "…", "annotations": [] } ] },
    { "type": "function_call", "id": "fc_…", "call_id": "call_…", "name": "…",
      "arguments": "{…}", "status": "completed" }
  ],
  "output_text": "…",
  "incomplete_details": null,
  "usage": { "input_tokens": 0, "output_tokens": 0, "total_tokens": 0 }
}
```

Function-call arguments stay a JSON string. `finish_reason: "length"` gives
`status: "incomplete"` with `incomplete_details.reason: "max_output_tokens"`;
`content_filter` gives `incomplete` with reason `content_filter`; anything else is
`completed`.

## Streaming

A request streams token by token only when the Surface has no response-side stage (see
[`ARCHITECTURE.md`](../ARCHITECTURE.md#streaming)). Otherwise a request that asked for
`stream: true` gets one buffered response, converted as above. Either way the caller gets
its own dialect.

The streaming pipeline always produces OpenAI Chat `chat.completion.chunk` events,
translating Anthropic and Copilot upstreams first. `reencode_sse_body` in
[`src/pipes/streaming_skin.rs`](../src/pipes/streaming_skin.rs) then rewrites that event
stream for the caller's dialect. OpenAI Chat is returned unchanged. Because the encoder runs
last, token accounting, completion reassembly for Governance Records, NER ID restoration,
and abort handling all run on the canonical stream first.

A response-cache hit on a streaming request is replayed as SSE through the same encoder
(see [`RESILIENCE_AND_CACHING.md`](RESILIENCE_AND_CACHING.md#response-cache)).

### Anthropic Messages events (`AnthropicSse`)

1. On the first chunk: `message_start` (id, role, model, `usage.input_tokens`, empty
   content), then `ping`.
2. Reasoning deltas open a `thinking` block first and stream `thinking_delta`.
3. Text opens a `text` block (`content_block_start`) and streams `text_delta` in
   `content_block_delta`.
4. A tool call closes any open block (`content_block_stop`), opens a `tool_use` block with
   id and name, and streams `input_json_delta.partial_json`.
5. At the end: `content_block_stop` for the open block, `message_delta` with
   `delta.stop_reason` and `usage.output_tokens`, then `message_stop`.

### OpenAI Responses events (`ResponsesSse`)

Each event is written as `event: <type>` plus `data: <json>`.

1. Start: `response.created`, then `response.in_progress`, with an empty `output`.
2. Reasoning: a `reasoning` output item, `response.reasoning_summary_part.added`, and
   `response.reasoning_summary_text.delta`.
3. Text: `response.output_item.added` (a `message` item),
   `response.content_part.added` (an `output_text` part), then
   `response.output_text.delta`.
4. Tool call: `response.output_item.added` (a `function_call` item) and
   `response.function_call_arguments.delta`.
5. End: the matching `…done` events (`response.reasoning_summary_text.done`,
   `response.output_text.done`, `response.content_part.done`,
   `response.function_call_arguments.done`, `response.output_item.done`), then
   `response.completed` with the full `response` and `usage`. There is no `[DONE]` line.

## Authentication header mapping

The stock Anthropic SDK sends its key in `x-api-key`. On an Anthropic Messages request
with no `Authorization` header, `handle_chat_completions` copies `x-api-key` into
`Authorization: Bearer <key>` before source authentication and policy run, so a Surface
that reads a bearer credential works unchanged. An explicit `Authorization` header is
never overwritten. Callers that already send `Authorization: Bearer` (for example through
`ANTHROPIC_AUTH_TOKEN`) are unaffected.

The copied value is a front-door credential: it is never offered to the provider as the
caller's own key. See [`PROVIDERS_AND_CREDENTIALS.md`](PROVIDERS_AND_CREDENTIALS.md) for
key sources and [`SOURCE_AUTH.md`](SOURCE_AUTH.md) for the credential checks.

## Errors

On an Anthropic Messages request, `reskin_error_response` rewrites every non-2xx JSON error
into Anthropic's envelope, keeping the message:

```json
{ "type": "error", "error": { "type": "invalid_request_error", "message": "…" } }
```

| Status | Anthropic `error.type` |
| --- | --- |
| 400 | `invalid_request_error` |
| 401 | `authentication_error` |
| 403 | `permission_error` |
| 404 | `not_found_error` |
| 413 | `request_too_large` |
| 429 | `rate_limit_error` |
| 529 | `overloaded_error` |
| any other 5xx, and anything else | `api_error` |

A body that is not JSON gets the status-derived type and the message `request failed`
(`anthropic_error_body`, `openai_error_to_anthropic` in
[`src/pipes/ingress.rs`](../src/pipes/ingress.rs)).

OpenAI Responses uses the same `{ "error": { "message", "type", "code" } }` envelope as
OpenAI Chat, so its errors are not rewritten.

## Observability and policy

Every response from the chat entry point, except the stage-event stream and the VP
challenge response, carries
`x-agent-stream-ingress-skin` with the negotiated dialect (`openai_chat`,
`anthropic_messages`, or `openai_responses`).

Governance Records always store the OpenAI Chat form of the request and response, so the
signed record schema and its hash chain are the same for every dialect.

Policy sees the caller's original path in `input.http.path`, so a Rego rule that matches on
path must allow `…/v1/messages` and `…/v1/responses` as well as `…/v1/chat/completions`.
See [`POLICY.md`](POLICY.md).

## File map

| Concern | Location |
| --- | --- |
| Dialect enum, detection, accepted-set check, Anthropic error envelopes | [`src/pipes/ingress.rs`](../src/pipes/ingress.rs) (`IngressSchema`, `detect_ingress_schema`, `is_ingress_accepted`, `anthropic_error_body`, `openai_error_to_anthropic`) |
| Request and response translations | [`src/pipes/request_shaping.rs`](../src/pipes/request_shaping.rs) (`transform_from_anthropic_request`, `transform_from_responses_request`, `transform_to_anthropic_response`, `transform_to_responses_response`) |
| Streaming encoders | [`src/pipes/streaming_skin.rs`](../src/pipes/streaming_skin.rs) (`reencode_sse_body`, `EgressSkin`, `AnthropicSse`, `ResponsesSse`) |
| Handler wiring, `x-api-key` mapping, error re-skin | [`src/pipes/handlers/http_handlers.rs`](../src/pipes/handlers/http_handlers.rs) (`handle_chat_completions`, `normalize_ingress_request`, `skin_success_body`, `reskin_error_response`) |
| Config field | [`src/pipes/config.rs`](../src/pipes/config.rs) (`accepted_ingress_schemas`) |

## Known limitations

- The stage-event stream (`x-agent-stream-emit-stages: true`, see
  [`OBSERVABILITY.md`](OBSERVABILITY.md)) bypasses `reskin_error_response`, so its errors
  keep the OpenAI envelope.
- The streaming encoders do not translate an upstream error frame into an Anthropic or
  Responses `error` event; a stream that fails part-way ends with the normal closing
  events.
- Gemini `generateContent`, the legacy `/v1/completions`, and Anthropic
  `/v1/messages/count_tokens` are not translated dialects. A `count_tokens` path is
  handled as OpenAI Chat.

## Related

- [`INFERENCE_CONTROLS.md`](INFERENCE_CONTROLS.md): reasoning, structured outputs, and
  prompt caching across dialects.
- [`MODALITIES.md`](MODALITIES.md): images, audio, and documents in each dialect.
- [`PROVIDERS_AND_CREDENTIALS.md`](PROVIDERS_AND_CREDENTIALS.md): provider wire formats
  and key sources.
- [`SOURCE_AUTH.md`](SOURCE_AUTH.md): caller authentication.
- [`../ARCHITECTURE.md`](../ARCHITECTURE.md): pipeline order.
- [`../CONTEXT.md`](../CONTEXT.md): glossary.
