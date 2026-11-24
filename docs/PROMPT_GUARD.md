# Prompt Guard

How Prompt Guard detects sensitive data on an LLM Surface, what it does with a
match, and how NER IDs pseudonymise values and restore them in the response. For the
other safety stages and the pipeline order, see [GUARDRAILS.md](GUARDRAILS.md).
Hosted documentation:
[PII protection](https://docs.affinidi.com/products/affinidi-trust-fabric/agent-stream/concepts/pii-protection/).

## Overview

Prompt Guard inspects the text on a Surface and, for each match, rejects the call,
redacts the value, or replaces it with a NER ID. It is the only safety stage that
rewrites content. With NER IDs, the provider and every review stage see consistent
placeholders instead of real values, and the caller can still receive the real values
back.

```text
John Smith lives at 101 Main Street. John's email is john.smith@example.com.
[PERSON_NER_001] lives at [ADDRESS_NER_001]. [PERSON_NER_001]'s email is [EMAIL_NER_001].
```

Detection is two-layered:

- **Patterns.** Built-in and custom regular expressions, deterministic and in-process.
  On the request and the response.
- **Model-backed detection.** An OpenAI-compatible model you choose finds free-form
  values that patterns miss: names, addresses, organisations, locations, and any type
  you name. On the request only.

![The Prompt Guard editor with two guards: a Regular Expression guard redacting built-in email and credit-card patterns, and an AI Matching guard that sends the request to a chosen model, detects selected entity types, and replaces each value with a NER ID.](assets/diagrams/screenshot-prompt-guard.png)

Prompt Guard is configured per Surface under `prompt_guard`
([`src/pipes/prompt_guard/config.rs`](../src/pipes/prompt_guard/config.rs)) and is off
until configured.

## Where it runs

On the request side, inside each executor attempt, in this order
(`execute_once` and `execute_streaming` in [`src/pipes/executor.rs`](../src/pipes/executor.rs)):

1. A check that every request and response pattern rule can be evaluated; see
   [Rules that cannot be evaluated](#rules-that-cannot-be-evaluated).
2. Pattern guards (`prompt_guard.request`), in list order.
3. Model PII detectors (`prompt_guard.llm_pii`), on the already-masked text.
4. Pronoun linking, when any request guard sets `link_pronouns`.

Then the request Expert Witnesses, Judge, and Decider run, then the model. On the
response side, after the Jury: pattern guards (`prompt_guard.response`), then the
response Expert Witnesses, then NER ID restore. The provider, Decider, Judge,
Jurors, and witnesses therefore only see the masked or pseudonymised text.

```mermaid
flowchart LR
    A[Caller request] --> B["Pattern guards (request)"]
    B --> C[Model PII detectors]
    C --> D["Request witnesses, Judge, Decider"]
    D --> E[Model sees NER IDs]
    E --> F["Jury, response pattern guards,<br/>response witnesses"]
    F --> G{"restore_in_response set?"}
    G -- yes --> H[NER ID restore]
    H --> I[Caller gets real values]
    G -- no --> J[Caller gets NER IDs]
```

All request-side steps run on both the buffered and the streaming path. Response
pattern guards force the buffered path; see
[GUARDRAILS.md](GUARDRAILS.md#pipeline-order).

Detection and masking cover each message's `content` (a string, or the `text` parts
of a content array) and assistant `tool_calls[].function.arguments`. A mask guard
rewrites tool-call arguments too, so a numeric ID of 14 or more digits in them is
masked as a card. When the arguments are JSON, a token that replaces a bare value
such as a number is quoted (`{"order_id": "<CREDIT_CARD>"}`), so they still parse.
Realtime voice sessions (`/v1/realtime`) run no Prompt Guard.

## Configuration

```jsonc
"prompt_guard": {
  "enabled": true,
  "request": [
    {
      "regex": {
        "action": "mask",
        "mask_mode": "pseudonymize",
        "restore_in_response": true,
        "link_pronouns": false,
        "rules": [
          { "builtin": "email" },
          { "builtin": "ssn" },
          { "pattern": "ACC-\\d{6}", "label": "account_id" }
        ]
      }
    }
  ],
  "response": [
    { "regex": { "action": "reject", "rules": [ { "builtin": "credit_card" } ] } }
  ],
  "llm_pii": [
    {
      "provider_type": "openai",
      "endpoint_url": "/v1/chat/completions",
      "model": "gpt-4o-mini",
      "api_key_secret": "pii-detector-key",
      "entity_types": ["PERSON", "ADDRESS", "ORG", "LOCATION"],
      "action": "mask",
      "mask_mode": "pseudonymize",
      "restore_in_response": true
    }
  ]
}
```

| Field | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Turns the whole Prompt Guard on or off. |
| `request` | `[]` | Pattern guards on the request. |
| `response` | `[]` | Pattern guards on the response. |
| `llm_pii` | `[]` | Model PII detectors on the request. A single object is also accepted. |
| `external` | none | Legacy single external guardrail, migrated into an Expert Witness at runtime; see [GUARDRAILS.md](GUARDRAILS.md#legacy-prompt_guardexternal). |

A Variant can override `prompt_guard` as a whole; see [ROUTING.md](ROUTING.md).

## Pattern guards

Each entry in `request` or `response` is `{ "regex": RegexRules, "rejection": RejectionConfig? }`.

| `regex` field | Default | Meaning |
| --- | --- | --- |
| `action` | `reject` | `reject` blocks on the first match; `mask` rewrites every match. |
| `mask_mode` | `redact` | With `mask`: `redact` replaces each match with `<ENTITY>`; `pseudonymize` replaces each distinct value with a NER ID. |
| `restore_in_response` | `false` | Request side, `pseudonymize` only: put the real values back in the answer. |
| `link_pronouns` | `false` | Request side, `pseudonymize` only: link a pronoun to a lone named person. |
| `rules` | required | Built-in or custom patterns, applied in order; a `mask` guard applies `credit_card` first (see below). |

A rule is either `{"builtin": "<key>"}` or `{"pattern": "<regex>", "label": "<name>"}`.
Rules run in sequence, each on the output of the one before. A `mask` guard runs
`credit_card` before its other rules, which keep their listed order. The card pattern
masks a whole run of digits joined by single spaces or dashes, so no other rule, such
as `phone_number`, `ssn` or `street_address`, can take part of a card first. A phone
number or SSN written right next to a card is masked with it as one `<CREDIT_CARD>`:
`+65 6123 4567 4545 4545 4545 4545` becomes `+<CREDIT_CARD>`, and
`4545 4545 4545 4545 123-45-6789` becomes `<CREDIT_CARD>`. For the same reason, an
international phone number of 14 or more digits on its own (`+49 1512 3456 7890`) is
labelled `<CREDIT_CARD>`, not `<PHONE_NUMBER>`, and a house number written right after
a card (`4545 4545 4545 4545 12 Main Street`) joins the card match, so `street_address`
no longer matches the rest of the address. This holds within one guard; across
separate guards, list the `credit_card` guard first. Guards run in sequence on the
rewritten text, so the order across guards matters:

- A mask guard with `credit_card` absorbs an SSN or phone number written right next to
  a card before later guards run, so a later reject guard on `ssn` does not see it and
  the request is masked rather than rejected.
- A `phone_number` or `street_address` guard listed before the `credit_card` guard
  takes part of a card and leaves the rest too short to match:
  `+1 415 555 0100 4545 4545 4545 4545` becomes `<PHONE_NUMBER>5 4545 4545 4545`.

A reject guard with `credit_card` refuses every input the card pattern matches,
including dates written next to each other (`Can we meet 2026-11-24 2026-11-25`),
order IDs (`Order ORD-20261124-000123`) and a phone number followed by more digits
(`212 555 1234 2026`). Put `credit_card` in a mask guard where such text is expected.
With `reject`,
processing stops at the first match, which returns the guard's `rejection` or the
default 403 body
`{"error":{"message":"Request rejected: content violates prompt guard policy","type":"prompt_guard_violation","code":"content_policy_violation"}}`.
The `INFO` log line for the rejection names the built-in pattern or custom rule that
matched, never the matched text.

The entity name used in a placeholder is the built-in key upper-cased (`EMAIL`,
`PHONE_NUMBER`, `STREET_ADDRESS`), or a custom rule's `label` upper-cased. A custom
rule without a label redacts to `<MASKED>` and pseudonymises as `CUSTOM`.

### Built-in patterns

Built-in patterns are loaded once at startup from `prompt-guard.json`, named by
`prompt_guard` under `[config_files]` in `config.toml`
([`src/pipes/prompt_guard/definitions.rs`](../src/pipes/prompt_guard/definitions.rs)).
The shipped file is
[`config/examples/prompt-guard.example.json`](../config/examples/prompt-guard.example.json).
Each entry has a `key`, `label`, `icon`, `description`, and `regex`. A pattern whose
regex does not compile cannot be used; see
[Rules that cannot be evaluated](#rules-that-cannot-be-evaluated).
`GET /v1/prompt-guard/config` serves the pattern list. An upgrade does not replace a
deployed `prompt-guard.json`; replace it from the shipped file to pick up pattern fixes.

| Key | Matches |
| --- | --- |
| `email` | Email addresses |
| `ssn` | US Social Security Numbers with a dash or space between groups (`NNN-NN-NNNN`, `NNN NN NNNN`), excluding invalid area, group and serial numbers |
| `ssn_simple` | Any `NNN-NN-NNNN` or `NNN NN NNNN`, dashes and spaces in any mix |
| `phone_number` | US, international (`+` country code), and Australian mobile numbers |
| `credit_card` | Any run of 14 or more digits written together or with single spaces or dashes between digits (`4545 4545 4545 4545`, `4111 1111 11111111`), matched whole, and 13-digit Visa numbers written together. There is no checksum, so long IDs, timestamps written as digits, grouped references, adjacent dates, numbered lists (`1 2 3 4 5 6 7 8 9 10 11 12`) and amounts grouped with spaces (`1 000 000 000 000 000`) also match. |

`credit_card`, `ssn` and `ssn_simple` match a number written straight after CJK or
other non-ASCII text (`卡号4545454545454545`, `社保号123-45-6789`), but not one written
straight after an ASCII letter, digit or `_` (`cc4545454545454545`). `credit_card` does
not catch digits separated by a no-break space, a tab, two spaces, dots or an en dash,
or a 13-digit Visa written with spaces (`4222 2222 2222 2`).
| `date_of_birth` | Dates preceded by birth keywords (birth, dob, born) |
| `ip_address` | IPv4 addresses with octet validation |
| `passport` | US passport numbers |
| `street_address` | Basic US street addresses |

### Rules that cannot be evaluated

A pattern rule cannot be evaluated when it names a built-in pattern that is not
defined, whose regex did not compile, or that is unavailable because
`prompt-guard.json` did not load, or when it is a custom `pattern` that does not
compile. Prompt Guard fails closed on such a rule:

- Saving a Surface, or one of its Variants, through the Admin API when its enabled
  Prompt Guard has one is refused with `400`, and the error names the rule. An
  unlabelled custom pattern is named by its position in its guard (`custom pattern #2`),
  never by its regex. Surfaces that arrive another way, such as a Surface template or a
  hot reload, are not checked when saved; they are refused at request time, below.
- A Surface already stored with one, for example after `prompt-guard.json` changed,
  refuses every request before any upstream call, whichever side the rule is on, with
  `502`. That covers chat, streamed, text-to-speech, file upload and transcription
  requests and GET passthrough reads; realtime voice sessions run no Prompt Guard and
  are not refused. The refusal is not retried under a `retry_policy`. The body is
  `{"error":{"message":"Prompt Guard rule unavailable","type":"guardrail_unavailable","code":"prompt_guard_pattern_unavailable"}}`.
  The guard's `rejection` is not used, and the `WARN` log line names the rule and why.
  Rejection telemetry records it under the stage of the rule's side (`regex_request` or
  `regex_response`), with source `prompt_guard_unavailable` and reason token
  `prompt_guard_pattern_unavailable`, which the shipped taxonomy classifies as
  `prompt_guard_unavailable` rather than as a content match. A deployed
  `rejection_categories.json` replaces the shipped taxonomy whole, so copy that
  category and its mapping from the example into it. Surfaces without
  such a rule are unaffected. The response cache runs before Prompt Guard on every
  request, so two exceptions apply: a semantic cache's embedder receives the request
  text, and a cache hit is still served.
- At startup, each built-in pattern that does not compile, or a file that did not load,
  is logged at `ERROR` and counted in `agent_stream_prompt_guard_pattern_errors_total`
  ([OBSERVABILITY.md](OBSERVABILITY.md)).

## Model-backed detection

Each entry in `llm_pii` (`LlmPiiConfig`) sends the request text to an
OpenAI-compatible chat-completions endpoint and asks it to return
`{"entities": [{"type", "text", "group"}]}`
([`src/pipes/prompt_guard/llm_pii.rs`](../src/pipes/prompt_guard/llm_pii.rs)).

![An AI Matching guard: provider, endpoint, model, and key secret; the entity types to detect, with presets and a custom type field; Use a NER ID to preserve context; toggles for restore in response, link coreferences, and cache detections; and Reject if PII detection is unavailable.](assets/diagrams/screenshot-prompt-guard-ai-matching.png)

| Field | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Runs this detector. |
| `provider_type` | `""` | Resolves a relative `endpoint_url` against the provider's base URL, like a Judge target. Empty means `endpoint_url` is a full URL. |
| `endpoint_url` | required | Full URL or a path such as `/v1/chat/completions`. |
| `model` | required | Detection model. |
| `api_key_secret` | none | Secret id for the detector's key, sent as a bearer token. |
| `entity_types` | `PERSON`, `ADDRESS`, `ORG`, `LOCATION`, `EMAIL_ADDRESS`, `PHONE_NUMBER` | Types the model is asked for; returned types outside the list are dropped. Any custom type name works. |
| `action` | `mask` | `mask` rewrites each value per `mask_mode`; `reject` blocks when any PII is found. |
| `mask_mode` | `pseudonymize` | `redact` or `pseudonymize`, with `action = mask`. |
| `rejection` | 403 prompt-guard body | Response for `action = reject`. |
| `restore_in_response` | `false` | Restore detected values in the answer. |
| `link_coreferences` | `false` | Collapse each coreference group to one NER ID. |
| `cache_detection` | `true` | Cache results in memory; see [Detector cache](#detector-cache). |
| `timeout_secs` | `10` | Per-call timeout. |
| `fail_closed` | `true` | When the detector is unavailable: `true` rejects the request, `false` continues with only the pattern masking already applied. |

With `action = reject`, `mask_mode`, `restore_in_response`, and `link_coreferences`
do not apply. `fail_closed` is separate from `action`: it decides what happens when
the detector errors or times out, not when it finds PII.

How detection works:

- The model returns values, not offsets. Each value is located in the text by
  substring match, with overlaps removed, so a model that rephrases a span cannot
  corrupt the request.
- Several detectors run concurrently, so the added latency is that of the slowest.
  Their results are applied one after another through one shared NER ID allocator,
  and a value caught by two detectors, or by a pattern and a detector, gets one ID.
  If any `reject` detector finds PII, the request is rejected.
- The system prompt is `pii_detection_prompt` at the top level of
  `prompt-guard.json`, with a built-in default when absent. `Allowed types: ...` is
  appended from `entity_types` on each call. The request asks for `temperature: 0`
  and JSON mode, adjusted by the model catalog for models that reject them.
- A detector with a stored key is checked against the caller's budget before the
  request makes any call; a budget refusal refuses the request even when
  `fail_closed` is `false`. A keyless detector is never refused for budget.

### Detector cache

With `cache_detection` on, results are cached per message, keyed by
`sha256(model, entity_types, message_text)`. A multi-turn chat re-sends earlier turns
verbatim, so only the newest message reaches the model; unseen messages are detected
in one batched call. With `link_coreferences` on, the cache is keyed on the whole
prompt instead, so the model still sees every mention together and only exact repeats
are reused. The cache is in memory only, never written to disk, and bounded to one
hour and 10,000 entries ([`src/pipes/prompt_guard/pii_cache.rs`](../src/pipes/prompt_guard/pii_cache.rs)).

### Detector health and test

| Route | Permission | Returns |
| --- | --- | --- |
| `GET /v1/prompt-guard/detector-stats` | `metrics.view` | Successful and failed detector calls since process start, and the error rate |
| `POST /v1/prompt-guard/detector-test` | `pipes.edit` | One live detector call against a sample sentence, cache bypassed: the detected entities or the error |

- A detector **with a stored API key** can be tested only after the surface is saved.
  The test sends the key only to the endpoint saved with it, and only with the saved model,
  so save a changed model before testing it. Only users who may view secrets
  (`secrets.view`) can save a stored key with a new endpoint.
- The test shows the endpoint's reply, so it refuses private, link-local, loopback and
  cloud-metadata addresses and follows no redirects. A self-hosted detector on a private
  network still works on live traffic but cannot be tested from the editor.
- A test waits at most 30 seconds for the detector, whatever `timeout_secs` says.

When a detector runs on a Surface with Governance Records on, the record gets a
`prompt_guard_model_pii` stage: `Observed` with the number of values masked and
detectors run, or `Flag` with the number of detectors that were unavailable when the
request continued with regex masking only. The stage never contains the value map.

## NER IDs

With `mask_mode: pseudonymize`, each distinct value becomes a NER ID of the form
`[{ENTITY}_NER_{NNN}]`, numbered from `001` per entity type in reading order.

- One allocator lives for one guard pass (the request side, or the response side) and
  is shared by every pattern guard and detector in that pass, across all messages. The
  same `(entity type, value)` always gets the same ID within a request.
- IDs are not stable across requests.
- The map from NER ID to value lives only for the request and is never written to
  disk. Governance Records store the caller's original request and the restored
  answer; the provider received only NER IDs.

### Name-variant linking

For `PERSON` values, a value whose name tokens are a subset or superset of a single
person already seen reuses that person's ID. Tokens are compared lower-cased, with
possessives, punctuation, and honorifics such as `Mr` and `Dr` removed. `John Smith`,
`John`, `John's`, and `Dr. Smith` all become `[PERSON_NER_001]`. A surname that
matches two known people is ambiguous and gets its own ID. Other types key on the
exact value.

### Pronoun linking

With `link_pronouns` on a request guard, a singular gendered pronoun (`he`, `him`,
`his`, `himself`, `she`, `her`, `hers`, `herself`) is replaced with a person's NER ID
only when exactly one distinct person ID appears before it in the message
(`link_pronouns_in_body` in [`src/pipes/prompt_guard/filter.rs`](../src/pipes/prompt_guard/filter.rs)).
With two or more people, or a pronoun before any person, it is left alone. `they` is
never linked. Pronouns are not PII, so this adds consistency, not privacy; with
restore on, the pronoun comes back as the person's name.

### Coreference groups

The detector tags each mention with a `group` shared by every mention of one
real-world entity, including aliases with no tokens in common (`Bob` and
`Robert Smith`, `Acme` and `Acme Corporation`). With `link_coreferences` on, every
mention in a group gets one NER ID keyed on the group's longest value, and restores
to that value. Only the values the detector returns are grouped, so common words are
never replaced. It applies with `mask_mode: pseudonymize`.

### Restore in the response

When a request pattern guard or a detector sets `restore_in_response`, the request's
NER ID map is kept for the response. After every model-facing stage, the real values
are spliced back into `choices[].message.content`, `delta.content`, and buffered
`tool_calls` arguments in one Aho-Corasick pass (`rehydrate_response`).

On a stream, a NER ID can be split across SSE chunks. The stream rehydrator
([`src/pipes/prompt_guard/stream_rehydrate.rs`](../src/pipes/prompt_guard/stream_rehydrate.rs))
holds back any trailing text that starts at an unclosed `[` and could still become a
NER ID, bounded by the longest ID, and emits completed IDs restored in one piece. Text
still held at the end is flushed before the final chunk. It is created only when a
restore map exists, so other streams pass through unchanged. A streamed Governance
Record holds the restored text the client received.

## Security and privacy

- **Trusted detector only.** The request text is sent to the detection model. Point
  it at a model you trust, ideally self-hosted.
- **Validated endpoint.** The detector's resolved endpoint is SSRF-checked when the
  Surface is saved (`LlmPiiConfig::validate`) and before each call.
- **Bounded input.** At most 256 KiB of text is sent to a detector
  (`MAX_DETECT_TEXT_BYTES`).
- **Injection-resistant framing.** The inspected text is wrapped in a per-call random
  delimiter, and a code-enforced instruction tells the model to treat it as data only,
  so a caller cannot easily talk the detector out of finding their PII. Pattern guards
  and `fail_closed` remain the hard backstops.
- **No persisted values.** The NER ID map and the detector cache stay in memory and
  are never written to disk.

## Known limitations

- Model-backed detection runs on the request only; the response has pattern guards.
- Text beyond the first 256 KiB of a request is not inspected by a detector.
- On a stream, restore covers `delta.content` only, not streamed tool-call argument
  fragments.
- NER IDs are stable within one request, not across requests.
- `prompt-guard.json` is read once at startup; editing it needs a restart.
- A content block cannot be retracted from bytes already streamed, which is why
  response pattern guards force the buffered path.

## Related

- [GUARDRAILS.md](GUARDRAILS.md): Expert Witness, Judge, Jury, and the pipeline order.
- [GOVERNANCE_RECORDS.md](GOVERNANCE_RECORDS.md): the `prompt_guard_model_pii` stage and recorded bodies.
- [PROVIDERS_AND_CREDENTIALS.md](PROVIDERS_AND_CREDENTIALS.md): secrets and the model catalog.
- [USAGE_LIMITS_AND_ATTRIBUTION.md](USAGE_LIMITS_AND_ATTRIBUTION.md): budget checks on detector calls.
- [RBAC.md](RBAC.md): `metrics.view` and `pipes.edit`.
- [CONFIGURATION_REFERENCE.md](CONFIGURATION_REFERENCE.md): `[config_files]` keys.
