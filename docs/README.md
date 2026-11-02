# Repository Documentation

The documents here explain what Agent Stream does, how it is built, and how to change it,
without needing to leave the repository. They describe the checked-out revision exactly,
including implementation details and limitations.

The hosted [Agent Stream documentation](https://docs.affinidi.com/products/affinidi-trust-fabric/agent-stream/)
adds procedures for deploying and operating an appliance, operator guides, and FAQs.

## Start Here

| Document | Scope |
| --- | --- |
| [Capabilities](CAPABILITIES.md) | What Agent Stream can do, in detail |
| [Architecture](../ARCHITECTURE.md) | How the system is put together and where in `src/` each part lives |
| [Build From Source](development/GETTING_STARTED.md) | Build and run this source tree locally |
| [Development Guide](development/DEVELOPMENT.md) | Debugging, Docker, named instances, scripts, and storage export |
| [Making Changes](development/MAKING_CHANGES.md) | Recipes for the recurring change shapes, organised by what you want to do |
| [Testing](development/TESTING.md) | The test layers, what belongs in each, and how to run them |
| [Releasing](development/RELEASING.md) | Versions, tags, changelog fragments, and release preparation |
| [Contributing](../CONTRIBUTING.md) | Contribution process and required checks |
| [Project glossary](../CONTEXT.md) | Canonical terminology for source, tests, and repository documentation |
| [Security policy](../SECURITY.md) | Private vulnerability reporting |

## Configuration

| Document | Scope |
| --- | --- |
| [Configuration files](CONFIGURATION_REFERENCE.md) | What each configuration file controls and the effect of its fields |
| [Configuration reload](CONFIGURATION_RELOAD.md) | Hot reload, startup-only settings, the reload endpoint, and Active and Standby server mode |
| [Encryption at rest](ENCRYPTION_AT_REST.md) | Key hierarchy, `[encryption]` settings, key sources, backup and restore |
| [Example configuration](../config/examples/README.md) | The example files and what each maps to |

## Implementation References

### Model traffic

| Document | Revision-specific scope |
| --- | --- |
| [Client API dialects](CLIENT_API_DIALECTS.md) | OpenAI Chat Completions, Anthropic Messages, and OpenAI Responses: negotiation, translation, streaming, errors |
| [Routing](ROUTING.md) | Variants, the Router, canary splits, and the Decider, Comparer, and Summariser modes |
| [Resilience and caching](RESILIENCE_AND_CACHING.md) | Retries, failover, load balancing, circuit breaker, rate limit, and the response cache |
| [Inference controls](INFERENCE_CONTROLS.md) | Reasoning, structured outputs, per-request routing, prompt caching, server tools, and the context-window guard |
| [Modalities](MODALITIES.md) | Images, audio, documents, realtime voice, voice safety, and the multimedia store |
| [Providers and credentials](PROVIDERS_AND_CREDENTIALS.md) | Providers, the model catalog, upstream headers, key sources, shared credentials, pricing, and billed cost |
| [IDE Surfaces](IDE_SURFACES.md) | IDE dispatch, the bootstrap contract, OAuth identifiers, and the VS Code extension |
| [Microsoft 365 Copilot](M365_COPILOT.md) | The Copilot provider, translation, dual tokens, and limitations |
| [Prompts](PROMPTS.md) | Stored Prompts, versions, rendering, and references from requests |

### Safety and governance

| Document | Revision-specific scope |
| --- | --- |
| [Guardrails](GUARDRAILS.md) | The guardrail stages and their order, Expert Witness providers, Judge, Jury and Redrive, and rejection categories |
| [Prompt Guard](PROMPT_GUARD.md) | Pattern and model detectors, actions, NER IDs, and restoring values |
| [Usage limits and attribution](USAGE_LIMITS_AND_ATTRIBUTION.md) | Members, Teams, the team gate, budgets, usage limits, and spend reporting |
| [Governance Records](GOVERNANCE_RECORDS.md) | Signed records, the hash chain, storage, retention, verification, and export |
| [LLM drift](LLM_DRIFT.md) | Drift dimensions, sampling, baselines and verdicts, replay evaluation, and alerts |

### Access and policy

| Document | Revision-specific scope |
| --- | --- |
| [Dashboard sign-in](DASHBOARD_SIGN_IN.md) | Passkey and SAML sign-in, sign-in throttling, sessions, the signed-in user's profile and avatar, image uploads, and dashboard settings |
| [Source authentication](SOURCE_AUTH.md) | Caller authentication methods, API keys, public discovery reads, and the inbound gate order |
| [Policy](POLICY.md) | Policy layers and packages, policy input, versioned definitions, appliance-wide enforcement, and dry run |
| [Management RBAC](RBAC.md) | Roles, permissions, enforcement, and the permissions response |
| [Management access tokens](ACCESS_TOKENS.md) | The PAT contract, resource scope, tenant ownership, delegation, and expiry |
| [Terms and consent](TERMS_AND_CONSENT.md) | Terms versions, acceptance records, and consent-pending sessions |

### Platform

| Document | Revision-specific scope |
| --- | --- |
| [Observability](OBSERVABILITY.md) | Logging, OpenTelemetry, metrics, the dashboard WebSocket, response headers, policy audit, and stage streaming |
| [Integrations](INTEGRATIONS.md) | Publishers, the event catalogue, runtime variables, templates, and delivery |
| [Fabric](FABRIC.md) | The appliance DID, Connection Points, mediators, pairing, and the forward receive path |

### Testing

| Document | Scope |
| --- | --- |
| [BDD guide](testing/bdd-gherkin.md) | The behaviour-test harness, runner profile, and rules |
| [BDD tool](testing/bdd-gherkin-tool.md) | The Gherkin inventory and lint workflow |

## Coverage

The [module map in `ARCHITECTURE.md`](../ARCHITECTURE.md#module-map) is the single record of
what documents each part of the source. Every top-level module in `src/` has a row, naming
either the document that covers it or, where there is none, the file to start reading.

For product tasks, start with the hosted [Quickstart](https://docs.affinidi.com/products/affinidi-trust-fabric/agent-stream/get-started/), [Guides](https://docs.affinidi.com/products/affinidi-trust-fabric/agent-stream/how-to-guides/), or [Reference](https://docs.affinidi.com/products/affinidi-trust-fabric/agent-stream/reference/).
