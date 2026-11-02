# Changelog

All notable changes to Affinidi Agent Stream will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-11-02

### Added

- Introduce LLM Surfaces for routing and governing model calls from agents and applications.
- Introduce IDE Surfaces that offer editors one governed model catalogue behind an OpenAI-compatible endpoint.
- Support OpenAI Chat Completions, Anthropic Messages, and OpenAI Responses client APIs against any provider.
- Support OpenAI, Anthropic, Gemini, Bedrock, Azure OpenAI, Microsoft 365 Copilot, and other native and OpenAI-compatible providers.
- Support operator, tenant, and caller-supplied provider keys, with secret-backed upstream headers and billed-cost tracking per key source.
- Support Variants, routing rules, canary splits, and Decider, Comparer, and Summariser model selection.
- Support failover, load balancing, retries, circuit breakers, rate limits, and exact and semantic response caching.
- Support reasoning, structured outputs, prompt caching, and Web Search and Web Fetch server tools.
- Support image, audio, document, and realtime voice inputs.
- Support Prompt Guard sensitive-data masking with pattern and model-backed detection and NER ID pseudonymisation.
- Support Judge, Jury, and Expert Witness guardrails with categorised rejections.
- Support API key, JWT, and mTLS source authentication.
- Support layered, versioned OPA/Rego policy with dry runs and Verifiable Presentation evidence.
- Support Members, Teams, budgets, usage limits, and per-stage cost attribution.
- Support versioned, reusable prompt templates.
- Support signed, hash-chained Governance Records issued as Verifiable Credentials.
- Support LLM drift detection against pinned baselines with replay evaluation.
- Support Prometheus, OpenTelemetry, Langfuse, and live pipeline stage streaming.
- Support usage, budget, and drift alerts and events through webhook, Slack, email, Kafka, Kinesis, Pulsar, and Redis Streams integrations.
- Support a web dashboard with real-time monitoring, a Surface sandbox, and hot configuration reload.
- Support admin RBAC, passkey and SAML sign-in, scoped management access tokens, and tenant-aware management.
- Support Terms and consent acceptance for dashboard users and access token owners.
- Support appliance-wide resource limits.
- Support DID-based appliance identity and DIDComm Trust Fabric connections governed by policy.
- Support encryption at rest, encrypted backups, redacted exports, secret management, and Active/Standby deployment.
- Redact secrets and personal data from logs and telemetry.
