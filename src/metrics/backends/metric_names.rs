//! Centralized metric name constants shared across all backends (Prometheus, OpenTelemetry, CloudWatch).

// ============ Prometheus Metric Names ============

pub mod prom {
    // Gateway core
    pub const REQUESTS_TOTAL: &str = "agent_stream_requests_total";
    pub const REQUESTS_SUCCESS_TOTAL: &str = "agent_stream_requests_success_total";
    pub const REQUESTS_FAILURE_TOTAL: &str = "agent_stream_requests_failure_total";
    pub const REQUESTS_GATEWAY_FAULT_TOTAL: &str = "agent_stream_requests_gateway_fault_total";
    pub const REQUEST_DURATION_SECONDS: &str = "agent_stream_request_duration_seconds";
    pub const ACTIVE_CONNECTIONS: &str = "agent_stream_active_connections";
    pub const BYTES_SENT_TOTAL: &str = "agent_stream_bytes_sent_total";
    pub const BYTES_RECEIVED_TOTAL: &str = "agent_stream_bytes_received_total";

    // Rule validation
    pub const RULE_VALIDATIONS_ACCEPTED_TOTAL: &str = "agent_stream_rule_validations_accepted_total";
    pub const RULE_VALIDATIONS_REJECTED_TOTAL: &str = "agent_stream_rule_validations_rejected_total";

    // Canary / variant routing decisions
    pub const VARIANT_ROUTING_DECISIONS_TOTAL: &str = "agent_stream_variant_routing_decisions_total";

    // Policy-decision audit (OPA enforcement points)
    pub const POLICY_DECISIONS_TOTAL: &str = "agent_stream_policy_decisions_total";
    pub const POLICY_EVALUATION_FAILURES_TOTAL: &str = "agent_stream_policy_evaluation_failures_total";

    // Governance audit records forwarded to `audit` integrations
    pub const AUDIT_FORWARD_TOTAL: &str = "agent_stream_audit_forward_total";

    // Auth
    #[allow(dead_code)]
    pub const AUTH_ATTEMPTS_TOTAL: &str = "agent_stream_auth_attempts_total";
    #[allow(dead_code)]
    pub const AUTH_FAILURES_TOTAL: &str = "agent_stream_auth_failures_total";

    // Identity & connection gauges
    pub const UNIQUE_IDENTITIES: &str = "agent_stream_unique_identities";
    pub const THROUGHPUT_BYTES_PER_SEC: &str = "agent_stream_throughput_bytes_per_sec";
    pub const CONNECTIONS_PER_MINUTE: &str = "agent_stream_connections_per_minute";
    pub const AVG_REQUEST_LATENCY_MS: &str = "agent_stream_avg_request_latency_ms";
    pub const AVG_RESPONSE_LATENCY_MS: &str = "agent_stream_avg_response_latency_ms";

    // LLM/Pipe (gen_ai semantic conventions)
    #[allow(dead_code)]
    pub const GEN_AI_TOKEN_USAGE_INPUT: &str = "gen_ai_client_token_usage_input";
    #[allow(dead_code)]
    pub const GEN_AI_TOKEN_USAGE_OUTPUT: &str = "gen_ai_client_token_usage_output";
    #[allow(dead_code)]
    pub const GEN_AI_REQUEST_DURATION_SECONDS: &str = "gen_ai_server_request_duration_seconds";
    #[allow(dead_code)]
    pub const GEN_AI_REQUEST_COUNT_TOTAL: &str = "gen_ai_server_request_count_total";
    #[allow(dead_code)]
    pub const GEN_AI_COST_USD_TOTAL: &str = "gen_ai_cost_usd_total";
    #[allow(dead_code)]
    pub const GEN_AI_ERROR_COUNT_TOTAL: &str = "gen_ai_server_error_count_total";

    // User lifecycle
    pub const USER_EVENTS_TOTAL: &str = "agent_stream_user_events_total";
    pub const USERS_ACTIVE: &str = "agent_stream_users_active";
    pub const USER_LOGINS_TOTAL: &str = "agent_stream_user_logins_total";

    // KMS envelope encryption
    pub const KMS_OPERATION_TOTAL: &str = "agent_stream_kms_operation_total";
    pub const KMS_OPERATION_DURATION_SECONDS: &str = "agent_stream_kms_operation_duration_seconds";
    pub const AFFINIDI_TERMS_REFRESH_TOTAL: &str = "agent_stream_affinidi_terms_refresh_total";
    pub const AFFINIDI_TERMS_REFRESH_DURATION_SECONDS: &str = "agent_stream_affinidi_terms_refresh_duration_seconds";
    pub const AFFINIDI_TERMS_CACHE_AGE_SECONDS: &str = "agent_stream_affinidi_terms_cache_age_seconds";
    pub const AFFINIDI_TERMS_PUBLICATION_SEQUENCE: &str = "agent_stream_affinidi_terms_publication_sequence";

    // LLM cross-provider failover — only reachable via the live request path
    // (run_failover_if_needed in pipes/executor.rs), which no inline unit test
    // exercises, so these are unreachable (and thus flagged dead_code) in the
    // test-only compilation despite being genuinely used in the real binary.
    #[allow(dead_code)]
    pub const LLM_FAILOVER_TOTAL: &str = "agent_stream_llm_failover_total";
    #[allow(dead_code)]
    pub const LLM_FAILOVER_BACKUP_ATTEMPTS_TOTAL: &str = "agent_stream_llm_failover_backup_attempts_total";
    #[allow(dead_code)]
    pub const LLM_FAILOVER_SUPPRESSED_TOTAL: &str = "agent_stream_llm_failover_suppressed_total";
    #[allow(dead_code)]
    pub const LLM_FAILOVER_DURATION_SECONDS: &str = "agent_stream_llm_failover_duration_seconds";

    // Work skipped because a spent budget refused its platform-key call.
    pub const BUDGET_SKIPPED_TOTAL: &str = "agent_stream_budget_skipped_total";

    // Platform-key streams billed an estimate because they reported no usage.
    // Only reachable via the live streaming path, so dead in the test build.
    #[allow(dead_code)]
    pub const STREAM_USAGE_ESTIMATED_TOTAL: &str = "agent_stream_stream_usage_estimated_total";
}

// ============ OpenTelemetry Instrument Names ============

pub mod otel {
    pub const CONNECTIONS_TOTAL: &str = "gateway.connections.total";
    pub const CONNECTION_LATENCY: &str = "gateway.connection.latency";
    pub const CONNECTIONS_ACTIVE: &str = "gateway.connections.active";

    pub const SURFACE_EXECUTIONS_TOTAL: &str = "gateway.pipe.executions.total";
    pub const SURFACE_TOKENS_TOTAL: &str = "gateway.pipe.tokens.total";
    pub const SURFACE_COST_TOTAL: &str = "gateway.pipe.cost.total";
    pub const SURFACE_LATENCY: &str = "gateway.pipe.latency";
    pub const SURFACE_GATEWAY_PROCESSING: &str = "gateway.pipe.gateway_processing";
    pub const SURFACE_TARGET_PROCESSING: &str = "gateway.pipe.target_processing";

    pub const CHANNEL_REQUESTS_TOTAL: &str = "gateway.channel.requests.total";
    pub const CHANNEL_LATENCY: &str = "gateway.channel.latency";

    pub const RULES_VALIDATIONS_TOTAL: &str = "gateway.rules.validations.total";

    pub const BYTES_SENT_TOTAL: &str = "gateway.bytes.sent.total";
    pub const BYTES_RECEIVED_TOTAL: &str = "gateway.bytes.received.total";

    pub const USER_EVENTS_TOTAL: &str = "gateway.user.events.total";
    pub const USER_LOGINS_TOTAL: &str = "gateway.user.logins.total";
}

// ============ CloudWatch Metric Names ============

pub mod cloudwatch {
    pub const REQUEST_COUNT: &str = "RequestCount";
    pub const SUCCESS_COUNT: &str = "SuccessCount";
    pub const FAILURE_COUNT: &str = "FailureCount";
    pub const GATEWAY_FAULT_COUNT: &str = "GatewayFaultCount";
    pub const SUCCESS_RATE: &str = "SuccessRate";
    pub const AVG_REQUEST_LATENCY: &str = "AverageRequestLatency";
    pub const REQUEST_LATENCY_SAMPLE_COUNT: &str = "RequestLatencySampleCount";
    pub const AVG_RESPONSE_LATENCY: &str = "AverageResponseLatency";
    pub const RESPONSE_LATENCY_SAMPLE_COUNT: &str = "ResponseLatencySampleCount";
    pub const ACTIVE_CONNECTIONS: &str = "ActiveConnections";
    pub const THROUGHPUT_BYTES_PER_SEC: &str = "ThroughputBytesPerSec";
    pub const CONNECTIONS_PER_MINUTE: &str = "ConnectionsPerMinute";
    pub const UNIQUE_IDENTITIES: &str = "UniqueIdentities";
    pub const RULE_ACCEPT_COUNT: &str = "RuleAcceptCount";
    pub const RULE_REJECT_COUNT: &str = "RuleRejectCount";
    pub const USER_CREATED_COUNT: &str = "UserCreatedCount";
    pub const ACTIVE_USERS: &str = "ActiveUsers";
    pub const USER_LOGINS: &str = "UserLogins";
}
