//! Prometheus metrics helpers

use lazy_static::lazy_static;
use prometheus::{
    Counter, Gauge, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts, Registry,
};

use super::metric_names::prom as names;

lazy_static! {
    /// Global Prometheus registry
    pub static ref REGISTRY: Registry = Registry::new();


    /// Total number of requests processed
    pub static ref REQUEST_COUNTER: Counter = {
        let opts = Opts::new(names::REQUESTS_TOTAL, "Total number of requests processed");
        let counter = Counter::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };


    /// Total number of successful requests
    pub static ref SUCCESS_COUNTER: Counter = {
        let opts = Opts::new(names::REQUESTS_SUCCESS_TOTAL, "Total number of successful requests");
        let counter = Counter::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };


    /// Total number of failed requests
    pub static ref FAILURE_COUNTER: Counter = {
        let opts = Opts::new(names::REQUESTS_FAILURE_TOTAL, "Total number of failed requests");
        let counter = Counter::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };


    /// Total number of gateway fault requests
    pub static ref GATEWAY_FAULT_COUNTER: Counter = {
        let opts = Opts::new(names::REQUESTS_GATEWAY_FAULT_TOTAL, "Total number of gateway fault requests");
        let counter = Counter::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };


    /// Request duration histogram (in seconds)
    pub static ref REQUEST_DURATION: Histogram = {
        let opts = HistogramOpts::new(names::REQUEST_DURATION_SECONDS, "Request duration in seconds")
            .buckets(vec![0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5, 5.0, 10.0]);
        let histogram = Histogram::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(histogram.clone())).unwrap();
        histogram
    };


    /// Number of currently active connections
    pub static ref ACTIVE_CONNECTIONS: Gauge = {
        let opts = Opts::new(names::ACTIVE_CONNECTIONS, "Number of currently active connections");
        let gauge = Gauge::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(gauge.clone())).unwrap();
        gauge
    };


    /// Total bytes sent
    pub static ref BYTES_SENT: IntCounter = {
        let opts = Opts::new(names::BYTES_SENT_TOTAL, "Total bytes sent to clients");
        let counter = IntCounter::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };


    /// Total bytes received
    pub static ref BYTES_RECEIVED: IntCounter = {
        let opts = Opts::new(names::BYTES_RECEIVED_TOTAL, "Total bytes received from clients");
        let counter = IntCounter::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };


    /// Number of validated rule acceptances
    pub static ref RULE_ACCEPT_COUNTER: Counter = {
        let opts = Opts::new(names::RULE_VALIDATIONS_ACCEPTED_TOTAL, "Total number of accepted rule validations");
        let counter = Counter::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };


    /// Number of validated rule rejections
    pub static ref RULE_REJECT_COUNTER: Counter = {
        let opts = Opts::new(names::RULE_VALIDATIONS_REJECTED_TOTAL, "Total number of rejected rule validations");
        let counter = Counter::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// Authentication attempts (labeled by channel and scheme)
    pub static ref AUTH_ATTEMPTS: IntCounterVec = {
        let opts = Opts::new(names::AUTH_ATTEMPTS_TOTAL, "Total number of authentication attempts");
        let counter = IntCounterVec::new(opts, &["channel_id", "scheme", "result"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// Authentication failures (labeled by channel, scheme, and reason)
    pub static ref AUTH_FAILURES: IntCounterVec = {
        let opts = Opts::new(names::AUTH_FAILURES_TOTAL, "Total number of authentication failures");
        let counter = IntCounterVec::new(opts, &["channel_id", "scheme", "reason"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// Canary / variant routing decisions.
    ///
    /// `variant` = the chosen variant alias, `"base"` for base/default and
    /// canary-skip outcomes, or the offending alias for rejections. Cardinality is
    /// bounded by the variant-alias grammar (`^[a-z0-9-]{1,32}$`); pipe ids are
    /// never used as labels.
    ///
    /// `decision` vocabulary (closed set): `explicit_alias` | `routing_rule` |
    /// `routing_rule_inline` | `canary` | `canary_skipped_disabled` |
    /// `canary_skipped_no_weight` | `canary_skipped_base_split` | `base_default` |
    /// `rejected_unknown` | `rejected_disabled` | `rejected_misconfigured`.
    pub static ref VARIANT_ROUTING_DECISIONS: IntCounterVec = {
        let opts = Opts::new(
            names::VARIANT_ROUTING_DECISIONS_TOTAL,
            "Variant/canary routing decisions (variant = chosen alias or \"base\"; \
             decision = explicit_alias|routing_rule|routing_rule_inline|canary|\
             canary_skipped_disabled|canary_skipped_no_weight|canary_skipped_base_split|\
             base_default|rejected_unknown|rejected_disabled|rejected_misconfigured)",
        );
        let counter = IntCounterVec::new(opts, &["variant", "decision"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// OPA policy decisions, labeled by evaluation point and outcome.
    ///
    /// `scope` (closed set): `pipe` | `ide` | `gateway` | `surface`.
    /// `decision` (closed set): `allow` | `deny` | `error` | `missing_engine`.
    /// Both labels are bounded low-cardinality vocabularies — route/pipe ids are
    /// never used as labels.
    pub static ref POLICY_DECISIONS: IntCounterVec = {
        let opts = Opts::new(
            names::POLICY_DECISIONS_TOTAL,
            "OPA policy decisions (scope = pipe|ide|gateway|surface; decision = allow|deny|error|missing_engine)",
        );
        let counter = IntCounterVec::new(opts, &["scope", "decision"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// OPA policy evaluation failures (engine errors and missing compiled
    /// engines), labeled by evaluation point. A subset of [`POLICY_DECISIONS`]
    /// broken out so operators can alert on evaluation health independently of
    /// the allow/deny ratio.
    pub static ref POLICY_EVALUATION_FAILURES: IntCounterVec = {
        let opts = Opts::new(
            names::POLICY_EVALUATION_FAILURES_TOTAL,
            "OPA policy evaluation failures (scope = pipe|ide|gateway|surface)",
        );
        let counter = IntCounterVec::new(opts, &["scope"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// Governance audit records forwarded to `audit` integrations. `dropped`
    /// means a full queue discarded the record before delivery; the record is
    /// still in the VP Audit Log.
    pub static ref AUDIT_FORWARD: IntCounterVec = {
        let opts = Opts::new(
            names::AUDIT_FORWARD_TOTAL,
            "Governance audit records forwarded to audit integrations (result = delivered|failed|dropped; integration_id is empty when the shared intake queue dropped the record)",
        );
        let counter = IntCounterVec::new(opts, &["result", "integration_id"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// Stored records skipped because they could not be loaded (labeled by entity, reason).
    /// A non-zero value means one or more persisted records are missing from memory.
    pub static ref STORAGE_LOAD_ERRORS: IntCounterVec = {
        let opts = Opts::new(
            names::STORAGE_LOAD_ERRORS_TOTAL,
            "Stored records skipped because they could not be loaded \
             (reason = missing|read_failed|decrypt_failed|parse_failed|migrate_failed)",
        );
        let counter = IntCounterVec::new(opts, &["entity", "reason"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// Number of identities seen
    pub static ref UNIQUE_IDENTITIES: IntGauge = {
        let opts = Opts::new(names::UNIQUE_IDENTITIES, "Number of unique agent identities observed");
        let gauge = IntGauge::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(gauge.clone())).unwrap();
        gauge
    };

    pub static ref AFFINIDI_TERMS_PUBLICATION_SEQUENCE: Gauge = {
        let opts = Opts::new(
            names::AFFINIDI_TERMS_PUBLICATION_SEQUENCE,
            "Current Affinidi Terms publication sequence",
        );
        let gauge = Gauge::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(gauge.clone())).unwrap();
        gauge
    };

    /// Throughput in bytes per second
    pub static ref THROUGHPUT_BYTES_PER_SEC: Gauge = {
        let opts = Opts::new(names::THROUGHPUT_BYTES_PER_SEC, "Throughput in bytes per second");
        let gauge = Gauge::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(gauge.clone())).unwrap();
        gauge
    };


    /// Connections per minute
    pub static ref CONNECTIONS_PER_MINUTE: Gauge = {
        let opts = Opts::new(names::CONNECTIONS_PER_MINUTE, "Connections per minute");
        let gauge = Gauge::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(gauge.clone())).unwrap();
        gauge
    };


    /// Average request latency in milliseconds
    pub static ref AVG_REQUEST_LATENCY_MS: Gauge = {
        let opts = Opts::new(names::AVG_REQUEST_LATENCY_MS, "Average request latency in milliseconds (client to target)");
        let gauge = Gauge::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(gauge.clone())).unwrap();
        gauge
    };


    /// Average response latency in milliseconds
    pub static ref AVG_RESPONSE_LATENCY_MS: Gauge = {
        let opts = Opts::new(names::AVG_RESPONSE_LATENCY_MS, "Average response latency in milliseconds (target to client)");
        let gauge = Gauge::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(gauge.clone())).unwrap();
        gauge
    };


    // ============ LLM/Pipe Metrics (OpenTelemetry gen_ai semantic conventions) ============


    /// LLM token usage counter (input tokens)
    pub static ref LLM_TOKEN_USAGE_INPUT: Counter = {
        let opts = Opts::new(names::GEN_AI_TOKEN_USAGE_INPUT, "Total number of input tokens consumed by LLM requests");
        let counter = Counter::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };


    /// LLM token usage counter (output tokens)
    pub static ref LLM_TOKEN_USAGE_OUTPUT: Counter = {
        let opts = Opts::new(names::GEN_AI_TOKEN_USAGE_OUTPUT, "Total number of output tokens generated by LLM responses");
        let counter = Counter::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };


    /// LLM request duration histogram
    pub static ref LLM_REQUEST_DURATION: Histogram = {
        let opts = HistogramOpts::new(names::GEN_AI_REQUEST_DURATION_SECONDS, "LLM request duration in seconds")
            .buckets(vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 30.0, 60.0]);
        let histogram = Histogram::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(histogram.clone())).unwrap();
        histogram
    };


    /// LLM request counter (total)
    pub static ref LLM_REQUEST_COUNT: Counter = {
        let opts = Opts::new(names::GEN_AI_REQUEST_COUNT_TOTAL, "Total number of LLM requests");
        let counter = Counter::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };


    /// LLM cost tracking counter (in USD)
    pub static ref LLM_COST_TOTAL: Counter = {
        let opts = Opts::new(names::GEN_AI_COST_USD_TOTAL, "Total cost of LLM usage in USD");
        let counter = Counter::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };


    /// LLM error counter
    pub static ref LLM_ERROR_COUNT: Counter = {
        let opts = Opts::new(names::GEN_AI_ERROR_COUNT_TOTAL, "Total number of LLM request errors");
        let counter = Counter::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };


    // ============ User Lifecycle Metrics ============


    /// User events counter (labeled by event type and role)
    pub static ref USER_EVENTS: IntCounterVec = {
        let opts = Opts::new(names::USER_EVENTS_TOTAL, "Total number of user lifecycle events");
        let counter = IntCounterVec::new(opts, &["event", "role"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// Current number of active users (labeled by role and status)
    pub static ref USERS_ACTIVE: IntGauge = {
        let opts = Opts::new(names::USERS_ACTIVE, "Current number of active (approved) users");
        let gauge = IntGauge::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(gauge.clone())).unwrap();
        gauge
    };

    /// User login counter (labeled by role)
    pub static ref USER_LOGINS: IntCounterVec = {
        let opts = Opts::new(names::USER_LOGINS_TOTAL, "Total number of user logins");
        let counter = IntCounterVec::new(opts, &["role"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    // ============ KMS Envelope Encryption Metrics ============

    /// AWS KMS per-value envelope operation outcomes (labeled by op, result).
    /// `op` = `generate_data_key` | `decrypt`; `result` = `ok` | `error`.
    pub static ref KMS_OPERATION: IntCounterVec = {
        let opts = Opts::new(
            names::KMS_OPERATION_TOTAL,
            "AWS KMS per-value envelope operation outcomes (op = generate_data_key|decrypt; result = ok|error)",
        );
        let counter = IntCounterVec::new(opts, &["op", "result"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// AWS KMS per-value envelope operation latency in seconds (labeled by op).
    pub static ref KMS_OPERATION_DURATION: HistogramVec = {
        let opts = HistogramOpts::new(
            names::KMS_OPERATION_DURATION_SECONDS,
            "AWS KMS per-value envelope operation duration in seconds",
        )
        .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5]);
        let h = HistogramVec::new(opts, &["op"]).unwrap();
        REGISTRY.register(Box::new(h.clone())).unwrap();
        h
    };

    pub static ref AFFINIDI_TERMS_REFRESH: IntCounterVec = {
        let opts = Opts::new(
            names::AFFINIDI_TERMS_REFRESH_TOTAL,
            "Affinidi Terms metadata refresh attempts by result",
        );
        let counter = IntCounterVec::new(opts, &["result"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    pub static ref AFFINIDI_TERMS_REFRESH_DURATION_SECONDS: Histogram = {
        let opts = HistogramOpts::new(
            names::AFFINIDI_TERMS_REFRESH_DURATION_SECONDS,
            "Affinidi Terms metadata refresh duration in seconds",
        );
        let histogram = Histogram::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(histogram.clone())).unwrap();
        histogram
    };

    pub static ref AFFINIDI_TERMS_CACHE_AGE_SECONDS: Gauge = {
        let opts = Opts::new(
            names::AFFINIDI_TERMS_CACHE_AGE_SECONDS,
            "Seconds since the last successful Affinidi Terms metadata refresh",
        );
        let gauge = Gauge::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(gauge.clone())).unwrap();
        gauge
    };

    // ============ LLM Cross-Provider Failover Metrics ============

    /// LLM cross-provider failover lifecycle events.
    ///
    /// `event` (closed set): `primary_failure` (an eligible primary error kicked
    /// off failover) | `backup_success` (a backup served the request) |
    /// `exhausted` (every backup failed).
    /// `reason` (closed set): the failing error class — `upstream_response` |
    /// `timeout` | `request_failed` | `retry_exhausted` | `invalid_response` |
    /// `circuit_open` | `rate_limit` | `prompt_guard`; or `none` for
    /// `backup_success`. Pipe/surface ids and endpoint URLs are never labels.
    pub static ref LLM_FAILOVER: IntCounterVec = {
        let opts = Opts::new(
            names::LLM_FAILOVER_TOTAL,
            "LLM cross-provider failover lifecycle events (event = primary_failure|backup_success|exhausted; \
             reason = error class or none)",
        );
        let counter = IntCounterVec::new(opts, &["event", "reason"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// Individual backup-target attempts during LLM failover.
    ///
    /// `provider` = the backup target's provider type (bounded by supported
    /// provider schemas). `target_index` = 1-based position in the configured
    /// failover-target list (bounded by the operator-authored target count).
    /// `result` (closed set): `success` | `failure`. Model names and endpoint
    /// URLs are never labels (unbounded) — they appear in logs only.
    pub static ref LLM_FAILOVER_BACKUP_ATTEMPTS: IntCounterVec = {
        let opts = Opts::new(
            names::LLM_FAILOVER_BACKUP_ATTEMPTS_TOTAL,
            "LLM failover backup-target attempts (provider = backup provider type; \
             target_index = 1-based target position; result = success|failure)",
        );
        let counter = IntCounterVec::new(opts, &["provider", "target_index", "result"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// Work with no safety role skipped because a spent member or team budget
    /// refused its platform-key call (see `teams::call_budget`).
    ///
    /// `kind` (closed set): `cache_embedding` | `drift_embedding` |
    /// `drift_replay`. Surface and member ids are never labels.
    pub static ref BUDGET_SKIPPED: IntCounterVec = {
        let opts = Opts::new(
            names::BUDGET_SKIPPED_TOTAL,
            "Work skipped because a spent budget refused its platform-key call \
             (kind = cache_embedding|drift_embedding|drift_replay)",
        );
        let counter = IntCounterVec::new(opts, &["kind"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// Streams on a key that bills that ended without reporting their usage,
    /// so they were billed an estimate (see `streaming::StreamOutcome::billed_tokens`).
    pub static ref STREAM_USAGE_ESTIMATED: IntCounter = {
        let opts = Opts::new(
            names::STREAM_USAGE_ESTIMATED_TOTAL,
            "Platform-key streams billed an estimate because they reported no usage",
        );
        let counter = IntCounter::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// Failover suppressed because the primary error is not failover-eligible,
    /// even though failover was configured and enabled.
    ///
    /// `reason` (closed set): `rate_limit` | `prompt_guard` (the two classes the
    /// gateway deliberately refuses to fail over — see `is_failover_eligible`).
    pub static ref LLM_FAILOVER_SUPPRESSED: IntCounterVec = {
        let opts = Opts::new(
            names::LLM_FAILOVER_SUPPRESSED_TOTAL,
            "LLM failover suppressed by non-eligible primary error (reason = rate_limit|prompt_guard)",
        );
        let counter = IntCounterVec::new(opts, &["reason"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// Wall-clock seconds spent in the failover path (first backup attempt to
    /// resolution), i.e. the latency failover adds on top of the primary attempt.
    pub static ref LLM_FAILOVER_DURATION: Histogram = {
        let opts = HistogramOpts::new(
            names::LLM_FAILOVER_DURATION_SECONDS,
            "Seconds spent attempting backup providers during LLM failover",
        )
        .buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0]);
        let histogram = Histogram::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(histogram.clone())).unwrap();
        histogram
    };
}

/// Track an AWS KMS per-value envelope operation outcome and latency.
///
/// `op`     = `generate_data_key` | `decrypt`
/// `result` = `ok` | `error`
pub fn track_kms_operation(
    op: &str,
    result: &str,
    duration_secs: f64,
) {
    KMS_OPERATION
        .with_label_values(&[op, result])
        .inc();
    KMS_OPERATION_DURATION
        .with_label_values(&[op])
        .observe(duration_secs);
}

/// Track an LLM cross-provider failover lifecycle event.
///
/// `event`  = `primary_failure` | `backup_success` | `exhausted`
/// `reason` = failing error class, or `none` for `backup_success`
pub fn track_llm_failover(
    event: &str,
    reason: &str,
) {
    LLM_FAILOVER
        .with_label_values(&[event, reason])
        .inc();
}

/// Track a single backup-target attempt during LLM failover.
///
/// `provider`     = backup target provider type
/// `target_index` = 1-based position in the failover-target list
/// `result`       = `success` | `failure`
pub fn track_llm_failover_backup_attempt(
    provider: &str,
    target_index: &str,
    result: &str,
) {
    LLM_FAILOVER_BACKUP_ATTEMPTS
        .with_label_values(&[provider, target_index, result])
        .inc();
}

/// Count one piece of work skipped because a spent budget refused its
/// platform-key call, returning the running total for `kind`.
pub fn track_budget_skipped(kind: &str) -> u64 {
    let counter = BUDGET_SKIPPED.with_label_values(&[kind]);
    counter.inc();
    counter.get()
}

/// Count one platform-key stream billed an estimate because it reported no
/// usage.
pub fn track_stream_usage_estimated() {
    STREAM_USAGE_ESTIMATED.inc();
}

/// Track a failover suppressed by a non-eligible primary error.
///
/// `reason` = `rate_limit` | `prompt_guard`
pub fn track_llm_failover_suppressed(reason: &str) {
    LLM_FAILOVER_SUPPRESSED
        .with_label_values(&[reason])
        .inc();
}

/// Record the wall-clock seconds spent in the failover path.
pub fn observe_llm_failover_duration(duration_secs: f64) {
    LLM_FAILOVER_DURATION.observe(duration_secs);
}

/// Get metrics in Prometheus text format
pub fn get_metrics() -> String {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder
        .encode(&metric_families, &mut buffer)
        .unwrap();
    String::from_utf8(buffer).unwrap()
}

/// Track a connection event in Prometheus metrics
pub fn track_connection(
    status: crate::metrics::ConnectionStatus,
    duration_ms: Option<u64>,
    bytes_sent: u64,
    bytes_received: u64,
) {
    use crate::metrics::ConnectionStatus;

    REQUEST_COUNTER.inc();

    match status {
        ConnectionStatus::Success => SUCCESS_COUNTER.inc(),
        ConnectionStatus::Failed => FAILURE_COUNTER.inc(),
        ConnectionStatus::GatewayFault => GATEWAY_FAULT_COUNTER.inc(),
    }

    if let Some(duration) = duration_ms {
        REQUEST_DURATION.observe(duration as f64 / 1000.0);
    }

    BYTES_SENT.inc_by(bytes_sent);
    BYTES_RECEIVED.inc_by(bytes_received);
}

/// Track a rule validation event
pub fn track_rule_validation(accepted: bool) {
    if accepted {
        RULE_ACCEPT_COUNTER.inc();
    } else {
        RULE_REJECT_COUNTER.inc();
    }
}

/// Track a variant/canary routing decision.
///
/// `variant` is the chosen alias (or `"base"` for base/default and canary-skip
/// outcomes, or the attempted alias for rejections); `decision` is one of the
/// closed vocabulary documented on [`VARIANT_ROUTING_DECISIONS`].
pub fn track_variant_routing(
    variant: &str,
    decision: &str,
) {
    VARIANT_ROUTING_DECISIONS
        .with_label_values(&[variant, decision])
        .inc();
}

/// Count one governance audit record forwarded to (or dropped for) an audit integration.
pub fn track_audit_forward(
    result: &str,
    integration_id: Option<&str>,
) {
    AUDIT_FORWARD
        .with_label_values(&[result, integration_id.unwrap_or_default()])
        .inc();
}

/// Track an authentication attempt result
pub fn _track_auth_attempt(
    channel_id: &str,
    scheme: &str,
    result: &str,
) {
    AUTH_ATTEMPTS
        .with_label_values(&[channel_id, scheme, result])
        .inc();
}

/// Track an authentication failure with a reason
pub fn _track_auth_failure(
    channel_id: &str,
    scheme: &str,
    reason: &str,
) {
    AUTH_FAILURES
        .with_label_values(&[channel_id, scheme, reason])
        .inc();
}

/// Update active connections gauge
#[allow(dead_code)]
pub fn set_active_connections(count: i64) {
    ACTIVE_CONNECTIONS.set(count as f64);
}

/// Update unique identities count
#[allow(dead_code)]
pub fn set_unique_identities(count: i64) {
    UNIQUE_IDENTITIES.set(count);
}

/// Track an LLM request
#[allow(dead_code)]
pub fn track_llm_request(
    input_tokens: u64,
    output_tokens: u64,
    duration_ms: u64,
    cost_usd: Option<f64>,
    is_error: bool,
) {
    LLM_REQUEST_COUNT.inc();

    if is_error {
        LLM_ERROR_COUNT.inc();
    } else {
        LLM_TOKEN_USAGE_INPUT.inc_by(input_tokens as f64);
        LLM_TOKEN_USAGE_OUTPUT.inc_by(output_tokens as f64);
        LLM_REQUEST_DURATION.observe(duration_ms as f64 / 1000.0);

        if let Some(cost) = cost_usd {
            LLM_COST_TOTAL.inc_by(cost);
        }
    }
}

/// Track a user lifecycle event (created, approved, updated, deleted)
pub fn track_user_event(
    event: &str,
    role: &str,
) {
    USER_EVENTS
        .with_label_values(&[event, role])
        .inc();
}

/// Track a user login
pub fn track_user_login(role: &str) {
    USER_LOGINS
        .with_label_values(&[role])
        .inc();
}

/// Track a stored record that was skipped because it could not be loaded.
pub fn track_storage_load_error(
    entity: &str,
    reason: &str,
) {
    STORAGE_LOAD_ERRORS
        .with_label_values(&[entity, reason])
        .inc();
}

/// Update the active users gauge
#[allow(dead_code)]
pub fn set_active_users(count: i64) {
    USERS_ACTIVE.set(count);
}
