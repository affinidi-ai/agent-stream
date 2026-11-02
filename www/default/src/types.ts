import React from 'react';
import type { ChannelProtocol } from './generated/ChannelProtocol';

export type TrustRegistryVerificationMode = 'source' | 'target';

export interface TrustRegistryVerificationConfig {
  enabled: boolean;
  mode: TrustRegistryVerificationMode;
}

// API Response Types
export type ChannelType = 'user' | 'onboarding' | 'system';
export type { ChannelProtocol };
export type { SurfaceProtocol } from './generated/SurfaceProtocol';
export type { SurfaceStatus } from './generated/SurfaceStatus';

export const PROTOCOLS = {
  a2a: 'a2a',
  mcp: 'mcp',
  didcomm: 'didcomm',
  marketplace: 'marketplace',
} as const satisfies Record<ChannelProtocol, ChannelProtocol>;

// Source Authentication configuration (replaces identity_config auth modes + source_authentication_strategy)
export type SourceAuthConfig =
  | {
      type: 'jwt_bearer';
      jwt_verification_strategy_id: string;
      audiences: string[];
      allow_missing_audience?: boolean;
      token_header: string;
      token_scheme: string;
    }
  | { type: 'api_key'; extraction: CredentialExtraction }
  | { type: 'api_key_provider'; extraction: CredentialExtraction; agent_id: string }
  | ({ type: 'mtls' } & MtlsAuthConfig);

// ── mTLS source-auth schema (mirrors src/source_auth/models.rs) ──────────
export type MtlsTrust =
  | { type: 'pinned'; certificate_ids: string[] }
  | {
      type: 'ca';
      ca_certificate_ids: string[];
      require_client_auth_eku?: boolean;
      check_crl?: boolean;
      require_ocsp?: boolean;
    };

export type MtlsIdentityBinding =
  | { type: 'fingerprint' }
  | { type: 'subject_cn' }
  | { type: 'dns_san' }
  | { type: 'uri_san' }
  | { type: 'subject_rdn'; oid: string };

export type MtlsIdentityBindingKind = MtlsIdentityBinding['type'];

export interface MtlsAuthConfig {
  trust: MtlsTrust;
  identity_binding: MtlsIdentityBinding;
  allowed_subjects: string[];
  allow_forwarded: boolean;
}

// Certificate kind drives which trust slot a cert can fill on an mTLS channel.
// Mirrors `src/certificates/mod.rs::CertificateKind`.
export type CertificateKind = 'server_leaf' | 'client_leaf' | 'ca';

export const CERTIFICATE_KINDS: Record<CertificateKind, CertificateKind> = {
  server_leaf: 'server_leaf',
  client_leaf: 'client_leaf',
  ca: 'ca',
};

export const CERTIFICATE_KIND_LABEL: Record<CertificateKind, string> = {
  server_leaf: 'Server leaf',
  client_leaf: 'Client leaf',
  ca: 'Certificate Authority',
};

// Management access token (PAT) — mirrors `src/access_tokens/mod.rs::AccessTokenMeta`.
export interface RequiredHeader {
  name: string;
  pattern: string;
}

export interface AccessTokenMeta {
  id: string;
  name: string;
  description: string;
  user_id: string;
  scopes: string[];
  resource_pattern?: string | null;
  required_headers: RequiredHeader[];
  created_by: string;
  parent_token_id?: string;
  delegation_depth?: number;
  rotation_generation?: number;
  rotated_at?: string;
  rotated_by?: string;
  created_at: string;
  last_used_at?: string;
  expires_at?: string;
  revoked_at?: string;
  active: boolean;
}

// The create response also carries the raw secret, shown to the operator once.
export interface AccessTokenCreated extends AccessTokenMeta {
  token: string;
}

export type SourceAuthMode = 'jwt_bearer' | 'api_key' | 'mtls';

export const SOURCE_AUTH_MODES = {
  jwt_bearer: 'jwt_bearer',
  api_key: 'api_key',
  mtls: 'mtls',
} as const satisfies Record<SourceAuthMode, SourceAuthMode>;

export type CredentialExtraction =
  | { source: 'http_header'; field: string }
  | { source: 'mcp_meta'; field: string }
  | { source: 'a2a_extension'; field: string };

// Managed Identity configuration (replaces identity_config payload mode)
export type ManagedIdentityConfig = {
  type: 'payload_extraction';
  meta_field: string;
  extension_rules?: {
    json_schema?: any;
    rules?: Array<{ [key: string]: any }>;
  };
};

export interface ChannelMetricsData {
  channel_config_id: string;
  time_series: Array<{
    timestamp: string;
    count: number;
    rule_accepts: number;
    rule_denies: number;
    gateway_faults: number;
    request_bytes: number;
    response_bytes: number;
    input_tokens: number;
    output_tokens: number;
  }>;
  latency_time_series: Array<{
    timestamp: string;
    avg_latency_ms: number;
    p50_latency_ms: number;
    p95_latency_ms: number;
    p99_latency_ms: number;
    min_latency_ms: number;
    max_latency_ms: number;
    sample_count: number;
  }>;
}

export interface Identity {
  name: string;
  did: string;
  identity_hash: string;
  created_at: string;
  last_used?: string;
  use_count?: number;
  usage_count?: number;
  last_used_at?: string;
  badge?: 'NEW' | 'ACTIVE';
  channel_config_id?: string;
  channel_name?: string;
  is_local?: boolean;
  verified?: boolean;
  tr_registered?: boolean | null;
  agent_identity?: Record<string, any>;
  // DID:webvh specific fields
  trust_score?: number;
  trust_components?: TrustScoreComponents;
  version?: number;
  status?: 'active' | 'inactive';
  has_tee?: boolean;
  has_cloud_attestation?: boolean;
  uuid?: string;
  scid?: string;
  uai?: string;
}

// DID:webvh Types
export interface TrustScoreComponents {
  genesis: number;
  behavioral: number;
  operational: number;
  attestation: number;
  history: number;
}

export interface TrustScoreResponse {
  did: string;
  overall_score: number;
  components: TrustScoreComponents;
  computed_at: string;
  version: number;
  has_tee: boolean;
  has_cloud_attestation: boolean;
}

export interface AgentDNA {
  /** `uai:1:<scid>:<genesis8>.<behavioral8>.<operational8>.<attestation8>` */
  uai: string;
  birthEvent: {
    scid: string;
    timestamp: string;
    initialGenesis: AgentDNAGenesis;
    birthEntryHash: string;
  };
  genesis: AgentDNAGenesis;
  behavioral: {
    latencyProfileHash?: string;
    challengeResponseHash?: string;
    tokenPatternHash?: string;
    behavioralHash: string;
    measuredAt: string;
  };
  operational: {
    teeAttestation?: {
      type?: string;
      quote?: string;
      measurementHash?: string;
      verifiedBy?: string;
      verifiedAt?: string;
    };
    cloudAttestation?: {
      provider?: string;
      projectId?: string;
      zone?: string;
      instanceId?: string;
      identityToken?: string;
    };
    capabilitiesHash: string;
    operationalHash: string;
    attestedAt: string;
  };
  attestations: {
    merkleRoot: string;
    count: number;
    lastUpdated?: string;
  };
}

/** Genesis fingerprint sub-type, shared between AgentDNA.genesis and AgentDNA.birthEvent.initialGenesis */
export interface AgentDNAGenesis {
  codeHash: string;
  modelSpec: {
    provider: string;
    model: string;
    version?: string;
  };
  configHash: string;
  ownershipProof?: string;
  genesisHash: string;
  computedAt: string;
}

export interface DidWebVhIdentity {
  id: string;
  did: string;
  uuid: string;
  scid: string;
  uai?: string;
  version: number;
  status: 'active' | 'inactive';
  controller: string;
  created_at: string;
  updated_at: string;
  metadata?: {
    name?: string;
    description?: string;
    deployment?: string;
    environment?: string;
    owner?: string;
    team?: string;
    cost_center?: string;
    agentDNA?: AgentDNA;
    [key: string]: any;
  };
  trust_score?: TrustScoreResponse;
}

export interface VersionHistoryEntry {
  version: number;
  timestamp: string;
  operation: 'birth' | 'update' | 'key_rotation' | 'transfer';
  signer: string;
  hash: string;
  changes?: string[];
  metadata?: Record<string, any>;
}

export interface PolicyConfig {
  overall_min: number;
  components: {
    genesis: { min: number; required: boolean };
    behavioral: { min: number; required: boolean };
    operational: { min: number; required: boolean; tee: boolean };
    attestation: { min: number; required: boolean; min_count: number };
    history: { min: number; required: boolean };
  };
  opa_policy?: string;
}

export interface CreateIdentityRequest {
  name: string;
  did_path: string;
  description?: string;
  metadata?: {
    llm_provider?: string;
    llm_model?: string;
    llm_version?: string;
    code_hash?: string;
    config_hash?: string;
    deployment_env?: string;
    has_tee?: boolean;
    has_cloud_attestation?: boolean;
    cloud_provider?: string;
    capabilities?: string[];
    owner?: string;
    team?: string;
    [key: string]: any;
  };
  generate_keys?: boolean;
}

export interface VirtualChannel {
  id: string; // UUID
  name: string;
  description: string;
  alias: string; // URL-safe identifier for $alias routing

  // Target configuration
  target_endpoint: string;
  endpoint_type?: 'url' | 'gateway';
  gateway_id?: string;
  gateway_channel?: string;

  // Protocol-specific
  primary_extension?: string;
  supported_extensions?: string[];
  mediator_id?: string;
  meeting_place_url?: string;

  // Agent card location override (for A2A/UCP protocols)
  override_agent_card_location?: boolean;
  agent_card_location_path?: string;

  // Extension rules
  extension_rules?: {
    json_schema?: any;
    rules?: Array<{ [key: string]: any }>;
  };

  // Metadata
  custom_metadata?: {
    enabled?: boolean;
    payload?: any;
    injection_target?: 'meta' | 'headers' | 'both';
  };
  response_custom_metadata?: {
    enabled?: boolean;
    payload?: any;
    injection_target?: 'meta' | 'headers' | 'both';
  };

  // Identity & Security
  source_auth?: SourceAuthConfig;
  managed_identity?: ManagedIdentityConfig;
  security_config?: any;

  // OPA policies (flat structure matching backend)
  opa_policy?: string;
  opa_enabled?: boolean;
  opa_policy_definition_id?: string;

  // Network policies
  rate_limit?: {
    requests: number;
    window_secs: number;
    burst?: number;
  };
  timeout?: {
    request_secs: number;
    connect_secs: number;
    idle_secs: number;
  };
  retry?: {
    max_attempts: number;
    initial_backoff_ms: number;
    max_backoff_ms: number;
    backoff_multiplier: number;
    retryable_status_codes: number[];
  };
  circuit_breaker?: {
    failure_threshold: number;
    success_threshold: number;
    timeout_secs: number;
    window_secs: number;
  };
  mirror?: {
    endpoint: string;
    percentage: number;
    wait_for_response: boolean;
    timeout_secs: number;
  };

  // Payment
  payment_policy?: any;
  mpp_policy?: any;

  // Publishing
  publish_to_did_document?: boolean;
  // Trust registry verification and injection
  // Note: agent_did is automatically extracted from AFFINIDI_AGENT_IDENTITY_EXTENSION
  trust_registry_verification: TrustRegistryVerificationConfig;
  trust_registry_injection?: {
    enabled?: boolean;
    trust_registry_did?: string;
    provider_did?: string;
  };
}

export interface Channel {
  name: string;
  description?: string;
  listen: string;
  target: string;
  enforce?: any;
  enforce_response?: any;
  health?: 'healthy' | 'unhealthy' | 'unknown';
  connection_count?: number;
  avg_latency?: number;
}

export interface LogEntry {
  timestamp: number; // Unix timestamp in milliseconds
  level: string; // INFO, WARN, ERROR, DEBUG, TRACE
  message: string; // Message without timestamp/color codes
  file_position: number; // Byte offset in the log file (for ordering)
}

export interface DashboardStats {
  total_identities: number;
  identities: Identity[];
  channels: Array<{
    config_id: string;
    name: string;
    description?: string;
    listen_address: string;
    route?: string;
    target_endpoint: string;
    fabric_target_name?: string; // Stored name for fabric:// endpoints
    enabled: boolean;
    extension_rules?: {
      rules: Array<{ [key: string]: any }>;
      json_schema?: any;
      [key: string]: any;
    };
    custom_metadata?: {
      enabled?: boolean;
      payload?: any;
    };
    source_auth?: SourceAuthConfig;
    managed_identity?: ManagedIdentityConfig;
    rule_count: number;
    accept_count: number;
    deny_count: number;
    gateway_faults: number;
    last_status: string | null;
    latest_payload?: any;
    channel_type?: ChannelType;
    protocol?: ChannelProtocol;
    identity_count?: number;
    supported_extensions?: string[];
    primary_extension?: string;
    trust_registry_verification?: {
      enabled?: boolean;
      mode?: 'source' | 'target';
    };
    trust_registry_injection?: {
      enabled?: boolean;
      trust_registry_did?: string;
      provider_did?: string;
    };
    target_auth?: {
      method: {
        static_secret?: {
          secret_id: string;
          header_name: string;
          header_format: string;
        };
      };
      target_identifier?: string;
      fallback?: string;
    };
  }>;
  ports: {
    proxy_channels: string[];
    identity_http: number;
    identity_https: number;
  };
  metrics: {
    total_connections: number;
    avg_latency: number | null;
    avg_request_latency: number | null;
    avg_response_latency: number | null;
    avg_pipe_gateway_processing_ms: number | null;
    avg_pipe_target_processing_ms: number | null;
    connections_window_minutes: number;
    latency_window_minutes: number;
    time_series: Array<{
      timestamp: string;
      count: number;
      rule_accepts: number;
      rule_denies: number;
      failed: number;
      gateway_faults: number;
      request_bytes: number;
      response_bytes: number;
      input_tokens: number;
      output_tokens: number;
    }>;
    channel_stats: Array<{
      channel_config_id: string;
      total_connections: number;
      successful: number;
      failed: number;
      gateway_faults: number;
      last_activity?: string | null;
    }>;
    source_dest_stats: Array<{
      channel_config_id: string;
      source: string;
      destination: string;
      count: number;
    }>;
    latency_stats: Array<{
      channel_config_id: string;
      source: string;
      destination: string;
      avg_latency_ms: number;
      min_latency_ms: number;
      max_latency_ms: number;
      p50_latency_ms: number;
      p95_latency_ms: number;
      p99_latency_ms: number;
      sample_count: number;
    }>;
    latency_time_series: Array<{
      timestamp: string;
      avg_latency_ms: number;
      p50_latency_ms: number;
      p95_latency_ms: number;
      p99_latency_ms: number;
      min_latency_ms: number;
      max_latency_ms: number;
      sample_count: number;
    }>;
    identity_channel_stats: Array<{
      identity_hash: string;
      channel_config_id: string;
      total_count: number;
      success_count: number;
      deny_count: number;
      fault_count: number;
    }>;
    pipe_stats: Array<{
      pipe_id: string;
      pipe_name: string | null;
      provider: string;
      model: string;
      total_requests: number;
      successful_requests: number;
      failed_requests: number;
      total_input_tokens: number;
      total_output_tokens: number;
      total_cost: number;
      avg_latency_ms: number;
      avg_gateway_processing_ms: number;
      avg_target_processing_ms: number;
      avg_request_bytes: number;
      avg_response_bytes: number;
      last_activity: string | null;
    }>;
  };
  proxy_info: {
    did: string;
    trust_registry_did?: string;
    uptime_seconds: number;
    uptime_formatted: string;
    extensions_enabled: boolean;
    watched_extensions: string[];
    proxy_domain: string;
    log_entries: LogEntry[];
    did_document: any;
  };
  tasks?: {
    summary: {
      total_tasks: number;
      running_tasks: number;
      total_connections: number;
      total_active_connections: number;
      total_bytes_transferred: number;
      avg_uptime_seconds: number;
    };
    tasks: Array<{
      task_id: string;
      config_id?: string | null;
      channel_name: string;
      listen_address: string;
      target_endpoint: string;
      started_at: string;
      status: string;
      total_connections: number;
      active_connections: number;
      bytes_sent: number;
      bytes_received: number;
      last_activity: string | null;
      error_count: number;
    }>;
    metrics: Array<{
      task_id: string;
      connections_per_minute: number;
      throughput_bytes_per_sec: number;
      avg_response_time_ms: number;
      uptime_seconds: number;
      cpu_usage_percent: number | null;
      memory_usage_mb: number | null;
    }>;
  };
  connection_point_tasks?: {
    summary: {
      total_listeners: number;
      connected: number;
      reconnecting: number;
      failed: number;
      total_messages: number;
      total_errors: number;
    };
    tasks: Array<{
      id: string;
      name: string;
      gateway_did: string;
      mediator_did: string;
      status: string;
      started_at: string;
      last_activity: string | null;
      message_count: number;
      error_count: number;
      reconnect_attempts: number;
    }>;
  };
  pipe_tasks?: {
    summary: {
      total_pipes: number;
      enabled: number;
      disabled: number;
      total_requests: number;
      total_cost: number;
    };
    tasks: Array<{
      id: string;
      name: string;
      description: string;
      status: string;
      enabled: boolean;
      provider: string;
      model: string;
      total_requests: number;
      total_cost: number;
      created_at: string;
      updated_at: string;
    }>;
  };
  unread_count: number;
  pipe_metrics?: {
    summaries: Array<{
      pipe_id: string;
      pipe_name: string;
      provider: string;
      model: string;
      total_requests: number;
      total_input_tokens: number;
      total_output_tokens: number;
      total_tokens: number;
      total_cost: number;
      avg_latency_ms: number;
      error_count: number;
      success_rate: number;
    }>;
    time_series: Array<{
      timestamp: string;
      input_tokens: number;
      output_tokens: number;
      requests: number;
      cost: number;
    }>;
    total_cost: number;
    total_tokens: number;
    total_requests: number;
  };
}

export interface Task {
  id: string;
  name: string;
  status: 'running' | 'completed' | 'failed' | 'pending';
  created_at: string;
  updated_at: string;
  progress?: number;
  result?: any;
  error?: string;
}

export interface FeatureFlags {
  /** Show the Audit entry in the sidebar.
   *  Default on (treated as `true` when undefined); set explicitly to
   *  `false` to hide the sidebar entry. The `/audit` route remains
   *  reachable directly even when hidden. */
  audit?: boolean;
}

export interface Settings {
  badge_threshold: number;
  metrics_retention: number;
  task_activity_window: number;
  connections_window: number;
  latency_window: number;
  onboarding_channel_ttl_seconds: number;
  refresh_interval_seconds: number; // Dashboard refresh rate (1-300 seconds)
  log_timestamp_format: 'utc' | 'local' | 'relative' | 'compact'; // Log timestamp display format
  bucket_seconds: number; // Time series bucket interval in seconds (30, 60, 3600, 21600)
  payments_min_display: number; // Minimum number of payment items to display
  feature_flags?: FeatureFlags; // Optional feature flags for experimental features
  prometheus_auth_enabled?: boolean;
  prometheus_auth_username?: string;
  audit_enabled?: boolean; // Master switch for durable audit-log recording
  audit_categories?: {
    policies?: boolean;
    trust_checks?: boolean;
    identity?: boolean;
  };
  appliance_id?: string; // Fills ${APPLIANCE_ID}; empty uses the appliance DID
}

/** Per-user settings overrides (display preferences only) */
export interface UserSettingsOverrides {
  refresh_interval_seconds?: number;
  log_timestamp_format?: string;
  bucket_seconds?: number;
  badge_threshold_minutes?: number;
  payments_min_display?: number;
}

export interface ChartDataPoint {
  x: string;
  y: number;
}

// Component Props Types
export interface StatCardProps {
  title: string;
  value: string | number;
  icon: string;
  color: 'primary' | 'success' | 'info' | 'warning' | 'danger';
  subtitle?: string;
  onClick?: () => void;
  badge?: {
    text: string;
    color: 'primary' | 'success' | 'info' | 'warning' | 'danger';
  };
  testId?: string;
}

export interface ChartCardProps {
  title: string | React.ReactNode;
  children: React.ReactNode;
  className?: string;
  headerActions?: React.ReactNode;
}

// Navigation Types
export type Page = 'dashboard' | 'identities' | 'channels' | 'tasks' | 'settings' | 'logs';

// Theme Types
export type Theme = 'light' | 'dark';

// WebSocket Types
export interface WebSocketMessage {
  type: 'stats' | 'log' | 'task_update' | 'channel_health' | 'connection';
  data: any;
}

export type WSStatus = 'CONNECTING' | 'CONNECTED' | 'DISCONNECTED' | 'ERROR';

// Metrics Types
export interface TruncateMetricsResult {
  connections_removed: number;
  connections_retained: number;
  events_removed: number;
  events_retained: number;
}

// Logs Types
export interface TruncateLogsResult {
  files_removed: number;
  bytes_freed: number;
  current_log_kept: boolean;
}
