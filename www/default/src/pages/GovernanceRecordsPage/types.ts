// API shapes for the signed governance records read/verify endpoints.

export type StageOutcome = 'allow' | 'block' | 'flag' | 'observed' | 'error';

export interface LlmCall {
  provider: string;
  model: string;
  retry_index: number;
  request_digest: string;
  response_digest?: string;
  input_tokens: number;
  output_tokens: number;
  cost: number;
}

export interface StageEntry {
  stage: string;
  outcome: StageOutcome;
  reason?: string;
  policy_id?: string;
  policy_version?: string;
  input_digest?: string;
  output_digest?: string;
  input?: string;
  output?: string;
  llm_call?: LlmCall;
}

export interface RecordMetrics {
  input_tokens: number;
  output_tokens: number;
  total_tokens: number;
  cost: number;
  latency_ms: number;
  provider?: string;
  model?: string;
}

export interface GovernanceRecord {
  record_id: string;
  trace_id?: string;
  surface_id: string;
  surface_name?: string;
  caller_identity_hash?: string;
  timestamp: string;
  prev_record_hash: string;
  stages: StageEntry[];
  prompt?: string;
  completion?: string;
  metrics: RecordMetrics;
  content_hash?: string;
}

export interface StoredRecord {
  record: GovernanceRecord;
  /** The signed W3C VC wrapping the record (opaque here). */
  signed_vc: unknown;
}

export interface ChainVerdict {
  surface_id: string;
  valid: boolean;
  count: number;
  error?: string;
}

/** A governance surface for the picker: its id plus (best-effort) human-readable
 * name and description. Name comes from the surface's latest record (so it
 * survives deletion); description is joined from the live surface config. */
export interface SurfaceSummary {
  surface_id: string;
  surface_name?: string;
  surface_description?: string;
}
