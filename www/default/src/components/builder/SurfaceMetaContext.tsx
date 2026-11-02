import { createContext, useContext } from 'react';
import type { AgentSurface } from '../../api';
import type { Protocol } from './elements/types';
import type {
  DriftForm,
  GovernanceRecordingForm,
  PipeCacheForm,
  PipeCanaryForm,
  PipeRoutingRuleForm,
  TeamAttributionForm,
  UsageAlertForm,
  VpEvidenceForm,
} from '../../pages/EditPipePage/types';

export type DidwebvhInjectionMode = 'header' | 'signed_header' | 'protocol_native';

export interface DidwebvhConfig {
  enabled: boolean;
  auto_create: boolean;
  identity_id: string;
  did_path: string;
  injection_mode: DidwebvhInjectionMode;
}

export const DEFAULT_DIDWEBVH_CONFIG: DidwebvhConfig = {
  enabled: false,
  auto_create: true,
  identity_id: '',
  did_path: '',
  injection_mode: 'header',
};

export interface SurfaceMetaValue {
  /**
   * Which builder hosts this meta. `'surface'` (default) is the full A2A
   * agent-surface editor; `'pipe'` is the LLM-surface (pipe) editor, which
   * only exposes name / description / enabled; `'ide'` is the IDE-surface
   * editor, which exposes the same name / description / enabled trio (no
   * LLM-specific controls).
   */
  variant?: 'surface' | 'pipe' | 'ide';
  name: string;
  description: string;
  tagsCsv: string;
  status: AgentSurface['status'];
  protocol: Protocol;
  publishToDid: boolean;
  /** Gateway-managed did:webvh identity injected on every outbound request. */
  didwebvh: DidwebvhConfig;
  /** True when fields shown to the user must be read-only. */
  readOnly: boolean;
  /** Whether the protocol field can still be changed. */
  protocolLocked: boolean;
  /** True for the create wizard (extra hints, no Last Activity, etc.). */
  isCreate: boolean;
  /** Optional last-activity timestamp for edit mode. */
  lastActivity?: string | null;
  /** Surface UUID; read-only display in edit mode. */
  surfaceId?: string;
  /**
   * Pipe-variant only: the surface-wide cumulative usage limit. `null` when no
   * limit is set. Edited on the pipe surface property sidebar.
   */
  surfaceUsageLimit?: {
    enabled: boolean;
    monthlyBudgetUsd: number | null;
    monthlyTokenCap: number | null;
  } | null;
  /**
   * Pipe-variant only: true when a metered stage other than the main LLM is
   * active (Judge, Jury, or Decider). When `false` the surface-wide cumulative
   * usage limit is mathematically identical to the single LLM-stage limit, so
   * the surface-wide control is redundant and is disabled in the editor (with an
   * explanatory infobox). `undefined` leaves the control enabled.
   */
  hasSecondaryStages?: boolean;
  /**
   * Pipe-variant only: team attribution opt-in (surface contributes usage to
   * team quotas). `null` when off. Surface-type agnostic.
   */
  teamAttribution?: TeamAttributionForm | null;
  /**
   * Pipe-variant only: whether SSE streaming passthrough is allowed when the
   * client requests it. Base-pipe-level (not variant-overridable).
   */
  streamingEnabled?: boolean;
  /**
   * Pipe-variant only: forward the caller's validated inbound bearer token as
   * the outbound provider credential (identity pass-through) instead of the
   * stored key. Requires jwt_bearer source auth. Variant-overridable.
   */
  forwardCallerToken?: boolean;
  /**
   * Client API formats this surface answers (ingress skins, path-negotiated):
   * `openai_chat`, `anthropic_messages`, `openai_responses`. Empty/undefined is
   * treated as all three. Base-pipe-level.
   */
  acceptedIngressSchemas?: string[];
  /**
   * Pipe-variant only: response cache config (exact/semantic). `null` when off.
   */
  cache?: PipeCacheForm | null;
  /**
   * Pipe-variant only: canary / A-B traffic split across variants. `null` when
   * off.
   */
  canary?: PipeCanaryForm | null;
  /** Aliases of the surface's variants (targets a canary split can route to). */
  variantAliases?: string[];
  /** Pipe-variant only: attribute-based routing rules. */
  routingRules?: PipeRoutingRuleForm[];
  /**
   * Pipe-variant only: whether attribute-based routing is enforced. When off the
   * rules are retained but not evaluated (enable-first, like canary).
   */
  routingEnabled?: boolean;
  /**
   * Pipe-variant only: breach / anomaly alerts that fire through the pipe
   * integration / notification system.
   */
  usageAlerts?: UsageAlertForm[];
  /**
   * Pipe-variant only: whether breach / anomaly alerts are enforced. When off the
   * alerts are retained but not evaluated (enable-first, like canary).
   */
  usageAlertsEnabled?: boolean;
  /**
   * Pipe-variant only: signed governance recording (`GovernanceRecordingConfig`).
   * `null`/absent when off. Base-pipe-level (not variant-overridable).
   */
  governanceRecording?: GovernanceRecordingForm | null;
  /**
   * Pipe-variant only: per-surface LLM drift monitoring (`DriftConfig`).
   * `null`/absent when off. Base-pipe-level (not variant-overridable).
   */
  drift?: DriftForm | null;
  /**
   * Pipe-variant only: per-surface verifiable-presentation evidence
   * (`VpEvidenceConfig`). `null`/absent when off. Base-pipe-level.
   */
  vpEvidence?: VpEvidenceForm | null;
  setName: (v: string) => void;
  setDescription: (v: string) => void;
  setTagsCsv: (v: string) => void;
  setStatus: (v: AgentSurface['status']) => void;
  setProtocol: (v: Protocol) => void;
  setPublishToDid: (v: boolean) => void;
  setDidwebvh: (v: DidwebvhConfig) => void;
  /** Pipe-variant only: persist the surface-wide cumulative usage limit. */
  setSurfaceUsageLimit?: (
    v: { enabled: boolean; monthlyBudgetUsd: number | null; monthlyTokenCap: number | null } | null
  ) => void;
  /** Pipe-variant only: persist the team attribution opt-in. */
  setTeamAttribution?: (v: TeamAttributionForm | null) => void;
  /** Pipe-variant only: persist the SSE streaming passthrough opt-out. */
  setStreamingEnabled?: (v: boolean) => void;
  /** Pipe-variant only: persist the identity pass-through credential mode. */
  setForwardCallerToken?: (v: boolean) => void;
  /** Persist the set of accepted client API formats (ingress skins). */
  setAcceptedIngressSchemas?: (v: string[]) => void;
  /** Pipe-variant only: persist the response cache config. */
  setCache?: (v: PipeCacheForm | null) => void;
  /** Pipe-variant only: persist the canary / A-B traffic split. */
  setCanary?: (v: PipeCanaryForm | null) => void;
  /** Pipe-variant only: persist attribute-based routing rules. */
  setRoutingRules?: (v: PipeRoutingRuleForm[]) => void;
  /** Pipe-variant only: persist whether attribute-based routing is enforced. */
  setRoutingEnabled?: (v: boolean) => void;
  /** Pipe-variant only: persist the breach / anomaly alerts. */
  setUsageAlerts?: (v: UsageAlertForm[]) => void;
  /** Pipe-variant only: persist whether breach / anomaly alerts are enforced. */
  setUsageAlertsEnabled?: (v: boolean) => void;
  /** Pipe-variant only: persist the signed governance-recording config. */
  setGovernanceRecording?: (v: GovernanceRecordingForm | null) => void;
  /** Pipe-variant only: persist the per-surface LLM drift-monitoring config. */
  setDrift?: (v: DriftForm | null) => void;
  /** Pipe-variant only: persist the per-surface VP evidence config. */
  setVpEvidence?: (v: VpEvidenceForm | null) => void;
  /** Optional callback to snapshot the current surface as a reusable template. */
  onSaveAsTemplate?: () => void;
}

const SurfaceMetaContext = createContext<SurfaceMetaValue | null>(null);

export const SurfaceMetaProvider = SurfaceMetaContext.Provider;

export function useSurfaceMeta(): SurfaceMetaValue {
  const v = useContext(SurfaceMetaContext);
  if (!v) {
    throw new Error('useSurfaceMeta must be used inside <SurfaceMetaProvider>');
  }
  return v;
}

export function useOptionalSurfaceMeta(): SurfaceMetaValue | null {
  return useContext(SurfaceMetaContext);
}
