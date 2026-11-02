import React from 'react';
import { SurfaceBuilder } from './SurfaceBuilder';
import type { SurfaceBuilderState, UseSurfaceBuilderReturn } from './hooks/useSurfaceBuilder';
import {
  DEFAULT_INPUT_MODALITIES,
  EMPTY_AUDIO_STREAMS,
  PipePanelDataProvider,
} from './elements/pipe/pipePanelData';
import type {
  AudioStreamsCatalog,
  InputModalitySupport,
  PipeLlmProvider,
  PipeSecretRef,
  PipeRoutingConfig,
  PipePromptGuardPattern,
} from './elements/pipe/pipePanelData';

/** Editable pipe-source fields surfaced back to the host page. */
export interface PipeSourceChange {
  listen_address: string;
  prefix: string;
  custom_path: string;
}

/** Editable pipe-upstream (LLM) fields surfaced back to the host page. */
export interface PipeUpstreamChange {
  endpoint: string;
  provider: string;
  model: string;
  api_key_secret_id: string;
  model_parameters: Record<string, unknown>;
  override_policy: Record<string, string>;
  cost_tracking_enabled: boolean;
  /**
   * Cross-provider failover config (`FailoverConfig`). `null` when no failover
   * is configured. Base-pipe-level (not variant-overridable). Mutually
   * exclusive with `load_balancing` at runtime.
   */
  failover?: unknown;
  /**
   * Weighted load-balancing pool (`LoadBalancingConfig`). `null` when off.
   * Base-pipe-level. Takes precedence over `failover` when both are set.
   */
  load_balancing?: unknown;
}

/**
 * Editable pipe-rate-limit fields surfaced back to the host page. `present`
 * reflects whether the rate-limit element is on the canvas at all; removing it
 * clears the feature, dragging it on enables it.
 */
export interface PipeRateLimitChange {
  present: boolean;
  enabled: boolean;
  requests_per_minute: number;
  tokens_per_minute: number;
}

/**
 * Editable pipe-opa-policy value surfaced back to the host page. `present`
 * reflects whether the OPA element is on the canvas at all; removing it clears
 * the gate, dragging it on enables it.
 */
export interface PipeOpaPolicyChange {
  present: boolean;
  enabled: boolean;
  policy_definition_id: string;
  log_decisions: boolean;
}

/** Editable pipe-prompt-guard value surfaced back to the host page. */
export interface PipePromptGuardChange {
  present: boolean;
  enabled: boolean;
  request: unknown[];
  response: unknown[];
  llm_pii: unknown[];
}

/** Editable pipe-judge value surfaced back to the host page. */
export interface PipeJudgeChange {
  present: boolean;
  judge: Record<string, unknown> | null;
}

/** Editable pipe-jury value surfaced back to the host page. */
export interface PipeJuryChange {
  present: boolean;
  jury: Record<string, unknown> | null;
}

/** Editable pipe-decider value surfaced back to the host page. */
export interface PipeDeciderChange {
  present: boolean;
  decider: Record<string, unknown> | null;
}

/**
 * Editable expert-witness roster surfaced back to the host page. Reassembled
 * from the two witness seam nodes into the flat backend `expert_witnesses`
 * list. `present` reflects whether any witness is configured at all.
 */
export interface PipeExpertWitnessesChange {
  present: boolean;
  witnesses: unknown[];
}

/**
 * A single usage-limit decoration surfaced back to the host page. `id` is the
 * canvas node id, reused as the backend `UsageLimit.id` so the limit
 * round-trips. Multiple limits can coexist (one per LLM / Judge / Jury stage,
 * plus a pipe-wide cumulative total).
 */
export interface PipeUsageLimitEntry {
  id: string;
  enabled: boolean;
  scope: 'cumulative' | 'stage';
  stage: 'llm' | 'judge' | 'jury' | null;
  /** Index of the targeted juror in `jury.jurors` (Jury stage only). */
  juror_index?: number | null;
  monthly_budget_usd: number | null;
  monthly_token_cap: number | null;
}

/** Editable pipe usage-limit set surfaced back to the host page. */
export interface PipeUsageLimitsChange {
  limits: PipeUsageLimitEntry[];
}

interface PipeBuilderPanelProps {
  /** The lifted builder instance shared with the form shell's palette. */
  builder: UseSurfaceBuilderReturn<SurfaceBuilderState>;
  /** Open a node's full-page editor (hosted as a left-cluster tab by the page). */
  onOpenFullscreenEditor: (id: string) => void;
  /** Display name shown in the canvas header. */
  name?: string;
  /** LLM provider catalogue for the upstream node's pickers. */
  llmProviders?: PipeLlmProvider[];
  /** Available secrets for the upstream node's API-key picker. */
  secrets?: PipeSecretRef[];
  /** Routing catalogue for the source node's listener/path pickers. */
  routing?: PipeRoutingConfig;
  /** Built-in PII pattern definitions for the prompt-guard editor. */
  promptGuardPatterns?: PipePromptGuardPattern[];
  /** Backend-published supported input modalities for the Inputs elements. */
  inputModalities?: InputModalitySupport;
  /** Backend-published audio-stream clip catalog for the realtime streaming config. */
  audioStreams?: AudioStreamsCatalog;
  /** Variants overlay pinned to the canvas top-left (pipe scope). */
  variantsWidget?: React.ReactNode;
  /**
   * Active variant id — used as the canvas remount key so switching a
   * variant re-seeds the d3 positions / pan-zoom from the incoming
   * variant's reseeded nodes and view ref. `null` / undefined = base.
   */
  activeVariantId?: string | null;
  /** Mirrors the live canvas pan/zoom so the page can persist/restore it. */
  canvasViewRef?: React.MutableRefObject<{ x: number; y: number; k: number } | null>;
  /** Mirrors the hide-disabled toolbar toggle so the page can persist it. */
  canvasSettingsRef?: React.MutableRefObject<{ hide_disabled: boolean } | null>;
  /** Initial value for the hide-disabled toggle, read from the loaded pipe. */
  initialHideDisabled?: boolean;
  /** Capture the current multi-selection as a partial template (Templates view). */
  onCreateTemplateFromSelection?: (selectedIds: string[]) => void;
}

/**
 * Mounts the shared visual builder body in `pipe` scope using the lifted
 * builder. The surface-only variants widget is hidden by the scope; the
 * settings cog opens the LLM Surface settings panel (name / description /
 * enabled) via `SurfaceMetaContext`. The builder itself (and the seams that
 * bridge its nodes back to the host form) live in `usePipeBuilder` so the form
 * shell can host a palette / elements / config view wired to the same nodes.
 */
export function PipeBuilderPanel({
  builder,
  onOpenFullscreenEditor,
  name,
  llmProviders,
  secrets,
  routing,
  promptGuardPatterns,
  inputModalities,
  audioStreams,
  variantsWidget,
  activeVariantId,
  canvasViewRef,
  canvasSettingsRef,
  initialHideDisabled,
  onCreateTemplateFromSelection,
}: PipeBuilderPanelProps) {
  const panelData = React.useMemo(
    () => ({
      llmProviders: llmProviders ?? [],
      secrets: secrets ?? [],
      routing: routing ?? { availableListenAddresses: [], pathPrefixes: [] },
      promptGuardPatterns: promptGuardPatterns ?? [],
      inputModalities: inputModalities ?? DEFAULT_INPUT_MODALITIES,
      audioStreams: audioStreams ?? EMPTY_AUDIO_STREAMS,
    }),
    [llmProviders, secrets, routing, promptGuardPatterns, inputModalities, audioStreams]
  );

  return (
    <PipePanelDataProvider value={panelData}>
      <SurfaceBuilder
        builder={builder}
        surfaceName={name || 'Pipe'}
        protocol="a2a"
        scope="pipe"
        onOpenFullscreenEditor={onOpenFullscreenEditor}
        topLeftSlot={variantsWidget}
        activeVariantId={activeVariantId}
        canvasViewRef={canvasViewRef}
        canvasSettingsRef={canvasSettingsRef}
        initialHideDisabled={initialHideDisabled}
        onCreateTemplateFromSelection={onCreateTemplateFromSelection}
      />
    </PipePanelDataProvider>
  );
}

export default PipeBuilderPanel;
