import { useCallback, useMemo } from 'react';
import type {
  PipeSourceChange,
  PipeUpstreamChange,
  PipeRateLimitChange,
  PipeOpaPolicyChange,
  PipePromptGuardChange,
  PipeJudgeChange,
  PipeJuryChange,
  PipeDeciderChange,
  PipeExpertWitnessesChange,
  PipeUsageLimitsChange,
} from '../../../components/builder/PipeBuilderPanel';
import type { PipeConfigLike } from '../../../components/builder/elements/pipe';
import {
  providerRequiresForwardCallerToken,
  type PipeLlmProvider,
} from '../../../components/builder/elements/pipe/pipePanelData';
import type { PromptGuardConfig } from '../tabs/promptGuardTypes';
import type { PipeFormData } from '../types';
import { buildPipeForCanvas } from '../pipeMappingHelpers';

export interface CanvasBindings {
  pipeForCanvas: PipeConfigLike;
  handleCanvasSourceChange: (change: PipeSourceChange) => void;
  handleCanvasUpstreamChange: (change: PipeUpstreamChange) => void;
  handleCanvasRateLimitChange: (change: PipeRateLimitChange) => void;
  handleCanvasOpaPolicyChange: (change: PipeOpaPolicyChange) => void;
  handleCanvasPromptGuardChange: (change: PipePromptGuardChange) => void;
  handleCanvasJudgeChange: (change: PipeJudgeChange) => void;
  handleCanvasJuryChange: (change: PipeJuryChange) => void;
  handleCanvasDeciderChange: (change: PipeDeciderChange) => void;
  handleCanvasExpertWitnessesChange: (change: PipeExpertWitnessesChange) => void;
  handleCanvasUsageLimitsChange: (change: PipeUsageLimitsChange) => void;
}

/**
 * Builds the canvas pipe snapshot and the per-element write seams. Each
 * handler merges a canvas edit back into the flat form and marks the editor
 * dirty. Pure relocation of the EditPipePage canvas wiring.
 */
export function useCanvasBindings(
  formData: PipeFormData,
  selectedPrefix: string,
  customPath: string,
  setFormData: React.Dispatch<React.SetStateAction<PipeFormData>>,
  setSelectedPrefix: (value: string) => void,
  setCustomPath: (value: string) => void,
  setIsModified: (value: boolean) => void,
  llmProviders: PipeLlmProvider[],
  routePrefixResolved = false
): CanvasBindings {
  const pipeForCanvas = useMemo(
    () => buildPipeForCanvas(formData, selectedPrefix, customPath, routePrefixResolved),
    [formData, selectedPrefix, customPath, routePrefixResolved]
  );

  const applyChange = useCallback(
    (patch: Partial<PipeFormData>) => {
      setFormData(prev => ({ ...prev, ...patch }));
      setIsModified(true);
    },
    [setFormData, setIsModified]
  );

  const handleCanvasSourceChange = useCallback(
    (change: PipeSourceChange) => {
      setSelectedPrefix(change.prefix);
      setCustomPath(change.custom_path);
      const normalizedPath = change.custom_path.startsWith('/')
        ? change.custom_path.slice(1)
        : change.custom_path;
      const newRoute = change.prefix && normalizedPath ? `${change.prefix}/${normalizedPath}` : '';
      applyChange({ listen_address: change.listen_address, route: newRoute });
    },
    [applyChange, setSelectedPrefix, setCustomPath]
  );

  const handleCanvasUpstreamChange = useCallback(
    (c: PipeUpstreamChange) => {
      // A provider that requires identity pass-through (e.g. Microsoft 365
      // Copilot, or any provider carrying `requires_forward_caller_token`)
      // auto-enables forwarding on selection so the surface is valid by
      // default. Property-driven — never keyed on a specific provider id. Only
      // turns forwarding ON here; the reverse (clearing it when the surface
      // leaves a requiring provider) is handled by a provider-transition effect
      // in EditPipePage so it works from both the form and the canvas.
      const requiresForward = providerRequiresForwardCallerToken(
        llmProviders.find(p => p.enum_value === c.provider)
      );
      applyChange({
        endpoint_url: c.endpoint,
        provider: c.provider,
        model: c.model,
        api_key_secret_id: c.api_key_secret_id,
        model_parameters: c.model_parameters,
        override_policy: c.override_policy,
        cost_tracking_enabled: c.cost_tracking_enabled,
        failover: (c.failover ?? null) as any,
        load_balancing: (c.load_balancing ?? null) as any,
        ...(requiresForward ? { forward_caller_token: true } : {}),
      });
    },
    [applyChange, llmProviders]
  );

  const handleCanvasRateLimitChange = useCallback(
    (c: PipeRateLimitChange) =>
      applyChange({
        rate_limit_enabled: c.present && c.enabled,
        requests_per_minute: c.requests_per_minute,
        tokens_per_minute: c.tokens_per_minute,
      }),
    [applyChange]
  );

  const handleCanvasOpaPolicyChange = useCallback(
    (c: PipeOpaPolicyChange) =>
      applyChange({
        opa_policy: c.present
          ? {
              enabled: c.enabled,
              policy_definition_id: c.policy_definition_id || undefined,
              log_decisions: c.log_decisions || undefined,
            }
          : null,
      }),
    [applyChange]
  );

  const handleCanvasPromptGuardChange = useCallback(
    (c: PipePromptGuardChange) => {
      const hasGuards = c.request.length > 0 || c.response.length > 0 || c.llm_pii.length > 0;
      applyChange({
        prompt_guard:
          !c.enabled && !hasGuards
            ? null
            : ({
                enabled: c.enabled,
                request: c.request,
                response: c.response,
                llm_pii: c.llm_pii,
              } as PromptGuardConfig),
      });
    },
    [applyChange]
  );

  const handleCanvasJudgeChange = useCallback(
    (c: PipeJudgeChange) => applyChange({ judge: (c.present ? c.judge : null) as any }),
    [applyChange]
  );

  const handleCanvasJuryChange = useCallback(
    (c: PipeJuryChange) => applyChange({ jury: (c.present ? c.jury : null) as any }),
    [applyChange]
  );

  const handleCanvasDeciderChange = useCallback(
    (c: PipeDeciderChange) => applyChange({ decider: (c.present ? c.decider : null) as any }),
    [applyChange]
  );

  const handleCanvasExpertWitnessesChange = useCallback(
    (c: PipeExpertWitnessesChange) =>
      applyChange({ expert_witnesses: (c.present ? c.witnesses : []) as any }),
    [applyChange]
  );

  const handleCanvasUsageLimitsChange = useCallback(
    (c: PipeUsageLimitsChange) => applyChange({ usage_limits: c.limits }),
    [applyChange]
  );

  return {
    pipeForCanvas,
    handleCanvasSourceChange,
    handleCanvasUpstreamChange,
    handleCanvasRateLimitChange,
    handleCanvasOpaPolicyChange,
    handleCanvasPromptGuardChange,
    handleCanvasJudgeChange,
    handleCanvasJuryChange,
    handleCanvasDeciderChange,
    handleCanvasExpertWitnessesChange,
    handleCanvasUsageLimitsChange,
  };
}
