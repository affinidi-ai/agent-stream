import React from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { useApp } from '../context/AppContext';
import { PipeBuilderPanel } from '../components/builder/PipeBuilderPanel';
import ConfigEditorFullscreen from '../components/builder/ConfigEditorFullscreen';
import {
  PipePanelDataProvider,
  providerRequiresForwardCallerToken,
} from '../components/builder/elements/pipe/pipePanelData';
import PipeFormShell, { type PipeShellView } from '../components/builder/PipeFormShell';
import ElementsListTab from '../components/builder/ElementsListTab';
import ElementPalette from '../components/builder/ElementPalette';
import PipeTemplatesPanel from '../components/builder/pipe-templates/PipeTemplatesPanel';
import { integrationIntegration } from '../components/connection-points/IntegrationsStep';
import PipeMonitoringTab from './EditPipePage/tabs/PipeMonitoringTab';
import PipeIntegrationsTab from './EditPipePage/tabs/PipeIntegrationsTab';
import ChatSandboxTab from './EditPipePage/tabs/ChatSandboxTab';
import {
  sandboxAuthFromProfile,
  tenantFromIssuer,
  type SandboxAuthConfig,
  type SandboxOAuthProfile,
} from '../utils/sandboxAuth';
import { apiClient } from '../api';
import PipeStarterPicker from './EditPipePage/PipeStarterPicker';
import { PipeManageActions } from './EditPipePage/PipeManageActions';
import { PipeConfigView } from './EditPipePage/PipeConfigView';
import PipeVariantSwitcher from '../components/builder/pipe-variants/PipeVariantSwitcher';
import PipeVariantPanel from '../components/builder/pipe-variants/PipeVariantPanel';
import {
  usePipeVariantSnapshots,
  type PipeVariantMeta,
} from '../components/builder/pipe-variants/usePipeVariantSnapshots';
import {
  buildPipeVariantOverrides,
  parsePipeVariants,
} from '../components/builder/pipe-variants/pipeVariantMapping';
import { PIPE_VARIANT_FIELDS } from '../components/builder/pipe-variants/pipeVariantSnapshot';
import {
  buildLlmPipeType,
  buildPipeForCanvas,
  mergeImportedPipeConfig,
} from './EditPipePage/pipeMappingHelpers';
import { syncVariantCatalogReferences } from './EditPipePage/variantCatalogSync';
import { buildCanvasBlob, registry } from '../components/builder/elements';
import { buildSurfaceContext } from '../components/builder/elements/surfaceContext';
import type { CanvasNode } from '../components/builder/SurfaceCanvas';
import {
  SurfaceMetaProvider,
  DEFAULT_DIDWEBVH_CONFIG,
  type SurfaceMetaValue,
} from '../components/builder/SurfaceMetaContext';
import { usePipeConfigData } from './EditPipePage/hooks/usePipeConfigData';
import { usePipeForm } from './EditPipePage/hooks/usePipeForm';
import { usePipeSave } from './EditPipePage/hooks/usePipeSave';
import { usePipeTemplatesView } from './EditPipePage/hooks/usePipeTemplatesView';
import {
  forwardTokenAfterProviderChange,
  validateForwardTokenRequired,
  validateForwardTokenSource,
  validateRoutingRules,
  validateUsageAlerts,
} from './EditPipePage/surfaceValidation';
import { usePipeDashboardSync } from './EditPipePage/hooks/usePipeDashboardSync';
import { useModelParameterDefaults } from './EditPipePage/hooks/useModelParameterDefaults';
import { useCanvasBindings } from './EditPipePage/hooks/useCanvasBindings';
import { usePipeBuilder } from './EditPipePage/hooks/usePipeBuilder';

const PIPE_WELCOME_DISMISSED_KEY = 'pipe-builder-welcome-dismissed';

const EditPipePage: React.FC = () => {
  const navigate = useNavigate();
  const { pipeId } = useParams<{ pipeId: string }>();
  const isNew = !pipeId || pipeId === 'new';
  const [searchParams, setSearchParams] = useSearchParams();
  const { state, actions } = useApp();

  const config = usePipeConfigData();
  const {
    llmProviders,
    secrets,
    routingConfig,
    promptGuardPatterns,
    inputModalities,
    audioStreams,
    configLoading,
  } = config;

  // Full-snapshot variant manager. Each variant is a complete snapshot of
  // the pipe's behavioural form slice; switching one swaps that slice into
  // the active form so the whole canvas re-renders for the variant. The
  // adapter folds a snapshot into the wire `overrides` using the same
  // `pipe_type` builder the base pipe uses.
  const variantAdapter = React.useMemo(
    () => ({
      buildOverrides: (snap: Parameters<typeof buildPipeVariantOverrides>[0]) =>
        buildPipeVariantOverrides(snap, llmProviders, buildLlmPipeType),
    }),
    [llmProviders]
  );
  const snapshots = usePipeVariantSnapshots(variantAdapter);

  // Mirror the active variant id into a ref so a reload (e.g. the one fired
  // after every save) can keep the user on the variant they were editing
  // instead of snapping back to base/default.
  const activeVariantIdRef = React.useRef(snapshots.activeVariantId);
  activeVariantIdRef.current = snapshots.activeVariantId;

  // Seed the variant manager from a freshly-loaded pipe and render the
  // active variant's resolved snapshot. After a save-triggered reload the
  // previously active variant is preserved; on first load there is nothing
  // to preserve and it falls back to the default variant (or base).
  const handlePipeLoaded = React.useCallback(
    (pipe: Parameters<typeof parsePipeVariants>[0], mapped: typeof formData) => {
      const { variantForms, defaultVariantId } = parsePipeVariants(pipe, mapped, llmProviders);
      const { activeForm } = snapshots.hydrate(mapped, variantForms, defaultVariantId, {
        preserveActiveId: activeVariantIdRef.current,
      });
      return activeForm;
    },
    // `snapshots.hydrate` is a stable useCallback from the manager.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [llmProviders, snapshots.hydrate]
  );

  const form = usePipeForm({ pipeId, llmProviders, routingConfig, onPipeLoaded: handlePipeLoaded });
  const { formData, loading, isModified, integrations } = form;

  // Latest form snapshot + routing parse, mirrored into refs so the variant
  // switch handler can read the current values without re-creating on every
  // keystroke (it runs imperatively off a click, not a render).
  const formDataRef = React.useRef(formData);
  formDataRef.current = formData;
  const selectedPrefixRef = React.useRef(form.selectedPrefix);
  selectedPrefixRef.current = form.selectedPrefix;
  const customPathRef = React.useRef(form.customPath);
  customPathRef.current = form.customPath;

  const builderRef = React.useRef<{
    state: { nodes: unknown[]; surfaceSize?: { w: number; h: number } };
  } | null>(null);
  const canvasViewRef = React.useRef<{ x: number; y: number; k: number } | null>(null);
  const canvasSettingsRef = React.useRef<{ hide_disabled: boolean } | null>(null);
  // Assigned to `pipeBuilder.reseedFromCanvas` once the builder exists (it is
  // created below this point). Lets the variant switch handler — declared
  // before the builder — drive an imperative reseed without a forward ref to
  // the whole controller.
  const reseedFromCanvasRef = React.useRef<
    ((projection: ReturnType<typeof buildPipeForCanvas>) => void) | null
  >(null);
  const getCanvasBlob = React.useCallback(() => {
    const b = builderRef.current;
    if (!b) return undefined;
    const size = b.state.surfaceSize;
    return buildCanvasBlob(b.state.nodes as Parameters<typeof buildCanvasBlob>[0], {
      surfaceSize: size ? { width: size.w, height: size.h } : undefined,
      view: canvasViewRef.current ?? undefined,
      settings: canvasSettingsRef.current ?? undefined,
    });
  }, []);

  // Reveal a canvas node on the surface (drives the blocking toast's "Show
  // me"). Assigned after the builder/tab controls exist further down.
  const showNodeRef = React.useRef<(nodeId: string) => void>(() => {});

  // Block save when an active canvas node is incomplete or invalid, pointing
  // the user at the first offending node — mirrors the agent surface's
  // create-time validation gate. Disabled middleware (muted judge/jury/prompt
  // guard) reports no fault, so it never blocks.
  const getBlockingReason = React.useCallback(() => {
    const nodes = (builderRef.current?.state.nodes ?? []) as CanvasNode[];
    // A disabled jury makes its jurors inert, so an incomplete juror under a
    // disabled jury must not block save (mirrors the canvas/list "Disabled").
    const juryDisabled = nodes.some(
      n =>
        n.type === 'pipe-jury' &&
        (n.config as { jury?: { enabled?: boolean } })?.jury?.enabled !== true
    );
    // Decider mode defers the base LLM's provider/model/key to the candidates
    // (Route) or the merger (Mirror), so the LLM node's own config never blocks
    // save while a decider is present.
    const deciderMode = nodes.some(n => n.type === 'pipe-decider');
    // Provider-aware context so feature dependencies (e.g. a juror whose
    // provider requires an API key) evaluate against the live catalogue —
    // the same source that drives the canvas marching-ants ring.
    const ctx = buildSurfaceContext('a2a', nodes, llmProviders);
    for (const node of nodes) {
      if (node.type === 'pipe-juror' && juryDisabled) continue;
      if (node.type === 'pipe-upstream' && deciderMode) continue;
      const reason = registry.getFaultReason(node.type, node.config);
      if (reason) {
        const label = registry.get(node.type)?.label ?? node.label ?? node.type;
        return { message: `${label}: ${reason}`, nodeId: node.id };
      }
      // Context-aware faults the static node definition can't detect (e.g. an
      // enabled juror missing its required API-key secret). Driven by the
      // node's `featureDependencies`, so the gate, the canvas ring, and the
      // sidebar warning stay in lockstep.
      const depError = registry
        .getDependencyWarnings(node.type, node.config, ctx)
        .find(w => w.severity === 'error');
      if (depError) {
        const label = registry.get(node.type)?.label ?? node.label ?? node.type;
        return { message: `${label}: ${depError.message}`, nodeId: node.id };
      }
    }
    // Surface-level, enable-first controls (attribute-based routing, breach &
    // anomaly alerts) live on `formData`, not on a normal canvas node. Alerts
    // flag with `nodeId: '__surface__'` (the surface fullscreen editor); routing
    // moved onto the Router element, so its fault points at the `pipe-router`
    // node's fullscreen instead.
    const form = formDataRef.current;

    // Identity pass-through (`forward_caller_token`) — property-driven, never
    // keyed on a specific provider id. Two backend rules are mirrored so the
    // surface shows invalid before the round-trip: (1) a provider that requires
    // forwarding must have it on; (2) forwarding requires a JWT-bearer Caller
    // Context so the forwarded token is validated. (1) points at the surface
    // editor (the switch); (2) points at the Caller Context node when present.
    const activeProvider = llmProviders.find(p => p.enum_value === form.provider);
    const requiredErr = validateForwardTokenRequired(
      providerRequiresForwardCallerToken(activeProvider),
      form.forward_caller_token
    );
    if (requiredErr) {
      return { message: `Surface: ${requiredErr}`, nodeId: '__surface__' };
    }
    if (form.forward_caller_token === true) {
      const callerAuth = nodes.find(n => n.type === 'pipe-caller-auth');
      const method = (callerAuth?.config as { method_type?: string } | undefined)?.method_type;
      const sourceErr = validateForwardTokenSource(form.forward_caller_token, method);
      if (sourceErr) {
        return { message: `Surface: ${sourceErr}`, nodeId: callerAuth?.id ?? '__surface__' };
      }
    }

    const routingError = validateRoutingRules(form.routing_enabled, form.routing_rules);
    if (routingError) {
      const routerNode = nodes.find(n => n.type === 'pipe-router');
      return { message: `Router: ${routingError}`, nodeId: routerNode?.id ?? '__surface__' };
    }
    const alertsError = validateUsageAlerts(form.usage_alerts_enabled, form.usage_alerts);
    if (alertsError) {
      return { message: `Surface: ${alertsError}`, nodeId: '__surface__' };
    }
    return null;
  }, [llmProviders]);
  const onShowNode = React.useCallback((nodeId: string) => showNodeRef.current(nodeId), []);

  // Fold the variant catalog into the wire shape at save time, snapshotting
  // the form being saved as the active variant first. The base pipe is
  // written from `baseSnapshot` so saving while a variant is active never
  // leaks that variant's config onto the base.
  const buildVariantsSlice = React.useCallback(
    (form: typeof formData) => snapshots.buildVariantsWireSlice(form),
    // `snapshots.buildVariantsWireSlice` is a stable useCallback.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [snapshots.buildVariantsWireSlice]
  );

  const save = usePipeSave({
    pipeId,
    isNew,
    llmProviders,
    formData,
    integrations,
    setFormData: form.setFormData,
    isModified,
    setIsModified: form.setIsModified,
    reloadPipe: form.reloadPipe,
    navigate,
    getCanvasBlob,
    getBlockingReason,
    onShowNode,
    buildVariantsSlice,
  });
  const { saving } = save;

  const templates = usePipeTemplatesView({
    isNew,
    initialTab: searchParams.get('tab'),
    setSearchParams,
    setFormData: form.setFormData,
    setIsModified: form.setIsModified,
  });
  const { activeTab } = templates;

  usePipeDashboardSync(pipeId, activeTab, state, actions);

  const selectedProvider = llmProviders.find(p => p.enum_value === formData.provider);
  const selectedModel = selectedProvider?.models.find(m => m.value === formData.model);
  useModelParameterDefaults(
    formData,
    form.setFormData,
    llmProviders,
    secrets,
    selectedProvider,
    selectedModel
  );

  const canvas = useCanvasBindings(
    formData,
    form.selectedPrefix,
    form.customPath,
    form.setFormData,
    form.setSelectedPrefix,
    form.setCustomPath,
    form.setIsModified,
    llmProviders,
    form.routePrefixResolved
  );

  const handleVariantsChange = React.useCallback(
    (variants: PipeVariantMeta[], defaultVariantId: string | null) => {
      // The snapshot manager owns the catalog + per-variant snapshots;
      // mirror the meta + default onto formData so save args / dirty
      // tracking and the catalog UI stay in sync.
      snapshots.setCatalog({ variants, defaultVariantId });
      const aliases = variants.map(v => v.alias);
      form.setFormData(prev => {
        const synced = syncVariantCatalogReferences(aliases, prev.canary, prev.routing_rules ?? []);
        return {
          ...prev,
          variants: variants as typeof prev.variants,
          default_variant_id: defaultVariantId,
          canary: synced.canary,
          routing_rules: synced.routingRules,
        };
      });
      form.setIsModified(true);
    },
    // form.setFormData / setIsModified are stable state setters;
    // snapshots.setCatalog is a stable useCallback.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [form.setFormData, form.setIsModified, snapshots.setCatalog]
  );

  // Switch the active variant: snapshot the current form under the old
  // variant, then swap the new variant's snapshot into the form so the
  // whole canvas re-renders for it. Switching alone does not dirty the
  // form (the snapshot signature excludes the active id).
  const handleSwitchVariant = React.useCallback(
    (variantId: string) => {
      // Capture the LIVE canvas (node positions + pan/zoom + surface size)
      // from the builder — these never reach formData until save, so the
      // outgoing variant must snapshot them here or its layout is lost.
      const liveCanvas = getCanvasBlob();
      const current = { ...formDataRef.current, canvas: liveCanvas } as typeof formDataRef.current;
      // eslint-disable-next-line no-console
      console.debug('[pipe-variants] switch: capture live canvas', {
        from: snapshots.activeVariantId,
        to: variantId,
        liveCanvas,
        jury: (current as { jury?: unknown }).jury,
      });
      // Snapshot the outgoing variant (carrying the live canvas) and swap in
      // the target variant's full snapshot (behavioural slice + its canvas).
      const next = snapshots.switchVariant(variantId, current);
      form.setFormData(prev => {
        const merged = { ...prev };
        for (const field of PIPE_VARIANT_FIELDS) {
          merged[field] = next[field];
        }
        (merged as typeof merged & { canvas?: unknown }).canvas = (
          next as typeof next & { canvas?: unknown }
        ).canvas;
        return merged;
      });
      // Re-seed the builder from the target's projection so node positions AND
      // every node config (jury / judge / prompt-guard / …) revert, and the
      // live view ref carries the target's pan/zoom. The canvas remounts
      // (keyed on the new active variant) and re-applies them.
      const projection = buildPipeForCanvas(next, selectedPrefixRef.current, customPathRef.current);
      // eslint-disable-next-line no-console
      console.debug('[pipe-variants] switch: reseed from target', {
        to: variantId,
        canvas: (next as { canvas?: unknown }).canvas,
        jury: (next as { jury?: unknown }).jury,
      });
      reseedFromCanvasRef.current?.(projection);
    },
    // getCanvasBlob is stable; snapshots.* are stable useCallbacks; refs are
    // stable; form.setFormData is a stable setter.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [getCanvasBlob, snapshots.switchVariant, snapshots.activeVariantId, form.setFormData]
  );

  // Apply a pasted/edited configuration from the Config tab into the editor.
  // Imports the incoming behavioural config + name/description while preserving
  // this surface's id/route/listener, then reseeds the canvas so it reflects
  // the imported payload. The user saves to persist.
  const handleApplyConfig = React.useCallback(
    (parsed: unknown): string | null => {
      const merged = mergeImportedPipeConfig(formDataRef.current, parsed, llmProviders);
      if (typeof merged === 'string') return merged;
      form.setFormData(merged);
      const projection = buildPipeForCanvas(
        merged,
        selectedPrefixRef.current,
        customPathRef.current
      );
      reseedFromCanvasRef.current?.(projection);
      form.setIsModified(true);
      return null;
    },
    // refs + llmProviders are stable; form.setFormData/setIsModified are stable setters.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [llmProviders, form.setFormData, form.setIsModified]
  );

  const pipeBuilder = usePipeBuilder(
    canvas.pipeForCanvas,
    {
      onSourceChange: canvas.handleCanvasSourceChange,
      onUpstreamChange: canvas.handleCanvasUpstreamChange,
      onRateLimitChange: canvas.handleCanvasRateLimitChange,
      onOpaPolicyChange: canvas.handleCanvasOpaPolicyChange,
      onPromptGuardChange: canvas.handleCanvasPromptGuardChange,
      onJudgeChange: canvas.handleCanvasJudgeChange,
      onJuryChange: canvas.handleCanvasJuryChange,
      onDeciderChange: canvas.handleCanvasDeciderChange,
      onExpertWitnessesChange: canvas.handleCanvasExpertWitnessesChange,
      onUsageLimitsChange: canvas.handleCanvasUsageLimitsChange,
    },
    () => form.setIsModified(true),
    !loading && !configLoading,
    canvasViewRef,
    canvasSettingsRef
  );
  builderRef.current = pipeBuilder.builder;
  reseedFromCanvasRef.current = pipeBuilder.reseedFromCanvas;
  showNodeRef.current = (nodeId: string) => {
    pipeBuilder.setEditorNodeId(nodeId);
    templates.setActiveTab('editor');
  };

  // When the surface leaves a provider that requires identity pass-through for
  // one that doesn't (e.g. Microsoft 365 Copilot → OpenAI), turn forwarding back
  // off so the Caller Context requirement it auto-enabled clears instead of
  // sticking. Watches the resolved provider so it fires from both the form and
  // the canvas; a manual forward toggle on a non-requiring provider is left
  // untouched (that transition is non-requiring → non-requiring).
  const prevProviderRef = React.useRef<string | null>(null);
  React.useEffect(() => {
    const prev = prevProviderRef.current;
    const cur = formData.provider;
    prevProviderRef.current = cur;
    if (prev === null || prev === cur) return;
    const nowRequires = providerRequiresForwardCallerToken(
      llmProviders.find(p => p.enum_value === cur)
    );
    const wasRequires = providerRequiresForwardCallerToken(
      llmProviders.find(p => p.enum_value === prev)
    );
    const next = forwardTokenAfterProviderChange(
      wasRequires,
      nowRequires,
      formData.forward_caller_token === true
    );
    if (next !== (formData.forward_caller_token === true)) {
      form.setFormData(p => ({ ...p, forward_caller_token: next }));
      form.setIsModified(true);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [formData.provider, llmProviders]);

  // Identity pass-through requires validated `jwt_bearer` source auth, so when
  // forwarding is enabled (either by the operator's switch or auto-enabled by
  // selecting a provider that requires it) ensure a Caller Context element
  // exists on the inbound edge. It is seeded as an unconfigured JWT-bearer node
  // so the operator still picks a verification strategy — the node-fault gate
  // keeps Save blocked until they do. When forwarding is later turned off (e.g.
  // switching from Copilot to a provider that doesn't require it), the node this
  // effect seeded is removed again — as long as the operator never configured it
  // — so the requirement clears instead of sticking. A configured / reconciled
  // Caller Context is the operator's and is left alone.
  const autoAddedCallerAuthRef = React.useRef(false);
  // Presence is tracked as a dependency so the effect self-heals: a canvas
  // reseed (first-config, variant switch, load) rebuilds nodes from
  // `nodesFromPipe`, which does not derive the Caller Context node — so if
  // forwarding still requires it, its disappearance re-runs this effect and it
  // is seeded again instead of leaving the surface with a requirement but no
  // visible element.
  const callerAuthNodePresent = pipeBuilder.builder.state.nodes.some(
    n => n.type === 'pipe-caller-auth'
  );
  React.useEffect(() => {
    if (!pipeBuilder.hydrated) return;
    // The seed must land while the canvas is mounted so the new edge node is
    // projected onto the inbound edge (a layout bump only reaches a mounted
    // canvas). Configuring the LLM in the fullscreen editor unmounts the canvas,
    // which reserved space but left the element unrendered; defer until the
    // visual view is active again — the effect re-runs on `activeTab`.
    if (activeTab !== 'visual') return;
    const b = pipeBuilder.builder;
    const nodes = b.state.nodes as CanvasNode[];
    const callerAuth = nodes.find(n => n.type === 'pipe-caller-auth');

    if (formData.forward_caller_token === true) {
      if (callerAuth) return;
      const source = nodes.find(n => n.type === 'pipe-source');
      if (!source) return;
      const upstream = nodes.find(n => n.type === 'pipe-upstream');
      const midX =
        ((source.position?.x ?? 0) + (upstream?.position?.x ?? source.position?.x ?? 0)) / 2;
      b.handleNodeAdd({
        id: 'pipe-caller-auth',
        type: 'pipe-caller-auth',
        label: 'Caller Context',
        configured: false,
        position: { x: midX, y: source.position?.y ?? 0 },
        parentId: source.id,
        config: {
          method_type: 'jwt_bearer',
          extraction_source: 'http_header',
          extraction_field: 'Authorization',
          jwt_token_header: 'Authorization',
          jwt_token_scheme: 'Bearer',
        },
      } as CanvasNode);
      // Re-run the layout so the new edge node is projected onto the inbound
      // edge and the canvas re-syncs its position cache (via externalRevision) —
      // without this the node stays hidden behind the source until the next
      // reload. The unconfigured node renders with the marching-ants "invalid"
      // ring, prompting the operator to pick a JWT verification strategy.
      b.handleAutoLayout();
      autoAddedCallerAuthRef.current = true;
      form.setIsModified(true);
      return;
    }

    // Forwarding is off: undo the node this effect seeded when the operator
    // never configured it (it still faults), so the Caller Context requirement
    // clears. A configured Caller Context (no fault) is preserved.
    if (
      autoAddedCallerAuthRef.current &&
      callerAuth &&
      registry.getFaultReason('pipe-caller-auth', callerAuth.config)
    ) {
      b.handleNodeRemove(callerAuth.id);
      b.handleAutoLayout();
      form.setIsModified(true);
    }
    autoAddedCallerAuthRef.current = false;
    // Read the builder imperatively; re-run when forwarding, hydration, the
    // presence of the Caller Context node, or the active view changes so a
    // reseed that drops it (or returning from the fullscreen editor to the
    // canvas) re-seeds it (and we never fight per-tick canvas edits).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [formData.forward_caller_token, pipeBuilder.hydrated, callerAuthNodePresent, activeTab]);

  // A machine-generated surface (e.g. one provisioned by an external control
  // plane) carries `auto_canvas: true` and has no hand-authored canvas, so run
  // Auto Layout the first time it opens in the visual builder — arranging the
  // raw graph and projecting edge-bound nodes (Caller Context) onto the inbound
  // edge — then clear the flag (marking the form modified) so the next save
  // persists the layout and a later hand-tuned canvas is never re-arranged.
  const autoCanvasRunRef = React.useRef(false);
  React.useEffect(() => {
    if (autoCanvasRunRef.current) return;
    if (!pipeBuilder.hydrated || activeTab !== 'visual') return;
    if (formData.auto_canvas !== true) return;
    autoCanvasRunRef.current = true;
    pipeBuilder.builder.handleAutoLayout();
    form.handleInputChange('auto_canvas', false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [formData.auto_canvas, pipeBuilder.hydrated, activeTab]);

  const editorNode = React.useMemo(
    () =>
      pipeBuilder.editorNodeId === '__surface__'
        ? // The surface itself is a synthetic canvas node (not in `state.nodes`),
          // so synthesize a minimal node here to drive its full-page editor.
          ({
            id: '__surface__',
            type: 'surface',
            label: 'LLM Surface',
            configured: true,
            config: {},
          } as never)
        : pipeBuilder.editorNodeId
          ? (pipeBuilder.builder.state.nodes.find(n => n.id === pipeBuilder.editorNodeId) ?? null)
          : null,
    [pipeBuilder.editorNodeId, pipeBuilder.builder.state.nodes]
  );

  const openEditor = React.useCallback(
    (id: string) => {
      pipeBuilder.setEditorNodeId(id);
      templates.setActiveTab('editor');
    },
    [pipeBuilder, templates]
  );

  const closeEditor = React.useCallback(() => {
    pipeBuilder.setEditorNodeId(null);
    templates.setActiveTab('visual');
  }, [pipeBuilder, templates]);

  // Open / close the variants catalog panel (a synthetic left-cluster
  // view; the pipe builder has no canvas node for variants).
  const openVariants = React.useCallback(() => {
    pipeBuilder.setEditorNodeId(null);
    templates.setActiveTab('pipe-variants');
  }, [pipeBuilder, templates]);

  const closeVariants = React.useCallback(() => {
    templates.setActiveTab('visual');
  }, [templates]);

  // Open the panel AND seed a new variant (zero-state "+" / dropdown "Add…").
  const addVariant = React.useCallback(() => {
    const id =
      typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
        ? crypto.randomUUID()
        : `v-${Math.random().toString(36).slice(2, 10)}-${Date.now().toString(36)}`;
    const used = new Set(snapshots.variants.map(v => v.alias.toLowerCase()));
    let n = snapshots.variants.length + 1;
    while (used.has(`alias${n}`)) n += 1;
    const alias = `alias${n}`;
    const next: PipeVariantMeta = { id, name: alias, alias, enabled: true };
    handleVariantsChange([...snapshots.variants, next], snapshots.defaultVariantId);
    handleSwitchVariant(id);
    openVariants();
  }, [
    snapshots.variants,
    snapshots.defaultVariantId,
    handleVariantsChange,
    handleSwitchVariant,
    openVariants,
  ]);

  const handleSelectView = React.useCallback(
    (key: string) => {
      if (key === 'editor') {
        templates.setActiveTab('editor');
        return;
      }
      if (key === 'pipe-variants') {
        templates.setActiveTab('pipe-variants');
        return;
      }
      templates.handleTabChange(key);
    },
    [templates]
  );

  // If the editor tab is active but its node was removed, fall back to the canvas.
  React.useEffect(() => {
    if (activeTab === 'editor' && !editorNode) {
      templates.setActiveTab('visual');
    }
  }, [activeTab, editorNode, templates]);

  // OAuth Identifier profiles (Credentials store) offered as the sandbox
  // "Sign in to test" identity. Loaded once; the Sandbox tab renders a picker
  // and the selected profile resolves to a browser PKCE config.
  const [oauthProfiles, setOauthProfiles] = React.useState<SandboxOAuthProfile[]>([]);
  React.useEffect(() => {
    let alive = true;
    apiClient
      .get<SandboxOAuthProfile[]>('/oauth-identifiers')
      .then(r => {
        if (alive) setOauthProfiles(Array.isArray(r.data) ? r.data : []);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);

  // JWT verification strategies — loaded so the sandbox can auto-match a sign-in
  // profile to the surface's inbound verification tenant (a `forward_caller_token`
  // surface accepts tokens from the tenant its Caller Context strategy trusts, so
  // the OAuth Identifier for that same tenant is the right sign-in identity).
  const [jwtStrategies, setJwtStrategies] = React.useState<
    Array<{ id: string; name: string; expected_issuer?: string }>
  >([]);
  React.useEffect(() => {
    let alive = true;
    apiClient
      .get<Array<{ id: string; name: string; expected_issuer?: string }>>(
        '/jwt-verification-strategies'
      )
      .then(r => {
        if (alive) setJwtStrategies(Array.isArray(r.data) ? r.data : []);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);

  // The JWT verification strategy the surface's Caller Context authenticates
  // with (canvas-authoritative: the `pipe-caller-auth` node holds it). Reactive
  // to canvas edits so picking a strategy re-derives the tenant match live.
  const callerAuthStrategyId = React.useMemo<string | null>(() => {
    const nodes = pipeBuilder.builder.state.nodes as CanvasNode[];
    const node = nodes.find(n => n.type === 'pipe-caller-auth');
    const id = (node?.config as { jwt_strategy_id?: string } | undefined)?.jwt_strategy_id;
    return typeof id === 'string' && id.trim() ? id : null;
  }, [pipeBuilder.builder.state.nodes]);

  // The OAuth Identifier whose Entra tenant matches the Caller Context strategy's
  // issuer tenant — the profile that issues tokens this surface accepts.
  const tenantMatchedProfileId = React.useMemo<string | null>(() => {
    if (!callerAuthStrategyId) return null;
    const strategy = jwtStrategies.find(s => s.id === callerAuthStrategyId);
    const tenant = tenantFromIssuer(strategy?.expected_issuer);
    if (!tenant) return null;
    const wanted = tenant.toLowerCase();
    const match = oauthProfiles.find(
      p =>
        (p.provider ?? 'entra') === 'entra' && (p.tenant_id ?? '').trim().toLowerCase() === wanted
    );
    return match?.id ?? null;
  }, [callerAuthStrategyId, jwtStrategies, oauthProfiles]);

  // Sandbox sign-in config, resolved **reference → surface-inline →
  // provider-default → auto-picked profile**: a referenced OAuth Identifier
  // profile wins, then the surface's inline `sandbox_auth`, then the provider
  // catalog default, and finally — only for an identity-pass-through surface
  // with no other config — an auto-picked profile: the one whose tenant matches
  // the Caller Context's verification strategy, else the sole OAuth Identifier
  // (so sign-in "just works" without the operator having to choose). This is
  // what lets a surface use a reusable Credentials profile instead of an inline
  // block (or a provider `sandbox_auth` in llm.json).
  const providerSandboxAuth = React.useMemo<SandboxAuthConfig | null>(
    () =>
      (llmProviders.find(p => p.enum_value === formData.provider)?.sandbox_auth as
        | SandboxAuthConfig
        | undefined) ?? null,
    [llmProviders, formData.provider]
  );
  // The profile auto-picked as a last resort (never overrides an explicit
  // reference / inline / provider default). Only for identity-pass-through
  // surfaces: prefer the tenant-matched profile, else the sole profile.
  const autoSandboxProfileId = React.useMemo<string | null>(() => {
    if (formData.sandbox_oauth_identifier_id) return null;
    if (formData.forward_caller_token !== true) return null;
    if (formData.sandbox_auth || providerSandboxAuth) return null;
    if (tenantMatchedProfileId) return tenantMatchedProfileId;
    return oauthProfiles.length === 1 ? (oauthProfiles[0]?.id ?? null) : null;
  }, [
    formData.sandbox_oauth_identifier_id,
    formData.forward_caller_token,
    formData.sandbox_auth,
    providerSandboxAuth,
    tenantMatchedProfileId,
    oauthProfiles,
  ]);
  const effectiveSandboxProfileId = formData.sandbox_oauth_identifier_id ?? autoSandboxProfileId;
  // Why the profile was auto-selected (drives the sandbox hint copy).
  const sandboxAutoSelectReason: 'tenant' | 'single' | null =
    formData.sandbox_oauth_identifier_id || !autoSandboxProfileId
      ? null
      : autoSandboxProfileId === tenantMatchedProfileId
        ? 'tenant'
        : 'single';
  const resolvedSandboxAuth = React.useMemo<SandboxAuthConfig | null>(() => {
    const refProfile = formData.sandbox_oauth_identifier_id
      ? sandboxAuthFromProfile(
          oauthProfiles.find(p => p.id === formData.sandbox_oauth_identifier_id)
        )
      : null;
    const autoProfile = autoSandboxProfileId
      ? sandboxAuthFromProfile(oauthProfiles.find(p => p.id === autoSandboxProfileId))
      : null;
    return (
      refProfile ??
      (formData.sandbox_auth as SandboxAuthConfig | null) ??
      providerSandboxAuth ??
      autoProfile ??
      null
    );
  }, [
    formData.sandbox_oauth_identifier_id,
    formData.sandbox_auth,
    autoSandboxProfileId,
    oauthProfiles,
    providerSandboxAuth,
  ]);

  const handleSelectSandboxProfile = React.useCallback(
    (id: string) => {
      form.setFormData(prev => ({ ...prev, sandbox_oauth_identifier_id: id || null }));
      form.setIsModified(true);
    },
    [form]
  );

  const editorPanelData = React.useMemo(
    () => ({
      llmProviders: llmProviders ?? [],
      secrets: secrets ?? [],
      routing: routingConfig
        ? {
            availableListenAddresses: routingConfig.available_listen_addresses,
            pathPrefixes: routingConfig.pipe_path_prefix,
          }
        : { availableListenAddresses: [], pathPrefixes: [] },
      promptGuardPatterns: promptGuardPatterns ?? [],
      inputModalities,
      audioStreams,
    }),
    [llmProviders, secrets, routingConfig, promptGuardPatterns, inputModalities, audioStreams]
  );

  const pipeSurfaceMeta: SurfaceMetaValue = {
    variant: 'pipe',
    name: formData.name,
    description: formData.description,
    tagsCsv: '',
    status: formData.enabled ? 'enabled' : 'disabled',
    protocol: 'a2a',
    publishToDid: false,
    didwebvh: DEFAULT_DIDWEBVH_CONFIG,
    readOnly: false,
    protocolLocked: true,
    isCreate: isNew,
    surfaceId: isNew ? undefined : pipeId,
    surfaceUsageLimit: formData.surface_usage_limit
      ? {
          enabled: formData.surface_usage_limit.enabled,
          monthlyBudgetUsd: formData.surface_usage_limit.monthly_budget_usd,
          monthlyTokenCap: formData.surface_usage_limit.monthly_token_cap,
        }
      : null,
    hasSecondaryStages:
      formData.judge?.enabled === true ||
      formData.jury?.enabled === true ||
      formData.decider?.enabled === true,
    teamAttribution: formData.team_attribution ?? null,
    streamingEnabled: formData.streaming_enabled,
    forwardCallerToken: formData.forward_caller_token,
    acceptedIngressSchemas: formData.accepted_ingress_schemas,
    cache: formData.cache ?? null,
    canary: formData.canary ?? null,
    variantAliases: snapshots.variants.map(v => v.alias).filter(Boolean),
    routingRules: formData.routing_rules ?? [],
    routingEnabled: formData.routing_enabled ?? false,
    usageAlerts: formData.usage_alerts ?? [],
    usageAlertsEnabled: formData.usage_alerts_enabled ?? false,
    governanceRecording: formData.governance_recording ?? null,
    drift: formData.drift ?? null,
    vpEvidence: formData.vp_evidence ?? null,
    setName: (v: string) => {
      form.setFormData(prev => ({ ...prev, name: v }));
      form.setIsModified(true);
    },
    setDescription: (v: string) => {
      form.setFormData(prev => ({ ...prev, description: v }));
      form.setIsModified(true);
    },
    setTagsCsv: () => {},
    setStatus: v => {
      form.setFormData(prev => ({ ...prev, enabled: v === 'enabled' }));
      form.setIsModified(true);
    },
    setProtocol: () => {},
    setPublishToDid: () => {},
    setDidwebvh: () => {},
    setSurfaceUsageLimit: v => {
      form.setFormData(prev => ({
        ...prev,
        surface_usage_limit: v
          ? {
              id: prev.surface_usage_limit?.id ?? 'usage-limit-cumulative',
              enabled: v.enabled,
              scope: 'cumulative',
              stage: null,
              monthly_budget_usd: v.monthlyBudgetUsd,
              monthly_token_cap: v.monthlyTokenCap,
            }
          : null,
      }));
      form.setIsModified(true);
    },
    setTeamAttribution: v => {
      form.setFormData(prev => ({ ...prev, team_attribution: v }));
      form.setIsModified(true);
    },
    setStreamingEnabled: v => {
      form.setFormData(prev => ({ ...prev, streaming_enabled: v }));
      form.setIsModified(true);
    },
    setForwardCallerToken: v => {
      form.setFormData(prev => ({ ...prev, forward_caller_token: v }));
      form.setIsModified(true);
    },
    setAcceptedIngressSchemas: v => {
      form.setFormData(prev => ({
        ...prev,
        accepted_ingress_schemas: v.length
          ? v
          : ['openai_chat', 'anthropic_messages', 'openai_responses'],
      }));
      form.setIsModified(true);
    },
    setCache: v => {
      form.setFormData(prev => ({ ...prev, cache: v }));
      form.setIsModified(true);
    },
    setCanary: v => {
      form.setFormData(prev => ({ ...prev, canary: v }));
      form.setIsModified(true);
    },
    setRoutingRules: v => {
      form.setFormData(prev => ({ ...prev, routing_rules: v }));
      form.setIsModified(true);
    },
    setRoutingEnabled: v => {
      form.setFormData(prev => ({ ...prev, routing_enabled: v }));
      form.setIsModified(true);
    },
    setUsageAlerts: v => {
      form.setFormData(prev => ({ ...prev, usage_alerts: v }));
      form.setIsModified(true);
    },
    setUsageAlertsEnabled: v => {
      form.setFormData(prev => ({ ...prev, usage_alerts_enabled: v }));
      form.setIsModified(true);
    },
    setGovernanceRecording: v => {
      form.setFormData(prev => ({ ...prev, governance_recording: v }));
      form.setIsModified(true);
    },
    setDrift: v => {
      form.setFormData(prev => ({ ...prev, drift: v }));
      form.setIsModified(true);
    },
    setVpEvidence: v => {
      form.setFormData(prev => ({ ...prev, vp_evidence: v }));
      form.setIsModified(true);
    },
  };

  // ── New-pipe welcome callout ─────────────────────────────────────────
  // Mirrors the New Surface flow: the first time the canvas is reached for a
  // brand-new pipe, float a callout above the LLM node showing the chosen
  // starter template's hint. A "do not show again" checkbox persists dismissal.
  const [welcomeShown, setWelcomeShown] = React.useState(false);
  const [welcomeDontShow, setWelcomeDontShow] = React.useState(false);
  const welcomeSeenRef = React.useRef(false);
  React.useEffect(() => {
    if (!isNew || activeTab !== 'visual' || welcomeSeenRef.current) return;
    if (templates.pipePickerShown) return;
    if (localStorage.getItem(PIPE_WELCOME_DISMISSED_KEY) === 'true') return;
    welcomeSeenRef.current = true;
    setWelcomeShown(true);
  }, [isNew, activeTab, templates.pipePickerShown]);
  const handleCloseWelcome = React.useCallback(() => {
    if (welcomeDontShow) localStorage.setItem(PIPE_WELCOME_DISMISSED_KEY, 'true');
    setWelcomeShown(false);
  }, [welcomeDontShow]);

  // Track the LLM node's screen rect so the callout floats above it. Polled
  // via rAF because the d3 canvas mutates SVG transforms outside React.
  const [calloutPos, setCalloutPos] = React.useState<{ x: number; y: number } | null>(null);
  React.useEffect(() => {
    if (!welcomeShown || activeTab !== 'visual') {
      setCalloutPos(null);
      return;
    }
    let raf = 0;
    const tick = () => {
      const el = document.querySelector('[data-node-id="pipe-upstream"]');
      if (el) {
        const r = (el as SVGGraphicsElement).getBoundingClientRect();
        setCalloutPos(prev => {
          const next = { x: r.left + r.width / 2, y: r.top };
          if (prev && Math.abs(prev.x - next.x) < 0.5 && Math.abs(prev.y - next.y) < 0.5) {
            return prev;
          }
          return next;
        });
      }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [welcomeShown, activeTab]);

  if (loading || configLoading || !pipeBuilder.hydrated) {
    return (
      <div
        style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          minHeight: '60vh',
        }}
      >
        <div className="spinner-border text-primary" role="status">
          <span className="sr-only">Loading...</span>
        </div>
      </div>
    );
  }

  if (templates.pipePickerShown) {
    return (
      <PipeStarterPicker
        templates={templates.starterPipeTemplates}
        loading={templates.pipeTemplates.loading}
        error={templates.pipeTemplates.error}
        applyingStarterId={templates.applyingStarterId}
        expandedId={templates.pickerExpandedId}
        onToggleExpand={templates.toggleExpanded}
        onApply={templates.handleApplyStarterTemplate}
        onCancel={() => navigate('/llm')}
        onStartBlank={() => templates.setPipePickerShown(false)}
      />
    );
  }

  const shellViews: PipeShellView[] = [
    { key: 'visual', label: 'Surface', icon: 'diagram-project' },
    { key: 'elements', label: 'Elements', icon: 'list' },
    { key: 'templates', label: 'Templates', icon: 'layer-group' },
    { key: 'monitoring', label: 'Monitoring', icon: 'chart-line' },
    {
      key: 'integrations',
      label: 'Integrations',
      icon: 'puzzle-piece',
      available: !!pipeId && pipeId !== 'new',
    },
    {
      key: 'sandbox',
      label: 'Sandbox',
      icon: 'flask',
      available: !!pipeId && pipeId !== 'new',
    },
    { key: 'config', label: 'Config', icon: 'code' },
  ];

  if (editorNode) {
    shellViews.push({
      key: 'editor',
      label: editorNode.label || 'Editor',
      icon: 'pen-to-square',
      onClose: closeEditor,
    });
  }

  if (activeTab === 'pipe-variants') {
    shellViews.push({
      key: 'pipe-variants',
      label: 'Variants',
      icon: 'code-branch',
      onClose: closeVariants,
    });
  }

  const headerBadges = (
    <>
      {formData.enabled ? (
        <span className="badge text-bg-success ms-2">Enabled</span>
      ) : (
        <span className="badge text-bg-secondary ms-2">Disabled</span>
      )}
      {formData.provider && <span className="badge text-bg-info ms-2">{formData.provider}</span>}
      {selectedProvider?.api_version_prefix && (
        <span className="badge text-bg-warning ms-2">
          {selectedProvider.api_version_prefix.replace('/', '')}
        </span>
      )}
      {formData.governance_recording?.enabled && (
        <span
          className="badge text-bg-dark ms-2"
          title="Signed governance records are captured for every interaction on this surface"
          data-testid="surface-governance-badge"
        >
          <i className="fas fa-file-shield me-1" aria-hidden="true" />
          Governance
        </span>
      )}
      {formData.drift?.enabled && (
        <span
          className="badge text-bg-dark ms-2"
          title="Behavioural drift dimensions are sampled for this surface (Monitoring → LLM Drift)"
          data-testid="surface-drift-badge"
        >
          <i className="fas fa-wave-square me-1" aria-hidden="true" />
          Drift
        </span>
      )}
      {formData.vp_evidence?.enabled && (
        <span
          className="badge text-bg-dark ms-2"
          title="This surface verifies an inbound verifiable presentation (VP) for policy"
          data-testid="surface-vp-badge"
        >
          <i className="fas fa-id-badge me-1" aria-hidden="true" />
          VP
        </span>
      )}
    </>
  );

  const manageActions = (
    <PipeManageActions
      saving={saving}
      isModified={isModified}
      isNew={isNew}
      onSave={save.handleSave}
      onDelete={save.handleDelete}
      onClose={() => {
        if (isModified) {
          if (!window.confirm('You have unsaved changes. Are you sure you want to close?')) return;
        }
        navigate('/llm');
      }}
    />
  );

  const renderActiveView = () => {
    switch (activeTab) {
      case 'elements':
        return (
          <div className="p-3">
            <ElementsListTab
              nodes={pipeBuilder.builder.state.nodes}
              onSelectNode={id => {
                pipeBuilder.builder.handleNodeClick(id);
                templates.handleTabChange('visual');
              }}
            />
          </div>
        );
      case 'config':
        return <PipeConfigView config={formData} onApply={handleApplyConfig} />;
      case 'pipe-variants':
        return (
          <div className="surface-builder-fullscreen">
            <div className="surface-builder-fullscreen-body">
              <div className="card shadow-sm mb-4">
                <div className="card-header bg-light d-flex justify-content-between align-items-center">
                  <h6 className="m-0 font-weight-bold text-primary">
                    <i className="fas fa-code-branch me-2" />
                    Variants
                  </h6>
                  <button
                    type="button"
                    className="btn btn-sm btn-outline-secondary"
                    onClick={closeVariants}
                  >
                    <i className="fas fa-times me-1" />
                    Close tab
                  </button>
                </div>
                <div className="card-body">
                  <PipeVariantPanel
                    variants={snapshots.variants}
                    defaultVariantId={snapshots.defaultVariantId}
                    activeVariantId={snapshots.activeVariantId}
                    listenAddress={formData.listen_address}
                    route={formData.route}
                    onChange={handleVariantsChange}
                    onSwitchVariant={handleSwitchVariant}
                  />
                </div>
              </div>
            </div>
          </div>
        );
      case 'editor':
        return editorNode ? (
          <SurfaceMetaProvider value={pipeSurfaceMeta}>
            <PipePanelDataProvider value={editorPanelData}>
              <div className="surface-builder-fullscreen">
                <ConfigEditorFullscreen
                  node={editorNode}
                  protocol="a2a"
                  allNodes={pipeBuilder.builder.state.nodes}
                  onUpdate={pipeBuilder.builder.handleNodeUpdate}
                  onCloseFullscreenEditor={closeEditor}
                />
              </div>
            </PipePanelDataProvider>
          </SurfaceMetaProvider>
        ) : null;
      case 'templates':
        return (
          <PipeTemplatesPanel
            onApplyTemplate={templates.handleApplyTemplateToPipe}
            currentPipe={formData}
            nodes={pipeBuilder.builder.state.nodes}
            getCanvasBlob={getCanvasBlob}
            createMode={templates.templatesCreateMode}
            onExitCreateMode={() => templates.setTemplatesCreateMode(false)}
          />
        );
      case 'monitoring':
        return pipeId ? (
          <PipeMonitoringTab
            pipeId={pipeId}
            pipeName={formData.name}
            state={state}
            actions={actions}
          />
        ) : (
          <div className="p-4 text-center text-muted">
            <i className="fas fa-chart-line fa-2x mb-2 d-block" />
            Monitoring data appears after the pipe is saved.
          </div>
        );
      case 'integrations':
        return pipeId && pipeId !== 'new' ? (
          <PipeIntegrationsTab
            pipeId={pipeId}
            integrations={integrations}
            onIntegrationsChange={(newIntegrations: integrationIntegration[]) => {
              form.setIntegrations(newIntegrations);
              form.setIsModified(true);
            }}
            isModified={isModified}
            isSaving={saving}
          />
        ) : null;
      case 'sandbox':
        return pipeId && pipeId !== 'new' ? (
          <ChatSandboxTab
            pipeId={pipeId}
            formData={formData}
            sandboxAuth={resolvedSandboxAuth}
            oauthProfiles={oauthProfiles}
            sandboxOAuthIdentifierId={formData.sandbox_oauth_identifier_id}
            effectiveProfileId={effectiveSandboxProfileId}
            autoSelectReason={sandboxAutoSelectReason}
            onSelectSandboxProfile={handleSelectSandboxProfile}
            variants={snapshots.variants.map(v => ({
              alias: v.alias,
              name: v.name,
              enabled: v.enabled !== false,
            }))}
            defaultVariantAlias={
              snapshots.variants.find(v => v.id === snapshots.defaultVariantId)?.alias ?? null
            }
          />
        ) : null;
      default:
        return null;
    }
  };

  return (
    <div className="container-fluid surface-page-fill">
      <PipeFormShell
        pipeName={isNew ? 'New LLM Pipe' : formData.name || 'LLM Pipe'}
        headerBadges={headerBadges}
        views={shellViews}
        activeView={activeTab}
        onSelectView={handleSelectView}
        canvasViewKey="visual"
        templateViewKey="templates"
        onCreateTemplate={() => {
          templates.setActiveTab('templates');
          templates.setTemplatesCreateMode(true);
        }}
        manageActions={manageActions}
        paletteSlot={
          <ElementPalette
            variant="inline"
            scope="pipe"
            protocol="a2a"
            existingNodes={pipeBuilder.builder.state.nodes}
            onAnyDragStart={() => templates.handleTabChange('visual')}
          />
        }
        canvas={
          <SurfaceMetaProvider value={pipeSurfaceMeta}>
            <PipeBuilderPanel
              builder={pipeBuilder.builder}
              onOpenFullscreenEditor={openEditor}
              canvasViewRef={canvasViewRef}
              canvasSettingsRef={canvasSettingsRef}
              initialHideDisabled={canvasSettingsRef.current?.hide_disabled ?? false}
              activeVariantId={snapshots.activeVariantId}
              name={formData.name}
              llmProviders={llmProviders}
              secrets={secrets}
              routing={
                routingConfig
                  ? {
                      availableListenAddresses: routingConfig.available_listen_addresses,
                      pathPrefixes: routingConfig.pipe_path_prefix,
                    }
                  : undefined
              }
              promptGuardPatterns={promptGuardPatterns}
              inputModalities={inputModalities}
              audioStreams={audioStreams}
              variantsWidget={
                <PipeVariantSwitcher
                  variants={snapshots.variants}
                  defaultVariantId={snapshots.defaultVariantId}
                  activeVariantId={snapshots.activeVariantId}
                  selected={activeTab === 'pipe-variants'}
                  onOpen={openVariants}
                  onAddVariant={addVariant}
                  onSwitchVariant={handleSwitchVariant}
                />
              }
            />
          </SurfaceMetaProvider>
        }
        canvasOverlay={
          welcomeShown && activeTab === 'visual' && calloutPos ? (
            <div
              className="surface-canvas-callout surface-canvas-callout--floating"
              style={{
                position: 'fixed',
                left: calloutPos.x,
                top: calloutPos.y - 16,
                transform: 'translate(-50%, -100%)',
              }}
            >
              <button
                type="button"
                className="surface-canvas-callout__close"
                aria-label="Dismiss"
                onClick={handleCloseWelcome}
              >
                <i className="fas fa-times" />
              </button>
              <div className="surface-canvas-callout__title">
                <i className="fas fa-info-circle me-2" />
                {templates.chosenTemplate?.name ?? 'Configure your LLM Surface'}
              </div>
              {templates.chosenTemplate?.starter_hint ? (
                <p className="surface-canvas-callout__body" style={{ whiteSpace: 'pre-wrap' }}>
                  {templates.chosenTemplate.starter_hint}
                </p>
              ) : (
                <p className="surface-canvas-callout__body">
                  Open the <strong>LLM</strong> node to choose an LLM provider, model and API key,
                  edit quotas and other management items, then click Save.
                </p>
              )}
              <div className="surface-canvas-callout__footer">
                <label className="surface-canvas-callout__dontshow">
                  <input
                    type="checkbox"
                    checked={welcomeDontShow}
                    onChange={e => setWelcomeDontShow(e.target.checked)}
                  />
                  Do not show this again
                </label>
                <button
                  type="button"
                  className="btn btn-sm btn-primary"
                  onClick={handleCloseWelcome}
                >
                  Got it
                </button>
              </div>
              <span className="surface-canvas-callout__tail" />
            </div>
          ) : null
        }
      >
        {renderActiveView()}
      </PipeFormShell>
    </div>
  );
};

export default EditPipePage;
