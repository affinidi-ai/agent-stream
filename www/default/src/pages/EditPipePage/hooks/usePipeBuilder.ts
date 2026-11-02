import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { MutableRefObject } from 'react';
import { useSurfaceBuilder } from '../../../components/builder/hooks/useSurfaceBuilder';
import type {
  SurfaceBuilderState,
  UseSurfaceBuilderReturn,
} from '../../../components/builder/hooks/useSurfaceBuilder';
import { nodesFromPipe, PIPE_SURFACE_SIZE } from '../../../components/builder/elements/pipe';
import {
  readCanvasSurfaceSize,
  readCanvasView,
  readCanvasSettings,
} from '../../../components/builder/elements';
import type { PipeConfigLike } from '../../../components/builder/elements/pipe';
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
import type { CanvasNode } from '../../../components/builder/SurfaceCanvas';
import {
  readSource,
  readUpstream,
  readRateLimit,
  readOpaPolicy,
  readPromptGuard,
  readJudge,
  readJury,
  readDecider,
  readExpertWitnesses,
  readUsageLimits,
} from '../pipeBuilderHelpers';

/** Canvas-edit callbacks the host page wires to its flat form state. */
export interface PipeBuilderHandlers {
  onSourceChange: (change: PipeSourceChange) => void;
  onUpstreamChange: (change: PipeUpstreamChange) => void;
  onRateLimitChange: (change: PipeRateLimitChange) => void;
  onOpaPolicyChange: (change: PipeOpaPolicyChange) => void;
  onPromptGuardChange: (change: PipePromptGuardChange) => void;
  onJudgeChange: (change: PipeJudgeChange) => void;
  onJuryChange: (change: PipeJuryChange) => void;
  onDeciderChange: (change: PipeDeciderChange) => void;
  onExpertWitnessesChange: (change: PipeExpertWitnessesChange) => void;
  onUsageLimitsChange: (change: PipeUsageLimitsChange) => void;
}

/**
 * Bridges one canvas node's config back to the host page. Reads the node's
 * editable slice on every node-state change and fires `onChange` only when
 * that slice genuinely differs from the previous value. The very first read
 * (the initial seed) is swallowed so mounting never reports a spurious edit.
 *
 * `seedVersion` re-baselines the seam without firing `onChange`: when it
 * changes (the builder is reseeded from a freshly loaded pipe) the next read
 * is treated as a new baseline. This stops the post-load reseed from being
 * mistaken for a user edit and marking the pipe dirty.
 */
function useNodeSeam<T>(
  nodes: CanvasNode[],
  read: (nodes: CanvasNode[]) => T,
  onChange: ((change: T) => void) | undefined,
  seedVersion: number
) {
  const lastRef = useRef<string | null>(null);
  const seedRef = useRef(seedVersion);
  useEffect(() => {
    const value = read(nodes);
    const snapshot = JSON.stringify(value);
    if (lastRef.current === null || seedRef.current !== seedVersion) {
      lastRef.current = snapshot;
      seedRef.current = seedVersion;
      return;
    }
    if (lastRef.current === snapshot) return;
    lastRef.current = snapshot;
    onChange?.(value);
  }, [nodes, read, onChange, seedVersion]);
}

export interface PipeBuilderController {
  builder: UseSurfaceBuilderReturn<SurfaceBuilderState>;
  editorNodeId: string | null;
  setEditorNodeId: (id: string | null) => void;
  /**
   * False until the builder's nodes reflect the loaded pipe. The host page
   * keeps its loading state while this is false so an existing pipe's saved
   * canvas is reseeded *before* the canvas first paints — otherwise the empty
   * initial nodes flash as "invalid" for a frame before the reseed lands.
   */
  hydrated: boolean;
  /**
   * Reseed the live builder from a freshly projected pipe snapshot — used on
   * a variant switch. Replaces every node (restoring the target variant's
   * positions, surface size, and per-node config), seeds the live pan/zoom
   * ref from the target's canvas blob, and re-baselines the config seams so
   * the switch is not mistaken for a user edit. The host pairs this with a
   * canvas remount (keyed on the active variant) so the d3 positions/view are
   * re-applied from the reseeded nodes + view ref.
   */
  reseedFromCanvas: (projection: PipeConfigLike) => void;
}

/**
 * Owns the shared visual builder for the pipe editor. Seeds it once from the
 * pipe snapshot (`pipeForCanvas`), then bridges every editable pipe node back
 * to the host form via per-node write seams. Lifting the builder out of
 * `PipeBuilderPanel` lets the form shell host a palette / elements / config
 * view wired to the same `builder.state.nodes`.
 */
export function usePipeBuilder(
  pipeForCanvas: PipeConfigLike | null,
  handlers: PipeBuilderHandlers,
  onLayoutCommit?: () => void,
  /**
   * True once the pipe's form data has finished loading. Until then the
   * snapshot is still the empty default, so the builder must not declare
   * itself hydrated (doing so would un-gate the page and flash the empty
   * initial nodes as "invalid" before the loaded config arrives).
   */
  ready = true,
  /**
   * Mirrors the live canvas pan/zoom transform. Seeded from the loaded pipe's
   * saved canvas blob so the view restores on load, then kept current by the
   * canvas; the host page reads it when persisting the canvas blob.
   */
  canvasViewRef?: MutableRefObject<{ x: number; y: number; k: number } | null>,
  /**
   * Mirrors the live hide-disabled toolbar toggle. Seeded from the loaded
   * pipe's saved canvas blob so the preference restores on load, then kept
   * current by the SurfaceBuilder; the host page reads it when persisting
   * the canvas blob.
   */
  canvasSettingsRef?: MutableRefObject<{ hide_disabled: boolean } | null>
): PipeBuilderController {
  const initialNodes = useMemo(() => nodesFromPipe(pipeForCanvas), [pipeForCanvas]);
  const initialSize = useMemo(() => {
    const saved = readCanvasSurfaceSize(pipeForCanvas as Record<string, unknown> | null);
    return saved ? { w: saved.width, h: saved.height } : { ...PIPE_SURFACE_SIZE };
  }, [pipeForCanvas]);
  const builder = useSurfaceBuilder<SurfaceBuilderState>(
    {
      nodes: initialNodes,
      selectedNodeId: null,
      surfaceSize: initialSize,
    },
    { onCommit: onLayoutCommit }
  );

  // The builder seeds its state exactly once (via `useState` inside
  // `useHistory`), but `pipeForCanvas` starts empty and is only populated
  // after the pipe loads asynchronously. Without an explicit reseed the
  // saved canvas (node positions, surface size, drag-on decorations) is
  // never applied — the canvas reverts to the default auto-laid-out spine
  // on every reload. Mirror the agent-surface detail page: when the loaded
  // canvas first arrives, replace the builder nodes once and re-baseline the
  // config seams so this load is not mistaken for a user edit.
  const [seedVersion, setSeedVersion] = useState(0);
  const [hydrated, setHydrated] = useState(false);
  const reseededRef = useRef(false);
  useEffect(() => {
    if (reseededRef.current) return;
    const src = pipeForCanvas as {
      route?: string;
      route_prefix?: string;
      route_prefix_resolved?: boolean;
      provider?: string;
      canvas?: { nodes?: unknown[] };
    } | null;
    const canvas = src?.canvas;
    const canvasNodes = canvas && Array.isArray(canvas.nodes) ? canvas.nodes : null;
    const hasSavedCanvas = !!canvasNodes && canvasNodes.length > 0;
    // A surface with no saved canvas blob — created via the API / config import
    // (e.g. the testkit) rather than the dashboard — still needs its loaded
    // config projected onto the canvas. Without this the builder keeps the
    // empty spine it was seeded with before the pipe loaded: only the Access
    // Point is later seeded (by the AP effect below), while the LLM / Judge /
    // Jury nodes stay on their empty initial values and render as
    // "unconfigured" (marching ants). Reseed such a pipe too — but only once it
    // carries real content (an upstream provider), so a brand-new blank pipe
    // (whose AP defaults are handled by the AP-seed effect below) is untouched.
    const isLoadedConfigOnly = !hasSavedCanvas && !!src?.provider;
    if (!hasSavedCanvas && !isLoadedConfigOnly) return;
    // The backend persists only the combined `route`; the editor parses it
    // back into prefix + custom path one render after the pipe loads. If we
    // reseed before that parse lands, the `pipe-source` node is restored with
    // an empty prefix/custom path and would read as invalid. Wait for the
    // parse to be *attempted* (route_prefix_resolved) — not for a match to be
    // *found* (route_prefix truthy) — so a route that no longer matches any
    // known prefix (a stale/removed prefix, or an unresolved template token)
    // still reseeds and hydrates instead of leaving the page spinning
    // forever; the Access Point node just renders unconfigured, same as any
    // other genuinely invalid saved config.
    if (src?.route && !src.route_prefix_resolved) return;
    reseededRef.current = true;
    const reseeded = nodesFromPipe(pipeForCanvas);
    const saved = readCanvasSurfaceSize(pipeForCanvas as Record<string, unknown> | null);
    // Seed the live view ref from the saved canvas blob so the canvas restores
    // the persisted pan/zoom on load (the canvas keeps the ref current after).
    if (canvasViewRef) {
      canvasViewRef.current = readCanvasView(pipeForCanvas);
    }
    if (canvasSettingsRef) {
      canvasSettingsRef.current = readCanvasSettings(pipeForCanvas) ?? { hide_disabled: false };
    }
    builder.setState(prev => ({
      ...prev,
      nodes: reseeded,
      surfaceSize: saved ? { w: saved.width, h: saved.height } : prev.surfaceSize,
    }));
    builder.replaceCommit();
    builder.bumpExternalRevision();
    setSeedVersion(v => v + 1);
    setHydrated(true);
  }, [pipeForCanvas, builder, canvasViewRef, canvasSettingsRef]);

  // Mark the builder hydrated once its nodes reflect the loaded pipe. A
  // saved-canvas pipe waits for the reseed effect above (which sets `hydrated`
  // when it commits); every other case (a brand-new pipe or a legacy pipe with
  // no saved canvas blob) has nothing to reseed, so it is hydrated as soon as
  // the form data has loaded. Gating on `ready` is essential: before the pipe
  // loads the snapshot is still the empty default with no canvas blob, and
  // declaring hydration then would un-gate the page and flash the empty nodes
  // as "invalid" before the saved config lands.
  useEffect(() => {
    if (hydrated || !ready) return;
    const src = pipeForCanvas as {
      route?: string;
      provider?: string;
      canvas?: { nodes?: unknown[] };
    } | null;
    const hasSavedCanvas = !!src?.canvas?.nodes && src.canvas.nodes.length > 0;
    if (hasSavedCanvas) return;
    // A blob-less but already-configured surface (an API/config import such as
    // a testkit pipe) is hydrated by the reseed effect above once it projects
    // the loaded config onto the canvas. Declaring hydration here would un-gate
    // the page on the empty pre-reseed spine and flash it as "invalid".
    if (src?.provider) return;
    setHydrated(true);
  }, [pipeForCanvas, hydrated, ready]);

  // New blank pipes have no saved `canvas` blob, so the reseed effect above
  // never fires — yet the access-point defaults (first listener / first path
  // prefix / random two-word custom path) are seeded into `pipeForCanvas`
  // asynchronously once the routing catalogue loads. Push them onto the live
  // `pipe-source` node so its dropdowns reflect the defaults, then re-baseline
  // the config seams so this one-time seed is not mistaken for a user edit.
  const apSeededRef = useRef(false);
  useEffect(() => {
    if (apSeededRef.current) return;
    const src = pipeForCanvas as
      | {
          listen_address?: string;
          route_prefix?: string;
          custom_path?: string;
          canvas?: { nodes?: unknown[] };
        }
      | null
      | undefined;
    if (!src) return;
    // Saved-canvas pipes are handled by the reseed effect above.
    if (src.canvas?.nodes && src.canvas.nodes.length > 0) return;
    const listen = src.listen_address ?? '';
    const prefix = src.route_prefix ?? '';
    const custom = src.custom_path ?? '';
    // Defaults have not been seeded into the snapshot yet — wait for them.
    if (!listen && !prefix && !custom) return;
    const node = builder.state.nodes.find(n => n.id === 'pipe-source');
    if (!node) return;
    const cfg = (node.config ?? {}) as {
      listen_address?: string;
      prefix?: string;
      custom_path?: string;
    };
    // The node already carries routing (a user edit or an earlier seed) —
    // don't clobber it.
    if (cfg.listen_address || cfg.prefix || cfg.custom_path) {
      apSeededRef.current = true;
      return;
    }
    apSeededRef.current = true;
    builder.handleNodeUpdate('pipe-source', {
      listen_address: listen,
      prefix,
      custom_path: custom,
    });
    setSeedVersion(v => v + 1);
  }, [pipeForCanvas, builder]);

  const nodes = builder.state.nodes;
  useNodeSeam(nodes, readSource, handlers.onSourceChange, seedVersion);
  useNodeSeam(nodes, readUpstream, handlers.onUpstreamChange, seedVersion);
  useNodeSeam(nodes, readRateLimit, handlers.onRateLimitChange, seedVersion);
  useNodeSeam(nodes, readOpaPolicy, handlers.onOpaPolicyChange, seedVersion);
  useNodeSeam(nodes, readPromptGuard, handlers.onPromptGuardChange, seedVersion);
  useNodeSeam(nodes, readJudge, handlers.onJudgeChange, seedVersion);
  useNodeSeam(nodes, readJury, handlers.onJuryChange, seedVersion);
  useNodeSeam(nodes, readDecider, handlers.onDeciderChange, seedVersion);
  useNodeSeam(nodes, readExpertWitnesses, handlers.onExpertWitnessesChange, seedVersion);
  useNodeSeam(nodes, readUsageLimits, handlers.onUsageLimitsChange, seedVersion);

  const [editorNodeId, setEditorNodeId] = useState<string | null>(null);

  // Reseed the builder from a target variant's projected snapshot. Mirrors the
  // post-load reseed effect above, but driven imperatively by a variant switch
  // rather than the one-time load guard. Runs synchronously so the host can
  // flip `activeVariantId` (the canvas remount key) in the same React batch —
  // the remounted canvas then re-seeds its d3 positions from the new
  // `node.position` values and its pan/zoom from the freshly-set view ref.
  const reseedFromCanvas = useCallback(
    (projection: PipeConfigLike) => {
      const reseeded = nodesFromPipe(projection);
      const saved = readCanvasSurfaceSize(projection as Record<string, unknown> | null);
      const view = readCanvasView(projection);
      const settings = readCanvasSettings(projection);
      // eslint-disable-next-line no-console
      console.debug('[pipe-variants] reseedFromCanvas', {
        nodeCount: reseeded.length,
        positions: reseeded
          .filter(n => n.position)
          .map(n => ({ id: n.id, x: n.position?.x, y: n.position?.y })),
        surfaceSize: saved,
        view,
        settings,
      });
      if (canvasViewRef) {
        canvasViewRef.current = view;
      }
      if (canvasSettingsRef) {
        canvasSettingsRef.current = settings ?? { hide_disabled: false };
      }
      builder.setState(prev => ({
        ...prev,
        nodes: reseeded,
        surfaceSize: saved ? { w: saved.width, h: saved.height } : prev.surfaceSize,
        selectedNodeId: null,
      }));
      builder.replaceCommit();
      builder.bumpExternalRevision();
      setSeedVersion(v => v + 1);
    },
    [builder, canvasViewRef, canvasSettingsRef]
  );

  return { builder, editorNodeId, setEditorNodeId, hydrated, reseedFromCanvas };
}
