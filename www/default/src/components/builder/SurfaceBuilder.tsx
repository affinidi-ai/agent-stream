import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import SurfaceCanvas, { type CanvasNode } from './SurfaceCanvas';
import NodeConfigPanel from './NodeConfigPanel';
import MultiSelectionPanel from './MultiSelectionPanel';
import SurfaceVariantsWidget from './SurfaceVariantsWidget';
import { RouteListenerBanner } from './elements/_shared/RouteListenerSection';
import type { UseSurfaceBuilderReturn, SurfaceBuilderState } from './hooks/useSurfaceBuilder';
import {
  synthesizeFabricCanvasNodes,
  resolveSyntheticNameBinding,
} from './elements/synthesizeFabric';
import { registry } from './elements/registry';
import type { BuilderScope, SurfaceContextSurfaceRef } from './elements/types';
import { usePipePanelData } from './elements/pipe/pipePanelData';
import { useIdePanelData } from './elements/ide/idePanelData';
import { serializePipeTemplate } from './pipe-templates/serializePipeTemplate';
import { showToast } from '../../utils/toaster';
import '../../pages/SurfaceBuilder.css';

interface SurfaceBuilderProps<T extends SurfaceBuilderState> {
  builder: UseSurfaceBuilderReturn<T>;
  surfaceName: string;
  protocol: string;
  /**
   * Authoring scope. `'surface'` (default) renders the full A2A surface
   * chrome (variants widget, surface-properties cog). `'pipe'` hides the
   * surface-only affordances so the same body manages a pipe.
   */
  scope?: BuilderScope;
  /** When true, the panel doesn't render itself when no node is selected. */
  hidePaletteWhenNoSelection?: boolean;
  onOpenFullscreenEditor?: (nodeId: string) => void;
  /**
   * Shared mutable ref tracking the resizable surface rectangle
   * dimensions. When provided, the canvas hydrates from and writes back
   * to it so the page can persist the size in the canvas blob.
   */
  surfaceSizeRef?: React.MutableRefObject<{ w: number; h: number } | null>;
  /**
   * Shared mutable ref tracking the d3 zoom transform (pan + scale).
   * When provided, the canvas hydrates from and writes back to it so
   * the page can persist the view in the canvas blob.
   */
  canvasViewRef?: React.MutableRefObject<{ x: number; y: number; k: number } | null>;
  /**
   * Shared mutable ref tracking per-canvas view preferences (currently
   * the `hide_disabled` toolbar toggle). When provided, the builder
   * writes back to it on each toggle so the page can persist the
   * setting in the canvas blob.
   */
  canvasSettingsRef?: React.MutableRefObject<{ hide_disabled: boolean } | null>;
  /**
   * Initial value for the hide-disabled toolbar toggle, read from the
   * loaded canvas blob by the parent page. Re-applied via effect on
   * change so a variant switch reseeds the preference.
   */
  initialHideDisabled?: boolean;
  /**
   * Currently active variant id (when the page hosts a variant
   * snapshot manager). When omitted, the variants widget acts as a
   * plain "open editor" affordance.
   */
  activeVariantId?: string | null;
  /**
   * Switch active variant. The variants widget invokes this when the
   * user picks an entry from its dropdown; the page is responsible for
   * swapping the canvas state via the snapshot manager.
   */
  onSwitchVariant?: (variantId: string) => void;
  /**
   * Open the variants editor AND seed a new variant entry. The widget
   * invokes this from its zero-state "+" affordance and from the
   * dropdown's "Add variant…" item.
   */
  onAddVariant?: () => void;
  /**
   * Called when the user clicks "Create Template from Selection" in
   * the multi-selection panel. Receives the current selected node ids
   * so the shell can build a partial-template seed and switch to the
   * Templates view in create mode.
   */
  onCreateTemplateFromSelection?: (selectedIds: string[]) => void;
  /**
   * Overlay pinned to the top-left of the canvas. Used by non-surface
   * scopes (e.g. the pipe editor) to host their own variants widget in
   * the same slot the surface variants widget occupies.
   */
  topLeftSlot?: React.ReactNode;
}

/**
 * The shared "palette + canvas + sidebar" body used by both the create
 * wizard and the surface detail page. Layout and styling come from
 * `SurfaceBuilder.css`'s `.surface-builder` class — height is computed
 * relative to the viewport so it always fills the available area.
 */
export function SurfaceBuilder<T extends SurfaceBuilderState>({
  builder,
  surfaceName,
  protocol,
  scope = 'surface',
  onOpenFullscreenEditor,
  surfaceSizeRef,
  canvasViewRef,
  canvasSettingsRef,
  initialHideDisabled,
  activeVariantId,
  onSwitchVariant,
  onAddVariant,
  onCreateTemplateFromSelection,
  topLeftSlot,
}: SurfaceBuilderProps<T>) {
  const isSurfaceScope = scope === 'surface';
  // Pipe-scoped builders are wrapped in a `PipePanelDataProvider`; surface
  // builders are not, so this resolves to the empty catalogue there. The
  // canvas only uses it for provider-aware fault checks (e.g. a juror
  // missing its required API key), which are pipe-only concerns.
  const { llmProviders: pipeLlmProviders } = usePipePanelData();
  // IDE-scoped builders are wrapped in an `IdePanelDataProvider` carrying the
  // live LLM-Surface list a catalogue member may reference. Threading it as the
  // canvas's `availableSurfaces` registry lets a member/catalogue draw the
  // marching-ants ring when its linked surface no longer exists. Resolves to
  // the empty catalogue (and thus `undefined` here) outside IDE scope, keeping
  // the generic builder free of cross-surface knowledge for other scopes.
  const { memberPipes: ideMemberPipes } = useIdePanelData();
  const availableSurfaces = useMemo<SurfaceContextSurfaceRef[] | undefined>(
    () =>
      scope === 'ide'
        ? ideMemberPipes.map(p => ({ id: p.id, type: 'llm-surface', name: p.name }))
        : undefined,
    [scope, ideMemberPipes]
  );
  const {
    state,
    commit,
    replaceCommit,
    selectedNode,
    handleDrop,
    handleNodeClick,
    handleNodeUpdate,
    handleNodeAdd,
    handleNodeRemove,
    handleNodeMove,
    handleSystemNodeMove,
    handleNodeResize,
    handleSurfaceResize,
    handleAutoLayout,
    handleUndo,
    handleRedo,
    canUndo,
    canRedo,
    handleCloseConfig,
    externalRevision,
    resetViewRev,
    setMultiSelection,
    multiSelectedIds,
  } = builder;

  // Snap-to-grid mode toggle. When on, node drags quantise to a fixed
  // grid; the shift modifier inverts behavior (held = free movement).
  // When off, drags are free and shift forces quantisation.
  const [gridSnap, setGridSnap] = useState(false);

  // Hide-disabled mode toggle. When on, muted nodes (opt-in middleware
  // like an unused Judge/Jury/prompt-guard) are removed from the render
  // and from auto-layout so the canvas presents cleanly. Seeded from
  // the parent's `initialHideDisabled` prop (populated from the loaded
  // canvas blob's `settings.hide_disabled`) and mirrored back onto
  // `canvasSettingsRef` so the parent can persist the setting on save.
  const [hideDisabled, setHideDisabled] = useState<boolean>(!!initialHideDisabled);
  useEffect(() => {
    setHideDisabled(!!initialHideDisabled);
  }, [initialHideDisabled]);
  useEffect(() => {
    if (canvasSettingsRef) {
      canvasSettingsRef.current = { hide_disabled: hideDisabled };
    }
  }, [hideDisabled, canvasSettingsRef]);
  const mutedFilter = useCallback(
    (n: { type: string; config?: any }) => !registry.isMuted(n.type, n.config),
    []
  );
  const handleAutoLayoutClick = useCallback(() => {
    if (hideDisabled) {
      handleAutoLayout(mutedFilter);
    } else {
      handleAutoLayout();
    }
  }, [handleAutoLayout, hideDisabled, mutedFilter]);
  const handleHideDisabledToggle = useCallback(() => {
    const next = !hideDisabled;
    setHideDisabled(next);
    if (canvasSettingsRef) {
      canvasSettingsRef.current = { hide_disabled: next };
    }
    // Re-run auto-layout so the surface reflows around the new visible set:
    // switching ON tightens the surface around non-muted nodes (AP/Response
    // re-align on the shortened chain, edge middleware re-projects onto the
    // fresh request edge), and switching OFF restores the full canonical
    // layout for every node. Excluded nodes keep their positions inside
    // `handleAutoLayout`, so hidden middleware isn't moved.
    if (next) {
      handleAutoLayout(mutedFilter);
    } else {
      handleAutoLayout();
    }
  }, [hideDisabled, canvasSettingsRef, handleAutoLayout, mutedFilter]);

  // Ctrl/Cmd+Shift+X copies the selected pipe elements to the clipboard as a
  // partial-template JSON — a quick, disk-free "capture selection" (LLM only).
  useEffect(() => {
    if (scope !== 'pipe') return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (!e.shiftKey || !(e.ctrlKey || e.metaKey) || (e.key !== 'X' && e.key !== 'x')) return;
      const el = e.target as HTMLElement | null;
      if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable))
        return;
      if (multiSelectedIds.length === 0) return;
      e.preventDefault();
      const items = serializePipeTemplate(state.nodes, { nodeIds: multiSelectedIds });
      if (items.length === 0) {
        showToast('error', 'None of the selected elements can be captured to a template.');
        return;
      }
      navigator.clipboard
        .writeText(JSON.stringify(items, null, 2))
        .then(() =>
          showToast(
            'success',
            `Copied ${items.length} element${items.length === 1 ? '' : 's'} to the clipboard.`
          )
        )
        .catch(() => showToast('error', 'Could not copy to the clipboard.'));
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [scope, multiSelectedIds, state.nodes]);

  // Inject the synthesised `local-gateway-hop → remote-gateway`
  // chain for every Target whose endpoint is a fabric:// URL.
  // The transformation is purely view-side and never enters
  // `state.nodes`, so persistence and edit gestures are unaffected.
  // We also drop the singleton `target-variant` node — it is the
  // surface-wide variants config carrier and the dedicated top-left
  // widget is its only entry point.
  //
  // Project the user-entered `config.name` onto `node.label` so a
  // rename in the properties panel is reflected on the canvas. The
  // original element-type label is kept as a fallback when no name
  // has been entered. This is purely view-side; persistence still
  // reads `config.name` from the source node.
  const displayNodes = useMemo(() => {
    const withoutVariants = state.nodes.filter(n => n.type !== 'target-variant');
    // When hiding disabled elements, drop muted spine/decoration nodes AND
    // chain-collapse `parentId` through any muted ancestor so the spine stays
    // walkable — e.g. hiding `pipe-judge` re-parents `pipe-upstream` onto
    // `pipe-prompt-guard-request`. Without this, downstream edge derivation
    // (`deriveEdges` and the SurfaceCanvas spine loop) emits links whose
    // source/target references a now-missing node, and `d3.forceLink().id(...)`
    // throws.
    let filtered = withoutVariants;
    if (hideDisabled) {
      const byId = new Map<string, CanvasNode>();
      for (const n of withoutVariants) byId.set(n.id, n);
      const mutedIds = new Set<string>();
      for (const n of withoutVariants) {
        if (registry.isMuted(n.type, n.config)) mutedIds.add(n.id);
      }
      const resolveParent = (pid: string | undefined): string | undefined => {
        let cur = pid;
        const seen = new Set<string>();
        while (cur && mutedIds.has(cur) && !seen.has(cur)) {
          seen.add(cur);
          cur = byId.get(cur)?.parentId;
        }
        return cur;
      };
      filtered = withoutVariants
        .filter(n => !mutedIds.has(n.id))
        .map(n => (n.parentId ? { ...n, parentId: resolveParent(n.parentId) } : n));
    }
    return synthesizeFabricCanvasNodes(filtered, state.surfaceSize).map(n => {
      const userName = typeof n.config?.name === 'string' ? (n.config.name as string).trim() : '';
      if (userName) return { ...n, label: userName };
      if (!n.label) return { ...n, label: registry.get(n.type)?.label ?? n.type };
      return n;
    });
  }, [state.nodes, state.surfaceSize, hideDisabled]);

  const accessPointUrl = useMemo(() => {
    const ap = state.nodes.find(n => n.type === 'access-point');
    if (ap) {
      const listen = ap.config?.listen_address;
      const route = ap.config?.route;
      return listen && route ? `${listen}${route}` : '';
    }
    // Pipe / IDE scope: the access point is a `pipe-source` / `ide-source`
    // node whose route is composed from the path prefix + custom path
    // (mirrors the surface AP).
    const src = state.nodes.find(n => n.type === 'pipe-source' || n.type === 'ide-source');
    if (src) {
      const listen =
        typeof src.config?.listen_address === 'string' ? src.config.listen_address : '';
      const prefix = typeof src.config?.prefix === 'string' ? src.config.prefix : '';
      const customPath = typeof src.config?.custom_path === 'string' ? src.config.custom_path : '';
      const normalized = customPath.startsWith('/') ? customPath.slice(1) : customPath;
      return listen && prefix && normalized ? `${listen}${prefix}/${normalized}` : '';
    }
    return '';
  }, [state.nodes]);

  // Clicking a synthesised node (`local-gateway-hop`, `remote-gateway`,
  // `remote-channel`) opens the same right-hand properties panel as
  // every other element. The synth nodes themselves are not in
  // `state.nodes`, so we resolve the click against `displayNodes`
  // and pass the synthesised CanvasNode through to the panel below
  // (via `synthSelectedNode`). Writes to `config.name` are intercepted
  // and persisted on the underlying parent target so the rename
  // survives across renders.
  const handleSynthAwareNodeClick = useCallback(
    (nodeId: string) => {
      handleNodeClick(nodeId);
    },
    [handleNodeClick]
  );

  // When the panel issues an update for a synth node, redirect the
  // write to the corresponding parent `config` field so the rename
  // persists in `state.nodes`. Non-synth updates fall through to the
  // standard handler unchanged. Used by the wired `NodeConfigPanel`
  // below in place of `handleNodeUpdate`.
  const handleSynthAwareNodeUpdate = useCallback(
    (nodeId: string, config: any) => {
      const binding = resolveSyntheticNameBinding(nodeId);
      if (!binding) {
        handleNodeUpdate(nodeId, config);
        return;
      }
      const parent = state.nodes.find(n => n.id === binding.parentId);
      if (!parent) return;
      const newName = typeof config?.name === 'string' ? config.name : '';
      handleNodeUpdate(binding.parentId, {
        ...(parent.config ?? {}),
        [binding.field]: newName,
      });
    },
    [handleNodeUpdate, state.nodes]
  );

  // Removal is disabled for synth nodes (`deletable: false` on each
  // definition hides the panel's delete affordance), but guard the
  // remove path anyway to be safe against keyboard/context-menu
  // gestures that might bypass the panel.
  const handleSynthAwareNodeRemove = useCallback(
    (nodeId: string) => {
      if (resolveSyntheticNameBinding(nodeId)) return;
      handleNodeRemove(nodeId);
    },
    [handleNodeRemove]
  );

  // Resolve the selected node, falling back to the synthesised list
  // so synth nodes can drive the properties panel like any other
  // element. The hook's own `selectedNode` only knows about
  // `state.nodes`, which by design excludes the synth chain.
  const effectiveSelectedNode = useMemo(() => {
    if (selectedNode) return selectedNode;
    const id = state.selectedNodeId;
    if (!id || !resolveSyntheticNameBinding(id)) return selectedNode;
    return displayNodes.find(n => n.id === id) ?? null;
  }, [selectedNode, state.selectedNodeId, displayNodes]);

  const exportPngRef = useRef<(() => void) | null>(null);
  const resetViewRef = useRef<(() => void) | null>(null);

  return (
    <div className="surface-builder">
      <SurfaceCanvas
        // Remount on variant switch so the internal positionsRef and
        // d3-zoom DOM transform reset and re-seed from the incoming
        // variant's saved positions / canvas.view. Without this the
        // prior variant's layout state persists and overwrites the
        // new variant's snapshot on first render, flipping dirty on
        // a pure variant switch (no user edits).
        key={activeVariantId ?? '__base__'}
        surfaceName={surfaceName}
        protocol={protocol}
        nodes={displayNodes}
        llmProviders={pipeLlmProviders}
        availableSurfaces={availableSurfaces}
        onNodeClick={handleSynthAwareNodeClick}
        onCanvasClick={handleCloseConfig}
        onDrop={handleDrop}
        onNodeMove={handleNodeMove}
        onSystemNodeMove={handleSystemNodeMove}
        onNodeResize={handleNodeResize}
        onMultiSelectionChange={setMultiSelection}
        multiSelectedIds={multiSelectedIds}
        selectedNodeId={state.selectedNodeId}
        externalRevision={externalRevision}
        resetViewRev={resetViewRev}
        surfaceSizeRef={surfaceSizeRef}
        surfaceSize={state.surfaceSize}
        onSurfaceResize={handleSurfaceResize}
        canvasViewRef={canvasViewRef}
        gridSnap={gridSnap}
        exportPngRef={exportPngRef}
        resetViewRef={resetViewRef}
      />
      {isSurfaceScope && (
        <SurfaceVariantsWidget
          nodes={state.nodes}
          selected={state.selectedNodeId === 'target-variant'}
          onOpen={() => handleNodeClick('target-variant')}
          activeVariantId={activeVariantId}
          onSwitchVariant={onSwitchVariant}
          onAddVariant={onAddVariant}
        />
      )}
      {!isSurfaceScope && topLeftSlot}
      {accessPointUrl && (
        <div className="surface-access-point-url-widget">
          <RouteListenerBanner label="Access Point" url={accessPointUrl} />
        </div>
      )}
      <div className="surface-toolbar-widget">
        <button
          type="button"
          className="surface-toolbar-btn"
          onClick={handleUndo}
          disabled={!canUndo}
          title="Undo (⌘Z / Ctrl+Z)"
          aria-label="Undo"
        >
          <i className="fas fa-undo" />
        </button>
        <button
          type="button"
          className="surface-toolbar-btn"
          onClick={handleRedo}
          disabled={!canRedo}
          title="Redo (⇧⌘Z / Ctrl+Shift+Z / Ctrl+Y)"
          aria-label="Redo"
        >
          <i className="fas fa-redo" />
        </button>
        <button
          type="button"
          className={`surface-toolbar-btn${gridSnap ? ' active' : ''}`}
          onClick={() => setGridSnap(g => !g)}
          title={
            gridSnap
              ? 'Snap to grid: on (hold Shift to move freely)'
              : 'Snap to grid: off (hold Shift to snap)'
          }
          aria-label="Toggle snap to grid"
          aria-pressed={gridSnap}
        >
          <i className="fas fa-border-all" />
        </button>
        <button
          type="button"
          className={`surface-toolbar-btn${hideDisabled ? ' active' : ''}`}
          onClick={handleHideDisabledToggle}
          title={
            hideDisabled
              ? 'Show all elements (including disabled)'
              : 'Hide disabled elements from the canvas'
          }
          aria-label="Toggle hide disabled elements"
          aria-pressed={hideDisabled}
        >
          <i className={`fas ${hideDisabled ? 'fa-eye-slash' : 'fa-eye'}`} />
        </button>
        <button
          type="button"
          className="surface-toolbar-btn"
          onClick={() => exportPngRef.current?.()}
          title="Download canvas as PNG"
          aria-label="Download canvas as PNG"
        >
          <i className="fas fa-camera" />
        </button>
        <button
          type="button"
          className="surface-toolbar-btn"
          onClick={handleAutoLayoutClick}
          title="Auto-layout (⌘L / Ctrl+L)"
          aria-label="Auto-layout"
        >
          <i className="fas fa-up-down-left-right" />
        </button>
        <button
          type="button"
          className="surface-toolbar-btn"
          onClick={() => resetViewRef.current?.()}
          title="Reset pan & zoom"
          aria-label="Reset pan and zoom"
        >
          <i className="fas fa-crosshairs" />
        </button>
        {(isSurfaceScope || scope === 'pipe' || scope === 'ide') && (
          <button
            type="button"
            className="surface-toolbar-btn"
            onClick={() => handleNodeClick('__surface__')}
            title={isSurfaceScope ? 'Surface properties' : 'Surface settings'}
            aria-label={isSurfaceScope ? 'Surface properties' : 'Surface settings'}
          >
            <i className="fas fa-cog" />
          </button>
        )}
      </div>
      <div onBlur={commit}>
        {multiSelectedIds.length >= 2 ? (
          <MultiSelectionPanel
            selectedIds={multiSelectedIds}
            allNodes={displayNodes}
            setSelection={setMultiSelection}
            onCreateTemplate={onCreateTemplateFromSelection}
            onClose={() => setMultiSelection([])}
          />
        ) : (
          <NodeConfigPanel
            node={effectiveSelectedNode}
            onUpdate={handleSynthAwareNodeUpdate}
            onRemove={handleSynthAwareNodeRemove}
            onClose={handleCloseConfig}
            onOpenFullscreenEditor={onOpenFullscreenEditor}
            protocol={protocol}
            allNodes={state.nodes}
            externalRevision={externalRevision}
            replaceCommit={replaceCommit}
            onAddNode={handleNodeAdd}
            onUpdateNodeConfig={handleNodeUpdate}
            onAutoLayout={handleAutoLayoutClick}
            onSelectNode={handleNodeClick}
          />
        )}
      </div>
    </div>
  );
}

export default SurfaceBuilder;
