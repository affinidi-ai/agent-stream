import { useCallback, useMemo, useRef, useState } from 'react';
import {
  computeOverridesFromPayload,
  resolveVariant,
  type VariantEntryWire,
  type SurfaceOverrides,
} from './resolve';

/**
 * Synthetic id used for the always-present "base" pseudo-variant. The
 * base represents the surface as it stands with no variant overlay
 * applied — when it is the active variant the canvas reflects the
 * unmodified surface; when it is the default (i.e. the surface has
 * `default_variant_id = null`) the runtime resolves alias-less URLs
 * to the bare surface.
 *
 * Never appears in the wire `variants[]` catalog — it's a UI-only
 * affordance. The snapshot map always carries an entry under this id
 * so switching to/from base is symmetric with named variants.
 */
export const BASE_VARIANT_ID = '__base__';

export interface VariantMeta {
  id: string;
  alias: string;
  name: string;
  description?: string;
  enabled?: boolean;
}

/**
 * Shallow value-equality on the variant catalog. Used to short-circuit
 * `setCatalog` when the upstream node-config mirror effect re-fires
 * with the same data — without this, every render of the page would
 * re-trigger `setVariants` and pump-loop the effect.
 */
function variantsEqual(a: VariantMeta[], b: VariantMeta[]): boolean {
  if (a === b) return true;
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    const x = a[i];
    const y = b[i];
    if (
      x.id !== y.id ||
      x.alias !== y.alias ||
      x.name !== y.name ||
      x.description !== y.description ||
      (x.enabled !== false) !== (y.enabled !== false)
    ) {
      return false;
    }
  }
  return true;
}

export interface UseVariantSnapshotsResult {
  /** Ordered list of variants currently known to the page. */
  variants: VariantMeta[];
  /** Currently active variant id (the one rendered on the canvas). */
  activeVariantId: string | null;
  /** Default variant id — the one addressed by the unmarked URL. */
  defaultVariantId: string | null;
  /** True iff there is at least one variant registered. */
  hasVariants: boolean;
  /**
   * Hydrate the snapshots map from a freshly-loaded surface payload.
   * Resolves each variant's overrides against the payload's base shape
   * and stores the result keyed by variant id.
   *
   * `opts.preserveActiveId` keeps the supplied id active when it still
   * resolves to a known variant (or to base) in the new payload. This
   * is what the page passes after a successful save so the canvas
   * stays on the user's current variant instead of snapping back to
   * the default. When omitted (or unresolvable), the active id falls
   * back to the surface's named default, then to base.
   */
  hydrateFromPayload: (
    payload: any,
    opts?: { preserveActiveId?: string | null }
  ) => { activePayload: any; activeId: string | null };
  /**
   * Snapshot the current active variant's payload (computed from the
   * canvas) and switch the active variant. Returns the payload that the
   * caller should use to rehydrate the canvas.
   */
  switchVariant: (newId: string, currentPayload: any) => any;
  /**
   * Replace the in-memory snapshot for a variant. Called by the page
   * whenever the active variant's canvas state changes (typically right
   * before save, or when the user manually re-snapshots).
   */
  setSnapshot: (variantId: string, payload: any) => void;
  /**
   * Promote the supplied list to be the canonical variant catalog
   * (e.g. user added/removed/renamed variants in the editor panel).
   * The default variant id is also updated.
   */
  setCatalog: (next: { variants: VariantMeta[]; defaultVariantId: string | null }) => void;
  /**
   * Build the wire-shape `variants[]` slice for save:
   *   - Default variant: identity-only entry with empty overrides.
   *   - Other variants: identity + `overrides` derived from their
   *     snapshot via `computeOverridesFromPayload`.
   *
   * `currentPayload` is treated as the active variant's latest state
   * (so the caller doesn't have to call `setSnapshot` first). The
   * returned `basePayload` is the default variant's snapshot — the
   * caller should use this as the base AgentSurface fields and merge
   * the returned `variants[]` + `defaultVariantId` on top.
   */
  buildVariantsWireSlice: (activePayload: any) => {
    variants: VariantEntryWire[];
    defaultVariantId: string | null;
    basePayload: any;
  };
  /**
   * Stable serialisable signature of all snapshots + catalog — used for
   * dirty tracking. Excludes `activeVariantId` because switching the
   * active variant must not, by itself, mark the form as dirty. Pass
   * `activeLivePayload` to splice the live (unsnapshotted) active
   * variant state into the map under its id, so in-progress edits on
   * the active variant register as dirty.
   */
  signature: (activeLivePayload?: any) => string;
  /**
   * Read the in-memory snapshot for a variant id. Used by the page to
   * re-render the canvas when `activeVariantId` is reassigned by
   * `setCatalog` (e.g. the user deleted the active variant in the
   * editor panel) — the page can't intercept that reassignment, so it
   * needs a way to fetch the new active variant's payload after the
   * fact and feed it back into the canvas state.
   */
  getSnapshot: (variantId: string) => any | undefined;
}

/**
 * Per-variant canvas snapshot manager. Each variant has a complete
 * resolved-payload snapshot in memory; switching variants swaps the
 * canvas state by handing the page a fresh payload to feed into
 * `setState`.
 *
 * The page keeps `activeVariantId` and the snapshots map in sync with
 * the variants editor (target-variant panel) — when the user adds or
 * removes a variant there, `setCatalog` is called to register/drop
 * snapshots.
 */
export function useVariantSnapshots(): UseVariantSnapshotsResult {
  const [variants, setVariants] = useState<VariantMeta[]>([]);
  const [defaultVariantId, setDefaultVariantId] = useState<string | null>(null);
  const [activeVariantId, setActiveVariantId] = useState<string | null>(null);
  const snapshotsRef = useRef<Record<string, any>>({});

  const hydrateFromPayload = useCallback(
    (
      payload: any,
      opts?: { preserveActiveId?: string | null }
    ): { activePayload: any; activeId: string | null } => {
      const list: VariantEntryWire[] = Array.isArray(payload?.variants) ? payload.variants : [];
      // Snapshot map: each variant's resolved payload, plus an
      // always-present base snapshot derived from the bare surface
      // (variants/default stripped). The base snapshot is what the
      // canvas shows when the user picks the "base" entry from the
      // widget; its contents are also what the wire `basePayload`
      // sends back on save.
      const snapshots: Record<string, any> = {};
      snapshots[BASE_VARIANT_ID] = resolveVariant(payload, {});
      const meta: VariantMeta[] = list.map(v => ({
        id: v.id,
        alias: v.alias,
        name: v.name,
        description: typeof v.description === 'string' ? v.description : undefined,
        enabled: v.enabled !== false,
      }));
      for (const v of list) {
        snapshots[v.id] = resolveVariant(payload, (v.overrides ?? {}) as SurfaceOverrides);
      }
      // Default variant id: the named one if the wire pins it, else
      // null (which means "base is the default").
      const namedDefault =
        typeof payload?.default_variant_id === 'string' &&
        list.some(v => v.id === payload.default_variant_id)
          ? payload.default_variant_id
          : null;
      // Active id: prefer the caller-supplied `preserveActiveId` when
      // it still resolves to a known variant in the new payload
      // (this is how a post-save re-hydrate keeps the user on their
      // current variant). Fall back to the named default, then to
      // base.
      const preserve = opts?.preserveActiveId;
      const preserved =
        preserve === BASE_VARIANT_ID || (preserve && list.some(v => v.id === preserve))
          ? preserve
          : null;
      const activeId = preserved ?? namedDefault ?? BASE_VARIANT_ID;
      snapshotsRef.current = snapshots;
      setVariants(meta);
      setDefaultVariantId(namedDefault);
      setActiveVariantId(activeId);
      const activePayload = snapshots[activeId];
      return { activePayload, activeId };
    },
    []
  );

  const switchVariant = useCallback(
    (newId: string, currentPayload: any): any => {
      if (!activeVariantId || newId === activeVariantId) {
        return snapshotsRef.current[newId] ?? currentPayload;
      }
      // Snapshot what's on the canvas right now under the OLD active id.
      // Strip surface-level catalog fields (`variants[]` /
      // `default_variant_id`) before storing — those belong to the
      // surface, not to a variant snapshot. Keeping them would let a
      // stale catalog leak back into the canvas the next time we
      // rebuild from this snapshot (e.g. resurrecting a variant the
      // user just deleted).
      snapshotsRef.current = {
        ...snapshotsRef.current,
        [activeVariantId]: resolveVariant(currentPayload, {}),
      };
      setActiveVariantId(newId);
      return snapshotsRef.current[newId] ?? currentPayload;
    },
    [activeVariantId]
  );

  const setSnapshot = useCallback((variantId: string, payload: any) => {
    snapshotsRef.current = {
      ...snapshotsRef.current,
      [variantId]: resolveVariant(payload, {}),
    };
  }, []);

  const getSnapshot = useCallback((variantId: string): any | undefined => {
    return snapshotsRef.current[variantId];
  }, []);

  const setCatalog = useCallback(
    (next: { variants: VariantMeta[]; defaultVariantId: string | null }) => {
      // Drop snapshots for variants no longer in the catalog. The
      // base snapshot is always preserved — it is not a member of
      // `next.variants` (base is implicit, never named) but it must
      // survive every catalog edit.
      const ids = new Set(next.variants.map(v => v.id));
      ids.add(BASE_VARIANT_ID);
      const filtered: Record<string, any> = {};
      for (const [k, v] of Object.entries(snapshotsRef.current)) {
        if (ids.has(k)) filtered[k] = v;
      }
      snapshotsRef.current = filtered;
      // Bail when nothing actually changed — otherwise React still
      // schedules a no-op re-render which re-runs any effect that
      // depends on `variants` / `activeVariantId` and causes a
      // pump-loop with the page's catalog-mirror useEffect.
      setVariants(prev => (variantsEqual(prev, next.variants) ? prev : next.variants));
      setDefaultVariantId(prev => (prev === next.defaultVariantId ? prev : next.defaultVariantId));
      setActiveVariantId(prev => {
        // Keep the current selection if it's still valid (named
        // variants live in `ids`; base is always valid). Fall back
        // to the new default, or to base when no named default is
        // marked — base is the implicit default in that case.
        if (prev && ids.has(prev)) return prev;
        return next.defaultVariantId ?? BASE_VARIANT_ID;
      });
    },
    []
  );

  const buildVariantsWireSlice = useCallback(
    (
      activePayload: any
    ): {
      variants: VariantEntryWire[];
      defaultVariantId: string | null;
      basePayload: any;
    } => {
      // Always re-snapshot the active variant from the live canvas
      // payload so the wire output reflects the latest edits.
      const snapshots: Record<string, any> =
        activeVariantId !== null
          ? { ...snapshotsRef.current, [activeVariantId]: activePayload }
          : snapshotsRef.current;
      // Every named variant projects its snapshot as a full overrides
      // delta against the base. There is no "identity-only default"
      // shortcut anymore — the named default's overrides live on top
      // of the bare base payload, exactly like every other variant.
      const wire: VariantEntryWire[] = variants.map(v => {
        const snapshot = snapshots[v.id];
        return {
          id: v.id,
          alias: v.alias,
          name: v.name,
          ...(v.description ? { description: v.description } : {}),
          enabled: v.enabled !== false,
          overrides: snapshot ? computeOverridesFromPayload(snapshot) : {},
        };
      });
      // Base payload for the wire surface = the always-present base
      // snapshot. The named default variant (if any) is resolved on
      // top of this base by the backend at request time. Falls back
      // to the active payload only as a defence-in-depth when the
      // base snapshot is somehow missing.
      const basePayload = snapshots[BASE_VARIANT_ID] ?? activePayload;
      // Backend allows `default_variant_id = null` even when variants[]
      // is non-empty — semantics: alias-less URLs resolve to the bare
      // base surface (no overrides applied). Only validate that, when
      // set, the id matches an existing variant; drop a stale id
      // rather than picking an arbitrary fallback (which would silently
      // apply that variant's overrides to base traffic).
      const effectiveDefault =
        defaultVariantId && wire.some(v => v.id === defaultVariantId) ? defaultVariantId : null;
      return { variants: wire, defaultVariantId: effectiveDefault, basePayload };
    },
    [variants, activeVariantId, defaultVariantId]
  );

  const signature = useCallback(
    (activeLivePayload?: any): string => {
      // Splice the live active payload into the snapshot map so
      // unsaved edits on the active variant flip dirty state. Without
      // this, edits between switches would go undetected because
      // `snapshotsRef.current[active]` only refreshes on switch/save.
      const snapshots =
        activeVariantId && activeLivePayload !== undefined
          ? { ...snapshotsRef.current, [activeVariantId]: activeLivePayload }
          : snapshotsRef.current;
      // The `target-variant` canvas node is a UI-only mirror of
      // `target.config.variants`. Per-variant `overrides.canvas`
      // blobs capture its state at snapshot time and go stale when
      // the user later renames/reorders variants — but the live
      // canvas keeps it in sync via the catalog mirror, so the stale
      // copy in the snapshot would flip dirty on every save+reload.
      // Strip it from every snapshot's canvas so the signature only
      // tracks data that is actually a source of truth.
      //
      // Also strip top-level `variants`, `default_variant_id`, and
      // `surface_id`: `switchVariant` stores snapshots via
      // `resolveVariant(payload, {})` which deletes the first two,
      // and the live splice's `buildPayload` omits `surface_id` (the
      // page adds it only at save time). The catalog identity is
      // already tracked separately via the signature's top-level
      // `v` (variants) and `d` (defaultVariantId) fields, so dropping
      // them from each snapshot entry removes a purely cosmetic
      // asymmetry between freshly-loaded and switch-rewritten slots.
      const normalize = (snap: any): any => {
        if (!snap || typeof snap !== 'object') return snap;
        const out: any = { ...snap };
        delete out.variants;
        delete out.default_variant_id;
        delete out.surface_id;
        const canvas = out.canvas;
        if (canvas && Array.isArray(canvas.nodes)) {
          const nodes = canvas.nodes.filter((n: any) => n?.id !== 'target-variant');
          if (nodes.length !== canvas.nodes.length) {
            out.canvas = { ...canvas, nodes };
          }
        }
        return out;
      };
      // Sort keys so insertion order (which differs between hydrate
      // and live-splice) doesn't produce false-positive dirty flips.
      const sortedSnapshots: Record<string, any> = {};
      for (const k of Object.keys(snapshots).sort()) {
        sortedSnapshots[k] = normalize(snapshots[k]);
      }
      // NOTE: `activeVariantId` is intentionally NOT in the signature
      // — switching variants alone must not mark the form dirty.
      return JSON.stringify({
        d: defaultVariantId,
        v: variants,
        s: sortedSnapshots,
      });
    },
    [variants, activeVariantId, defaultVariantId]
  );

  return useMemo(
    () => ({
      variants,
      activeVariantId,
      defaultVariantId,
      hasVariants: variants.length > 0,
      hydrateFromPayload,
      switchVariant,
      setSnapshot,
      setCatalog,
      buildVariantsWireSlice,
      signature,
      getSnapshot,
    }),
    [
      variants,
      activeVariantId,
      defaultVariantId,
      hydrateFromPayload,
      switchVariant,
      setSnapshot,
      setCatalog,
      buildVariantsWireSlice,
      signature,
      getSnapshot,
    ]
  );
}
