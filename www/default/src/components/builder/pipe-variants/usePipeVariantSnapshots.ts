import { useCallback, useMemo, useRef, useState } from 'react';
import type { PipeFormData, UpstreamHeaderForm } from '../../../pages/EditPipePage/types';
import {
  applySnapshotToFormData,
  snapshotFromFormData,
  type PipeSnapshot,
} from './pipeVariantSnapshot';

/**
 * Per-variant snapshot manager for the pipe builder — the pipe analogue
 * of the surface `useVariantSnapshots`. Each variant is a full snapshot
 * of the pipe's behavioural form slice; switching a variant swaps that
 * slice into `PipeFormData`, re-rendering the whole canvas for the
 * variant. Identity / routing fields and the catalog itself never live
 * inside a snapshot.
 */

/**
 * Synthetic id for the always-present "base" pseudo-variant — the pipe
 * with no variant overlay. Never appears in the wire `variants[]`.
 */
export const BASE_VARIANT_ID = '__base__';

export interface PipeVariantMeta {
  id: string;
  alias: string;
  name: string;
  description?: string;
  enabled?: boolean;
}

/** Wire shape for one pipe variant catalog entry. */
export interface PipeVariantWire {
  id: string;
  alias: string;
  name: string;
  description?: string;
  enabled?: boolean;
  overrides?: PipeVariantOverridesWire;
}

/**
 * Wire `PipeVariantOverrides` (`src/pipes/pipe_variants.rs`). Built as a
 * frozen snapshot (`complete: true`) so each variant is self-contained
 * and later base edits do not leak in. `pipe_type` carries the resolved
 * upstream; the remaining behavioural fields mirror the backend struct.
 */
export interface PipeVariantOverridesWire {
  complete: boolean;
  pipe_type?: unknown;
  override_policy?: Record<string, string>;
  prompt_guard?: unknown;
  judge?: unknown;
  jury?: unknown;
  rate_limit?: unknown;
  cost_tracking?: unknown;
  upstream_headers?: UpstreamHeaderForm[];
  opa_policy?: unknown;
  realtime?: unknown;
  audio_input?: unknown;
  image_input?: unknown;
  document_ingestion?: unknown;
  canvas?: unknown;
}

/**
 * Adapter the page supplies so the manager can fold a behavioural
 * snapshot into the wire override shape (reusing the same `pipe_type`
 * builder the base pipe uses) and back.
 */
export interface PipeWireAdapter {
  /** Build wire `overrides` for a variant snapshot (frozen, `complete: true`). */
  buildOverrides: (snap: PipeSnapshot) => PipeVariantOverridesWire;
}

function metaEqual(a: PipeVariantMeta[], b: PipeVariantMeta[]): boolean {
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

export interface UsePipeVariantSnapshotsResult {
  variants: PipeVariantMeta[];
  activeVariantId: string | null;
  defaultVariantId: string | null;
  hasVariants: boolean;
  /**
   * Seed the snapshot map from a freshly-loaded pipe. The base snapshot
   * is the bare pipe form; each variant's snapshot is the base overlaid
   * with that variant's already-unfolded form slice. Returns the form
   * the page should render and which variant is active.
   */
  hydrate: (
    baseForm: PipeFormData,
    variantForms: Array<{ meta: PipeVariantMeta; snapshot: PipeSnapshot }>,
    defaultVariantId: string | null,
    opts?: { preserveActiveId?: string | null }
  ) => { activeForm: PipeFormData; activeId: string | null };
  /**
   * Snapshot the current form under the active variant and switch. Returns
   * the form the canvas should now render.
   */
  switchVariant: (newId: string, currentForm: PipeFormData) => PipeFormData;
  /** Replace the in-memory snapshot for a variant from a form. */
  setSnapshot: (variantId: string, form: PipeFormData) => void;
  /** Read the stored snapshot (behavioural slice) for a variant id. */
  getSnapshot: (variantId: string) => PipeSnapshot | undefined;
  /** Promote the supplied catalog (add/remove/rename) + default. */
  setCatalog: (next: { variants: PipeVariantMeta[]; defaultVariantId: string | null }) => void;
  /**
   * Build the wire `variants[]` + `default_variant_id` for save, and the
   * base behavioural slice (so the caller writes base fields from the
   * base snapshot, not from whatever variant is active).
   */
  buildVariantsWireSlice: (activeForm: PipeFormData) => {
    variants: PipeVariantWire[];
    defaultVariantId: string | null;
    baseSnapshot: PipeSnapshot;
  };
  /** Stable signature of snapshots + catalog for dirty tracking. */
  signature: (activeLiveForm?: PipeFormData) => string;
}

export function usePipeVariantSnapshots(adapter: PipeWireAdapter): UsePipeVariantSnapshotsResult {
  const [variants, setVariants] = useState<PipeVariantMeta[]>([]);
  const [defaultVariantId, setDefaultVariantId] = useState<string | null>(null);
  const [activeVariantId, setActiveVariantId] = useState<string | null>(null);
  const snapshotsRef = useRef<Record<string, PipeSnapshot>>({});

  const hydrate = useCallback(
    (
      baseForm: PipeFormData,
      variantForms: Array<{ meta: PipeVariantMeta; snapshot: PipeSnapshot }>,
      nextDefault: string | null,
      opts?: { preserveActiveId?: string | null }
    ): { activeForm: PipeFormData; activeId: string | null } => {
      const snapshots: Record<string, PipeSnapshot> = {};
      snapshots[BASE_VARIANT_ID] = snapshotFromFormData(baseForm);
      const meta: PipeVariantMeta[] = variantForms.map(v => v.meta);
      for (const v of variantForms) {
        snapshots[v.meta.id] = v.snapshot;
      }
      const namedDefault =
        nextDefault && variantForms.some(v => v.meta.id === nextDefault) ? nextDefault : null;
      const preserve = opts?.preserveActiveId;
      const preserved =
        preserve === BASE_VARIANT_ID || (preserve && variantForms.some(v => v.meta.id === preserve))
          ? preserve
          : null;
      const activeId = preserved ?? namedDefault ?? BASE_VARIANT_ID;
      snapshotsRef.current = snapshots;
      setVariants(meta);
      setDefaultVariantId(namedDefault);
      setActiveVariantId(activeId);
      const activeForm = applySnapshotToFormData(baseForm, snapshots[activeId]);
      return { activeForm, activeId };
    },
    []
  );

  const switchVariant = useCallback(
    (newId: string, currentForm: PipeFormData): PipeFormData => {
      if (!activeVariantId || newId === activeVariantId) {
        const snap = snapshotsRef.current[newId];
        return snap ? applySnapshotToFormData(currentForm, snap) : currentForm;
      }
      snapshotsRef.current = {
        ...snapshotsRef.current,
        [activeVariantId]: snapshotFromFormData(currentForm),
      };
      setActiveVariantId(newId);
      const snap = snapshotsRef.current[newId];
      return snap ? applySnapshotToFormData(currentForm, snap) : currentForm;
    },
    [activeVariantId]
  );

  const setSnapshot = useCallback((variantId: string, form: PipeFormData) => {
    snapshotsRef.current = {
      ...snapshotsRef.current,
      [variantId]: snapshotFromFormData(form),
    };
  }, []);

  const getSnapshot = useCallback((variantId: string): PipeSnapshot | undefined => {
    return snapshotsRef.current[variantId];
  }, []);

  const setCatalog = useCallback(
    (next: { variants: PipeVariantMeta[]; defaultVariantId: string | null }) => {
      const ids = new Set(next.variants.map(v => v.id));
      ids.add(BASE_VARIANT_ID);
      const filtered: Record<string, PipeSnapshot> = {};
      for (const [k, v] of Object.entries(snapshotsRef.current)) {
        if (ids.has(k)) filtered[k] = v;
      }
      snapshotsRef.current = filtered;
      setVariants(prev => (metaEqual(prev, next.variants) ? prev : next.variants));
      setDefaultVariantId(prev => (prev === next.defaultVariantId ? prev : next.defaultVariantId));
      setActiveVariantId(prev => {
        if (prev && ids.has(prev)) return prev;
        return next.defaultVariantId ?? BASE_VARIANT_ID;
      });
    },
    []
  );

  const buildVariantsWireSlice = useCallback(
    (
      activeForm: PipeFormData
    ): {
      variants: PipeVariantWire[];
      defaultVariantId: string | null;
      baseSnapshot: PipeSnapshot;
    } => {
      const snapshots: Record<string, PipeSnapshot> =
        activeVariantId !== null
          ? { ...snapshotsRef.current, [activeVariantId]: snapshotFromFormData(activeForm) }
          : snapshotsRef.current;
      const wire: PipeVariantWire[] = variants.map(v => {
        const snapshot = snapshots[v.id];
        return {
          id: v.id,
          alias: v.alias,
          name: v.name,
          ...(v.description ? { description: v.description } : {}),
          enabled: v.enabled !== false,
          overrides: snapshot ? adapter.buildOverrides(snapshot) : { complete: true },
        };
      });
      // `snapshots[BASE]` already resolves to the live form when base is the
      // active variant and to the stored base otherwise, so a non-base active
      // form never leaks onto the base pipe. The `activeForm` fallback is a
      // last resort only when no base snapshot exists at all.
      const baseSnapshot =
        snapshots[BASE_VARIANT_ID] ??
        snapshotsRef.current[BASE_VARIANT_ID] ??
        snapshotFromFormData(activeForm);
      const effectiveDefault =
        defaultVariantId && wire.some(v => v.id === defaultVariantId) ? defaultVariantId : null;
      return { variants: wire, defaultVariantId: effectiveDefault, baseSnapshot };
    },
    [variants, activeVariantId, defaultVariantId, adapter]
  );

  const signature = useCallback(
    (activeLiveForm?: PipeFormData): string => {
      const snapshots: Record<string, PipeSnapshot> =
        activeVariantId && activeLiveForm !== undefined
          ? { ...snapshotsRef.current, [activeVariantId]: snapshotFromFormData(activeLiveForm) }
          : snapshotsRef.current;
      const sorted: Record<string, PipeSnapshot> = {};
      for (const k of Object.keys(snapshots).sort()) {
        sorted[k] = snapshots[k];
      }
      return JSON.stringify({ d: defaultVariantId, v: variants, s: sorted });
    },
    [variants, activeVariantId, defaultVariantId]
  );

  return useMemo(
    () => ({
      variants,
      activeVariantId,
      defaultVariantId,
      hasVariants: variants.length > 0,
      hydrate,
      switchVariant,
      setSnapshot,
      getSnapshot,
      setCatalog,
      buildVariantsWireSlice,
      signature,
    }),
    [
      variants,
      activeVariantId,
      defaultVariantId,
      hydrate,
      switchVariant,
      setSnapshot,
      getSnapshot,
      setCatalog,
      buildVariantsWireSlice,
      signature,
    ]
  );
}
