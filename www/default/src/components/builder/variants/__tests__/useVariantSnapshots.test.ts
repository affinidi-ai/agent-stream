import { act, renderHook } from '@testing-library/react';
import { BASE_VARIANT_ID, useVariantSnapshots } from '../useVariantSnapshots';

const samplePayload = {
  access_point: { rate_limit: { rpm: 1 }, primary_extension: 'base' },
  target: { endpoint: 'https://base/x', auth: { kind: 'none' } },
  variants: [
    { id: 'v1', alias: 'def', name: 'Default' },
    {
      id: 'v2',
      alias: 'fast',
      name: 'Fast',
      overrides: {
        access_point: { rate_limit: { rpm: 99 } },
        target: { endpoint: 'https://fast/y' },
      },
    },
  ],
  default_variant_id: 'v1',
};

describe('useVariantSnapshots', () => {
  it('starts empty', () => {
    const { result } = renderHook(() => useVariantSnapshots());
    expect(result.current.variants).toEqual([]);
    expect(result.current.activeVariantId).toBeNull();
    expect(result.current.defaultVariantId).toBeNull();
    expect(result.current.hasVariants).toBe(false);
  });

  it('hydrates from a payload — variants metadata, default + active set, snapshots resolved', () => {
    const { result } = renderHook(() => useVariantSnapshots());
    let activePayload: any;
    let activeId: string | null = null;
    act(() => {
      const r = result.current.hydrateFromPayload(samplePayload);
      activePayload = r.activePayload;
      activeId = r.activeId;
    });
    expect(activeId).toBe('v1');
    expect(result.current.activeVariantId).toBe('v1');
    expect(result.current.defaultVariantId).toBe('v1');
    expect(result.current.variants.map(v => v.id)).toEqual(['v1', 'v2']);
    expect(result.current.hasVariants).toBe(true);
    // Default variant resolves to the base shape, sans variants/default_variant_id.
    expect(activePayload.access_point.rate_limit).toEqual({ rpm: 1 });
    expect(activePayload.variants).toBeUndefined();
    expect(activePayload.default_variant_id).toBeUndefined();
  });

  it('switchVariant snapshots the previous canvas state and returns the next variant payload', () => {
    const { result } = renderHook(() => useVariantSnapshots());
    act(() => {
      result.current.hydrateFromPayload(samplePayload);
    });
    // User edits the default variant on the canvas: bump rpm to 7.
    const editedDefault = {
      access_point: { rate_limit: { rpm: 7 }, primary_extension: 'base' },
      target: { endpoint: 'https://base/x', auth: { kind: 'none' } },
    };
    let nextPayload: any;
    act(() => {
      nextPayload = result.current.switchVariant('v2', editedDefault);
    });
    expect(result.current.activeVariantId).toBe('v2');
    // Returned payload is v2's resolved snapshot (overrides applied on the original base).
    expect(nextPayload.access_point.rate_limit).toEqual({ rpm: 99 });
    expect(nextPayload.target.endpoint).toEqual('https://fast/y');
    // Switching back returns the previously snapshotted edited default (rpm: 7).
    let backPayload: any;
    act(() => {
      backPayload = result.current.switchVariant('v1', nextPayload);
    });
    expect(backPayload.access_point.rate_limit).toEqual({ rpm: 7 });
  });

  it('switchVariant to the same id is a no-op that returns the existing snapshot', () => {
    const { result } = renderHook(() => useVariantSnapshots());
    act(() => {
      result.current.hydrateFromPayload(samplePayload);
    });
    const sameAgain: any = result.current.switchVariant('v1', { junk: true });
    // Same-id branch returns the stored snapshot without mutating it.
    expect(sameAgain.junk).toBeUndefined();
    expect(sameAgain.access_point.rate_limit).toEqual({ rpm: 1 });
  });

  it('setCatalog drops snapshots for removed variants and resets active to default if missing', () => {
    const { result } = renderHook(() => useVariantSnapshots());
    act(() => {
      result.current.hydrateFromPayload(samplePayload);
    });
    // Switch to v2 so it's active, then remove it from the catalog.
    act(() => {
      result.current.switchVariant('v2', samplePayload);
    });
    expect(result.current.activeVariantId).toBe('v2');
    act(() => {
      result.current.setCatalog({
        variants: [{ id: 'v1', alias: 'def', name: 'Default' }],
        defaultVariantId: 'v1',
      });
    });
    expect(result.current.variants.map(v => v.id)).toEqual(['v1']);
    expect(result.current.activeVariantId).toBe('v1');
  });

  it('buildVariantsWireSlice projects every named variant as a full overrides delta against the base', () => {
    const { result } = renderHook(() => useVariantSnapshots());
    act(() => {
      result.current.hydrateFromPayload(samplePayload);
    });
    // Switch to v2 then re-edit it on the "canvas" (rpm bumped to 123).
    act(() => {
      result.current.switchVariant('v2', samplePayload);
    });
    const liveV2 = {
      access_point: { rate_limit: { rpm: 123 } },
      target: { endpoint: 'https://fast/y', auth: { kind: 'none' } },
    };
    const wire = result.current.buildVariantsWireSlice(liveV2);
    // v1 is the named default — it now carries its full snapshot as
    // overrides (the base lives separately under wire.basePayload and
    // is the un-overridden surface).
    expect(wire.defaultVariantId).toBe('v1');
    const v1Wire = wire.variants.find(v => v.id === 'v1')!;
    const v2Wire = wire.variants.find(v => v.id === 'v2')!;
    expect(v1Wire.overrides?.access_point).toEqual({
      rate_limit: { rpm: 1 },
      primary_extension: 'base',
    });
    expect(v2Wire.overrides?.access_point).toEqual({ rate_limit: { rpm: 123 } });
    expect(v2Wire.overrides?.target).toEqual({
      endpoint: 'https://fast/y',
      auth: { kind: 'none' },
    });
    // basePayload is the always-present base snapshot — the unmodified surface.
    expect(wire.basePayload.access_point.rate_limit).toEqual({ rpm: 1 });
  });

  it('returns the base snapshot when there are no variants', () => {
    const { result } = renderHook(() => useVariantSnapshots());
    let activePayload: any;
    let activeId: string | null = null;
    act(() => {
      const r = result.current.hydrateFromPayload({ access_point: { rate_limit: { rpm: 1 } } });
      activePayload = r.activePayload;
      activeId = r.activeId;
    });
    // No named variants — base is the implicit default and the active
    // selection. The hook reports `BASE_VARIANT_ID` as the active id.
    expect(activeId).toBe(BASE_VARIANT_ID);
    expect(activePayload).toEqual({ access_point: { rate_limit: { rpm: 1 } } });
    expect(result.current.hasVariants).toBe(false);
    expect(result.current.defaultVariantId).toBeNull();
  });
});
