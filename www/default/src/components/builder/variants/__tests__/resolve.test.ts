import { computeOverridesFromPayload, resolveVariant } from '../resolve';

describe('computeOverridesFromPayload', () => {
  it('emits only the complete flag when access_point/target are absent', () => {
    expect(computeOverridesFromPayload({})).toEqual({ complete: true });
  });

  it('extracts whitelisted access_point fields and skips unknown ones', () => {
    const overrides = computeOverridesFromPayload({
      access_point: {
        // identifier — must NOT be picked up as an override
        listen_address: '0.0.0.0:8080',
        protocol: 'a2a',
        route: '/agent',
        // overridable
        rate_limit: { rpm: 100 },
        publish_to_did_document: true,
        primary_extension: 'foo',
      },
    });
    expect(overrides.complete).toBe(true);
    expect(overrides.access_point).toEqual({
      rate_limit: { rpm: 100 },
      publish_to_did_document: true,
      primary_extension: 'foo',
    });
    expect(overrides.target).toBeUndefined();
  });

  it('extracts whitelisted target fields', () => {
    const overrides = computeOverridesFromPayload({
      target: {
        endpoint: 'https://upstream.example/api',
        auth: { kind: 'bearer', token: 'x' },
        mpp_auto_pay: true,
        mpp_auto_pay_max_amount: '0.10',
        // not in TARGET_FIELDS — should be ignored
        unknown_field: 42,
      },
    });
    expect(overrides.target).toEqual({
      endpoint: 'https://upstream.example/api',
      auth: { kind: 'bearer', token: 'x' },
      mpp_auto_pay: true,
      mpp_auto_pay_max_amount: '0.10',
    });
  });

  it('treats null and undefined fields as absent', () => {
    const overrides = computeOverridesFromPayload({
      access_point: { rate_limit: null, primary_extension: undefined },
      target: {},
    });
    expect(overrides.access_point).toBeUndefined();
    expect(overrides.target).toBeUndefined();
  });

  it('captures the canvas blob verbatim so per-variant layout survives save/reload', () => {
    const canvas = {
      version: 1,
      view: { x: 10, y: 20, k: 1.5 },
      nodes: [
        { id: 'node-a', position: { x: 100, y: 50 } },
        { id: 'node-b', position: { x: 200, y: 80 } },
      ],
    };
    const overrides = computeOverridesFromPayload({ canvas });
    expect(overrides.canvas).toEqual(canvas);
  });
});

describe('resolveVariant', () => {
  it('returns a deep clone of the base when overrides are empty', () => {
    const base = { access_point: { rate_limit: { rpm: 1 } } };
    const out = resolveVariant(base, {});
    expect(out).toEqual(base);
    expect(out.access_point).not.toBe(base.access_point);
  });

  it('shallow-merges access_point and target overrides over the base', () => {
    const base = {
      access_point: { rate_limit: { rpm: 1 }, primary_extension: 'a' },
      target: { endpoint: 'https://base/x', auth: { kind: 'none' } },
    };
    const out = resolveVariant(base, {
      access_point: { rate_limit: { rpm: 9 } },
      target: { auth: { kind: 'bearer', token: 't' } },
    });
    expect(out.access_point).toEqual({
      rate_limit: { rpm: 9 },
      primary_extension: 'a',
    });
    expect(out.target).toEqual({
      endpoint: 'https://base/x',
      auth: { kind: 'bearer', token: 't' },
    });
  });

  it('strips variants and default_variant_id from the resolved view', () => {
    const base = {
      variants: [{ id: 'v1', alias: 'a', name: 'A' }],
      default_variant_id: 'v1',
      access_point: { rate_limit: { rpm: 1 } },
    };
    const out = resolveVariant(base, {});
    expect(out.variants).toBeUndefined();
    expect(out.default_variant_id).toBeUndefined();
    expect(out.access_point).toEqual({ rate_limit: { rpm: 1 } });
  });

  it('wholesale-replaces the canvas blob when the variant override carries one', () => {
    const base = {
      access_point: { rate_limit: { rpm: 1 } },
      canvas: {
        version: 1,
        nodes: [{ id: 'node-a', position: { x: 0, y: 0 } }],
      },
    };
    const variantCanvas = {
      version: 1,
      nodes: [
        { id: 'node-x', position: { x: 100, y: 50 } },
        { id: 'node-y', position: { x: 200, y: 80 } },
      ],
    };
    const out = resolveVariant(base, { canvas: variantCanvas });
    expect(out.canvas).toEqual(variantCanvas);
  });

  it('inherits the base canvas when the variant override has no canvas key', () => {
    const baseCanvas = {
      version: 1,
      nodes: [{ id: 'node-a', position: { x: 0, y: 0 } }],
    };
    const out = resolveVariant({ canvas: baseCanvas }, { target: { endpoint: 'x' } });
    expect(out.canvas).toEqual(baseCanvas);
  });

  it('complete:true wholesale-replaces base AP fields, preserving listen_address/route/protocol', () => {
    // The frozen-snapshot mode that backs the "copy on create, then
    // diverge" model. Base grew a new caller_authentication after the
    // variant was created \u2014 the variant must NOT inherit it.
    const base = {
      access_point: {
        listen_address: '0.0.0.0:8080',
        route: '/api',
        protocol: 'a2a',
        caller_authentication: { methods: [{ strategy: 'jwt' }] },
        primary_extension: 'base-ext',
      },
    };
    const out = resolveVariant(base, {
      complete: true,
      access_point: {
        // variant was captured before base grew caller_authentication,
        // so this snapshot doesn't carry it
        primary_extension: 'variant-ext',
      },
    });
    expect(out.access_point.caller_authentication).toBeUndefined();
    expect(out.access_point.primary_extension).toEqual('variant-ext');
    // Surface-level identifiers always carried from base.
    expect(out.access_point.listen_address).toEqual('0.0.0.0:8080');
    expect(out.access_point.route).toEqual('/api');
    expect(out.access_point.protocol).toEqual('a2a');
  });

  it('complete:false (legacy) still inherits base AP fields not present in override', () => {
    const base = {
      access_point: {
        listen_address: '0.0.0.0:8080',
        caller_authentication: { methods: [{ strategy: 'jwt' }] },
        primary_extension: 'base-ext',
      },
    };
    const out = resolveVariant(base, {
      access_point: { primary_extension: 'variant-ext' },
    });
    // Legacy sparse: base's caller_authentication leaks through.
    expect(out.access_point.caller_authentication).toEqual({ methods: [{ strategy: 'jwt' }] });
    expect(out.access_point.primary_extension).toEqual('variant-ext');
  });

  it('round-trips: resolveVariant(base, computeOverridesFromPayload(payload)) preserves AP/Target', () => {
    const base = {
      access_point: {
        listen_address: '0.0.0.0:1',
        protocol: 'a2a',
        route: '/r',
        rate_limit: { rpm: 1 },
        primary_extension: 'base',
      },
      target: { endpoint: 'https://base/x', auth: { kind: 'none' } },
    };
    const payload = {
      access_point: {
        listen_address: '0.0.0.0:1',
        protocol: 'a2a',
        route: '/r',
        rate_limit: { rpm: 42 },
        primary_extension: 'variant',
        publish_to_did_document: true,
      },
      target: { endpoint: 'https://variant/y', auth: { kind: 'bearer', token: 'tok' } },
    };
    const overrides = computeOverridesFromPayload(payload);
    const resolved = resolveVariant(base, overrides);
    expect(resolved.access_point.rate_limit).toEqual({ rpm: 42 });
    expect(resolved.access_point.primary_extension).toEqual('variant');
    expect(resolved.access_point.publish_to_did_document).toBe(true);
    // identifier carried from base — overrides never include it
    expect(resolved.access_point.listen_address).toEqual('0.0.0.0:1');
    expect(resolved.target).toEqual({
      endpoint: 'https://variant/y',
      auth: { kind: 'bearer', token: 'tok' },
    });
  });
});
