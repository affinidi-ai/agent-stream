import {
  driftSeriesKey,
  driftStatusTone,
  formatDriftValue,
  type DriftDimensionInfo,
  type DriftSurface,
} from '../types';
import { targetVariantOptions } from '../evalTargets';

const rate: DriftDimensionInfo = {
  id: 'refusal_rate',
  label: 'Refusal rate',
  unit: 'ratio',
  is_rate: true,
};
const latency: DriftDimensionInfo = {
  id: 'latency_ms',
  label: 'Latency',
  unit: 'ms',
  is_rate: false,
};
const tokens: DriftDimensionInfo = {
  id: 'output_tokens',
  label: 'Output tokens',
  unit: 'tokens',
  is_rate: false,
};
const chars: DriftDimensionInfo = {
  id: 'response_length',
  label: 'Response length',
  unit: 'chars',
  is_rate: false,
};
const cost: DriftDimensionInfo = {
  id: 'cost',
  label: 'Cost',
  unit: 'usd',
  is_rate: false,
};

describe('drift helpers', () => {
  it('builds a namespaced drift series key', () => {
    expect(driftSeriesKey('pipe-1', 'latency_ms')).toBe('drift:surface:pipe-1:latency_ms');
  });

  it('formats a rate dimension as a percentage', () => {
    expect(formatDriftValue(0.1234, rate)).toBe('12.3%');
    expect(formatDriftValue(1, rate)).toBe('100.0%');
  });

  it('formats gauge dimensions with their unit', () => {
    expect(formatDriftValue(842.7, latency)).toBe('843 ms');
    expect(formatDriftValue(128.4, tokens)).toBe('128');
    expect(formatDriftValue(431.6, chars)).toBe('432');
    expect(formatDriftValue(0.001234, cost)).toBe('$0.0012');
  });

  it('maps a drift status to a bootstrap tone and label', () => {
    expect(driftStatusTone('drift')).toEqual({ tone: 'danger', label: 'Drift' });
    expect(driftStatusTone('warn')).toEqual({ tone: 'warning', label: 'Warn' });
    expect(driftStatusTone('stable')).toEqual({ tone: 'success', label: 'Stable' });
    expect(driftStatusTone('unknown')).toEqual({ tone: 'secondary', label: 'No baseline' });
  });

  it("lists a target surface's variants with Base variant first", () => {
    const surfaces: DriftSurface[] = [
      { surface_id: 'a', surface_name: 'Alpha', variants: [{ alias: 'v2', name: 'Cheap' }] },
      { surface_id: 'b', surface_name: 'Beta' },
    ];
    expect(targetVariantOptions(surfaces, 'a')).toEqual([
      { value: '', label: 'Base variant' },
      { value: 'v2', label: 'Cheap' },
    ]);
  });

  it('returns only Base variant for a surface with no variants', () => {
    const surfaces: DriftSurface[] = [{ surface_id: 'b', surface_name: 'Beta' }];
    expect(targetVariantOptions(surfaces, 'b')).toEqual([{ value: '', label: 'Base variant' }]);
  });
});
