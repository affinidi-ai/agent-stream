import { formatCost, outcomeTone, recordDisposition, shortDigest } from '../governanceHelpers';
import type { GovernanceRecord, StageEntry } from '../types';

function record(outcomes: StageEntry['outcome'][]): GovernanceRecord {
  return {
    record_id: 'r1',
    surface_id: 's1',
    timestamp: '2026-08-12T00:00:00Z',
    prev_record_hash: 'sha256:genesis',
    stages: outcomes.map(outcome => ({ stage: 'x', outcome })),
    metrics: { input_tokens: 0, output_tokens: 0, total_tokens: 0, cost: 0, latency_ms: 0 },
  };
}

describe('outcomeTone', () => {
  it('maps each outcome to a badge tone', () => {
    expect(outcomeTone('allow')).toBe('success');
    expect(outcomeTone('block')).toBe('danger');
    expect(outcomeTone('error')).toBe('warning');
    expect(outcomeTone('flag')).toBe('info');
    expect(outcomeTone('observed')).toBe('secondary');
  });
});

describe('recordDisposition', () => {
  it('prioritises block over error, flag, and allow', () => {
    expect(recordDisposition(record(['allow', 'error', 'block']))).toBe('block');
  });

  it('prioritises error over flag and allow', () => {
    expect(recordDisposition(record(['allow', 'flag', 'error']))).toBe('error');
  });

  it('prioritises flag over allow', () => {
    expect(recordDisposition(record(['allow', 'flag']))).toBe('flag');
  });

  it('defaults to allow when no stopping outcome is present', () => {
    expect(recordDisposition(record(['observed', 'allow']))).toBe('allow');
  });
});

describe('shortDigest', () => {
  it('abbreviates a sha256 digest', () => {
    expect(shortDigest('sha256:abcdef0123456789')).toBe('sha256:abcdef…6789');
  });

  it('returns an em dash for a missing digest', () => {
    expect(shortDigest(undefined)).toBe('—');
  });

  it('leaves a short digest untouched', () => {
    expect(shortDigest('sha256:abcd')).toBe('sha256:abcd');
  });
});

describe('formatCost', () => {
  it('renders zero and sub-cent and cent+ costs at sensible precision', () => {
    expect(formatCost(0)).toBe('$0.00');
    expect(formatCost(0.0000012)).toBe('$0.000001');
    expect(formatCost(0.5)).toBe('$0.5000');
  });
});
