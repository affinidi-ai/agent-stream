import {
  RUN_STATUS_TONE,
  compareRuns,
  matchesRunFilter,
  qualityTone,
  runFailureGuidance,
  runSurfaceName,
  runVerdictStatus,
  surfaceNameById,
  triggerMeta,
} from '../driftRunHistoryHelpers';
import type { DimensionVerdict, DriftRun, DriftSurface } from '../types';

const run = (over: Partial<DriftRun>): DriftRun => ({
  id: 'r1',
  suite_id: 's1',
  suite_name: 's1',
  surface_id: 's1',
  ran_at: '2026-08-29T12:00:00.000Z',
  trigger: 'manual',
  total: 10,
  passed: 8,
  errors: 0,
  quality: 0.8,
  status: 'completed',
  progress_done: 10,
  samples: [],
  ...over,
});

const surfaces: DriftSurface[] = [{ surface_id: 's1', surface_name: 'Support bot' }];

describe('driftRunHistoryHelpers', () => {
  it('resolves a surface name, falling back to the id', () => {
    expect(runSurfaceName(run({ surface_id: 's1' }), surfaces)).toBe('Support bot');
    expect(runSurfaceName(run({ surface_id: 'unknown' }), surfaces)).toBe('unknown');
  });

  it('resolves a surface id to a name via surfaceNameById', () => {
    expect(surfaceNameById('s1', surfaces)).toBe('Support bot');
    expect(surfaceNameById('other', surfaces)).toBe('other');
  });

  it('tones quality by band', () => {
    expect(qualityTone(0.95)).toBe('success');
    expect(qualityTone(0.6)).toBe('warning');
    expect(qualityTone(0.2)).toBe('danger');
  });

  it('describes the trigger', () => {
    expect(triggerMeta('scheduled').label).toBe('Scheduled');
    expect(triggerMeta('manual').label).toBe('Manual');
  });

  it('maps every run status to a badge tone', () => {
    expect(RUN_STATUS_TONE.completed).toBe('success');
    expect(RUN_STATUS_TONE.failed).toBe('danger');
    expect(RUN_STATUS_TONE.running).toBe('info');
  });

  it('matches the free-text filter across fields', () => {
    const r = run({ status: 'failed', trigger: 'scheduled', variant: 'eu' });
    expect(matchesRunFilter(r, '', 'Support bot')).toBe(true);
    expect(matchesRunFilter(r, 'support', 'Support bot')).toBe(true);
    expect(matchesRunFilter(r, 'failed', 'Support bot')).toBe(true);
    expect(matchesRunFilter(r, 'scheduled', 'Support bot')).toBe(true);
    expect(matchesRunFilter(r, 'eu', 'Support bot')).toBe(true);
    expect(matchesRunFilter(r, 'nomatch', 'Support bot')).toBe(false);
  });

  it('sorts by quality, passed rate, and time', () => {
    const a = run({ id: 'a', quality: 0.9, passed: 9, total: 10, ran_at: '2026-08-29T10:00:00Z' });
    const b = run({ id: 'b', quality: 0.4, passed: 2, total: 10, ran_at: '2026-08-29T11:00:00Z' });
    const nameOf = (x: DriftRun) => runSurfaceName(x, surfaces);
    expect(compareRuns(a, b, 'quality', nameOf)).toBeGreaterThan(0);
    expect(compareRuns(a, b, 'passed', nameOf)).toBeGreaterThan(0);
    expect(compareRuns(a, b, 'ranAt', nameOf)).toBeLessThan(0);
    const dv = (status: DimensionVerdict['status']): DimensionVerdict[] => [
      { dimension: 'response_length', label: 'Response length', status, sample_count: 1 },
    ];
    const warned = run({ id: 'w', dimension_verdicts: dv('warn') });
    const stable = run({ id: 's2', dimension_verdicts: dv('stable') });
    expect(compareRuns(warned, stable, 'verdict', nameOf)).toBeGreaterThan(0);
  });

  it('surfaces the worst judged dimension verdict, ignoring baseline-less dims', () => {
    const v = (dimension: string, status: DimensionVerdict['status']): DimensionVerdict => ({
      dimension,
      label: dimension,
      status,
      sample_count: 5,
    });
    // A warn on a judged dimension shows even when quality has no baseline.
    expect(
      runVerdictStatus(
        run({ dimension_verdicts: [v('quality', 'unknown'), v('response_length', 'warn')] })
      )
    ).toBe('warn');
    // Drift outranks warn.
    expect(runVerdictStatus(run({ dimension_verdicts: [v('a', 'warn'), v('b', 'drift')] }))).toBe(
      'drift'
    );
    // A baseline-less dim never drags an otherwise-stable run to "no baseline".
    expect(
      runVerdictStatus(run({ dimension_verdicts: [v('a', 'stable'), v('b', 'unknown')] }))
    ).toBe('stable');
    // Nothing judged → unknown ("No baseline").
    expect(runVerdictStatus(run({ dimension_verdicts: [v('a', 'unknown')] }))).toBe('unknown');
    expect(runVerdictStatus(run({ dimension_verdicts: [] }))).toBe('unknown');
  });

  it('sorts unknown semantic distance below any measured value', () => {
    const measured = run({ id: 'm', semantic_distance: 0.1 });
    const missing = run({ id: 'n', semantic_distance: undefined });
    const nameOf = (x: DriftRun) => runSurfaceName(x, surfaces);
    expect(compareRuns(measured, missing, 'semantic', nameOf)).toBeGreaterThan(0);
  });

  it('gives no failure guidance for a successful run', () => {
    expect(runFailureGuidance(run({ status: 'completed' }))).toBeNull();
  });

  it('explains a no-sessions failure with recourse', () => {
    const g = runFailureGuidance(
      run({ status: 'failed', total: 0, failure_reason: 'no sessions to replay' })
    );
    expect(g?.tone).toBe('warning');
    expect(g?.reason).toMatch(/no captured sessions/i);
    expect(g?.recourse).toMatch(/schedule/i);
  });

  it('explains an all-errored failure as a danger with upstream recourse', () => {
    const g = runFailureGuidance(
      run({
        status: 'failed',
        total: 5,
        errors: 5,
        failure_reason: 'all 5 replayed sessions failed',
      })
    );
    expect(g?.tone).toBe('danger');
    expect(g?.recourse).toMatch(/upstream|provider|credential/i);
  });

  it('explains an auto-suspension and a cancellation', () => {
    const suspended = runFailureGuidance(
      run({ status: 'failed', failure_reason: 'auto-suspended after 3 consecutive failures' })
    );
    expect(suspended?.recourse).toMatch(/manual evaluation/i);
    const cancelled = runFailureGuidance(run({ status: 'cancelled' }));
    expect(cancelled?.tone).toBe('warning');
  });

  it('explains a run stopped at its cost ceiling', () => {
    const g = runFailureGuidance(
      run({
        status: 'stopped',
        total: 3,
        progress_done: 3,
        cost_usd: 5.01,
        failure_reason: 'run cost ceiling $5.00 reached (spent $5.01)',
      })
    );
    expect(g?.tone).toBe('warning');
    expect(g?.reason).toMatch(/cost ceiling/i);
    // The operator needs to know the partial run is not in the charts, and how
    // to let a full run through next time.
    expect(g?.recourse).toMatch(/not folded into the drift charts/i);
    expect(g?.recourse).toMatch(/fewer sessions|cost ceiling/i);
  });

  it('explains a run stopped by the target surface usage limit', () => {
    const g = runFailureGuidance(
      run({
        status: 'stopped',
        failure_reason:
          "target surface usage limit reached: monthly budget $20.00 reached for scope 'cumulative' (spent $20.40)",
      })
    );
    expect(g?.tone).toBe('warning');
    // Evaluation replays are billable traffic on the same limits as live calls.
    expect(g?.recourse).toMatch(/same limits as live traffic/i);
  });
});
