import {
  densifyOpsSeries,
  densifySeries,
  type OpsSeriesResponse,
  type SeriesResponse,
} from '../usageSeries';

const DAY = 86_400;

const usage = (points: SeriesResponse['points']): SeriesResponse => ({
  key: 'surfaces:all',
  resolution: '24h',
  step_secs: DAY,
  points,
});

describe('densifySeries', () => {
  it('fills empty buckets between two far-apart points so the timeline is even', () => {
    // Two points three days apart at daily resolution: 27 Jun and 30 Jun.
    const jun27 = 1_719_446_400; // 2024-06-27T00:00:00Z (day-aligned)
    const jun30 = jun27 + 3 * DAY;
    const out = densifySeries(
      usage([
        { t: jun27, cost: 1, tokens: 10, requests: 2 },
        { t: jun30, cost: 4, tokens: 40, requests: 5 },
      ])
    );
    expect(out.points.map(p => p.t)).toEqual([jun27, jun27 + DAY, jun27 + 2 * DAY, jun30]);
    // Real samples are preserved; the two inserted gap buckets are zeroed.
    expect(out.points[0]).toEqual({ t: jun27, cost: 1, tokens: 10, requests: 2 });
    expect(out.points[1]).toEqual({ t: jun27 + DAY, cost: 0, tokens: 0, requests: 0 });
    expect(out.points[2]).toEqual({ t: jun27 + 2 * DAY, cost: 0, tokens: 0, requests: 0 });
    expect(out.points[3]).toEqual({ t: jun30, cost: 4, tokens: 40, requests: 5 });
  });

  it('leaves a series with fewer than two points unchanged', () => {
    const one = usage([{ t: 1_719_446_400, cost: 1, tokens: 1, requests: 1 }]);
    expect(densifySeries(one).points).toHaveLength(1);
    expect(densifySeries(usage([])).points).toHaveLength(0);
  });

  it('preserves and reorders already-contiguous points without inserting gaps', () => {
    const t0 = 1_719_446_400;
    const out = densifySeries(
      usage([
        { t: t0 + DAY, cost: 2, tokens: 0, requests: 1 },
        { t: t0, cost: 1, tokens: 0, requests: 1 },
      ])
    );
    expect(out.points.map(p => p.t)).toEqual([t0, t0 + DAY]);
  });

  it('bails to the raw sparse series when the grid would be unreasonably large', () => {
    // 30s buckets a full year apart would expand to ~1M buckets — keep sparse.
    const t0 = 1_719_446_400;
    const sparse: SeriesResponse = {
      key: 'surfaces:all',
      resolution: '30s',
      step_secs: 30,
      points: [
        { t: t0, cost: 1, tokens: 0, requests: 1 },
        { t: t0 + 31_536_000, cost: 1, tokens: 0, requests: 1 },
      ],
    };
    expect(densifySeries(sparse).points).toHaveLength(2);
  });

  it('fills the whole requested window when a range is given (equal-width days)', () => {
    // Two full days at daily resolution, but the first day has data only on its
    // second bucket and the second day only on its first — without a range the
    // grid would start/end at the data, giving unequal spans. With the window it
    // spans every day boundary, so each day occupies the same width.
    const day0 = 1_719_446_400; // day-aligned
    const from = day0; // window covers three day-buckets: day0, +1d, +2d
    const to = day0 + 2 * DAY;
    const out = densifySeries(usage([{ t: day0 + DAY, cost: 5, tokens: 50, requests: 3 }]), {
      from,
      to,
    });
    // Grid: day0, day0+DAY, day0+2*DAY (floor(to/DAY)*DAY) → three equal slots.
    expect(out.points.map(p => p.t)).toEqual([day0, day0 + DAY, day0 + 2 * DAY]);
    expect(out.points[0]).toEqual({ t: day0, cost: 0, tokens: 0, requests: 0 });
    expect(out.points[1]).toEqual({ t: day0 + DAY, cost: 5, tokens: 50, requests: 3 });
    expect(out.points[2]).toEqual({ t: day0 + 2 * DAY, cost: 0, tokens: 0, requests: 0 });
  });

  it('fills leading and trailing empty spans across a window with one data point', () => {
    // A single data point mid-window still yields a full grid across the window.
    const day0 = 1_719_446_400;
    const out = densifySeries(usage([{ t: day0 + 2 * DAY, cost: 1, tokens: 1, requests: 1 }]), {
      from: day0,
      to: day0 + 4 * DAY,
    });
    expect(out.points.map(p => p.t)).toEqual([
      day0,
      day0 + DAY,
      day0 + 2 * DAY,
      day0 + 3 * DAY,
      day0 + 4 * DAY,
    ]);
    expect(out.points.filter(p => p.cost > 0)).toHaveLength(1);
  });

  it('snaps a genuinely multi-day sub-day window to whole local days (equal width)', () => {
    const HOUR = 3600;
    // Local midnights so the local-day snapping is deterministic in this tz.
    const day0 = Math.floor(new Date(2025, 0, 1, 0, 0, 0).getTime() / 1000);
    const day1 = Math.floor(new Date(2025, 0, 2, 0, 0, 0).getTime() / 1000);
    const day2 = Math.floor(new Date(2025, 0, 3, 0, 0, 0).getTime() / 1000);
    // A window spanning MORE than one day (partial edges): mid-day-0 to mid-day-2.
    const from = day0 + 15 * HOUR;
    const to = day2 + 9 * HOUR;
    const out = densifySeries(
      {
        key: 'surfaces:all',
        resolution: '1h',
        step_secs: HOUR,
        points: [{ t: day0 + 16 * HOUR, cost: 1, tokens: 1, requests: 1 }],
      },
      { from, to }
    );
    const localMidnightMs = (t: number) => new Date(t * 1000).setHours(0, 0, 0, 0);
    const d0 = out.points.filter(p => localMidnightMs(p.t) === day0 * 1000).length;
    const d1 = out.points.filter(p => localMidnightMs(p.t) === day1 * 1000).length;
    // The interior days are complete and therefore equal width, despite the
    // partial edges — the snap rounds the window out to whole local days.
    expect(d0).toBe(d1);
    expect(d0).toBe(24);
  });

  it('fills a sub-day window of one day or less to its exact bounds (span matches selection)', () => {
    const HOUR = 3600;
    const day0 = Math.floor(new Date(2025, 0, 1, 0, 0, 0).getTime() / 1000);
    const day1 = Math.floor(new Date(2025, 0, 2, 0, 0, 0).getTime() / 1000);
    // An 18h rolling window straddling local midnight is NOT snapped out to two
    // whole days — snapping would draw a ~48h span for a sub-24h selection,
    // disagreeing with the scrubber's highlight. It fills exactly [from, to].
    const from = day0 + 15 * HOUR;
    const to = day1 + 9 * HOUR;
    const out = densifySeries(
      {
        key: 'surfaces:all',
        resolution: '1h',
        step_secs: HOUR,
        points: [{ t: day0 + 16 * HOUR, cost: 1, tokens: 1, requests: 1 }],
      },
      { from, to }
    );
    // Exact grid: floor(from/step) .. floor(to/step), inclusive → 15h day0 to 9h day1.
    expect(out.points[0].t).toBe(day0 + 15 * HOUR);
    expect(out.points[out.points.length - 1].t).toBe(day1 + 9 * HOUR);
    expect(out.points).toHaveLength(19); // 9 buckets on day0 + 10 on day1, not 48
    const localMidnightMs = (t: number) => new Date(t * 1000).setHours(0, 0, 0, 0);
    expect(out.points.filter(p => localMidnightMs(p.t) === day0 * 1000)).toHaveLength(9);
    expect(out.points.filter(p => localMidnightMs(p.t) === day1 * 1000)).toHaveLength(10);
  });
});

describe('densifyOpsSeries', () => {
  it('fills gaps with fully-zeroed operational buckets', () => {
    const t0 = 1_719_446_400;
    const ops: OpsSeriesResponse = {
      key: 'ops:all',
      resolution: '24h',
      step_secs: DAY,
      points: [
        {
          t: t0,
          connections: 5,
          failed: 1,
          gateway_faults: 0,
          rule_accepts: 4,
          rule_denies: 1,
          request_bytes: 100,
          response_bytes: 200,
          input_tokens: 10,
          output_tokens: 20,
          avg_latency_ms: 12,
          p50_latency_ms: 10,
          p95_latency_ms: 30,
          p99_latency_ms: 40,
          min_latency_ms: 5,
          max_latency_ms: 50,
          latency_samples: 5,
        },
        {
          t: t0 + 2 * DAY,
          connections: 3,
          failed: 0,
          gateway_faults: 0,
          rule_accepts: 3,
          rule_denies: 0,
          request_bytes: 60,
          response_bytes: 90,
          input_tokens: 6,
          output_tokens: 9,
          avg_latency_ms: 8,
          p50_latency_ms: 7,
          p95_latency_ms: 20,
          p99_latency_ms: 25,
          min_latency_ms: 4,
          max_latency_ms: 30,
          latency_samples: 3,
        },
      ],
    };
    const out = densifyOpsSeries(ops);
    expect(out.points.map(p => p.t)).toEqual([t0, t0 + DAY, t0 + 2 * DAY]);
    const gap = out.points[1];
    expect(gap.connections).toBe(0);
    expect(gap.request_bytes).toBe(0);
    expect(gap.avg_latency_ms).toBe(0);
    expect(gap.latency_samples).toBe(0);
  });
});
