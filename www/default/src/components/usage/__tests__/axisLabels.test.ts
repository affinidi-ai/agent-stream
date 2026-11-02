import { dateBoundaries, fullStamp, makeAxisLabels } from '../usageSeries';

const DAY = 86_400;
const HOUR = 3600;

// Local midnight on a non-DST date, so the date-change logic (which keys off the
// local calendar date) is deterministic regardless of the runner's timezone.
const JAN1 = Math.floor(new Date(2025, 0, 1, 0, 0, 0).getTime() / 1000);

describe('makeAxisLabels', () => {
  it('returns time-only labels at sub-day resolution (dates go in the date row)', () => {
    // Six hourly buckets across two days — none should carry a month name; the
    // date is drawn separately by the date-boundary plugin.
    const ts = [0, 1, 2, 24, 25, 26].map(h => JAN1 + h * HOUR);
    const labels = makeAxisLabels(ts, HOUR);
    expect(labels.every(l => !/[A-Z][a-z]{2}\b/.test(l))).toBe(true);
    // Every label is a time (contains a digit).
    expect(labels.every(l => /\d/.test(l))).toBe(true);
  });

  it('shows a date for every bucket at day resolution', () => {
    const ts = [0, 1, 2, 3].map(d => JAN1 + d * DAY);
    const labels = makeAxisLabels(ts, DAY);
    expect(labels.every(l => /^[A-Z][a-z]{2}\b/.test(l))).toBe(true);
    // Distinct days → distinct labels.
    expect(new Set(labels).size).toBe(4);
  });

  it('shows month/year for month-or-coarser resolution', () => {
    const ts = [JAN1, JAN1 + 31 * DAY];
    const labels = makeAxisLabels(ts, 2_592_000);
    expect(labels.every(l => /\d{2}/.test(l))).toBe(true);
  });

  it('returns an empty array for no timestamps', () => {
    expect(makeAxisLabels([], HOUR)).toEqual([]);
  });
});

describe('dateBoundaries', () => {
  it('marks the first bucket of each calendar date with its label', () => {
    // Three buckets on day 1, three on day 2 — two boundaries at indices 0 and 3.
    const ts = [0, 1, 2, 24, 25, 26].map(h => JAN1 + h * HOUR);
    const b = dateBoundaries(ts);
    expect(b.map(x => x.index)).toEqual([0, 3]);
    expect(b[0].label).not.toEqual(b[1].label);
    expect(b.every(x => /^[A-Z][a-z]{2}\b/.test(x.label))).toBe(true);
  });

  it('returns a single boundary when every bucket is the same date', () => {
    const ts = [0, 1, 2].map(h => JAN1 + h * HOUR);
    const b = dateBoundaries(ts);
    expect(b).toHaveLength(1);
    expect(b[0].index).toBe(0);
  });

  it('returns an empty array for no timestamps', () => {
    expect(dateBoundaries([])).toEqual([]);
  });
});

describe('fullStamp', () => {
  it('renders a full date+time for a timestamp', () => {
    const s = fullStamp(JAN1);
    expect(s).toContain('2025');
    expect(s.length).toBeGreaterThan(0);
  });

  it('returns an empty string for undefined', () => {
    expect(fullStamp(undefined)).toBe('');
  });
});
