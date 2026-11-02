import { formatDuration } from '../usageSeries';

const MIN = 60;
const HOUR = 3600;
const DAY = 86_400;
const MONTH = 2_592_000; // 30-day approximation used by the label

describe('formatDuration', () => {
  it('normalises a months-scale span to the 3 most significant units', () => {
    expect(formatDuration(3 * MONTH + 5 * DAY + 2 * HOUR + 13 * MIN)).toBe(
      '3 months, 5 days, 2 hours'
    );
  });

  it('normalises a days-scale span', () => {
    expect(formatDuration(3 * DAY + 2 * HOUR)).toBe('3 days, 2 hours');
  });

  it('uses singular units for a value of one', () => {
    expect(formatDuration(1 * DAY + 1 * HOUR + 1 * MIN)).toBe('1 day, 1 hour, 1 minute');
  });

  it('shows a single unit when the rest are zero', () => {
    expect(formatDuration(2 * MONTH)).toBe('2 months');
    expect(formatDuration(45 * MIN)).toBe('45 minutes');
  });

  it('skips zero intermediate units, keeping the top 3 non-zero', () => {
    // 3 months, 0 days, 2 hours, 10 minutes → months + hours + minutes.
    expect(formatDuration(3 * MONTH + 2 * HOUR + 10 * MIN)).toBe('3 months, 2 hours, 10 minutes');
  });

  it('falls back to seconds for small and zero spans', () => {
    expect(formatDuration(30)).toBe('30 seconds');
    expect(formatDuration(0)).toBe('0 seconds');
  });
});
