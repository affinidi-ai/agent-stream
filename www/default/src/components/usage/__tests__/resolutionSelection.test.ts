import { defaultResolutionFor, forcedResolutionFits, overviewResolutionFor } from '../usageSeries';

const HOUR = 3600;
const DAY = 86_400;

describe('defaultResolutionFor', () => {
  // The smart auto-default now picks the finest readable tier so wide windows
  // still show per-day detail instead of an over-coarse handful of points.
  it('maps common preset windows to readable tiers', () => {
    expect(defaultResolutionFor(24 * HOUR)).toBe('1h'); // 24 buckets
    expect(defaultResolutionFor(7 * DAY)).toBe('12h'); // 14 buckets
    expect(defaultResolutionFor(30 * DAY)).toBe('24h'); // 30 daily buckets
    expect(defaultResolutionFor(365 * DAY)).toBe('30d'); // ~12 monthly buckets
  });

  it('picks the finest tier for narrow windows', () => {
    expect(defaultResolutionFor(5 * 60)).toBe('30s');
    expect(defaultResolutionFor(6 * HOUR)).toBe('30m');
  });

  it('falls back to the coarsest tier for windows wider than a year', () => {
    expect(defaultResolutionFor(5 * 365 * DAY)).toBe('1y');
  });
});

describe('forcedResolutionFits', () => {
  it('rejects a forced tier far too fine for the window (would not fill/render)', () => {
    // 1-minute buckets over 30 days ≈ 43k slots — reverts to auto.
    expect(forcedResolutionFits('1m', 30 * DAY)).toBe(false);
  });

  it('keeps a forced fine tier when the window is short enough to fill', () => {
    // 1-minute buckets over 3 days ≈ 4320 slots — under the fill ceiling.
    expect(forcedResolutionFits('1m', 3 * DAY)).toBe(true);
  });

  it('rejects a forced tier too coarse for the window', () => {
    // Daily buckets over a 30-second window yields under one bar.
    expect(forcedResolutionFits('24h', 30)).toBe(false);
  });

  it('rejects the 30s tier at or above a 24h window (too much data to scrub)', () => {
    expect(forcedResolutionFits('30s', DAY)).toBe(false);
    expect(forcedResolutionFits('30s', 7 * DAY)).toBe(false);
  });

  it('keeps the 30s tier for windows under 24h', () => {
    expect(forcedResolutionFits('30s', 12 * HOUR)).toBe(true);
    expect(forcedResolutionFits('30s', 5 * 60)).toBe(true);
  });

  it('always accepts auto or an unknown label', () => {
    expect(forcedResolutionFits('auto', 30 * DAY)).toBe(true);
    expect(forcedResolutionFits('nonsense', 30 * DAY)).toBe(true);
  });
});

describe('overviewResolutionFor', () => {
  // The overview must follow the chart's tier so a rail bar covers no more
  // time than one chart bucket — otherwise a bar in the rail can indicate
  // activity in a slice the user's narrower selection window doesn't cover.
  it('returns the chart tier when it fits over the domain', () => {
    // 30m over 1 day = 48 buckets — well under the cap.
    expect(overviewResolutionFor('30m', DAY)).toBe('30m');
    // 1h over 30 days = 720 buckets — still under the cap.
    expect(overviewResolutionFor('1h', 30 * DAY)).toBe('1h');
  });

  // The classic bug: 30D preset → 1Y rail domain → user shrinks window to
  // 6 hours → chart auto-picks 30m tier. 30m over 1Y = 17520 buckets, over the
  // 5000-bucket cap, so the overview should step up to the finest coarser
  // tier that fits (1h = 8760 buckets ≤ 5000? no; 12h = 730 ≤ 5000 yes).
  it('walks to a coarser tier when the chart tier exceeds the payload cap', () => {
    expect(overviewResolutionFor('30m', 365 * DAY)).toBe('12h');
  });

  // A truly fine chart tier over a wide domain still yields the finest coarser
  // tier that fits — not the chart tier and not `auto`, so the rail is at
  // worst one tier wider than the chart.
  it('never returns a tier finer than the chart', () => {
    // 30s over 30 days = 86400 buckets — cap forces a walk; 12h fits (60).
    const res = overviewResolutionFor('30s', 30 * DAY);
    expect(['1m', '5m', '30m', '1h', '12h', '24h']).toContain(res);
  });

  it('falls back to auto for an unknown chart tier', () => {
    expect(overviewResolutionFor('nonsense', DAY)).toBe('auto');
  });
});
