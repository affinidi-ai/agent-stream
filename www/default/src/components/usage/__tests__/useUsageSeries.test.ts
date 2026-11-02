import { windowForSecs } from '../usageSeries';

const NOW = 1700000000; // Fixed "now" for deterministic testing

/**
 * Mock the global Date to return a fixed timestamp.
 */
function mockNow(timestamp: number) {
  const original = Date.now;
  Date.now = jest.fn(() => timestamp * 1000);
  return () => {
    Date.now = original;
  };
}

describe('scrubber overview is anchored to the fixed rail domain', () => {
  let unmock: () => void;

  beforeEach(() => {
    unmock = mockNow(NOW);
  });

  afterEach(() => {
    unmock();
  });

  it('spans the fixed domain [now - domainSecs, now] (endOffset 0)', () => {
    // The scrubber renders a FIXED domain anchored to `now`, and the selection
    // window pans WITHIN it. The overview must therefore be fetched for that
    // same fixed domain (endOffset 0) — NOT the committed window's endOffset.
    // Sliding it by the pan offset would move the fetched data out from under
    // the fixed render domain, making rail bars near `now` vanish when the
    // selection is panned into the past (the regression this guards against).
    const domainSecs = 86400; // 24 hours
    const overview = windowForSecs(domainSecs, 0);

    expect(overview.to).toBe(NOW);
    expect(overview.from).toBe(NOW - domainSecs);
  });

  it('does not move when the selection is panned into the past', () => {
    // The chart uses a non-zero endOffset when panned, but the overview always
    // uses endOffset 0, so its window is identical whether live or panned.
    const domainSecs = 86400;
    const panOffsetSecs = 43200; // selection panned 12h back

    const overviewLive = windowForSecs(domainSecs, 0);
    const overviewWhilePanned = windowForSecs(domainSecs, 0); // still endOffset 0
    const chartWhilePanned = windowForSecs(domainSecs, panOffsetSecs);

    expect(overviewWhilePanned.from).toBe(overviewLive.from);
    expect(overviewWhilePanned.to).toBe(overviewLive.to);
    // The panned chart window really is different from the anchored overview.
    expect(chartWhilePanned.to).toBeLessThan(overviewLive.to);
  });

  it('keeps the panned chart window inside the fixed domain', () => {
    // The selection can only pan within [now - domainSecs, now], so the fixed
    // overview always fully covers it.
    const domainSecs = 86400; // rail extent
    const chartWindowSecs = 10800; // 3h selection
    const panOffsetSecs = 43200; // panned 12h back, still within the domain

    const domain = windowForSecs(domainSecs, 0);
    const chart = windowForSecs(chartWindowSecs, panOffsetSecs);

    expect(chart.from).toBeGreaterThanOrEqual(domain.from);
    expect(chart.to).toBeLessThanOrEqual(domain.to);
  });
});
