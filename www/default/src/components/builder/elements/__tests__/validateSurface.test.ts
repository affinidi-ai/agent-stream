/**
 * `validateSurfacePayload` unit tests.
 */

import { validateSurfacePayload, hasBlockingIssues } from '../validateSurface';
// Side-effect import: registers every element definition so the
// validator's registry-aware checks (e.g. parent-type classification
// for the chain-leak watchdog) can resolve types.
import '../index';

describe('validateSurfacePayload', () => {
  const ok = () => ({
    name: 'My Surface',
    target: { endpoint: 'https://upstream/y' },
  });

  it('returns no issues for a minimally-valid surface', () => {
    const issues = validateSurfacePayload(ok());
    expect(issues).toEqual([]);
    expect(hasBlockingIssues(issues)).toBe(false);
  });

  it('flags missing surface name as an error', () => {
    const issues = validateSurfacePayload({ ...ok(), name: '' });
    expect(issues.find(i => i.path === 'name')).toMatchObject({ severity: 'error' });
    expect(hasBlockingIssues(issues)).toBe(true);
  });

  it('flags whitespace-only surface name as an error', () => {
    const issues = validateSurfacePayload({ ...ok(), name: '   ' });
    expect(issues.find(i => i.path === 'name')).toMatchObject({ severity: 'error' });
  });

  it('warns on empty target endpoint without blocking', () => {
    const issues = validateSurfacePayload({ ...ok(), target: { endpoint: '' } });
    const ep = issues.find(i => i.path === 'target.endpoint');
    expect(ep).toMatchObject({ severity: 'warning', nodeId: 'target' });
    expect(hasBlockingIssues(issues)).toBe(false);
  });

  it('warns on canvas nodes whose parentId is missing', () => {
    const payload = {
      ...ok(),
      canvas: {
        nodes: [
          { id: 'access-point', parentId: null },
          { id: 'target', parentId: 'access-point' },
          { id: 'orphan', parentId: 'ghost-id' },
        ],
      },
    };
    const issues = validateSurfacePayload(payload);
    const orphan = issues.find(i => i.nodeId === 'orphan');
    expect(orphan).toMatchObject({
      severity: 'warning',
      message: expect.stringContaining('missing parent "ghost-id"'),
    });
  });

  it('warns when target anchor is parented to a non-chain node', () => {
    const payload = {
      ...ok(),
      canvas: {
        nodes: [
          { id: '__surface__' },
          { id: 'access-point', parentId: '__surface__' },
          { id: 'rogue', type: 'npc-endpoint' },
          { id: 'target', parentId: 'rogue' },
        ],
      },
    };
    const issues = validateSurfacePayload(payload);
    const leak = issues.find(i => i.nodeId === 'target');
    expect(leak).toMatchObject({ severity: 'warning' });
    expect(leak!.message).toContain('chain parent leaking');
  });

  it('does NOT warn when target is parented to a chain middleware (legitimate splice output)', () => {
    // Edge-drop middlewares (networking, custom-metadata, …)
    // re-parent the target onto themselves to encode chain order in
    // `parentId` for `deriveEdges` to recover. This is by design and
    // must not trip the structural-leak watchdog.
    const payload = {
      ...ok(),
      canvas: {
        nodes: [
          { id: '__surface__' },
          { id: 'access-point', parentId: '__surface__' },
          { id: 'networking', type: 'networking', parentId: 'access-point' },
          { id: 'target', parentId: 'networking' },
        ],
      },
    };
    const issues = validateSurfacePayload(payload);
    expect(issues.find(i => i.nodeId === 'target')).toBeUndefined();
  });

  it('does NOT warn when target is parented to access-point or surface', () => {
    const payload = {
      ...ok(),
      canvas: {
        nodes: [
          { id: 'access-point', parentId: '__surface__' },
          { id: 'target', parentId: 'access-point' },
        ],
      },
    };
    const issues = validateSurfacePayload(payload);
    expect(issues.find(i => i.nodeId === 'target')).toBeUndefined();
  });

  it('returns a single error for null/undefined payload', () => {
    expect(validateSurfacePayload(null)).toMatchObject([{ severity: 'error' }]);
    expect(validateSurfacePayload(undefined)).toMatchObject([{ severity: 'error' }]);
  });
});
