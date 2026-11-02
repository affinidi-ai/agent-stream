/**
 * Structural validation of a built surface payload.
 *
 * Runs *after* `registry.buildPayload` and *before* the API call.
 * Per-node "incomplete reason" already covers field-level requirements
 * (handled by `computeBlockingReason` in the page); this layer catches
 * shape problems that only surface once individual element slices are
 * stitched together — typically empty endpoints, empty required
 * top-level metadata, and dangling references on the canvas blob.
 *
 * Issues are returned (never thrown) so callers can render them in the
 * UI. `error` severity should block save; `warning` should inform.
 */

import { registry } from './registry';

export type ValidationSeverity = 'error' | 'warning';

export interface ValidationIssue {
  severity: ValidationSeverity;
  message: string;
  /**
   * Optional canvas node id the issue is attached to. The save toast
   * uses this to offer a "Show me" jump action.
   */
  nodeId?: string;
  /**
   * Optional dot-notation payload path the issue is attached to. Used
   * by the JSON editor to highlight the offending slice.
   */
  path?: string;
}

/**
 * Validate the built payload. Cheap, side-effect-free, no async.
 */
export function validateSurfacePayload(payload: any): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  if (!payload || typeof payload !== 'object') {
    issues.push({ severity: 'error', message: 'Surface payload is missing or malformed.' });
    return issues;
  }

  // Surface-level metadata.
  if (typeof payload.name !== 'string' || payload.name.trim().length === 0) {
    issues.push({
      severity: 'error',
      message: 'Surface name is required.',
      path: 'name',
    });
  }

  // Target endpoint — required for any surface that proxies to an
  // upstream. Surfaces wired exclusively to NPCs (managed agents) may
  // legitimately leave this empty; we surface it as a warning so the
  // user notices but don't hard-block.
  const targetEndpoint = payload?.target?.endpoint;
  if (typeof targetEndpoint !== 'string' || targetEndpoint.trim().length === 0) {
    issues.push({
      severity: 'warning',
      message: 'Target endpoint is empty — requests cannot be proxied upstream.',
      nodeId: 'target',
      path: 'target.endpoint',
    });
  }

  // Canvas blob — dangling parent refs and obvious chain leaks.
  const canvasNodes: any[] = Array.isArray(payload?.canvas?.nodes) ? payload.canvas.nodes : [];
  if (canvasNodes.length > 0) {
    const ids = new Set(canvasNodes.map(n => n?.id).filter(id => typeof id === 'string'));
    for (const n of canvasNodes) {
      if (typeof n?.parentId === 'string' && n.parentId && !ids.has(n.parentId)) {
        issues.push({
          severity: 'warning',
          message: `Canvas node "${n.id}" references missing parent "${n.parentId}".`,
          nodeId: typeof n.id === 'string' ? n.id : undefined,
        });
      }
    }
    // The `target` anchor should not be parented to a node that
    // doesn't legitimately sit on the request chain. Edge-drop
    // middleware (payment, networking, custom-metadata, etc.) re-parent
    // the target onto themselves by design — that's how the chain
    // order is encoded in `parentId` for `deriveEdges` to recover.
    // We only warn when the parent is something genuinely unexpected
    // (e.g. an NPC, an off-chain node) so the watchdog still catches
    // real structural drift without crying wolf on the routine
    // chain-splice output.
    const target = canvasNodes.find(n => n?.id === 'target');
    if (
      target &&
      typeof target.parentId === 'string' &&
      target.parentId &&
      target.parentId !== 'access-point' &&
      target.parentId !== '__surface__'
    ) {
      const parent = canvasNodes.find(n => n?.id === target.parentId);
      const parentDef = typeof parent?.type === 'string' ? registry.get(parent.type) : undefined;
      const parentIsChainMiddleware = parentDef?.dropMode === 'edge';
      if (!parentIsChainMiddleware) {
        issues.push({
          severity: 'warning',
          message: `Target anchor is parented to "${target.parentId}" — chain parent leaking onto an anchor.`,
          nodeId: 'target',
        });
      }
    }
  }

  return issues;
}

/** Convenience: any error-severity issues present? */
export function hasBlockingIssues(issues: ValidationIssue[]): boolean {
  return issues.some(i => i.severity === 'error');
}
