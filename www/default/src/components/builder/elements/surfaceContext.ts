import type { CanvasNode } from '../SurfaceCanvas';
import type {
  Protocol,
  SurfaceContext,
  SurfaceContextLlmProvider,
  SurfaceContextSurfaceRef,
} from './types';

/**
 * Build a `SurfaceContext` from the canvas node list.
 * Used by `registry.getDependencyWarnings()` and similar context-aware checks.
 * `llmProviders` is only meaningful in a pipe-scoped builder; surface-scoped
 * callers omit it. `availableSurfaces` is the cross-surface dependency-target
 * registry (e.g. the IDE editor's live LLM-Surface list); omit it when the
 * host has no such registry so existence checks stay inert.
 */
export function buildSurfaceContext(
  protocol: string | undefined,
  allNodes: CanvasNode[] | undefined,
  llmProviders?: SurfaceContextLlmProvider[],
  availableSurfaces?: SurfaceContextSurfaceRef[]
): SurfaceContext {
  const nodes = allNodes ?? [];
  const accessPoint = nodes.find(n => n.type === 'access-point');
  const target = nodes.find(n => n.type === 'target');
  return {
    protocol: (protocol as Protocol) || 'a2a',
    accessPoint: accessPoint?.config ?? {},
    target: target?.config ?? {},
    allNodes: nodes,
    llmProviders: llmProviders ?? [],
    availableSurfaces,
  };
}
