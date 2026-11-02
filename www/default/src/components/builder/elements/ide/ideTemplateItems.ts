/**
 * Partial IDE-surface template support — the IDE analog of
 * `serializePipeTemplate` / `applyPipeTemplateItems`.
 *
 * A partial template is an additive bundle of reusable canvas elements that
 * merges onto an existing surface. For IDE surfaces the reusable elements are
 * the **front-door governance singletons** — Caller Context (`ide-caller-auth`),
 * OPA Policy (`ide-opa-policy`) and Rate Limit (`ide-rate-limit`) — i.e. a
 * shareable "governance pack". Members and the source→catalogue→response spine
 * are intentionally NOT serializable: members reference specific LLM surfaces by
 * id and the spine is auto-seeded, so neither makes sense in a portable bundle.
 *
 * `serializeIdeTemplate` reads the selected governance nodes into
 * `PipeTemplateItem`s; `applyIdeTemplateItems` merges such a bundle back onto a
 * live IDE canvas, replacing any existing singleton of the same type and leaving
 * everything else untouched. The two round-trip exactly.
 */

import type { CanvasNode } from '../../SurfaceCanvas';
import type { PipeTemplateItem } from '../../../../api';
import type { SourceAuthConfig } from '../../../../types';
import { flattenSourceAuth, readSourceAuthFromNode } from '../caller-auth/sourceAuthMapping';

/** IDE node types capturable into a partial template item. */
export const TEMPLATABLE_IDE_NODE_TYPES: ReadonlySet<string> = new Set([
  'ide-caller-auth',
  'ide-opa-policy',
  'ide-rate-limit',
]);

export function canSerializeIdeNode(node: CanvasNode): boolean {
  return TEMPLATABLE_IDE_NODE_TYPES.has(node.type);
}

/** Human label for a node row in the create-template picker. */
export function describeIdeNode(node: CanvasNode): string {
  return node.label || node.type;
}

export interface SerializeIdeTemplateOptions {
  /**
   * Restrict capture to these node ids (a canvas selection). When omitted every
   * serializable node is captured.
   */
  nodeIds?: Iterable<string>;
}

const str = (v: unknown): string => (typeof v === 'string' ? v : '');
const numOrUndef = (v: unknown): number | undefined => (typeof v === 'number' ? v : undefined);

/**
 * Capture the selected IDE governance nodes as partial template items. Pure —
 * returns a fresh array, never mutates the nodes. Items round-trip exactly
 * through {@link applyIdeTemplateItems}.
 */
export function serializeIdeTemplate(
  nodes: CanvasNode[],
  options: SerializeIdeTemplateOptions = {}
): PipeTemplateItem[] {
  const allow = options.nodeIds ? new Set(options.nodeIds) : null;
  const included = nodes.filter(n => canSerializeIdeNode(n) && (!allow || allow.has(n.id)));
  const first = (type: string): CanvasNode | undefined => included.find(n => n.type === type);
  const items: PipeTemplateItem[] = [];

  const opa = first('ide-opa-policy');
  if (opa) {
    const c = (opa.config ?? {}) as Record<string, unknown>;
    items.push({
      scope: 'middleware',
      kind: 'ide-opa-policy',
      config: {
        enabled: c.enabled !== false,
        policy_definition_id: str(c.policy_definition_id),
        log_decisions: c.log_decisions === true,
      },
    });
  }

  const rl = first('ide-rate-limit');
  if (rl) {
    const c = (rl.config ?? {}) as Record<string, unknown>;
    const rpm = numOrUndef(c.requests_per_minute);
    const tpm = numOrUndef(c.tokens_per_minute);
    items.push({
      scope: 'middleware',
      kind: 'ide-rate-limit',
      config: {
        enabled: c.enabled !== false,
        ...(rpm !== undefined ? { requests_per_minute: rpm } : {}),
        ...(tpm !== undefined ? { tokens_per_minute: tpm } : {}),
      },
    });
  }

  const auth = first('ide-caller-auth');
  if (auth) {
    // The caller-context node holds a flattened config; capture the wire
    // `SourceAuthConfig` so it round-trips through `flattenSourceAuth` on apply.
    // A partially-configured node (e.g. JWT bearer with no strategy) yields
    // `null` and is skipped, so a template never carries a broken auth block.
    const wire = readSourceAuthFromNode(auth);
    if (wire) items.push({ scope: 'source', kind: 'ide-caller-auth', config: wire });
  }

  return items;
}

/**
 * Merge a partial template's `items[]` onto the current IDE canvas nodes,
 * replacing any existing governance singleton of the same type and leaving the
 * spine, members and gate chips untouched. Pure — returns fresh nodes; the
 * caller re-runs the IDE auto-layout to seat the new element on the
 * source→catalogue edge. Unknown kinds are skipped (forward-compat).
 */
export function applyIdeTemplateItems(
  nodes: CanvasNode[],
  items: PipeTemplateItem[]
): CanvasNode[] {
  let next = [...nodes];
  const replaceType = (type: string, node: CanvasNode | null) => {
    next = next.filter(n => n.type !== type);
    if (node) next.push(node);
  };

  for (const item of items) {
    const cfg = (item.config ?? {}) as Record<string, unknown>;
    switch (item.kind) {
      case 'ide-opa-policy': {
        const policyId = str(cfg.policy_definition_id);
        replaceType('ide-opa-policy', {
          id: 'ide-opa-policy',
          type: 'ide-opa-policy',
          label: 'OPA Policy',
          configured: cfg.enabled === false || !!policyId,
          parentId: 'ide-source',
          config: {
            enabled: cfg.enabled !== false,
            policy_definition_id: policyId,
            log_decisions: cfg.log_decisions === true,
          },
        });
        break;
      }
      case 'ide-rate-limit': {
        replaceType('ide-rate-limit', {
          id: 'ide-rate-limit',
          type: 'ide-rate-limit',
          label: 'Rate Limit',
          configured: true,
          parentId: 'ide-source',
          config: {
            enabled: cfg.enabled !== false,
            requests_per_minute:
              typeof cfg.requests_per_minute === 'number' ? cfg.requests_per_minute : 60,
            tokens_per_minute:
              typeof cfg.tokens_per_minute === 'number' ? cfg.tokens_per_minute : 100000,
          },
        });
        break;
      }
      case 'ide-caller-auth': {
        const flat = flattenSourceAuth(cfg as unknown as SourceAuthConfig);
        replaceType(
          'ide-caller-auth',
          flat
            ? {
                id: 'ide-caller-auth',
                type: 'ide-caller-auth',
                label: 'Caller Context',
                configured: true,
                parentId: 'ide-source',
                config: flat,
              }
            : null
        );
        break;
      }
      default:
        break;
    }
  }

  return next;
}
