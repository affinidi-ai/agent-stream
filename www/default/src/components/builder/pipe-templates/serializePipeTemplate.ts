/**
 * Inverse of {@link applyPipeTemplateItems}: convert canvas nodes back
 * into `PipeTemplateItem`s suitable for saving as a partial pipe
 * template (an additive item bundle).
 *
 * A full pipe template carries a whole-pipe snapshot; a partial template
 * carries only the items the author chose, so this reads each
 * serializable node's editable slice and emits the matching item `kind`.
 * The emitted `config` keys round-trip exactly through
 * `applyPipeTemplateItems`. Instance secret bindings
 * (`api_key_secret_id`) are dropped by default so a template is portable
 * and never leaks a secret reference.
 */

import type { CanvasNode } from '../SurfaceCanvas';
import type { PipeTemplateItem } from '../../../api';

/** Pipe node types that can be captured into a partial template item. */
export const TEMPLATABLE_PIPE_NODE_TYPES: ReadonlySet<string> = new Set([
  'pipe-source',
  'pipe-upstream',
  'pipe-rate-limit',
  'pipe-cost-tracking',
  'pipe-override-policy',
  'pipe-prompt-guard',
  'pipe-judge',
  'pipe-jury',
  'pipe-decider',
]);

export function canSerializePipeNode(node: CanvasNode): boolean {
  return TEMPLATABLE_PIPE_NODE_TYPES.has(node.type);
}

/** Human label for a node row in the create-template picker. */
export function describePipeNode(node: CanvasNode): string {
  return node.label || node.type;
}

export interface SerializePipeTemplateOptions {
  /**
   * Restrict capture to these node ids (a canvas selection). When omitted
   * every serializable node is captured.
   */
  nodeIds?: Iterable<string>;
  /**
   * Drop instance-specific secret bindings (`api_key_secret_id`) from the
   * captured upstream config so the template stays portable. Default true.
   */
  scrubSecrets?: boolean;
}

const str = (v: unknown): string => (typeof v === 'string' ? v : '');
const numOrUndef = (v: unknown): number | undefined => (typeof v === 'number' ? v : undefined);

/**
 * Capture the given canvas nodes as partial pipe template items. Pure —
 * returns a fresh array, never mutates the nodes. Items are emitted in a
 * stable order (source → upstream → middleware) regardless of node order.
 */
export function serializePipeTemplate(
  nodes: CanvasNode[],
  options: SerializePipeTemplateOptions = {}
): PipeTemplateItem[] {
  const scrubSecrets = options.scrubSecrets !== false;
  const allow = options.nodeIds ? new Set(options.nodeIds) : null;

  const included = nodes.filter(n => canSerializePipeNode(n) && (!allow || allow.has(n.id)));
  const byType = (type: string) => included.filter(n => n.type === type);
  const first = (type: string): CanvasNode | undefined => byType(type)[0];

  const items: PipeTemplateItem[] = [];

  const source = first('pipe-source');
  if (source) {
    items.push({
      scope: 'source',
      kind: 'pipe-source',
      config: { listen_address: str(source.config?.listen_address) },
    });
  }

  const upstream = first('pipe-upstream');
  if (upstream) {
    const config: Record<string, unknown> = {
      provider: str(upstream.config?.provider),
      model: str(upstream.config?.model),
      endpoint: str(upstream.config?.endpoint),
    };
    const secret = str(upstream.config?.api_key_secret_id);
    if (!scrubSecrets && secret) config.api_key_secret_id = secret;
    items.push({ scope: 'upstream', kind: 'pipe-upstream', config });
  }

  const rateLimit = first('pipe-rate-limit');
  if (rateLimit) {
    const rpm = numOrUndef(rateLimit.config?.requests_per_minute);
    const tpm = numOrUndef(rateLimit.config?.tokens_per_minute);
    items.push({
      scope: 'middleware',
      kind: 'pipe-rate-limit',
      config: {
        enabled: rateLimit.config?.enabled !== false,
        ...(rpm !== undefined ? { requests_per_minute: rpm } : {}),
        ...(tpm !== undefined ? { tokens_per_minute: tpm } : {}),
      },
    });
  }

  const cost = first('pipe-cost-tracking');
  if (cost) {
    const inPrice = numOrUndef(cost.config?.input_price_per_1k);
    const outPrice = numOrUndef(cost.config?.output_price_per_1k);
    items.push({
      scope: 'middleware',
      kind: 'pipe-cost-tracking',
      config: {
        enabled: cost.config?.enabled === true,
        ...(inPrice !== undefined ? { input_price_per_1k: inPrice } : {}),
        ...(outPrice !== undefined ? { output_price_per_1k: outPrice } : {}),
      },
    });
  }

  const override = first('pipe-override-policy');
  if (override) {
    const entries = Array.isArray(override.config?.entries) ? override.config.entries : [];
    items.push({
      scope: 'middleware',
      kind: 'pipe-override-policy',
      config: { entries },
    });
  }

  const guards = byType('pipe-prompt-guard');
  if (guards.length > 0) {
    const request = guards.map(n => n.config?.request).find(r => Array.isArray(r) && r.length > 0);
    const response = guards
      .map(n => n.config?.response)
      .find(r => Array.isArray(r) && r.length > 0);
    const llmPii = guards.map(n => n.config?.llm_pii).find(r => Array.isArray(r) && r.length > 0);
    items.push({
      scope: 'middleware',
      kind: 'pipe-prompt-guard',
      config: {
        request: Array.isArray(request) ? request : [],
        response: Array.isArray(response) ? response : [],
        llm_pii: Array.isArray(llmPii) ? llmPii : [],
      },
    });
  }

  const judge = first('pipe-judge');
  if (judge && judge.config?.judge && typeof judge.config.judge === 'object') {
    items.push({
      scope: 'middleware',
      kind: 'pipe-judge',
      config: { judge: judge.config.judge },
    });
  }

  const jury = first('pipe-jury');
  if (jury && jury.config?.jury && typeof jury.config.jury === 'object') {
    // The jury node owns only jury-level settings; the jurors are first-class
    // sibling nodes. Reassemble the jurors array from them (ordered by their
    // stored index) so the captured `jury` config round-trips a complete jury
    // — mirrors `readJury`. Juror nodes are read from the full node list, not
    // the (possibly selection-filtered) `included` set, so capturing the jury
    // always captures its jurors.
    const jurors = nodes
      .filter(n => n.type === 'pipe-juror')
      .map(n => {
        const cfg = (n.config ?? {}) as { juror?: unknown; jurorIndex?: unknown };
        const juror =
          cfg.juror && typeof cfg.juror === 'object'
            ? (cfg.juror as Record<string, unknown>)
            : null;
        const index = typeof cfg.jurorIndex === 'number' ? cfg.jurorIndex : 0;
        return { index, juror };
      })
      .filter((e): e is { index: number; juror: Record<string, unknown> } => e.juror !== null)
      .sort((a, b) => a.index - b.index)
      .map(e => e.juror);
    items.push({
      scope: 'middleware',
      kind: 'pipe-jury',
      config: { jury: { ...(jury.config.jury as Record<string, unknown>), jurors } },
    });
  }

  const decider = first('pipe-decider');
  if (decider && decider.config?.decider && typeof decider.config.decider === 'object') {
    // The decider node owns only router-level settings; the candidates are
    // first-class sibling nodes. Reassemble the candidates array from them
    // (ordered by their stored index) so the captured `decider` config
    // round-trips a complete decider — mirrors `readDecider`.
    const candidates = nodes
      .filter(n => n.type === 'pipe-candidate')
      .map(n => {
        const cfg = (n.config ?? {}) as { candidate?: unknown; candidateIndex?: unknown };
        const candidate =
          cfg.candidate && typeof cfg.candidate === 'object'
            ? (cfg.candidate as Record<string, unknown>)
            : null;
        const index = typeof cfg.candidateIndex === 'number' ? cfg.candidateIndex : 0;
        return { index, candidate };
      })
      .filter(
        (e): e is { index: number; candidate: Record<string, unknown> } => e.candidate !== null
      )
      .sort((a, b) => a.index - b.index)
      .map(e => e.candidate);
    items.push({
      scope: 'middleware',
      kind: 'pipe-decider',
      config: { decider: { ...(decider.config.decider as Record<string, unknown>), candidates } },
    });
  }

  return items;
}
