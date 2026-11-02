/**
 * Conversion between the pipe edit form's flat `formData` and the
 * portable `pipe` snapshot carried by a {@link PipeTemplate}.
 *
 * A pipe is a flat linear config (not a node graph), so a template
 * always carries a complete snapshot — there is no partial/item
 * variant like surface templates have. Apply merges the snapshot into
 * the current form; serialize snapshots the current form, dropping
 * volatile per-instance fields and tokenizing the name / route so the
 * result is reusable.
 */

import {
  applyPipePlaceholders,
  clearUnresolvedPipeTokens,
  type PipePlaceholderContext,
} from './pipePlaceholders';

/** Fields that are per-instance and must never be baked into a template. */
const VOLATILE_FIELDS = ['id', 'created_at', 'updated_at'] as const;

/**
 * Snapshot the current pipe form into a template `pipe` blob. Volatile
 * fields are stripped and the name / route are replaced with their
 * placeholder tokens so the template is portable.
 */
export function pipeFormToTemplateBlob(formData: Record<string, any>): Record<string, any> {
  const blob: Record<string, any> = { ...formData };
  for (const field of VOLATILE_FIELDS) delete blob[field];
  if (typeof blob.name === 'string' && blob.name.trim()) blob.name = '$SURFACE_NAME';
  if (typeof blob.route === 'string' && blob.route.trim()) blob.route = '$SURFACE_ROUTE';
  return blob;
}

/**
 * Resolve a template `pipe` blob against the current form context:
 * substitute any known tokens that have a value, then blank the rest so
 * the form validator surfaces the missing required fields rather than
 * leaking literal `$SURFACE_NAME` tokens into the UI.
 */
export function resolvePipeTemplateBlob(
  blob: Record<string, any>,
  ctx: PipePlaceholderContext
): Record<string, any> {
  const substituted = applyPipePlaceholders(blob, ctx);
  const resolved = clearUnresolvedPipeTokens(substituted) as Record<string, any>;
  return resolved;
}
