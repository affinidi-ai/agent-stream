/**
 * Merge one streamed content chunk into the accumulated answer.
 *
 * Different providers stream in two incompatible shapes:
 *  - **Incremental** (OpenAI / Anthropic): each chunk's `delta.content` is only
 *    the *new* piece, so the client concatenates.
 *  - **Cumulative snapshot** (Microsoft 365 Copilot / Entra, and some proxies):
 *    each chunk re-sends the *whole answer so far*, growing a little each time.
 *    Concatenating those duplicates the text and makes the UI jump.
 *
 * This helper handles both without knowing the provider: if the incoming chunk
 * is a superset of what we already have (a cumulative snapshot), we keep only
 * the snapshot; if it's a stale/duplicate shorter snapshot we ignore it; and
 * otherwise we treat it as an incremental delta and append it.
 *
 * Pure and side-effect-free so it can be unit-tested and reused.
 */
export function mergeStreamedContent(acc: string, incoming: string): string {
  if (!incoming) return acc;
  if (!acc) return incoming;
  // Cumulative snapshot — the chunk contains everything we already have plus
  // the new tail. Adopt the fuller snapshot (only the new suffix is visible).
  if (incoming.startsWith(acc)) return incoming;
  // Stale or duplicate snapshot that is shorter than (or equal to) what we
  // already rendered — nothing new to add.
  if (acc.startsWith(incoming)) return acc;
  // Incremental delta — a brand-new piece of the answer; append it.
  return acc + incoming;
}
