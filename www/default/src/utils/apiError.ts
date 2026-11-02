/**
 * Turn a backend error response into a user-friendly toast string.
 *
 * The gateway returns JSON error bodies in a few shapes — `{ message }`,
 * `{ error, details }`, `{ error }`, `{ error: { message } }`, `{ detail }` —
 * so dumping the raw body into a toast shows unreadable JSON. These helpers
 * pull the human message out and append the HTTP status in parentheses, e.g.
 * `"Appliance limit reached… (403)"`.
 */

/** Best-effort human message from a response body (JSON or plain text). */
export function extractErrorMessage(body: string | null | undefined): string | null {
  const trimmed = (body ?? '').trim();
  if (!trimmed) return null;
  try {
    return messageFromJson(JSON.parse(trimmed)) ?? trimmed;
  } catch {
    // Not JSON — the body is already plain text.
    return trimmed;
  }
}

function messageFromJson(value: unknown): string | null {
  if (value == null) return null;
  if (typeof value === 'string') return value.trim() || null;
  if (typeof value !== 'object') return String(value);
  const obj = value as Record<string, unknown>;
  // Ordered by how the gateway most commonly names the field. `details` comes
  // before `error` because `{ error, details }` bodies put a generic status
  // label in `error` and the specific reason in `details`.
  for (const candidate of [obj.message, obj.details, obj.error, obj.detail, obj.msg, obj.reason]) {
    if (typeof candidate === 'string' && candidate.trim()) return candidate.trim();
    if (
      candidate &&
      typeof candidate === 'object' &&
      typeof (candidate as { message?: unknown }).message === 'string' &&
      (candidate as { message: string }).message.trim()
    ) {
      return (candidate as { message: string }).message.trim();
    }
  }
  return null;
}

/**
 * Compose the string shown to the user: the extracted body message (falling
 * back to the status text, then a generic label) with the HTTP status in
 * parentheses.
 */
export function formatApiError(
  status: number | undefined,
  body: string | null | undefined,
  statusText?: string
): string {
  const message = extractErrorMessage(body) || (statusText || '').trim() || 'Request failed';
  return status ? `${message} (${status})` : message;
}
