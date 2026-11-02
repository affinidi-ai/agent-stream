/**
 * Placeholder engine for pipe templates.
 *
 * A pipe template ships a verbatim `pipe` snapshot (the same flat shape
 * the pipe edit form holds). To keep templates reusable, instance-specific
 * string fields may carry placeholder tokens that the apply step
 * substitutes against the current form context:
 *
 *   - `$SURFACE_NAME`     → the pipe's display name
 *   - `$SURFACE_ROUTE`    → the pipe's listen route
 *   - `$SURFACE_ENDPOINT` → the upstream endpoint URL
 *
 * Pure TypeScript — the Rust side treats the `pipe` blob as opaque. The
 * substitution is substring-based and case-sensitive so values like
 * `"$SURFACE_ROUTE/v1"` work. Unknown tokens are left untouched.
 */

export const PIPE_PLACEHOLDER_TOKENS = [
  '$SURFACE_NAME',
  '$SURFACE_ROUTE',
  '$SURFACE_ENDPOINT',
] as const;

export type PipePlaceholderToken = (typeof PIPE_PLACEHOLDER_TOKENS)[number];

export interface PipePlaceholderContext {
  name?: string;
  route?: string;
  endpoint?: string;
}

const TOKEN_TO_CONTEXT_KEY: Record<PipePlaceholderToken, keyof PipePlaceholderContext> = {
  $SURFACE_NAME: 'name',
  $SURFACE_ROUTE: 'route',
  $SURFACE_ENDPOINT: 'endpoint',
};

const LEGACY_TOKEN_TO_CONTEXT_KEY = {
  $PIPE_NAME: 'name',
  $PIPE_ROUTE: 'route',
  $PIPE_ENDPOINT: 'endpoint',
} as const satisfies Record<string, keyof PipePlaceholderContext>;

type KnownPipePlaceholderToken = PipePlaceholderToken | keyof typeof LEGACY_TOKEN_TO_CONTEXT_KEY;

const KNOWN_TOKEN_TO_CONTEXT_KEY: Record<KnownPipePlaceholderToken, keyof PipePlaceholderContext> =
  {
    ...TOKEN_TO_CONTEXT_KEY,
    ...LEGACY_TOKEN_TO_CONTEXT_KEY,
  };

// Anchored to `$` followed by uppercase / underscore so `$SURFACE_ROUTES`
// does not partially match `$SURFACE_ROUTE`.
const TOKEN_RE = /\$[A-Z_]+/g;

function isKnownToken(raw: string): raw is KnownPipePlaceholderToken {
  return Object.prototype.hasOwnProperty.call(KNOWN_TOKEN_TO_CONTEXT_KEY, raw);
}

function substituteString(input: string, ctx: PipePlaceholderContext): string {
  return input.replace(TOKEN_RE, match => {
    if (!isKnownToken(match)) return match;
    const value = ctx[KNOWN_TOKEN_TO_CONTEXT_KEY[match]];
    if (value === undefined || value === null || value === '') return match;
    return value;
  });
}

function walk(node: unknown, ctx: PipePlaceholderContext): unknown {
  if (typeof node === 'string') return substituteString(node, ctx);
  if (Array.isArray(node)) return node.map(entry => walk(entry, ctx));
  if (node && typeof node === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      out[k] = walk(v, ctx);
    }
    return out;
  }
  return node;
}

/**
 * Deep-walk `payload` and replace placeholder tokens in every string.
 * The input is never mutated.
 */
export function applyPipePlaceholders<T = unknown>(payload: T, ctx: PipePlaceholderContext): T {
  return walk(payload, ctx) as T;
}

/**
 * Strip any remaining known placeholder tokens from string fields so the
 * pipe form sees empty strings (which it then prompts the user to fill)
 * instead of literal `$SURFACE_NAME` / `$SURFACE_ROUTE` leaking into the UI.
 */
export function clearUnresolvedPipeTokens<T = unknown>(payload: T): T {
  const visit = (node: unknown): unknown => {
    if (typeof node === 'string') {
      return node.replace(TOKEN_RE, m => (isKnownToken(m) ? '' : m));
    }
    if (Array.isArray(node)) return node.map(visit);
    if (node && typeof node === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
        out[k] = visit(v);
      }
      return out;
    }
    return node;
  };
  return visit(payload) as T;
}
