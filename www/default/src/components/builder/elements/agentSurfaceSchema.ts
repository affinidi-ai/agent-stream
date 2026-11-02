/**
 * AgentSurface payload field inventory.
 *
 * Mirrored by hand from `src/config/agent_surface.rs` — the source of
 * truth lives in Rust. This module exists so the build-time payload
 * audit can assert that every element's `payloadPath` and every edge
 * slot's `payloadPathTemplate` resolves to a real persisted field.
 *
 * If a backend field is added/renamed/removed, update this file too.
 * The audit test in `__tests__/payloadAudit.test.ts` is the regression
 * gate.
 *
 * Path conventions:
 * - Dotted JSON paths rooted at the AgentSurface payload.
 * - The frontend translation layer in `src/api.ts` rewrites
 *   `target.agent_identity` → `target.identity_injection` on submit;
 *   the UI-side path is what we list here so the builder code reads
 *   cleanly and the translation is an implementation detail.
 */

/**
 * Every persisted path the UI is allowed to write to (or the
 * translation chokepoint in `src/api.ts` rewrites to a real one).
 */
export const AGENT_SURFACE_PATHS: ReadonlySet<string> = new Set([
  // ── Top level ────────────────────────────────────────────────────
  'surface_id',
  'name',
  'description',
  'status',
  'agent_did',
  'tags',
  'access_point',
  'target',
  'canvas',
  'outbound_credentials',

  // ── Identity slots (channel-level managed identity split) ────────
  'identity_slots.inbound',
  'identity_slots.protected',
  'identity_slots.external',

  // ── AccessPoint ──────────────────────────────────────────────────
  'access_point.listen_address',
  'access_point.route',
  'access_point.protocol',
  'access_point.caller_authentication',
  'access_point.caller_context',
  'access_point.identity_resolution',
  'access_point.inbound_policy',
  'access_point.rate_limit',
  'access_point.extension_validation',
  'access_point.trust_registry_verification',
  'access_point.publish_to_did_document',
  'access_point.supported_extensions',
  'access_point.agent_card_path',
  'access_point.response_custom_metadata',
  'access_point.didwebvh_identity',

  // ── Target ───────────────────────────────────────────────────────
  'target.endpoint',
  'target.auth',
  'target.policy',
  'target.response_policy',
  'target.payment_policy',
  'target.networking',
  'target.identity_injection',
  'target.trust_registry_injection',
  'target.trust_registry_injection_inbound',
  'target.extension_rules',
  'target.custom_metadata',
  'target.response_custom_metadata',
  'target.mcp_identity_config',
  'target.fabric_target_name',
  'target.mpp_auto_pay',
  'target.mpp_auto_pay_max_amount',
]);

/**
 * UI-side aliases the api.ts translation layer rewrites on submit.
 * Listed here so the audit treats them as valid even though they
 * never appear on the wire.
 */
export const UI_ONLY_ALIASES: ReadonlySet<string> = new Set([
  // `target.agent_identity` → `target.identity_injection` (see
  // `toBackendSurface` in src/api.ts).
  'target.agent_identity',
]);

/**
 * Normalise a slot's `payloadPathTemplate` (which may contain
 * `{owner}` substitutions) into a schema-comparable path with
 * `[*]` for any variable slot id.
 */
export function normalisePath(template: string): string {
  return template.replace(/\[\{owner\}\]/g, '[*]').replace(/\.\{owner\}/g, '.*');
}

/**
 * True when `path` (already normalised by `normalisePath` if it had
 * `{owner}`) is either a real AgentSurface field or a known UI alias.
 */
export function isKnownAgentSurfacePath(path: string): boolean {
  if (!path) return false;
  if (AGENT_SURFACE_PATHS.has(path)) return true;
  if (UI_ONLY_ALIASES.has(path)) return true;
  return false;
}
