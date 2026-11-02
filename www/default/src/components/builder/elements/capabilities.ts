/**
 * Capability constants for the element registry.
 *
 * Capabilities are strings that describe what an element provides or needs.
 * Compatibility checks compare a candidate's `requires` against the union
 * of capabilities provided by source/target nodes.
 */

// ─── Pipeline capabilities ──────────────────────────────────────────────────
export const PIPELINE_SOURCE = 'pipeline-source'; // access-point provides
export const PIPELINE_SINK = 'pipeline-sink'; // target provides
export const PIPELINE_EDGE = 'pipeline-edge'; // middleware lives between source/sink

// ─── Structural capabilities ──────────────────────────────────────
export const SURFACE_PERIMETER = 'surface-perimeter'; // AP snaps to surface edge
export const SURFACE_INTERIOR = 'surface-interior'; // Target lives inside surface
export const MIDDLEWARE_SLOT = 'middleware-slot'; // Can host middleware on its edges

// ─── Feature capabilities (what middleware can attach to) ───────────────────
export const IDENTITY_TARGET = 'identity-target';
export const POLICY_TARGET = 'policy-target';
export const PAYMENT_TARGET = 'payment-target';
export const NETWORKING_TARGET = 'networking-target';
export const RATE_LIMIT_TARGET = 'rate-limit-target';
export const EXTENSION_TARGET = 'extension-target';
export const METADATA_TARGET = 'metadata-target';
export const MCP_TOOL_TARGET = 'mcp-tool-target';
export const CREDENTIAL_TARGET = 'credential-target';

// ─── Actor capabilities ─────────────────────────────────────────────────────
export const NPC_CONNECTABLE = 'npc-connectable'; // Can have NPC nodes attached
export const CONFIGURABLE = 'configurable'; // Has a config panel

// ─── Edge-attach hints (which side of the pipeline middleware runs on) ──────
export const ATTACHES_TO_INGRESS = 'attaches-to-ingress'; // AP-side
export const ATTACHES_TO_TARGET = 'attaches-to-target'; // Target-side

// ─── Pipe scope capabilities ────────────────────────────────────────────────
// The Pipe builder reuses the generic pipeline shape (source → body →
// upstream) but with its own anchor capabilities so pipe middleware only
// docks on pipe nodes.
export const PIPE_SOURCE = 'pipe-source'; // pipe-source provides (caller into the pipe)
export const PIPE_BODY = 'pipe-body'; // pipe-body provides (the configured pipe itself)
export const PIPE_UPSTREAM = 'pipe-upstream'; // pipe-upstream provides (the LLM hero)
export const PIPE_RESPONSE = 'pipe-response'; // pipe-response provides (the pipe's reply exit)

// ─── IDE scope capabilities ─────────────────────────────────────────────────
// The IDE builder reuses the generic pipeline shape (source → catalog) with
// its own anchor capabilities so IDE governance only docks on IDE nodes. The
// catalog aggregates member LLM Surfaces into a governed model-discovery menu.
export const IDE_SOURCE = 'ide-source'; // ide-source provides (caller into the IDE front door)
export const IDE_CATALOG = 'ide-catalog'; // ide-catalog provides (the aggregating hero)
export const IDE_RESPONSE = 'ide-response'; // ide-response provides (the catalogue's reply exit)
export const IDE_MEMBER = 'ide-member'; // ide-member provides (an exposed member surface)
