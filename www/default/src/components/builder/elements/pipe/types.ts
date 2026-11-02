/**
 * Pipe-scope node type identifiers.
 *
 * These mirror the pipe members of the closed `SurfaceNodeType` union in
 * `../../nodeTypes.ts`. Every member is registered with `scope: 'pipe'` so it
 * only appears in the Pipe builder palette. Keep the two in sync.
 */
export type PipeNodeType =
  | 'pipe-source'
  | 'pipe-upstream'
  | 'pipe-response'
  | 'pipe-caller-auth'
  | 'pipe-rate-limit'
  | 'pipe-cost-tracking'
  | 'pipe-override-policy'
  | 'pipe-opa-policy'
  | 'pipe-prompt-guard'
  | 'pipe-judge'
  | 'pipe-jury'
  | 'pipe-decider'
  | 'pipe-web-search'
  | 'pipe-web-fetch'
  | 'pipe-router'
  | 'pipe-audio-input'
  | 'pipe-audio-stream'
  | 'pipe-image-input'
  | 'pipe-document-input'
  | 'pipe-drift-harness';

/** Backend `PipeType` discriminants, mirrored from `src/pipes/config.rs`. */
export type PipeKind = 'llm' | 'webhook' | 'ide_catalog';
