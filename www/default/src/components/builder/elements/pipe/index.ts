/**
 * Pipe-scope element exports and helpers.
 *
 * Registration happens in the main `elements/index.ts` barrel (which imports
 * `pipeAnchorDefinitions` and registers them alongside the surface elements),
 * so this module only re-exports the pipe pieces consumers need.
 */
export { pipeAnchorDefinitions } from './definitions';
export { nodesFromPipe, PIPE_SURFACE_SIZE } from './nodesFromPipe';
export type { PipeConfigLike } from './nodesFromPipe';
export type { PipeNodeType, PipeKind } from './types';
