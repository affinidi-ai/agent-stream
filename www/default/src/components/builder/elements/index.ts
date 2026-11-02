/**
 * Element registry — entry point.
 *
 * Importing this module registers every element definition. Consumers should
 * import `registry` from here (or directly from `./registry`).
 */

import { registry } from './registry';

import { surfaceDefinition } from './surface/definition';
import { networkingDefinition } from './networking/definition';
import { rateLimitDefinition } from './rate-limit/definition';
import { customMetadataDefinition } from './custom-metadata/definition';
import { extensionValidationDefinition } from './extension-validation/definition';
import { extensionRulesDefinition } from './extension-rules/definition';
import { targetVariantDefinition } from './target-variant/definition';
import { callerAuthDefinition } from './caller-auth/definition';
import { credentialDelegationDefinition } from './credential-delegation/definition';

import { npcDefinitions } from './npc/definition';
import { humanDefinition } from './human/definition';
import { callerDefinition } from './caller/definition';
import { localGatewayHopDefinition } from './local-gateway-hop/definition';
import { remoteGatewayDefinition } from './remote-gateway/definition';
import { remoteChannelDefinition } from './remote-channel/definition';

import { pipeAnchorDefinitions } from './pipe/definitions';
import { ideAnchorDefinitions } from './ide/definitions';

// Core (auto-created with the surface)
registry.register(surfaceDefinition);

// Enhancement middleware
registry.register(networkingDefinition);
registry.register(rateLimitDefinition);
registry.register(customMetadataDefinition);
registry.register(extensionValidationDefinition);
registry.register(extensionRulesDefinition);
registry.register(targetVariantDefinition);
registry.register(callerAuthDefinition);
registry.register(credentialDelegationDefinition);

// NPCs and actors
for (const npc of npcDefinitions) registry.register(npc);
registry.register(humanDefinition);
registry.register(callerDefinition);

// Synthesised fabric:// destination representation (canvas-only, never persisted)
registry.register(localGatewayHopDefinition);
registry.register(remoteGatewayDefinition);
registry.register(remoteChannelDefinition);

// Pipe-scope anchors (scope: 'pipe'). Registered on the shared registry;
// surface palettes are unaffected thanks to the scope filter.
for (const def of pipeAnchorDefinitions) registry.register(def);

// IDE-scope anchors (scope: 'ide'). Same registry, scope filter keeps them
// out of the surface and pipe palettes.
for (const def of ideAnchorDefinitions) registry.register(def);

export { registry } from './registry';
export type { DependencyWarning } from './registry';
export {
  buildCanvasBlob,
  readCanvasSurfaceSize,
  readCanvasView,
  readCanvasSettings,
  isEmptySlice,
  readPayloadPath,
} from './registry';
export type { CanvasBlob } from './registry';
export { buildSurfaceContext } from './surfaceContext';
export { validateSurfacePayload, hasBlockingIssues } from './validateSurface';
export type { ValidationIssue, ValidationSeverity } from './validateSurface';
export type {
  NodeDefinition,
  NodeShape,
  NodeType,
  Protocol,
  PipelineStage,
  Cardinality,
  PaletteCategory,
  BuilderScope,
  ResizeRange,
  CompatibilitySpec,
  SurfaceContext,
  FeatureDependency,
  ConfigPanelProps,
} from './types';
export * as Capabilities from './capabilities';
