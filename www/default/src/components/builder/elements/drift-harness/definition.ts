import * as Cap from '../capabilities';
import type { NodeDefinition } from '../types';
import DriftHarnessPanel from './DriftHarnessPanel';
import DriftHarnessFullscreenPanel from './DriftHarnessFullscreenPanel';

/**
 * **Drift Harness** — an LLM-bound monitoring element for an LLM surface.
 *
 * It carries no request-pipeline role: it configures behavioural drift
 * monitoring (refusal / safety / length / latency / schema-validity + replay
 * evaluation), regression gating, and `drift.detected` alerting for the surface
 * as a whole. Following the Router pattern, the node is a thin handle whose only
 * config is a mirror `enabled` flag; the real configuration is the surface's
 * base-pipe `drift` block, read and written through the surface meta in the
 * sidebar + full-page editor. `llmTool` binds it to the LLM node's top landing
 * area and lays it out in the tool row above the LLM — the same drop target as
 * the Inputs/Tools elements — so it is never a free-floating surface node.
 */
export const pipeDriftHarnessDefinition: NodeDefinition = {
  type: 'pipe-drift-harness',
  label: 'Drift Harness',
  description: "Monitor and alert on this surface's behavioural drift",
  icon: '\uf83e', // fa-wave-square
  paletteIcon: 'fa-wave-square',
  color: '#20c997',
  shape: 'circle',
  defaultRadius: 18,
  resizable: false,
  draggable: true,
  deletable: true,
  containedInSurface: true,
  edgeConstrained: false,
  xWeight: 0.5,
  stage: 'middleware',
  cardinality: 'singleton',
  paletteCategory: 'enhancement',
  paletteOrder: 30,
  scope: 'pipe',
  dropMode: 'canvas',
  llmTool: true,
  hiddenFromPalette: false,
  defaultConfig: () => ({ enabled: true }),
  help: {
    title: 'Drift Harness',
    bodyHtml:
      '<p>Monitor how this LLM surface&apos;s behaviour changes over time — <strong>refusal rate</strong>, <strong>safety-flag rate</strong>, <strong>response length</strong>, <strong>latency</strong>, <strong>schema validity</strong>, plus replay-graded <strong>semantic drift</strong> and <strong>quality</strong> — against a pinned baseline.</p><p>Enable sampling to fold live traffic into per-dimension time series (see the <strong>LLM Drift</strong> page), optionally block saves while the surface is regressing, and fire a <strong>drift.detected</strong> alert to your chosen integrations when it moves past the baseline. All of it is configured in the full-page editor.</p>',
  },
  provides: [Cap.CONFIGURABLE],
  requires: {},
  mutedReason: c => (c?.enabled === false ? 'Disabled' : null),
  incompleteReason: () => null,
  ConfigPanel: DriftHarnessPanel,
  FullscreenPanel: DriftHarnessFullscreenPanel,
  summary: c => (c?.enabled === false ? 'off' : 'monitoring'),
};
