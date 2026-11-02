import React, { Suspense } from 'react';
import type { ConfigPanelProps } from '../types';
import type { DeciderConfig } from '../../../shared/deciderModel';
import { DEFAULT_DECIDER_PROMPT } from '../../../shared/deciderModel';

// Lazily resolved so the element registry (and its unit tests) never pull the
// editor's heavy provider-selector dependency graph into module load.
const DeciderEditor = React.lazy(() => import('../../../../pages/EditPipePage/tabs/DeciderEditor'));

/**
 * Full-area editor for the pipe-decider node. The node's config carries the
 * decider under `config.decider`; this panel hands that slice to DeciderEditor
 * and merges every change back via `updateField('decider', …)`. The candidate
 * roster lives on sibling pipe-candidate nodes and is reassembled by the host
 * page's seam (`readDecider`); this editor owns the router LLM and prompt.
 */
const PipeDeciderFullscreenPanel: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  closeFullscreenEditor,
}) => {
  const decider = (config?.decider ?? {
    enabled: false,
    llm: { provider_type: '', model: '', endpoint_url: '' },
    system_prompt: DEFAULT_DECIDER_PROMPT,
    candidates: [],
  }) as DeciderConfig;
  return (
    <Suspense fallback={<div className="p-4 text-muted">Loading decider editor…</div>}>
      <DeciderEditor
        decider={decider}
        onChange={updates => updateField('decider', { ...decider, ...updates })}
        onClose={closeFullscreenEditor}
      />
    </Suspense>
  );
};

export default PipeDeciderFullscreenPanel;
