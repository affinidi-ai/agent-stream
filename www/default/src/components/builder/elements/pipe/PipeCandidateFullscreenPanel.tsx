import React, { Suspense } from 'react';
import type { ConfigPanelProps } from '../types';
import type { DeciderCandidate } from '../../../shared/deciderModel';

// Lazily resolved so the element registry (and its unit tests) never pull the
// editor's heavy provider-selector dependency graph into module load.
const CandidateEditor = React.lazy(
  () => import('../../../../pages/EditPipePage/tabs/CandidateEditor')
);

/**
 * Full-area editor for a single pipe-candidate node. The node's config carries
 * the candidate under `config.candidate`; this panel hands that slice to
 * CandidateEditor and merges every change back via `updateField('candidate',
 * …)`. The host page's seam reassembles the decider's candidate array from all
 * candidate nodes on the way back out (`readDecider`).
 */
const PipeCandidateFullscreenPanel: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  closeFullscreenEditor,
}) => {
  const candidate = (config?.candidate ?? {
    id: '',
    name: '',
    description: '',
    llm: { provider_type: '', model: '', endpoint_url: '' },
  }) as DeciderCandidate;
  return (
    <Suspense fallback={<div className="p-4 text-muted">Loading candidate editor…</div>}>
      <CandidateEditor
        candidate={candidate}
        onChange={updates => updateField('candidate', { ...candidate, ...updates })}
        onClose={closeFullscreenEditor}
      />
    </Suspense>
  );
};

export default PipeCandidateFullscreenPanel;
