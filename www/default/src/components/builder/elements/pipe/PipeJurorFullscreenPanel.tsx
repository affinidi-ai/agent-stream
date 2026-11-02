import React, { Suspense } from 'react';
import type { ConfigPanelProps } from '../types';
import type { JurorConfig } from '../../../shared/jurorModel';

// Lazily resolved so the element registry (and its unit tests) never pull
// JurorEditor's heavy ESM dependency graph (provider selector, decision
// evaluator, marketplace fetch) into module load. The chunk is fetched only
// when the editor actually renders.
const JurorEditor = React.lazy(() => import('../../../../pages/EditPipePage/tabs/JurorEditor'));

/**
 * Full-area editor for a single pipe-juror node. The node's config carries
 * the juror under `config.juror`; this panel hands that slice to JurorEditor
 * and merges every change back via `updateField('juror', …)`. The host page's
 * seam reassembles the jury's juror array from all juror nodes on the way
 * back out (`readJury`). Identity (name / enable) is edited in the node's
 * sidebar panel; this editor owns the complex LLM / strictness / decision
 * config.
 */
const PipeJurorFullscreenPanel: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  closeFullscreenEditor,
}) => {
  const juror = (config?.juror ?? {
    name: '',
    llm: {},
    system_prompt: '',
    decision: {},
  }) as JurorConfig;
  return (
    <Suspense fallback={<div className="p-4 text-muted">Loading juror editor…</div>}>
      <JurorEditor
        juror={juror}
        onChange={updates => updateField('juror', { ...juror, ...updates })}
        onClose={closeFullscreenEditor}
      />
    </Suspense>
  );
};

export default PipeJurorFullscreenPanel;
