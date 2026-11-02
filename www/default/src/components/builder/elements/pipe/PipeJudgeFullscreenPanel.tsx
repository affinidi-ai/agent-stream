import React, { Suspense } from 'react';
import type { ConfigPanelProps } from '../types';
import type { JudgeConfig } from '../../../../pages/EditPipePage/tabs/JudgeTab';

// Lazily resolved so the element registry (and its unit tests) never pull
// JudgeTab's heavy ESM dependency graph (the d3-backed pipe-flow) into module
// load. The chunk is fetched only when the editor actually renders.
const JudgeTab = React.lazy(() => import('../../../../pages/EditPipePage/tabs/JudgeTab'));

/**
 * Full-area editor for the pipe-judge node — the single-model response review
 * (builtin moderation vs user-defined LLM judge, strictness controls, focus
 * areas, provider/secret selection, rules). Reuses the existing JudgeTab
 * component verbatim (it loads its own provider/secret/marketplace data and
 * only ever raises `handleInputChange('judge', …)`), adapting the canvas node
 * config to the tab's `formData` shape. The host page's seam propagates the
 * judge change back into the pipe's `judge` block. `prompt_guard` / `jury` are
 * passed through read-only so the editor's mini pipe-flow renders.
 */
const PipeJudgeFullscreenPanel: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  closeFullscreenEditor,
}) => {
  const formData = {
    judge: (config?.judge ?? null) as JudgeConfig | null,
    prompt_guard: config?.prompt_guard ?? null,
    jury: config?.jury ?? null,
  };
  return (
    <Suspense fallback={<div className="p-4 text-muted">Loading judge editor…</div>}>
      <JudgeTab
        formData={formData}
        handleInputChange={(field, value) => {
          if (field === 'judge') updateField('judge', value);
        }}
        setIsModified={() => {}}
        hideEnableToggle
        onClose={closeFullscreenEditor}
      />
    </Suspense>
  );
};

export default PipeJudgeFullscreenPanel;
