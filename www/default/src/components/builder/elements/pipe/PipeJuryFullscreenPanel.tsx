import React, { Suspense } from 'react';
import type { ConfigPanelProps } from '../types';
import type { JuryConfig } from '../../../../pages/EditPipePage/tabs/JuryTab';

// Lazily resolved so the element registry (and its unit tests) never pull
// JuryTab's heavy ESM dependency graph (the d3-backed pipe-flow) into module
// load. The chunk is fetched only when the editor actually renders.
const JuryTab = React.lazy(() => import('../../../../pages/EditPipePage/tabs/JuryTab'));

/**
 * Full-area editor for the pipe-jury node — the jury-level verdict and redrive
 * settings (redrive policy, retry prompt, final negative-verdict response).
 * Reuses the `JuryTab` component, which in the pipe builder renders only these
 * jury-level controls: the execution-mode picker and the jurors roster live on
 * the jury node's sidebar instead, and each juror is a first-class node with
 * its own editor. JuryTab only ever raises `handleInputChange('jury', …)`; the
 * host page's seam propagates the jury-level change back into the pipe's `jury`
 * block (the juror array is reassembled from the juror nodes by `readJury`).
 */
const PipeJuryFullscreenPanel: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  closeFullscreenEditor,
}) => {
  const formData = {
    jury: (config?.jury ?? null) as JuryConfig | null,
  };
  return (
    <Suspense fallback={<div className="p-4 text-muted">Loading jury editor…</div>}>
      <JuryTab
        formData={formData}
        handleInputChange={(field, value) => {
          if (field === 'jury') updateField('jury', value);
        }}
        setIsModified={() => {}}
        hideEnableToggle
        onClose={closeFullscreenEditor}
      />
    </Suspense>
  );
};

export default PipeJuryFullscreenPanel;
