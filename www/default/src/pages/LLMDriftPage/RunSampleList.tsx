import React from 'react';
import type { SampleOutcome } from './types';

/** The per-sample pass/fail list shared by the latest-run view and the run
 * history. Each row shows the pass/fail badge, the prompt, and the graded
 * output (or error), all truncated with a full-text tooltip. */
const RunSampleList: React.FC<{ samples: SampleOutcome[] }> = ({ samples }) => (
  <div className="drift-run-samples">
    {samples.map((s, i) => (
      <div className="d-flex gap-2 small py-1 align-items-center" key={i}>
        <span className={`badge text-bg-${s.passed ? 'success' : 'danger'} flex-shrink-0`}>
          {s.passed ? 'pass' : 'fail'}
        </span>
        <span className="text-truncate flex-grow-1" title={s.input}>
          {s.input}
        </span>
        <span
          className="text-truncate text-muted"
          style={{ maxWidth: '40%' }}
          title={s.error ?? s.output ?? ''}
        >
          {s.error ?? s.output ?? ''}
        </span>
      </div>
    ))}
  </div>
);

export default RunSampleList;
