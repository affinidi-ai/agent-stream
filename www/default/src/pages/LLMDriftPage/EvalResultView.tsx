import React from 'react';
import RunSampleList from './RunSampleList';
import type { DriftRun } from './types';

/** Bootstrap tone for a stability score (`0..1`). */
function qualityTone(quality: number): string {
  if (quality >= 0.8) return 'success';
  if (quality >= 0.5) return 'warning';
  return 'danger';
}

/**
 * Compact result of a completed replay evaluation: the stability /
 * semantic-distance headline metrics + a per-session list of the replayed
 * answers. (Latency lands on the Latency drift chart, not here.)
 */
const EvalResultView: React.FC<{ result: DriftRun }> = ({ result }) => (
  <div className="drift-run-result border-top mt-3 pt-3" data-testid="eval-run-result">
    <div className="d-flex align-items-center flex-wrap gap-2 mb-2">
      <span
        className={`badge text-bg-${qualityTone(result.quality)}`}
        data-testid="eval-run-quality"
        title="Fraction of replays whose answer stayed close to the originally-captured one"
      >
        Stable {(result.quality * 100).toFixed(0)}%
      </span>
      <span
        className={`badge text-bg-${result.semantic_distance == null ? 'secondary' : 'info'}`}
        data-testid="eval-run-semantic-distance"
        title="Mean cosine distance of a replayed answer from the originally-captured one"
      >
        Semantic distance{' '}
        {result.semantic_distance == null ? 'n/a' : result.semantic_distance.toFixed(3)}
      </span>
      <span className="small text-muted">
        {result.passed}/{result.total} stable
        {result.errors > 0 ? ` · ${result.errors} error${result.errors === 1 ? '' : 's'}` : ''}
      </span>
      {(result.target_surface_id || result.variant) && (
        <span
          className="badge text-bg-warning"
          data-testid="eval-run-experiment"
          title="Experiment — ran through a different surface / variant"
        >
          via {result.target_surface_id ?? 'this surface'}
          {result.variant ? ` → ${result.variant}` : ''}
        </span>
      )}
    </div>
    <RunSampleList samples={result.samples} />
  </div>
);

export default EvalResultView;
