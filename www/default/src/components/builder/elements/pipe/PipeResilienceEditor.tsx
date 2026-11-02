import React, { Suspense } from 'react';
import {
  FailoverConfig,
  LoadBalancingConfig,
  LoadBalancingStrategy,
  makeDefaultFailover,
  makeDefaultLoadBalancing,
} from '../../../shared/resilienceModel';
import { DeciderLlm, makeDefaultDeciderLlm } from '../../../shared/deciderModel';
import { useLlmTargetCatalog } from '../../../../pages/EditPipePage/tabs/useLlmTargetCatalog';

// Lazily resolved so the element registry (and its unit tests) never pull the
// provider selector's dependency graph into module load. The chunk is fetched
// only when a target is actually rendered.
const DeciderLlmEditor = React.lazy(
  () => import('../../../../pages/EditPipePage/tabs/DeciderLlmEditor')
);

type ResilienceMode = 'off' | 'failover' | 'load_balancing';

interface PipeResilienceEditorProps {
  failover: FailoverConfig | null;
  loadBalancing: LoadBalancingConfig | null;
  onChange: (next: {
    failover: FailoverConfig | null;
    load_balancing: LoadBalancingConfig | null;
  }) => void;
}

const editorFallback = <div className="text-muted small">Loading LLM editor…</div>;

/**
 * Failover & load-balancing editor for the LLM upstream. The backend treats the
 * two as mutually exclusive (load balancing wins at runtime), so this surfaces a
 * single three-way mode — Off / Failover / Load balancing — and edits whichever
 * config the mode selects, clearing the other. Each backup target reuses the
 * shared {@link DeciderLlmEditor} (the same `LLMTarget` shape decider candidates
 * use). Both configs are base-pipe-level and not variant-overridable.
 */
const PipeResilienceEditor: React.FC<PipeResilienceEditorProps> = ({
  failover,
  loadBalancing,
  onChange,
}) => {
  const mode: ResilienceMode = loadBalancing ? 'load_balancing' : failover ? 'failover' : 'off';

  // Loaded once here and shared with every target editor below, so a pool of N
  // backups issues one catalog fetch instead of N.
  const { llmProviders, secrets } = useLlmTargetCatalog();

  const setMode = (next: ResilienceMode) => {
    if (next === 'off') {
      onChange({ failover: null, load_balancing: null });
    } else if (next === 'failover') {
      onChange({ failover: failover ?? makeDefaultFailover(), load_balancing: null });
    } else {
      onChange({ failover: null, load_balancing: loadBalancing ?? makeDefaultLoadBalancing() });
    }
  };

  // ── Failover ──
  const fo = failover ?? makeDefaultFailover();
  const setFailover = (next: FailoverConfig) => onChange({ failover: next, load_balancing: null });
  const addFailoverTarget = () =>
    setFailover({ ...fo, targets: [...fo.targets, { llm: makeDefaultDeciderLlm() }] });
  const removeFailoverTarget = (i: number) =>
    setFailover({ ...fo, targets: fo.targets.filter((_, idx) => idx !== i) });
  const moveFailoverTarget = (i: number, dir: -1 | 1) => {
    const j = i + dir;
    if (j < 0 || j >= fo.targets.length) return;
    const targets = [...fo.targets];
    [targets[i], targets[j]] = [targets[j], targets[i]];
    setFailover({ ...fo, targets });
  };
  const updateFailoverLlm = (i: number, llm: DeciderLlm) => {
    const targets = [...fo.targets];
    targets[i] = { llm };
    setFailover({ ...fo, targets });
  };

  // ── Load balancing ──
  const lb = loadBalancing ?? makeDefaultLoadBalancing();
  const setLoadBalancing = (next: LoadBalancingConfig) =>
    onChange({ failover: null, load_balancing: next });
  const addLbTarget = () =>
    setLoadBalancing({
      ...lb,
      targets: [...lb.targets, { llm: makeDefaultDeciderLlm(), weight: 1 }],
    });
  const removeLbTarget = (i: number) =>
    setLoadBalancing({ ...lb, targets: lb.targets.filter((_, idx) => idx !== i) });
  const updateLbLlm = (i: number, llm: DeciderLlm) => {
    const targets = [...lb.targets];
    targets[i] = { ...targets[i], llm };
    setLoadBalancing({ ...lb, targets });
  };
  const updateLbWeight = (i: number, weight: number) => {
    const targets = [...lb.targets];
    targets[i] = { ...targets[i], weight: Math.max(0, weight) };
    setLoadBalancing({ ...lb, targets });
  };

  return (
    <div className="card shadow-sm mb-4">
      <div className="card-header bg-light">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-shuffle me-2"></i>
          Failover &amp; Load Balancing
          <small className="text-muted ms-2">Route to other-vendor providers for resilience</small>
        </h6>
      </div>
      <div className="card-body">
        <div className="btn-group btn-group-sm mb-3" role="group" aria-label="Resilience mode">
          <button
            type="button"
            className={`btn ${mode === 'off' ? 'btn-primary' : 'btn-outline-primary'}`}
            onClick={() => setMode('off')}
          >
            Off
          </button>
          <button
            type="button"
            className={`btn ${mode === 'failover' ? 'btn-primary' : 'btn-outline-primary'}`}
            onClick={() => setMode('failover')}
          >
            Failover
          </button>
          <button
            type="button"
            className={`btn ${mode === 'load_balancing' ? 'btn-primary' : 'btn-outline-primary'}`}
            onClick={() => setMode('load_balancing')}
          >
            Load balancing
          </button>
        </div>

        {mode === 'failover' && (
          <div>
            <p className="text-muted" style={{ fontSize: '13px' }}>
              On a transport or upstream failure of the primary provider, the request is retried
              against each backup in order until one succeeds.
            </p>
            {fo.targets.map((t, i) => (
              <div key={i} className="border rounded p-3 mb-3">
                <div className="d-flex justify-content-between align-items-center mb-2">
                  <strong style={{ fontSize: '13px' }}>Backup {i + 1}</strong>
                  <div className="btn-group btn-group-sm">
                    <button
                      type="button"
                      className="btn btn-outline-secondary"
                      disabled={i === 0}
                      onClick={() => moveFailoverTarget(i, -1)}
                      title="Move up"
                    >
                      <i className="fas fa-arrow-up"></i>
                    </button>
                    <button
                      type="button"
                      className="btn btn-outline-secondary"
                      disabled={i === fo.targets.length - 1}
                      onClick={() => moveFailoverTarget(i, 1)}
                      title="Move down"
                    >
                      <i className="fas fa-arrow-down"></i>
                    </button>
                    <button
                      type="button"
                      className="btn btn-outline-danger"
                      onClick={() => removeFailoverTarget(i)}
                      title="Remove backup"
                    >
                      <i className="fas fa-trash"></i>
                    </button>
                  </div>
                </div>
                <Suspense fallback={editorFallback}>
                  <DeciderLlmEditor
                    llm={t.llm}
                    onChange={llm => updateFailoverLlm(i, llm)}
                    idPrefix={`failover-${i}`}
                    providers={llmProviders}
                    secrets={secrets}
                  />
                </Suspense>
              </div>
            ))}
            <button
              type="button"
              className="btn btn-sm btn-outline-primary"
              onClick={addFailoverTarget}
            >
              <i className="fas fa-plus me-1"></i>Add backup provider
            </button>
          </div>
        )}

        {mode === 'load_balancing' && (
          <div>
            <p className="text-muted" style={{ fontSize: '13px' }}>
              {lb.strategy === 'lowest_latency'
                ? 'Requests are routed to the pool member with the lowest observed latency (EWMA). A failed request falls through to the remaining members.'
                : lb.strategy === 'lowest_cost'
                  ? 'Requests are routed to the pool member with the lowest catalog price for its model. A failed request falls through to the remaining members.'
                  : 'Requests are distributed across the primary provider and the pool below by weight (weighted round-robin). A failed request falls through to the remaining members.'}
            </p>
            <div className="mb-3" style={{ maxWidth: '260px' }}>
              <label className="form-label small fw-bold">Strategy</label>
              <select
                className="form-select form-select-sm"
                value={lb.strategy ?? 'weighted'}
                onChange={e =>
                  setLoadBalancing({
                    ...lb,
                    strategy: e.target.value as LoadBalancingStrategy,
                  })
                }
              >
                <option value="weighted">Weighted round-robin</option>
                <option value="lowest_latency">Lowest latency</option>
                <option value="lowest_cost">Lowest cost</option>
              </select>
              <small className="form-text text-muted">
                Weights below still gate which members participate (0 = fallthrough only).
              </small>
            </div>
            <div className="mb-3" style={{ maxWidth: '220px' }}>
              <label className="form-label small fw-bold">Primary weight</label>
              <input
                type="number"
                min={0}
                className="form-control form-control-sm"
                value={lb.primary_weight}
                onChange={e =>
                  setLoadBalancing({
                    ...lb,
                    primary_weight: Math.max(0, Number(e.target.value) || 0),
                  })
                }
              />
              <small className="form-text text-muted">
                Weight of this pipe&apos;s own provider. 0 keeps it as a fallthrough only.
              </small>
            </div>
            {lb.targets.map((t, i) => (
              <div key={i} className="border rounded p-3 mb-3">
                <div className="d-flex justify-content-between align-items-center mb-2">
                  <strong style={{ fontSize: '13px' }}>Pool member {i + 1}</strong>
                  <button
                    type="button"
                    className="btn btn-sm btn-outline-danger"
                    onClick={() => removeLbTarget(i)}
                    title="Remove member"
                  >
                    <i className="fas fa-trash"></i>
                  </button>
                </div>
                <div className="mb-3" style={{ maxWidth: '160px' }}>
                  <label className="form-label small fw-bold">Weight</label>
                  <input
                    type="number"
                    min={0}
                    className="form-control form-control-sm"
                    value={t.weight}
                    onChange={e => updateLbWeight(i, Number(e.target.value) || 0)}
                  />
                </div>
                <Suspense fallback={editorFallback}>
                  <DeciderLlmEditor
                    llm={t.llm}
                    onChange={llm => updateLbLlm(i, llm)}
                    idPrefix={`lb-${i}`}
                    providers={llmProviders}
                    secrets={secrets}
                  />
                </Suspense>
              </div>
            ))}
            <button type="button" className="btn btn-sm btn-outline-primary" onClick={addLbTarget}>
              <i className="fas fa-plus me-1"></i>Add pool member
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default PipeResilienceEditor;
