import React, { useEffect, useState } from 'react';
import { Form } from 'react-bootstrap';
import type { ConfigPanelProps } from '../types';
import SecretSelector, { Secret } from '../../../shared/SecretSelector';
import { useOptionalSurfaceMeta } from '../../SurfaceMetaContext';
import { SURFACE_PROTOCOL_OPTIONS, getProtocolLabel } from '../../protocols';
import { formatDateTime, timeAgo } from '../../../../utils/stringUtils';
import { apiClient } from '../../../../api';
import { useIntegrationsAccess } from '../../../../hooks/useIntegrationsAccess';
import IntegrationsAdminOnlyNotice from '../../../integrations/IntegrationsAdminOnlyNotice';
import type {
  CallerIdentitySourceForm,
  DriftForm,
  GovernanceRecordingForm,
  PipeCacheForm,
  PipeCanaryForm,
  PipeRoutingRuleForm,
  TeamAttributionForm,
  UsageAlertForm,
  UsageAlertType,
  VpEvidenceForm,
} from '../../../../pages/EditPipePage/types';
import CallerIdentitySourcesEditor from './CallerIdentitySourcesEditor';
import EmbeddingsTargetEditor, { deriveEmbeddingsUrl } from './EmbeddingsTargetEditor';
import { usePipePanelData } from '../pipe/pipePanelData';
import type { LLMProvider } from '../../../../pages/EditPipePage/types';

export { deriveEmbeddingsUrl };

export type SurfaceUsageLimit = {
  enabled: boolean;
  monthlyBudgetUsd: number | null;
  monthlyTokenCap: number | null;
};

const toUsageNum = (raw: string): number | null => {
  if (raw.trim() === '') return null;
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 ? n : null;
};

/**
 * Surface-wide cumulative usage-limit control for the pipe (LLM surface)
 * editor. Lives on the surface property sidebar and caps spend / tokens across
 * every metered stage of the pipe.
 */
export const SurfaceUsageLimitControls: React.FC<{
  value: SurfaceUsageLimit | null;
  onChange: (v: SurfaceUsageLimit | null) => void;
  disabled?: boolean;
}> = ({ value, onChange, disabled }) => {
  const enabled = value?.enabled === true;
  return (
    <div>
      <div className="form-check form-switch">
        <input
          className="form-check-input"
          type="checkbox"
          role="switch"
          id="surface-usage-limit-enabled"
          data-testid="surface-usage-limit-enabled"
          checked={enabled}
          disabled={disabled}
          onChange={e =>
            onChange(
              e.target.checked
                ? {
                    enabled: true,
                    monthlyBudgetUsd: value?.monthlyBudgetUsd ?? null,
                    monthlyTokenCap: value?.monthlyTokenCap ?? null,
                  }
                : null
            )
          }
        />
        <label className="form-check-label small" htmlFor="surface-usage-limit-enabled">
          <strong>Enforce surface-wide usage limit</strong>
        </label>
      </div>
      {enabled && value && (
        <div className="mt-2">
          <div className="mb-3">
            <label className="form-label small text-muted mb-1">Monthly budget (USD)</label>
            <input
              type="number"
              min={0}
              step="0.01"
              className="form-control form-control-sm"
              data-testid="surface-usage-limit-budget"
              value={value.monthlyBudgetUsd ?? ''}
              disabled={disabled}
              onChange={e => onChange({ ...value, monthlyBudgetUsd: toUsageNum(e.target.value) })}
              placeholder="No budget cap"
            />
          </div>
          <div className="mb-0">
            <label className="form-label small text-muted mb-1">Monthly token cap</label>
            <input
              type="number"
              min={0}
              step="1"
              className="form-control form-control-sm"
              data-testid="surface-usage-limit-tokens"
              value={value.monthlyTokenCap ?? ''}
              disabled={disabled}
              onChange={e => onChange({ ...value, monthlyTokenCap: toUsageNum(e.target.value) })}
              placeholder="No token cap"
            />
          </div>
        </div>
      )}
    </div>
  );
};

/**
 * Surface opt-in for team usage attribution. Surface-type agnostic: it only
 * declares where the caller email lives on an inbound request and how the
 * resulting per-member / per-team usage is enforced. The runtime gate that
 * consumes this lives at the request boundary (not inside any one surface
 * type), so a future Memory surface gets this for free.
 */
const DEFAULT_CACHE: PipeCacheForm = {
  enabled: true,
  ttl_seconds: 3600,
  max_entries: 1000,
  mode: 'exact',
  similarity_threshold: 0.95,
  embedder: null,
};

/**
 * Canary / A-B traffic split across the base surface and every variant. When
 * enabled and a request does not address a variant explicitly, the gateway
 * routes by weight. Percentages always total 100% — one row per target (base +
 * each variant), base defaulting to 100% and the rest to 0%; typing a value
 * rebalances the others proportionally so the total never overflows. Disabling
 * retains the values (`enabled: false`) so a surface can be saved, reloaded,
 * and re-enabled without rework.
 */
export const CanaryControls: React.FC<{
  value: PipeCanaryForm | null;
  variantAliases: string[];
  onChange: (v: PipeCanaryForm | null) => void;
  disabled?: boolean;
}> = ({ value, variantAliases, onChange, disabled }) => {
  const enabled = value?.enabled === true;

  // The canonical set of targets is the base surface ('') plus every variant.
  const targets = ['', ...variantAliases];

  // Base defaults to 100% and each variant to 0% (only when nothing is stored
  // yet). Otherwise read the stored weight per target, defaulting a target with
  // no stored entry (e.g. a variant added after the split was configured) to 0%.
  const rows: PipeCanarySplitForm[] = (() => {
    const stored = value?.splits ?? [];
    const byVariant = new Map(stored.map(s => [s.variant, s.weight]));
    const hasStored = stored.length > 0;
    return targets.map((variant, i) => {
      const w = byVariant.get(variant);
      if (typeof w === 'number') return { variant, weight: w };
      return { variant, weight: !hasStored && i === 0 ? 100 : 0 };
    });
  })();

  const total = rows.reduce((s, r) => s + r.weight, 0);
  const singleTarget = rows.length <= 1;

  /** Initialise a fresh split: base 100%, every variant 0%. */
  const initialRows = (): PipeCanarySplitForm[] =>
    targets.map((variant, i) => ({ variant, weight: i === 0 ? 100 : 0 }));

  /**
   * Set one target's weight and rebalance the others so the total stays 100%.
   * The remaining budget (`100 - value`) is distributed across the other rows
   * in proportion to their current weights (all to the base when the others are
   * all zero), and integer rounding drift is absorbed by the largest other row.
   */
  const setWeight = (index: number, raw: number) => {
    const next = rows.map(r => ({ ...r }));
    const clamped = Math.max(0, Math.min(100, Math.round(Number.isFinite(raw) ? raw : 0)));
    next[index].weight = clamped;

    const otherIdx = next.map((_, i) => i).filter(i => i !== index);
    if (otherIdx.length === 0) {
      next[index].weight = 100; // a lone target must be 100%
    } else {
      const remaining = 100 - clamped;
      const otherSum = otherIdx.reduce((s, i) => s + next[i].weight, 0);
      if (otherSum === 0) {
        const target = otherIdx.includes(0) ? 0 : otherIdx[0];
        next[target].weight = remaining;
      } else {
        otherIdx.forEach(i => {
          next[i].weight = Math.round((next[i].weight / otherSum) * remaining);
        });
        const drift = 100 - next.reduce((s, r) => s + r.weight, 0);
        if (drift !== 0) {
          const adj = otherIdx.reduce(
            (best, i) => (next[i].weight > next[best].weight ? i : best),
            otherIdx[0]
          );
          next[adj].weight = Math.max(0, next[adj].weight + drift);
        }
      }
    }
    onChange({ enabled: true, splits: next });
  };

  return (
    <div>
      <Form.Check
        type="switch"
        id="surface-canary-enabled"
        label="Enable canary split"
        checked={enabled}
        disabled={disabled}
        onChange={e => {
          if (e.target.checked) {
            const splits = value?.splits?.length ? value.splits : initialRows();
            onChange({ enabled: true, splits });
          } else {
            // Retain the split values but stop enforcing them.
            onChange(value ? { enabled: false, splits: value.splits ?? [] } : null);
          }
        }}
      />
      {enabled && (
        <div className="mt-2">
          <div className="alert alert-info py-2 mb-3" style={{ fontSize: '12px' }}>
            <i className="fas fa-info-circle me-1" /> Requests that don&apos;t target a variant
            explicitly are split across the base surface and each variant by these percentages,
            which always total 100%.
            {singleTarget && ' Add variants to split traffic.'}
          </div>
          {rows.map((row, idx) => (
            <div
              className="d-flex align-items-center justify-content-between mb-2"
              key={row.variant || '__base__'}
            >
              <span className="small text-truncate me-2">
                {row.variant === '' ? 'Base surface' : row.variant}
              </span>
              <div className="input-group input-group-sm" style={{ width: 96, flex: '0 0 auto' }}>
                <input
                  type="number"
                  className="form-control text-end"
                  min={0}
                  max={100}
                  value={row.weight}
                  disabled={disabled || singleTarget}
                  onChange={e => setWeight(idx, Number(e.target.value))}
                />
                <span className="input-group-text">%</span>
              </div>
            </div>
          ))}
          <div className={`small mt-1 ${total === 100 ? 'text-muted' : 'text-danger'}`}>
            Total: {total}%{total !== 100 ? ' — must be 100%' : ''}
          </div>
        </div>
      )}
    </div>
  );
};

/** Attribute-based routing rules: match a request header or body field and
 * route to a variant alias. Enable-first (like canary): the rules are retained
 * when disabled but not enforced. Inline provider targets set via the API are
 * preserved but not edited here. */
export const RoutingRulesControls: React.FC<{
  value: PipeRoutingRuleForm[];
  variantAliases: string[];
  enabled: boolean;
  onEnabledChange: (v: boolean) => void;
  onChange: (v: PipeRoutingRuleForm[]) => void;
  disabled?: boolean;
  hideEnableSwitch?: boolean;
}> = ({
  value,
  variantAliases,
  enabled,
  onEnabledChange,
  onChange,
  disabled,
  hideEnableSwitch,
}) => {
  const rules = value ?? [];
  const setRule = (idx: number, rule: PipeRoutingRuleForm) => {
    const next = [...rules];
    next[idx] = rule;
    onChange(next);
  };
  const enableSwitch = hideEnableSwitch ? null : (
    <Form.Check
      type="switch"
      id="surface-routing-enabled"
      label="Enable attribute-based routing"
      checked={enabled}
      disabled={disabled}
      onChange={e => {
        const v = e.target.checked;
        onEnabledChange(v);
        if (v && rules.length === 0) {
          onChange([
            { match: { kind: 'header', name: '', equals: '' }, target: { variant: null } },
          ]);
        }
      }}
    />
  );
  if (!hideEnableSwitch && !enabled) {
    return <div>{enableSwitch}</div>;
  }
  return (
    <div>
      {enableSwitch}
      <div className="alert alert-info py-2 mb-3 mt-2" style={{ fontSize: '12px' }}>
        <i className="fas fa-info-circle me-1" /> Route a request to a variant by matching a request
        header, a top-level body field, or an <strong>attachment type</strong> (image / audio /
        document / realtime voice). Evaluated before canary; an explicit <code>$alias</code> always
        wins. Anything unmatched — including plain text — goes to the base surface.
      </div>
      {rules.map((rule, idx) => {
        const kind = rule.match.kind;
        const inline = rule.target.variant ? '' : rule.target.llm ? ' (inline target)' : '';
        const equalsOf = (m: PipeRoutingRuleForm['match']): string =>
          m.kind === 'modality' ? '' : m.equals;
        return (
          <div className="border rounded p-2 mb-2" key={idx}>
            <div className="input-group input-group-sm mb-2">
              <select
                className="form-control"
                style={{ maxWidth: 130 }}
                value={kind}
                disabled={disabled}
                onChange={e => {
                  const k = e.target.value as 'header' | 'body_field' | 'modality';
                  const equals = equalsOf(rule.match);
                  setRule(idx, {
                    ...rule,
                    match:
                      k === 'modality'
                        ? { kind: 'modality', has: 'image' }
                        : k === 'header'
                          ? { kind: 'header', name: '', equals }
                          : { kind: 'body_field', field: '', equals },
                  });
                }}
              >
                <option value="header">Header</option>
                <option value="body_field">Body field</option>
                <option value="modality">Attachment type</option>
              </select>
              {kind === 'modality' ? (
                <select
                  className="form-control"
                  value={(rule.match as { has: string }).has || 'image'}
                  disabled={disabled}
                  onChange={e =>
                    setRule(idx, { ...rule, match: { kind: 'modality', has: e.target.value } })
                  }
                >
                  <option value="image">Image file</option>
                  <option value="audio">Audio file</option>
                  <option value="document">Document file</option>
                  <option value="realtime">Realtime voice (WebSocket)</option>
                  <option value="text" disabled>
                    Text → base surface
                  </option>
                </select>
              ) : (
                <>
                  <input
                    type="text"
                    className="form-control"
                    placeholder={kind === 'header' ? 'Header name' : 'Field name'}
                    value={kind === 'header' ? (rule.match as any).name : (rule.match as any).field}
                    disabled={disabled}
                    onChange={e => {
                      const v = e.target.value;
                      const equals = equalsOf(rule.match);
                      setRule(idx, {
                        ...rule,
                        match:
                          kind === 'header'
                            ? { kind: 'header', name: v, equals }
                            : { kind: 'body_field', field: v, equals },
                      });
                    }}
                  />
                  <span className="input-group-text">=</span>
                  <input
                    type="text"
                    className="form-control"
                    placeholder="equals"
                    value={equalsOf(rule.match)}
                    disabled={disabled}
                    onChange={e => {
                      const equals = e.target.value;
                      setRule(idx, {
                        ...rule,
                        match:
                          kind === 'header'
                            ? { kind: 'header', name: (rule.match as any).name, equals }
                            : { kind: 'body_field', field: (rule.match as any).field, equals },
                      });
                    }}
                  />
                </>
              )}
            </div>
            <div className="input-group input-group-sm">
              <span className="input-group-text">→ variant{inline}</span>
              <select
                className="form-control"
                value={rule.target.variant ?? ''}
                disabled={disabled || !!rule.target.llm}
                onChange={e =>
                  setRule(idx, {
                    ...rule,
                    target: { ...rule.target, variant: e.target.value || null },
                  })
                }
              >
                <option value="">Base surface</option>
                {variantAliases.map(alias => (
                  <option key={alias} value={alias}>
                    {alias}
                  </option>
                ))}
              </select>
              <button
                type="button"
                className="btn btn-outline-danger"
                disabled={disabled}
                onClick={() => onChange(rules.filter((_, i) => i !== idx))}
                title="Delete rule"
              >
                <i className="fas fa-trash" />
              </button>
            </div>
          </div>
        );
      })}
      <button
        type="button"
        className="btn btn-sm btn-outline-secondary"
        disabled={disabled}
        onClick={() =>
          onChange([
            ...rules,
            { match: { kind: 'header', name: '', equals: '' }, target: { variant: null } },
          ])
        }
      >
        <i className="fas fa-plus me-1" /> Add routing rule
      </button>
    </div>
  );
};

/** Response-cache config: exact or semantic matching, with TTL and bounds. */
export const CacheControls: React.FC<{
  value: PipeCacheForm | null;
  onChange: (v: PipeCacheForm | null) => void;
  disabled?: boolean;
}> = ({ value, onChange, disabled }) => {
  const { llmProviders, secrets } = usePipePanelData();
  const providers = llmProviders as unknown as LLMProvider[];
  const enabled = value?.enabled === true;
  const cfg = value ?? DEFAULT_CACHE;
  const update = (patch: Partial<PipeCacheForm>) => onChange({ ...cfg, ...patch, enabled: true });
  const embedder = cfg.embedder ?? { endpoint_url: '', model: '', api_key_secret: '' };
  const updateEmbedder = (patch: Partial<PipeCacheForm['embedder'] & object>) =>
    update({ embedder: { ...embedder, ...patch } });

  // Only providers with a derivable OpenAI-shaped embeddings endpoint can back
  // the semantic cache; the embedder posts a plain `{ model, input }` body.
  const embeddingProviders = providers.filter(p => deriveEmbeddingsUrl(p) !== '');
  // Resolve the current endpoint back to a catalogue provider (so the dropdown
  // reflects a saved config); '' = custom / unmatched URL.
  const selectedProvider =
    embeddingProviders.find(p => deriveEmbeddingsUrl(p) === embedder.endpoint_url) ?? null;

  // A saved config with a non-empty endpoint that matches no catalogue provider
  // is a custom endpoint; an empty endpoint with no provider is "unselected".
  const savedCustom = !selectedProvider && embedder.endpoint_url !== '';
  const [customChosen, setCustomChosen] = useState(savedCustom);
  const isCustom = !selectedProvider && (customChosen || savedCustom);
  const isUnselected = !selectedProvider && !isCustom;
  const selectValue = selectedProvider ? selectedProvider.enum_value : isCustom ? '__custom__' : '';

  const onSelectProvider = (val: string) => {
    if (val === '') {
      // "Select…" — nothing chosen; clear endpoint + model.
      setCustomChosen(false);
      updateEmbedder({ endpoint_url: '', model: '' });
      return;
    }
    if (val === '__custom__') {
      // "Custom / other" — reveal the editable endpoint field.
      setCustomChosen(true);
      updateEmbedder({ endpoint_url: '', model: '' });
      return;
    }
    const prov = embeddingProviders.find(p => p.enum_value === val) ?? null;
    setCustomChosen(false);
    if (prov) updateEmbedder({ endpoint_url: deriveEmbeddingsUrl(prov), model: '' });
  };

  return (
    <div>
      <div className="alert alert-info py-2 mb-3" style={{ fontSize: '12px' }}>
        <i className="fas fa-info-circle me-1" /> Serve an identical (exact) or semantically-similar
        repeat request from cache without a provider call, cutting cost and latency. Applies to the
        buffered chat/embeddings path; cache hits are billed at zero spend.
      </div>
      <div className="form-check form-switch">
        <input
          className="form-check-input"
          type="checkbox"
          role="switch"
          id="surface-cache-enabled"
          data-testid="surface-cache-enabled"
          checked={enabled}
          disabled={disabled}
          onChange={e => onChange(e.target.checked ? { ...DEFAULT_CACHE } : null)}
        />
        <label className="form-check-label small" htmlFor="surface-cache-enabled">
          <strong>Enable response cache</strong>
        </label>
      </div>

      {enabled && value && (
        <div className="mt-2">
          <div className="row g-2 mb-2">
            <div className="col">
              <label className="form-label small text-muted mb-1">TTL (seconds)</label>
              <input
                type="number"
                min={1}
                className="form-control form-control-sm"
                value={cfg.ttl_seconds}
                disabled={disabled}
                onChange={e => update({ ttl_seconds: Math.max(1, Number(e.target.value) || 0) })}
              />
            </div>
            <div className="col">
              <label className="form-label small text-muted mb-1">Max entries</label>
              <input
                type="number"
                min={1}
                className="form-control form-control-sm"
                value={cfg.max_entries}
                disabled={disabled}
                onChange={e => update({ max_entries: Math.max(1, Number(e.target.value) || 0) })}
              />
            </div>
          </div>

          <div className="mb-2">
            <label className="form-label small text-muted mb-1">Matching mode</label>
            <Form.Select
              size="sm"
              value={cfg.mode}
              disabled={disabled}
              onChange={e =>
                update({
                  mode: e.target.value === 'semantic' ? 'semantic' : 'exact',
                  embedder:
                    e.target.value === 'semantic'
                      ? (cfg.embedder ?? { endpoint_url: '', model: '' })
                      : null,
                })
              }
            >
              <option value="exact">Exact — identical normalized request</option>
              <option value="semantic">Semantic — embedding similarity</option>
            </Form.Select>
          </div>

          {cfg.mode === 'semantic' && (
            <div className="ms-1 ps-2 border-start">
              <div className="mb-2">
                <label className="form-label small text-muted mb-1">
                  Similarity threshold ({cfg.similarity_threshold.toFixed(2)})
                </label>
                <input
                  type="range"
                  min={0.5}
                  max={1}
                  step={0.01}
                  className="form-range"
                  value={cfg.similarity_threshold}
                  disabled={disabled}
                  onChange={e => update({ similarity_threshold: Number(e.target.value) })}
                />
              </div>
              <div className="mb-2">
                <label className="form-label small text-muted mb-1">Embedder provider</label>
                <Form.Select
                  size="sm"
                  value={selectValue}
                  disabled={disabled}
                  onChange={e => onSelectProvider(e.target.value)}
                >
                  <option value="">Select an embeddings provider…</option>
                  {embeddingProviders.map(p => (
                    <option key={p.enum_value} value={p.enum_value}>
                      {p.name}
                    </option>
                  ))}
                  <option value="__custom__">Custom / other</option>
                </Form.Select>
                <div className="form-text text-muted">
                  OpenAI-compatible embeddings providers. Picking one selects its endpoint and
                  models automatically.
                </div>
              </div>
              {isCustom && (
                <div className="mb-2">
                  <label className="form-label small text-muted mb-1">Embedder endpoint URL</label>
                  <input
                    type="text"
                    className="form-control form-control-sm"
                    placeholder="https://api.openai.com/v1/embeddings"
                    value={embedder.endpoint_url}
                    disabled={disabled}
                    onChange={e => updateEmbedder({ endpoint_url: e.target.value })}
                  />
                  <div className="form-text text-muted">
                    Only needed for a provider not in the list above.
                  </div>
                </div>
              )}
              <div className="mb-2">
                <label className="form-label small text-muted mb-1">Embedder model</label>
                {selectedProvider && selectedProvider.models.length > 0 ? (
                  <Form.Select
                    size="sm"
                    value={embedder.model}
                    disabled={disabled}
                    onChange={e => updateEmbedder({ model: e.target.value })}
                  >
                    <option value="">Select an embedding model…</option>
                    {selectedProvider.models.map(m => (
                      <option key={m.value} value={m.value}>
                        {m.name}
                      </option>
                    ))}
                  </Form.Select>
                ) : (
                  <input
                    type="text"
                    className="form-control form-control-sm"
                    placeholder={
                      isUnselected ? 'Select a provider first' : 'text-embedding-3-small'
                    }
                    value={embedder.model}
                    disabled={disabled || isUnselected}
                    onChange={e => updateEmbedder({ model: e.target.value })}
                  />
                )}
              </div>
              <div className="mb-0">
                {disabled || isUnselected ? (
                  <>
                    <label className="form-label small text-muted mb-1">API key (secret)</label>
                    <Form.Select
                      size="sm"
                      disabled
                      value={embedder.api_key_secret ?? ''}
                      onChange={() => {}}
                    >
                      <option value="">
                        {isUnselected ? 'Select a provider first' : 'None (no auth)'}
                      </option>
                      {embedder.api_key_secret && (
                        <option value={embedder.api_key_secret}>
                          {secrets.find(s => s.id === embedder.api_key_secret)?.name ??
                            embedder.api_key_secret}
                        </option>
                      )}
                    </Form.Select>
                  </>
                ) : (
                  <SecretSelector
                    secrets={secrets}
                    selectedSecretId={embedder.api_key_secret ?? ''}
                    onChange={secretId => updateEmbedder({ api_key_secret: secretId || null })}
                    label="API key (secret)"
                    emptyLabel="None (no auth)"
                    helpText="Select an API-key secret from the store — no raw keys here."
                  />
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export const TeamAttributionControls: React.FC<{
  value: TeamAttributionForm | null;
  onChange: (v: TeamAttributionForm | null) => void;
  disabled?: boolean;
}> = ({ value, onChange, disabled }) => {
  const enabled = value?.enabled === true;
  const sources: CallerIdentitySourceForm[] = value?.caller_identity_sources ?? [];

  // Non-deleted teams, for the surface→team access mapping below. Fetched once;
  // the built-in "Anonymous" team appears here like any other team.
  const [teams, setTeams] = useState<Array<{ id: string; name: string; status: string }>>([]);
  useEffect(() => {
    let alive = true;
    apiClient
      .get<Array<{ id: string; name: string; status: string }>>('/teams')
      .then(r => {
        if (alive)
          setTeams(Array.isArray(r.data) ? r.data.filter(t => t.status !== 'deleted') : []);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);

  const toggleAllowedTeam = (id: string) => {
    const current = value?.allowed_teams ?? [];
    const next = current.includes(id) ? current.filter(t => t !== id) : [...current, id];
    onChange({ ...(value as TeamAttributionForm), allowed_teams: next });
  };

  return (
    <div>
      <div className="form-check form-switch">
        <input
          className="form-check-input"
          type="checkbox"
          role="switch"
          id="team-attribution-enabled"
          data-testid="team-attribution-enabled"
          checked={enabled}
          disabled={disabled}
          onChange={e =>
            onChange(
              e.target.checked
                ? {
                    enabled: true,
                    caller_identity_sources:
                      sources.length > 0 ? sources : [{ type: 'header', name: 'x-user-email' }],
                    auto_provision: value?.auto_provision ?? false,
                    enforce: value?.enforce ?? false,
                    allow_individual_overage: value?.allow_individual_overage ?? false,
                    allowed_teams: value?.allowed_teams ?? [],
                  }
                : null
            )
          }
        />
        <label className="form-check-label small" htmlFor="team-attribution-enabled">
          <strong>Surface use contributes to team quotas</strong>
        </label>
      </div>
      {enabled && value && (
        <div className="mt-2">
          <CallerIdentitySourcesEditor
            sources={value.caller_identity_sources}
            disabled={disabled}
            onChange={next => onChange({ ...value, caller_identity_sources: next })}
          />
          <div className="form-check form-switch mb-2">
            <input
              className="form-check-input"
              type="checkbox"
              role="switch"
              id="team-attribution-auto-provision"
              data-testid="team-attribution-auto-provision"
              checked={value.auto_provision === true}
              disabled={disabled}
              onChange={e => onChange({ ...value, auto_provision: e.target.checked })}
            />
            <label className="form-check-label small" htmlFor="team-attribution-auto-provision">
              Auto-provision unrecognised verified callers into members (per Enrolment rules)
            </label>
          </div>
          <div className="form-check form-switch mb-2">
            <input
              className="form-check-input"
              type="checkbox"
              role="switch"
              id="team-attribution-enforce"
              data-testid="team-attribution-enforce"
              checked={value.enforce}
              disabled={disabled}
              onChange={e => onChange({ ...value, enforce: e.target.checked })}
            />
            <label className="form-check-label small" htmlFor="team-attribution-enforce">
              Enforce team / member limits (block at 429)
            </label>
          </div>
          <div className="form-check form-switch mb-0">
            <input
              className="form-check-input"
              type="checkbox"
              role="switch"
              id="team-attribution-overage"
              data-testid="team-attribution-overage"
              checked={value.allow_individual_overage}
              disabled={disabled || !value.enforce}
              onChange={e => onChange({ ...value, allow_individual_overage: e.target.checked })}
            />
            <label className="form-check-label small" htmlFor="team-attribution-overage">
              Allow individuals to exceed their personal cap (team cap still applies)
            </label>
          </div>
          <div className="mt-3 pt-3">
            <label className="form-label small text-muted mb-1">Restrict surface to teams</label>
            <div className="small text-muted mb-2">
              Leave empty to allow any recognised caller. Add teams to allow only their members
              (access control, applied even without enforcement).
            </div>
            {(value.allowed_teams ?? []).length > 0 && (
              <div className="mb-2">
                {(value.allowed_teams ?? []).map(id => {
                  const t = teams.find(tm => tm.id === id);
                  return (
                    <div
                      className="d-flex align-items-center justify-content-between border rounded px-2 py-1 mb-1"
                      key={id}
                      data-testid={`team-attribution-allowed-${id}`}
                    >
                      <span className="small">
                        {t ? t.name : id}
                        {t && t.status !== 'enabled' ? ' (disabled)' : ''}
                        {!t ? ' (not found)' : ''}
                      </span>
                      <button
                        type="button"
                        className="btn btn-sm btn-outline-danger"
                        disabled={disabled}
                        title="Remove team"
                        data-testid={`team-attribution-allowed-remove-${id}`}
                        onClick={() => toggleAllowedTeam(id)}
                      >
                        <i className="fas fa-times" />
                      </button>
                    </div>
                  );
                })}
              </div>
            )}
            {(() => {
              const available = teams.filter(t => !(value.allowed_teams ?? []).includes(t.id));
              const placeholder =
                teams.length === 0
                  ? 'No teams available'
                  : available.length === 0
                    ? 'All teams added'
                    : 'Select a team to allow…';
              return (
                <Form.Select
                  size="sm"
                  value=""
                  data-testid="team-attribution-allowed-select"
                  disabled={disabled || available.length === 0}
                  onChange={e => {
                    if (e.target.value) toggleAllowedTeam(e.target.value);
                  }}
                >
                  <option value="">{placeholder}</option>
                  {available.map(t => (
                    <option key={t.id} value={t.id}>
                      {t.name}
                      {t.status !== 'enabled' ? ' (disabled)' : ''}
                    </option>
                  ))}
                </Form.Select>
              );
            })()}
          </div>
        </div>
      )}
    </div>
  );
};

type UsageAlertMeta = {
  label: string;
  thresholdLabel: string;
  hint: string;
  step: string;
  min: number;
};

const USAGE_ALERT_META: Record<UsageAlertType, UsageAlertMeta> = {
  cost_threshold: {
    label: 'Cost per request',
    thresholdLabel: 'Cost ceiling (USD)',
    hint: 'Fires when a single request costs more than this.',
    step: '0.01',
    min: 0,
  },
  token_threshold: {
    label: 'Tokens per request',
    thresholdLabel: 'Token ceiling',
    hint: 'Fires when a single request uses more than this many tokens.',
    step: '1',
    min: 0,
  },
  error_rate: {
    label: 'Error rate',
    thresholdLabel: 'Error-rate ceiling (0–1)',
    hint: 'Fires when the rolling 5-minute error rate exceeds this fraction.',
    step: '0.01',
    min: 0,
  },
  cost_spike: {
    label: 'Cost spike',
    thresholdLabel: 'Spike multiplier (× mean)',
    hint: 'Fires when a request costs more than this multiple of the recent mean. Must be > 1.',
    step: '0.1',
    min: 1,
  },
};

const ALERT_TYPE_ORDER: UsageAlertType[] = [
  'cost_threshold',
  'token_threshold',
  'error_rate',
  'cost_spike',
];

/**
 * Breach / anomaly alerts for the pipe (LLM surface). Each alert evaluates a
 * per-execution or rolling-window signal and, when tripped, fires through the
 * pipe integration / notification system. Lives on the surface property
 * sidebar; the runtime detector is surface-type agnostic.
 */
export const UsageAlertsControls: React.FC<{
  value: UsageAlertForm[];
  enabled: boolean;
  onEnabledChange: (v: boolean) => void;
  onChange: (v: UsageAlertForm[]) => void;
  disabled?: boolean;
}> = ({ value, enabled, onEnabledChange, onChange, disabled }) => {
  const integrationsAccess = useIntegrationsAccess();
  const [channels, setChannels] = useState<Array<{ id: string; name: string }>>([]);
  useEffect(() => {
    if (integrationsAccess !== 'allowed') return;
    let alive = true;
    apiClient
      .get<Array<{ id: string; name: string }>>('/integrations')
      .then(r => {
        if (alive) setChannels(Array.isArray(r.data) ? r.data : []);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, [integrationsAccess]);

  const hasAlerts = value.length > 0;

  const addAlert = () => {
    onChange([...value, { alert_type: 'cost_threshold', threshold: 1, notification_channels: [] }]);
  };

  const updateAlert = (index: number, patch: Partial<UsageAlertForm>) => {
    onChange(value.map((a, i) => (i === index ? { ...a, ...patch } : a)));
  };

  const removeAlert = (index: number) => {
    onChange(value.filter((_, i) => i !== index));
  };

  const toggleChannel = (index: number, id: string) => {
    const current = value[index]?.notification_channels ?? [];
    const next = current.includes(id) ? current.filter(c => c !== id) : [...current, id];
    updateAlert(index, { notification_channels: next });
  };

  const enableSwitch = (
    <Form.Check
      type="switch"
      id="surface-usage-alerts-enabled"
      label="Enable breach & anomaly alerts"
      checked={enabled}
      disabled={disabled}
      onChange={e => {
        const v = e.target.checked;
        onEnabledChange(v);
        if (v && value.length === 0) {
          onChange([{ alert_type: 'cost_threshold', threshold: 1, notification_channels: [] }]);
        }
      }}
    />
  );
  if (!enabled) {
    return <div>{enableSwitch}</div>;
  }
  return (
    <div>
      {enableSwitch}
      {!hasAlerts ? (
        <div className="small text-muted mt-2">
          No alerts configured. Add one to be notified on cost, token, error-rate, or cost-spike
          breaches.
        </div>
      ) : (
        <div className="mt-2">
          {value.map((alert, i) => {
            const m = USAGE_ALERT_META[alert.alert_type];
            return (
              <div className="border rounded p-2 mb-2" key={i} data-testid={`usage-alert-${i}`}>
                <div className="d-flex justify-content-between align-items-center mb-2">
                  <Form.Select
                    size="sm"
                    style={{ maxWidth: '60%' }}
                    data-testid={`usage-alert-type-${i}`}
                    value={alert.alert_type}
                    disabled={disabled}
                    onChange={e => updateAlert(i, { alert_type: e.target.value as UsageAlertType })}
                  >
                    {ALERT_TYPE_ORDER.map(t => (
                      <option key={t} value={t}>
                        {USAGE_ALERT_META[t].label}
                      </option>
                    ))}
                  </Form.Select>
                  <button
                    type="button"
                    className="btn btn-sm btn-outline-danger"
                    data-testid={`usage-alert-remove-${i}`}
                    disabled={disabled}
                    onClick={() => removeAlert(i)}
                    aria-label="Remove alert"
                  >
                    <i className="fas fa-trash" />
                  </button>
                </div>
                <div className="mb-2">
                  <label className="form-label small text-muted mb-1">{m.thresholdLabel}</label>
                  <input
                    type="number"
                    min={m.min}
                    step={m.step}
                    className="form-control form-control-sm"
                    data-testid={`usage-alert-threshold-${i}`}
                    value={Number.isFinite(alert.threshold) ? alert.threshold : ''}
                    disabled={disabled}
                    onChange={e => updateAlert(i, { threshold: Number(e.target.value) })}
                  />
                  <div className="small text-muted mt-1">{m.hint}</div>
                </div>
                <div>
                  <label className="form-label small text-muted mb-1">Notify via</label>
                  {integrationsAccess === 'denied' ? (
                    <IntegrationsAdminOnlyNotice data-testid={`usage-alert-${i}-admin-only`} />
                  ) : channels.length === 0 ? (
                    <div className="small text-muted">
                      No integrations available. Create one under Integrations.
                    </div>
                  ) : (
                    channels.map(c => (
                      <div className="form-check" key={c.id}>
                        <input
                          className="form-check-input"
                          type="checkbox"
                          id={`usage-alert-${i}-channel-${c.id}`}
                          data-testid={`usage-alert-${i}-channel-${c.id}`}
                          checked={(alert.notification_channels ?? []).includes(c.id)}
                          disabled={disabled}
                          onChange={() => toggleChannel(i, c.id)}
                        />
                        <label
                          className="form-check-label small"
                          htmlFor={`usage-alert-${i}-channel-${c.id}`}
                        >
                          {c.name}
                        </label>
                      </div>
                    ))
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
      <div className="d-flex justify-content-end mt-1">
        <button
          type="button"
          className="btn btn-link btn-sm p-0"
          data-testid="usage-alert-add"
          disabled={disabled}
          onClick={addAlert}
        >
          <i className="fas fa-plus me-1" /> Add alert
        </button>
      </div>
    </div>
  );
};

const fmtUsd = (n: number): string =>
  `$${n.toLocaleString(undefined, { minimumFractionDigits: 0, maximumFractionDigits: 2 })}`;

/** One-line summaries of each surface management control, shown on the property
 * sidebar next to a "Configure" link that opens the full-page editor. */
export const summarizeUsageLimit = (v: SurfaceUsageLimit | null): string => {
  if (!v?.enabled) return 'Off';
  const parts: string[] = [];
  if (v.monthlyBudgetUsd != null) parts.push(`${fmtUsd(v.monthlyBudgetUsd)}/mo`);
  if (v.monthlyTokenCap != null) parts.push(`${v.monthlyTokenCap.toLocaleString()} tok/mo`);
  return parts.length ? `On — ${parts.join(', ')}` : 'On — no caps set';
};

export const summarizeTeamAttribution = (v: TeamAttributionForm | null): string => {
  if (!v?.enabled) return 'Off';
  const bits: string[] = [];
  bits.push(v.enforce ? 'enforced' : 'tracking only');
  if ((v.allowed_teams ?? []).length > 0) bits.push(`${v.allowed_teams!.length} team(s) allowed`);
  return `On — ${bits.join(', ')}`;
};

export const DEFAULT_DRIFT: DriftForm = {
  enabled: true,
  sample_rate: 1,
};

/**
 * LLM drift-monitoring controls for the surface. When enabled, a `sample_rate`
 * fraction of the surface's live traffic is scored into its drift dimensions
 * (refusal rate, safety-flag rate, response length, latency, schema validity),
 * reviewed under Monitoring → LLM Drift. Lives on the surface property sidebar
 * (feature row) and the fullscreen Surface Configuration editor.
 */
export const DriftMonitoringControls: React.FC<{
  value: DriftForm | null;
  onChange: (v: DriftForm | null) => void;
  disabled?: boolean;
}> = ({ value, onChange, disabled }) => {
  const enabled = value?.enabled === true;
  const cfg = value ?? DEFAULT_DRIFT;
  const pct = Math.round((cfg.sample_rate ?? 1) * 100);
  const { llmProviders, secrets } = usePipePanelData();
  const embProviders = llmProviders as unknown as LLMProvider[];
  const embSecrets = secrets as unknown as Secret[];
  const evalEnabled = cfg.eval?.enabled === true;
  const schedEnabled = cfg.eval?.schedule?.enabled === true;
  const intervalMin = Math.max(5, Math.round((cfg.eval?.schedule?.interval_secs ?? 3600) / 60));
  const patchEval = (patch: Partial<NonNullable<DriftForm['eval']>>) =>
    onChange({ ...cfg, enabled: true, eval: { ...(cfg.eval ?? {}), enabled: true, ...patch } });
  return (
    <div>
      <div className="alert alert-info py-2 mb-3" style={{ fontSize: '12px' }}>
        <i className="fas fa-info-circle me-1" /> Sample this surface's live traffic to track
        behavioural <strong>drift dimensions</strong> (refusal rate, safety-flag rate, response
        length, latency, schema validity) over time. Review them under{' '}
        <strong>Monitoring → LLM Drift</strong>.
      </div>
      <div className="form-check form-switch">
        <input
          className="form-check-input"
          type="checkbox"
          role="switch"
          id="surface-drift-enabled"
          data-testid="surface-drift-enabled"
          checked={enabled}
          disabled={disabled}
          onChange={e =>
            onChange(
              e.target.checked
                ? { ...DEFAULT_DRIFT, ...(value ?? {}), enabled: true }
                : value
                  ? { ...value, enabled: false }
                  : null
            )
          }
        />
        <label className="form-check-label small" htmlFor="surface-drift-enabled">
          <strong>Monitor drift on live traffic</strong>
        </label>
      </div>

      {enabled && (
        <div className="mt-3">
          <label htmlFor="surface-drift-sample-rate" className="form-label small mb-1">
            Sample rate — <strong>{pct}%</strong> of interactions
          </label>
          <input
            type="range"
            className="form-range"
            id="surface-drift-sample-rate"
            data-testid="surface-drift-sample-rate"
            min={0}
            max={100}
            step={5}
            value={pct}
            disabled={disabled}
            onChange={e =>
              onChange({ ...cfg, enabled: true, sample_rate: Number(e.target.value) / 100 })
            }
          />
          <div className="form-text">
            Lower the rate on a high-traffic surface to cut overhead; 100% samples every
            interaction. Sampling reads signals already produced on the request path — no extra
            model calls.
          </div>

          <label className="form-label small fw-semibold mt-3 mb-1">
            Warn &amp; drift thresholds
          </label>
          <p className="form-text mt-0 mb-2">
            Each drift dimension (refusal rate, safety flags, response length, latency, schema
            validity, semantic distance) is compared to its <strong>pinned baseline</strong> as a{' '}
            <strong>relative change</strong> — e.g. a baseline latency of 800&nbsp;ms now averaging
            1000&nbsp;ms is a 25% change. These two thresholds turn that change into a status:{' '}
            <strong>Warn</strong> is the early-caution level (amber) and <strong>Drift</strong> is
            the alert level (red). The worst dimension sets the surface&apos;s overall status, and
            crossing <strong>Drift</strong> is what fires the alert below.
          </p>
          <div className="row g-2">
            <div className="col-6">
              <label htmlFor="surface-drift-warn" className="form-label small mb-1">
                Warn threshold — <strong>{Math.round((cfg.warn_threshold ?? 0.25) * 100)}%</strong>
              </label>
              <input
                type="number"
                className="form-control form-control-sm"
                id="surface-drift-warn"
                data-testid="surface-drift-warn"
                min={1}
                max={100}
                step={1}
                value={Math.round((cfg.warn_threshold ?? 0.25) * 100)}
                disabled={disabled}
                onChange={e =>
                  onChange({
                    ...cfg,
                    enabled: true,
                    warn_threshold: Math.max(0.01, Number(e.target.value) / 100),
                  })
                }
              />
              <div className="form-text">Amber — early caution.</div>
            </div>
            <div className="col-6">
              <label htmlFor="surface-drift-threshold" className="form-label small mb-1">
                Drift threshold — <strong>{Math.round((cfg.drift_threshold ?? 0.5) * 100)}%</strong>
              </label>
              <input
                type="number"
                className="form-control form-control-sm"
                id="surface-drift-threshold"
                data-testid="surface-drift-threshold"
                min={1}
                max={200}
                step={1}
                value={Math.round((cfg.drift_threshold ?? 0.5) * 100)}
                disabled={disabled}
                onChange={e =>
                  onChange({
                    ...cfg,
                    enabled: true,
                    drift_threshold: Math.max(0.01, Number(e.target.value) / 100),
                  })
                }
              />
              <div className="form-text">Red — fires the alert.</div>
            </div>
          </div>
          <div className="form-text mb-2">
            Tighter (lower) percentages catch smaller regressions sooner but are noisier; loosen
            them for a surface with naturally variable output. Re-pin the baseline after an
            intentional change (new model, prompt, or guards) so the comparison stays meaningful.
          </div>

          <div className="form-check form-switch mt-2">
            <input
              className="form-check-input"
              type="checkbox"
              role="switch"
              id="surface-drift-gate"
              data-testid="surface-drift-gate"
              checked={cfg.gate_on_regression === true}
              disabled={disabled}
              onChange={e =>
                onChange({ ...cfg, enabled: true, gate_on_regression: e.target.checked })
              }
            />
            <label className="form-check-label small" htmlFor="surface-drift-gate">
              <strong>Block saves on regression</strong> — refuse a surface save while it is
              drifting past its baseline (re-pin the baseline or disable to proceed)
            </label>
          </div>

          <hr className="my-3" />
          <div className="form-check form-switch">
            <input
              className="form-check-input"
              type="checkbox"
              role="switch"
              id="surface-drift-eval-enabled"
              data-testid="surface-drift-eval-enabled"
              checked={evalEnabled}
              disabled={disabled}
              onChange={e =>
                onChange({
                  ...cfg,
                  enabled: true,
                  eval: { ...(cfg.eval ?? {}), enabled: e.target.checked },
                })
              }
            />
            <label className="form-check-label small" htmlFor="surface-drift-eval-enabled">
              <strong>Replay evaluation</strong> — periodically re-run this surface's captured
              sessions (its "indicative surface data") and compare each new answer to the
              originally-captured one (semantic distance, latency, length, …)
            </label>
          </div>

          {evalEnabled && (
            <div className="mt-3 ps-3 border-start">
              <label className="form-label small mb-1">
                Embeddings model — measures how far a replayed answer has moved
              </label>
              <EmbeddingsTargetEditor
                value={cfg.eval?.embeddings ?? null}
                onChange={emb => patchEval({ embeddings: emb })}
                llmProviders={embProviders}
                secrets={embSecrets}
                disabled={disabled}
              />
              <div className="form-text mb-3">
                Chosen from the model catalogue — no hand-typed URL. Without it a replay can't
                measure semantic drift.
              </div>

              <div className="form-check form-switch">
                <input
                  className="form-check-input"
                  type="checkbox"
                  role="switch"
                  id="surface-drift-eval-schedule"
                  data-testid="surface-drift-eval-schedule"
                  checked={schedEnabled}
                  disabled={disabled}
                  onChange={e =>
                    patchEval({
                      schedule: {
                        enabled: e.target.checked,
                        interval_secs: cfg.eval?.schedule?.interval_secs ?? 3600,
                      },
                    })
                  }
                />
                <label className="form-check-label small" htmlFor="surface-drift-eval-schedule">
                  <strong>Run automatically</strong>
                </label>
              </div>
              {schedEnabled && (
                <div className="mt-2 mb-2">
                  <label htmlFor="surface-drift-eval-interval" className="form-label small mb-1">
                    Every
                  </label>
                  <div className="input-group input-group-sm" style={{ maxWidth: 220 }}>
                    <input
                      type="number"
                      className="form-control"
                      id="surface-drift-eval-interval"
                      data-testid="surface-drift-eval-interval"
                      min={5}
                      step={5}
                      value={intervalMin}
                      disabled={disabled}
                      onChange={e =>
                        patchEval({
                          schedule: {
                            enabled: true,
                            interval_secs: Math.max(5, Number(e.target.value)) * 60,
                          },
                        })
                      }
                    />
                    <span className="input-group-text">min (min 5)</span>
                  </div>
                </div>
              )}

              <div className="mt-2" style={{ maxWidth: 220 }}>
                <label htmlFor="surface-drift-eval-max" className="form-label small mb-1">
                  Max sessions per run
                </label>
                <input
                  type="number"
                  className="form-control form-control-sm"
                  id="surface-drift-eval-max"
                  data-testid="surface-drift-eval-max"
                  min={1}
                  max={200}
                  step={1}
                  value={cfg.eval?.max_sessions ?? 50}
                  disabled={disabled}
                  onChange={e =>
                    patchEval({ max_sessions: Math.max(1, Math.min(200, Number(e.target.value))) })
                  }
                />
              </div>

              <div className="mt-2" style={{ maxWidth: 220 }}>
                <label htmlFor="surface-drift-eval-cost" className="form-label small mb-1">
                  Cost ceiling per run
                </label>
                <div className="input-group input-group-sm">
                  <span className="input-group-text">$</span>
                  <input
                    type="number"
                    className="form-control form-control-sm"
                    id="surface-drift-eval-cost"
                    data-testid="surface-drift-eval-cost"
                    min={0}
                    step={0.5}
                    value={cfg.eval?.max_run_cost_usd ?? ''}
                    placeholder="appliance default"
                    disabled={disabled}
                    onChange={e => {
                      const raw = e.target.value.trim();
                      patchEval({
                        max_run_cost_usd: raw === '' ? undefined : Math.max(0, Number(raw)),
                      });
                    }}
                  />
                </div>
                <div className="form-text small">
                  A replay is a real upstream call billed to this surface, and counts against its
                  usage limits. A run stops part-way once it has spent this much. Leave blank for
                  the appliance default; 0 removes the ceiling.
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export const DEFAULT_GOVERNANCE_RECORDING: GovernanceRecordingForm = {
  enabled: true,
  capture_bodies: true,
  include_streaming: true,
  retention_days: 0,
  export: null,
};

type BodyCaptureChoice = 'all' | 'blocked' | 'none';

/** The `capture_bodies` value each body-capture choice saves (as the backend writes it). */
const BODY_CAPTURE_VALUES: Record<BodyCaptureChoice, GovernanceRecordingForm['capture_bodies']> = {
  all: true,
  blocked: 'blocked',
  none: false,
};

/** The body-capture choice a saved `capture_bodies` value means (absent keeps every body). */
const bodyCaptureChoice = (
  value: GovernanceRecordingForm['capture_bodies'] | string
): BodyCaptureChoice => {
  if (value === false || value === 'none') return 'none';
  if (value === 'blocked') return 'blocked';
  return 'all';
};

/**
 * Signed governance-recording controls for the LLM surface. When enabled, every
 * interaction on the surface is captured as a signed, chained W3C VC; the
 * sub-options tune body capture, streaming capture, local retention, and the
 * export targets (OpenTelemetry and/or configured integrations that fan the
 * signed record out to webhook, Slack, email, Kafka/Kinesis/Pulsar/Redis, or
 * Langfuse). Lives on the surface property sidebar (feature row) and the
 * fullscreen Surface Configuration editor.
 */
export const GovernanceRecordingControls: React.FC<{
  value: GovernanceRecordingForm | null;
  onChange: (v: GovernanceRecordingForm | null) => void;
  disabled?: boolean;
}> = ({ value, onChange, disabled }) => {
  const enabled = value?.enabled === true;
  const cfg = value ?? DEFAULT_GOVERNANCE_RECORDING;
  const update = (patch: Partial<GovernanceRecordingForm>) =>
    onChange({ ...cfg, ...patch, enabled: true });
  const exportOtel = cfg.export?.otel === true;
  const exportIntegrations = cfg.export?.integrations ?? [];
  const setExport = (next: { otel: boolean; integrations: string[] }) =>
    update({ export: next.otel || next.integrations.length > 0 ? next : null });
  const toggleIntegration = (id: string, on: boolean) => {
    const ids = on ? [...exportIntegrations, id] : exportIntegrations.filter(x => x !== id);
    setExport({ otel: exportOtel, integrations: ids });
  };

  const [integrations, setIntegrations] = useState<
    Array<{ id: string; name: string; type: string; category?: string; status?: string }>
  >([]);
  const integrationsAccess = useIntegrationsAccess();
  useEffect(() => {
    if (!enabled || integrationsAccess !== 'allowed') return;
    let active = true;
    apiClient
      .get('/integrations')
      .then(res => {
        if (active) setIntegrations(Array.isArray(res.data) ? res.data : []);
      })
      .catch(() => {
        if (active) setIntegrations([]);
      });
    return () => {
      active = false;
    };
  }, [enabled, integrationsAccess]);
  const activeIntegrations = integrations.filter(
    i => (i.status ?? 'active') === 'active' && i.category === 'llm_governance'
  );

  return (
    <div>
      <div className="alert alert-info py-2 mb-3" style={{ fontSize: '12px' }}>
        <i className="fas fa-info-circle me-1" /> Capture a signed, tamper-evident record of every
        interaction (prompt, processing stages, completion, metrics) as a W3C Verifiable Credential
        signed by the appliance DID, chained per surface and encrypted at rest. Review them under{' '}
        <strong>Monitoring → Governance</strong>.
      </div>
      <div className="form-check form-switch">
        <input
          className="form-check-input"
          type="checkbox"
          role="switch"
          id="surface-governance-enabled"
          data-testid="surface-governance-enabled"
          checked={enabled}
          disabled={disabled}
          onChange={e =>
            onChange(
              e.target.checked
                ? { ...DEFAULT_GOVERNANCE_RECORDING, ...(value ?? {}), enabled: true }
                : value
                  ? { ...value, enabled: false }
                  : null
            )
          }
        />
        <label className="form-check-label small" htmlFor="surface-governance-enabled">
          <strong>Record signed governance records</strong>
        </label>
      </div>

      {enabled && (
        <div className="mt-2">
          <div className="mb-2">
            <label
              className="form-label small text-muted mb-1"
              htmlFor="surface-governance-record-outcomes"
            >
              Record
            </label>
            <select
              className="form-select form-select-sm"
              id="surface-governance-record-outcomes"
              data-testid="surface-governance-record-outcomes"
              value={cfg.record_outcomes ?? 'all'}
              disabled={disabled}
              onChange={e =>
                update({
                  record_outcomes: e.target.value as GovernanceRecordingForm['record_outcomes'],
                })
              }
            >
              <option value="all">Every interaction</option>
              <option value="blocked">Blocked interactions only</option>
              <option value="blocked_and_failed">Blocked and failed interactions</option>
            </select>
          </div>
          <div className="mb-2">
            <label
              className="form-label small text-muted mb-1"
              htmlFor="surface-governance-capture-bodies"
            >
              Keep prompt &amp; completion bodies
            </label>
            <select
              className="form-select form-select-sm"
              id="surface-governance-capture-bodies"
              data-testid="surface-governance-capture-bodies"
              value={bodyCaptureChoice(cfg.capture_bodies)}
              disabled={disabled}
              onChange={e =>
                update({ capture_bodies: BODY_CAPTURE_VALUES[e.target.value as BodyCaptureChoice] })
              }
            >
              <option value="all">For every recorded interaction</option>
              <option value="blocked">For blocked interactions only</option>
              <option value="none">Never (digests only)</option>
            </select>
          </div>
          <div className="form-check form-switch mb-2">
            <input
              className="form-check-input"
              type="checkbox"
              role="switch"
              id="surface-governance-include-streaming"
              data-testid="surface-governance-include-streaming"
              checked={cfg.include_streaming !== false}
              disabled={disabled}
              onChange={e => update({ include_streaming: e.target.checked })}
            />
            <label
              className="form-check-label small"
              htmlFor="surface-governance-include-streaming"
            >
              Record streamed interactions
            </label>
          </div>
          <div className="mb-2">
            <label className="form-label small text-muted mb-1">
              Local retention (days, 0 = keep indefinitely)
            </label>
            <input
              type="number"
              min={0}
              step={1}
              className="form-control form-control-sm"
              data-testid="surface-governance-retention"
              value={cfg.retention_days ?? 0}
              disabled={disabled}
              onChange={e => update({ retention_days: Math.max(0, Number(e.target.value) || 0) })}
            />
          </div>
          <div className="mb-2">
            <label className="form-label small text-muted mb-1">Integrations</label>
            <div className="small text-muted mb-2" style={{ fontSize: '11px' }}>
              Export each signed record to the local store (always on) plus any selected targets.
              Only integrations created under the <strong>LLM Governance</strong> category are
              listed here.
            </div>
            <div className="form-check form-switch mb-2">
              <input
                className="form-check-input"
                type="checkbox"
                role="switch"
                id="surface-governance-export-otel"
                data-testid="surface-governance-export-otel"
                checked={exportOtel}
                disabled={disabled}
                onChange={e =>
                  setExport({ otel: e.target.checked, integrations: exportIntegrations })
                }
              />
              <label className="form-check-label small" htmlFor="surface-governance-export-otel">
                OpenTelemetry exporter
              </label>
            </div>
            {integrationsAccess === 'denied' ? (
              <IntegrationsAdminOnlyNotice data-testid="surface-governance-integrations-admin-only" />
            ) : activeIntegrations.length === 0 ? (
              <div
                className="small text-muted fst-italic"
                data-testid="surface-governance-no-integrations"
              >
                No LLM Governance integrations configured.{' '}
                <a
                  href="/integrations/integrations/wizard?category=llm_governance"
                  target="_blank"
                  rel="noopener noreferrer"
                  data-testid="surface-governance-create-integration"
                >
                  Click here to create one
                </a>
                .
              </div>
            ) : (
              <div data-testid="surface-governance-integrations">
                {activeIntegrations.map(i => (
                  <div className="form-check" key={i.id}>
                    <input
                      className="form-check-input"
                      type="checkbox"
                      id={`surface-governance-integration-${i.id}`}
                      data-testid={`surface-governance-integration-${i.id}`}
                      checked={exportIntegrations.includes(i.id)}
                      disabled={disabled}
                      onChange={e => toggleIntegration(i.id, e.target.checked)}
                    />
                    <label
                      className="form-check-label small"
                      htmlFor={`surface-governance-integration-${i.id}`}
                    >
                      {i.name} <span className="text-muted">({i.type})</span>
                    </label>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export const summarizeBool = (on: boolean | undefined, onLabel = 'On'): string =>
  on ? onLabel : 'Off';

const INGRESS_FORMAT_LABELS: Record<string, string> = {
  openai_chat: 'OpenAI Chat',
  anthropic_messages: 'Anthropic Messages',
  openai_responses: 'OpenAI Responses',
};

export const summarizeIngressFormats = (v: string[] | undefined): string => {
  const list = v && v.length ? v : ['openai_chat', 'anthropic_messages', 'openai_responses'];
  if (list.length >= 3) return 'All (OpenAI, Anthropic, Responses)';
  return list.map(k => INGRESS_FORMAT_LABELS[k] ?? k).join(', ');
};

export const summarizeCache = (v: PipeCacheForm | null): string => {
  if (!v?.enabled) return 'Off';
  return v.mode === 'semantic' ? 'On — semantic matching' : 'On — exact matching';
};

export const summarizeCanary = (v: PipeCanaryForm | null): string => {
  if (!v?.enabled) return 'Off';
  const n = v.splits?.length ?? 0;
  return n ? `On — ${n} split(s)` : 'On';
};

export const summarizeRoutingRules = (
  enabled: boolean | undefined,
  v: PipeRoutingRuleForm[] | undefined
): string => {
  if (!enabled) return 'Off';
  const n = v?.length ?? 0;
  return n ? `On — ${n} rule(s)` : 'On — no rules';
};

export const summarizeUsageAlerts = (
  enabled: boolean | undefined,
  v: UsageAlertForm[] | undefined
): string => {
  if (!enabled) return 'Off';
  const n = v?.length ?? 0;
  return n ? `On — ${n} alert(s)` : 'On — no alerts';
};

export const summarizeGovernance = (v: GovernanceRecordingForm | null | undefined): string => {
  if (!v?.enabled) return 'Off';
  const targets: string[] = [];
  if (v.export?.otel) targets.push('OTEL');
  const count = v.export?.integrations?.length ?? 0;
  if (count > 0) targets.push(`${count} integration${count === 1 ? '' : 's'}`);
  return targets.length > 0 ? `On — ${targets.join(', ')}` : 'On';
};

export const summarizeDrift = (v: DriftForm | null | undefined): string => {
  if (!v?.enabled) return 'Off';
  const pct = Math.round((v.sample_rate ?? 1) * 100);
  return `On — ${pct}% sampled`;
};

export const DEFAULT_VP_EVIDENCE: VpEvidenceForm = {
  enabled: true,
  require_present: false,
  source: 'header',
  header_name: 'X-Agent-Stream-Presentation',
};

/**
 * Per-surface verifiable-presentation evidence controls. When enabled, an
 * inbound VP (carried in a header or the JSON body) is cryptographically
 * verified and injected as `input.identity_binding` for the surface's OPA
 * policy — e.g. allow only when a VP signed by a known issuer is present.
 */
export const VpEvidenceControls: React.FC<{
  value: VpEvidenceForm | null;
  onChange: (v: VpEvidenceForm | null) => void;
  disabled?: boolean;
}> = ({ value, onChange, disabled }) => {
  const enabled = value?.enabled === true;
  const cfg = value ?? DEFAULT_VP_EVIDENCE;
  const update = (patch: Partial<VpEvidenceForm>) => onChange({ ...cfg, ...patch, enabled: true });
  const source = cfg.source ?? 'header';
  return (
    <div>
      <div className="alert alert-info py-2 mb-3" style={{ fontSize: '12px' }}>
        <i className="fas fa-info-circle me-1" /> Verify an inbound verifiable presentation and
        expose it to the surface policy as <code>input.identity_binding</code> (holder DID, issuer
        DID, verified flag, and VC claims) — so a policy can allow only when a VP signed by a known
        issuer is present.
      </div>
      <div className="form-check form-switch">
        <input
          className="form-check-input"
          type="checkbox"
          role="switch"
          id="surface-vp-enabled"
          data-testid="surface-vp-enabled"
          checked={enabled}
          disabled={disabled}
          onChange={e =>
            onChange(
              e.target.checked
                ? { ...DEFAULT_VP_EVIDENCE, ...(value ?? {}), enabled: true }
                : value
                  ? { ...value, enabled: false }
                  : null
            )
          }
        />
        <label className="form-check-label small" htmlFor="surface-vp-enabled">
          <strong>Evaluate VP evidence</strong>
        </label>
      </div>

      {enabled && (
        <div className="mt-2">
          <div className="form-check form-switch mb-2">
            <input
              className="form-check-input"
              type="checkbox"
              role="switch"
              id="surface-vp-require-present"
              data-testid="surface-vp-require-present"
              checked={cfg.require_present === true}
              disabled={disabled}
              onChange={e => update({ require_present: e.target.checked })}
            />
            <label className="form-check-label small" htmlFor="surface-vp-require-present">
              Deny when no VP is presented
            </label>
          </div>
          <div className="mb-2">
            <label className="form-label small mb-1" htmlFor="surface-vp-source">
              VP carried in
            </label>
            <select
              className="form-select form-select-sm"
              id="surface-vp-source"
              data-testid="surface-vp-source"
              value={source}
              disabled={disabled}
              onChange={e => update({ source: e.target.value as 'header' | 'body' })}
            >
              <option value="header">Request header</option>
              <option value="body">JSON body field</option>
            </select>
          </div>
          {source === 'header' && (
            <div className="mb-1">
              <label className="form-label small mb-1" htmlFor="surface-vp-header">
                Header name
              </label>
              <input
                type="text"
                className="form-control form-control-sm"
                id="surface-vp-header"
                data-testid="surface-vp-header"
                value={cfg.header_name ?? ''}
                placeholder="X-Agent-Stream-Presentation"
                disabled={disabled}
                onChange={e => update({ header_name: e.target.value || undefined })}
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export const summarizeVpEvidence = (v: VpEvidenceForm | null | undefined): string => {
  if (!v?.enabled) return 'Off';
  const bits: string[] = [v.source === 'body' ? 'body' : 'header'];
  if (v.require_present) bits.push('required');
  return `On — ${bits.join(', ')}`;
};

const SurfacePanel: React.FC<ConfigPanelProps> = ({ openFullscreenEditor }) => {
  const meta = useOptionalSurfaceMeta();

  if (!meta) {
    return <div className="text-muted small">Surface metadata is unavailable in this context.</div>;
  }

  const {
    name,
    description,
    tagsCsv,
    status,
    protocol,
    publishToDid,
    didwebvh,
    readOnly,
    protocolLocked,
    isCreate,
    lastActivity,
    surfaceId,
    setName,
    setDescription,
    setTagsCsv,
    setStatus,
    setProtocol,
    setPublishToDid,
    setDidwebvh,
    onSaveAsTemplate,
  } = meta;

  const disabled = readOnly;
  const protocolDisabled = disabled || protocolLocked;

  if (meta.variant === 'ide') {
    return (
      <div className="config-section">
        <Form.Group className="mb-3">
          <Form.Label className="small text-muted mb-1">
            Name <span className="text-danger">*</span>
          </Form.Label>
          <Form.Control
            id="surface-name"
            size="sm"
            type="text"
            value={name}
            onChange={e => setName(e.target.value)}
            disabled={disabled}
            isInvalid={!disabled && !name.trim()}
            placeholder="Name this IDE Surface"
          />
          {!disabled && !name.trim() && (
            <Form.Control.Feedback type="invalid" style={{ fontSize: '10px' }}>
              IDE Surface name is required.
            </Form.Control.Feedback>
          )}
        </Form.Group>

        <Form.Group className="mb-3">
          <Form.Label className="small text-muted mb-1">Description</Form.Label>
          <Form.Control
            size="sm"
            type="text"
            value={description}
            onChange={e => setDescription(e.target.value)}
            disabled={disabled}
            placeholder="Optional description"
          />
        </Form.Group>

        <div className="form-check">
          <input
            type="checkbox"
            className="form-check-input"
            id="surface-enabled"
            checked={status !== 'disabled'}
            onChange={e => setStatus(e.target.checked ? 'enabled' : 'disabled')}
            disabled={disabled}
          />
          <label className="form-check-label small" htmlFor="surface-enabled">
            <strong>IDE Surface enabled</strong>
            {status === 'disabled' && (
              <span className="badge text-bg-warning ms-2">
                <i className="fas fa-power-off" /> DISABLED
              </span>
            )}
          </label>
        </div>

        {surfaceId && (
          <div className="mt-3">
            <Form.Label className="small text-muted mb-1">Surface ID</Form.Label>
            <Form.Control size="sm" type="text" value={surfaceId} readOnly disabled />
          </div>
        )}
      </div>
    );
  }

  if (meta.variant === 'pipe') {
    return (
      <div className="config-section">
        <Form.Group className="mb-3">
          <Form.Label className="small text-muted mb-1">
            Name <span className="text-danger">*</span>
          </Form.Label>
          <Form.Control
            id="surface-name"
            size="sm"
            type="text"
            value={name}
            onChange={e => setName(e.target.value)}
            disabled={disabled}
            isInvalid={!disabled && !name.trim()}
            placeholder="Name this LLM Surface"
          />
          {!disabled && !name.trim() && (
            <Form.Control.Feedback type="invalid" style={{ fontSize: '10px' }}>
              LLM Surface name is required.
            </Form.Control.Feedback>
          )}
        </Form.Group>

        <Form.Group className="mb-3">
          <Form.Label className="small text-muted mb-1">Description</Form.Label>
          <Form.Control
            size="sm"
            type="text"
            value={description}
            onChange={e => setDescription(e.target.value)}
            disabled={disabled}
            placeholder="Optional description"
          />
        </Form.Group>

        <div className="form-check">
          <input
            type="checkbox"
            className="form-check-input"
            id="surface-enabled"
            checked={status !== 'disabled'}
            onChange={e => setStatus(e.target.checked ? 'enabled' : 'disabled')}
            disabled={disabled}
          />
          <label className="form-check-label small" htmlFor="surface-enabled">
            <strong>Surface Enabled</strong>
            {status === 'disabled' && (
              <span className="badge text-bg-warning ms-2">
                <i className="fas fa-power-off" /> DISABLED
              </span>
            )}
          </label>
        </div>

        <div className="mt-3">
          <label className="small text-muted mb-1">Surface Features</label>
          {(() => {
            const rows: Array<{ title: string; summary: string; active: boolean }> = [];
            if (meta.setSurfaceUsageLimit)
              rows.push({
                title: 'Surface-wide usage limit',
                summary: summarizeUsageLimit(meta.surfaceUsageLimit ?? null),
                active: meta.surfaceUsageLimit?.enabled === true,
              });
            if (meta.setTeamAttribution)
              rows.push({
                title: 'Team usage attribution',
                summary: summarizeTeamAttribution(meta.teamAttribution ?? null),
                active: meta.teamAttribution?.enabled === true,
              });
            if (meta.setStreamingEnabled)
              rows.push({
                title: 'SSE streaming passthrough',
                summary: summarizeBool(meta.streamingEnabled !== false, 'Allowed'),
                active: meta.streamingEnabled !== false,
              });
            if (meta.setForwardCallerToken)
              rows.push({
                title: 'Identity pass-through',
                summary: summarizeBool(meta.forwardCallerToken === true),
                active: meta.forwardCallerToken === true,
              });
            if (meta.setAcceptedIngressSchemas)
              rows.push({
                title: 'Client API formats',
                summary: summarizeIngressFormats(meta.acceptedIngressSchemas),
                active: (meta.acceptedIngressSchemas?.length ?? 3) < 3,
              });
            if (meta.setCache)
              rows.push({
                title: 'Response cache',
                summary: summarizeCache(meta.cache ?? null),
                active: meta.cache?.enabled === true,
              });
            if (meta.setCanary)
              rows.push({
                title: 'Canary / A-B traffic split',
                summary: summarizeCanary(meta.canary ?? null),
                active: meta.canary?.enabled === true,
              });
            if (meta.setRoutingRules)
              rows.push({
                title: 'Attribute-based routing',
                summary: summarizeRoutingRules(meta.routingEnabled, meta.routingRules),
                active: meta.routingEnabled === true,
              });
            if (meta.setUsageAlerts)
              rows.push({
                title: 'Breach & anomaly alerts',
                summary: summarizeUsageAlerts(meta.usageAlertsEnabled, meta.usageAlerts),
                active: meta.usageAlertsEnabled === true,
              });
            if (meta.setGovernanceRecording)
              rows.push({
                title: 'Governance recording',
                summary: summarizeGovernance(meta.governanceRecording),
                active: meta.governanceRecording?.enabled === true,
              });
            if (meta.setVpEvidence)
              rows.push({
                title: 'VP evidence',
                summary: summarizeVpEvidence(meta.vpEvidence),
                active: meta.vpEvidence?.enabled === true,
              });
            return (
              <dl className="row mb-0 small g-0">
                {rows.map(r => (
                  <React.Fragment key={r.title}>
                    <dt className="col-7 fw-normal text-muted text-truncate">{r.title}</dt>
                    <dd
                      className={`col-5 mb-1 text-end text-truncate ${r.active ? '' : 'text-muted'}`}
                    >
                      {r.summary}
                    </dd>
                  </React.Fragment>
                ))}
              </dl>
            );
          })()}
          {openFullscreenEditor && (
            <button
              type="button"
              className="btn btn-outline-primary btn-sm w-100 mt-2"
              data-testid="surface-configure"
              onClick={() => openFullscreenEditor()}
            >
              <i className="fas fa-pen-to-square me-1" /> Configure Surface Features
            </button>
          )}
        </div>

        {surfaceId && (
          <div className="mt-3">
            <Form.Label className="small text-muted mb-1">Surface ID</Form.Label>
            <Form.Control size="sm" type="text" value={surfaceId} readOnly disabled />
          </div>
        )}
      </div>
    );
  }

  return (
    <>
      <div className="config-section">
        <Form.Group className="mb-3">
          <Form.Label className="small text-muted mb-1">
            Name <span className="text-danger">*</span>
          </Form.Label>
          <Form.Control
            id="surface-name"
            size="sm"
            type="text"
            value={name}
            onChange={e => setName(e.target.value)}
            disabled={disabled}
            isInvalid={!disabled && !name.trim()}
          />
          {!disabled && !name.trim() && (
            <Form.Control.Feedback type="invalid" style={{ fontSize: '10px' }}>
              Surface name is required.
            </Form.Control.Feedback>
          )}
        </Form.Group>

        <Form.Group className="mb-3">
          <Form.Label className="small text-muted mb-1">Description</Form.Label>
          <Form.Control
            size="sm"
            type="text"
            value={description}
            onChange={e => setDescription(e.target.value)}
            disabled={disabled}
            placeholder="Optional description"
          />
        </Form.Group>

        <Form.Group className="mb-3">
          <Form.Label className="small text-muted mb-1">Tags</Form.Label>
          <Form.Control
            size="sm"
            type="text"
            value={tagsCsv}
            onChange={e => setTagsCsv(e.target.value)}
            disabled={disabled}
            placeholder="comma, separated, tags"
          />
        </Form.Group>
      </div>

      <div className="config-section">
        <Form.Group className="mb-2">
          <Form.Label className="small text-muted mb-1 d-block">
            Protocol <span className="text-danger">*</span>
            {protocolLocked && (
              <span className="badge text-bg-primary ms-2">{getProtocolLabel(protocol)}</span>
            )}
          </Form.Label>
          <Form.Select
            size="sm"
            value={protocol}
            onChange={e => setProtocol(e.target.value as typeof protocol)}
            disabled={protocolDisabled}
          >
            {SURFACE_PROTOCOL_OPTIONS.map(p => (
              <option key={p} value={p}>
                {getProtocolLabel(p)}
              </option>
            ))}
          </Form.Select>
          <small className="form-text text-muted">
            {protocolLocked ? (
              <>
                <i className="fas fa-lock me-1" />
                Protocol locks once the surface contains configured elements.
              </>
            ) : (
              <>Choose the protocol for this surface. Locks when you start adding elements.</>
            )}
          </small>
        </Form.Group>
      </div>

      <div className="config-section">
        <div className="form-check">
          <input
            type="checkbox"
            className="form-check-input"
            id="surface-enabled"
            checked={status !== 'disabled'}
            onChange={e => setStatus(e.target.checked ? 'enabled' : 'disabled')}
            disabled={disabled}
          />
          <label className="form-check-label small" htmlFor="surface-enabled">
            <strong>Surface enabled</strong>
            {status === 'disabled' && (
              <span className="badge text-bg-warning ms-2">
                <i className="fas fa-power-off" /> DISABLED
              </span>
            )}
          </label>
        </div>
        <div className="form-check mt-2">
          <input
            type="checkbox"
            className="form-check-input"
            id="surface-publish-did"
            checked={publishToDid}
            onChange={e => setPublishToDid(e.target.checked)}
            disabled={disabled}
          />
          <label className="form-check-label small" htmlFor="surface-publish-did">
            <strong>Publish to Gateway DID document</strong>
            {publishToDid && (
              <span className="badge text-bg-info ms-2">
                <i className="fas fa-globe" /> PUBLISHED
              </span>
            )}
          </label>
        </div>
      </div>

      <div className="config-section">
        <label>Gateway DID Injection</label>
        <div className="surface-info-panel mb-2">
          <i className="fas fa-info-circle me-2" />
          <i>
            When enabled, the Gateway injects a did:webvh identity on every outbound request
            transiting this surface. Applies to the Managed Agent &rarr; External exit point.
            Downstream services use it to verify routing provenance and attribute traffic to this
            Gateway.
          </i>
        </div>
        <Form.Check
          type="switch"
          id="surface-didwebvh-enabled"
          label="Enable Gateway DID injection (did:webvh)"
          checked={didwebvh.enabled}
          disabled={disabled}
          onChange={e => setDidwebvh({ ...didwebvh, enabled: e.target.checked })}
        />
        {didwebvh.enabled && (
          <>
            <Form.Group className="mt-2">
              <Form.Label className="small text-muted mb-1">Identity ID (optional)</Form.Label>
              <Form.Control
                size="sm"
                type="text"
                placeholder="existing identity UUID"
                value={didwebvh.identity_id}
                disabled={disabled}
                onChange={e => setDidwebvh({ ...didwebvh, identity_id: e.target.value })}
              />
              <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
                Bind to an existing managed identity. Leave blank to create a new one.
              </Form.Text>
            </Form.Group>
            <Form.Check
              type="switch"
              id="surface-didwebvh-autocreate"
              className="mt-2"
              label="Auto-create identity if it does not exist"
              checked={didwebvh.auto_create}
              disabled={disabled}
              onChange={e => setDidwebvh({ ...didwebvh, auto_create: e.target.checked })}
            />
            <Form.Group className="mt-2">
              <Form.Label className="small text-muted mb-1">DID Path (optional)</Form.Label>
              <Form.Control
                size="sm"
                type="text"
                placeholder="custom-path-segment"
                value={didwebvh.did_path}
                disabled={disabled}
                onChange={e => setDidwebvh({ ...didwebvh, did_path: e.target.value })}
              />
              <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
                Custom path segment for the DID; defaults to the surface name.
              </Form.Text>
            </Form.Group>
            <Form.Group className="mt-2">
              <Form.Label className="small text-muted mb-1">Injection Mode</Form.Label>
              <Form.Select
                size="sm"
                value={didwebvh.injection_mode}
                disabled={disabled}
                onChange={e =>
                  setDidwebvh({
                    ...didwebvh,
                    injection_mode: e.target.value as typeof didwebvh.injection_mode,
                  })
                }
              >
                <option value="header">Header (X-DID-Identity)</option>
                <option value="signed_header">Signed Header (X-DID-Signed-Identity)</option>
                <option value="protocol_native">Protocol Native (A2A ext / MCP _meta)</option>
              </Form.Select>
            </Form.Group>
          </>
        )}
      </div>

      {!isCreate && (
        <div className="config-section">
          {surfaceId && (
            <div className="mb-2">
              <Form.Label className="small text-muted mb-1">Surface ID</Form.Label>
              <Form.Control size="sm" type="text" value={surfaceId} readOnly disabled />
            </div>
          )}
          <div className="small">
            <i className="fas fa-clock text-muted me-2" />
            <strong>Last Activity:</strong>{' '}
            {lastActivity ? (
              <span>
                {timeAgo(lastActivity)}
                <span className="text-muted"> — {formatDateTime(lastActivity, true)}</span>
              </span>
            ) : (
              <span className="text-muted">No activity recorded</span>
            )}
          </div>
        </div>
      )}

      {onSaveAsTemplate && !disabled && (
        <div className="config-section">
          <button
            type="button"
            className="btn btn-outline-primary btn-sm w-100"
            onClick={onSaveAsTemplate}
            title="Snapshot the current surface as a reusable template"
          >
            <i className="fas fa-bookmark me-1" /> Save Surface as Template…
          </button>
        </div>
      )}
    </>
  );
};

export default SurfacePanel;
