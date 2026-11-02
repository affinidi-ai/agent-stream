import React, { useState, useEffect } from 'react';
import { apiClient } from '../../api';
import MarketplacePurchaseModal from './MarketplacePurchaseModal';
import { formatDateTime } from '../../utils/stringUtils';
import { UI_COLORS, withAlpha } from '../../utils/uiPalette';

/** Shape of a model returned by the marketplace API (proxied via gateway). */
export interface MarketplaceModel {
  id: string;
  name: string;
  provider: string;
  logo: string;
  category: string;
  description: string;
  rating: number;
  reviewCount: number;
  pricing: string;
  contextWindow: string;
  capabilities: string[];
  /** Identifies which marketplace provider this model came from (multi-marketplace). */
  marketplace_id?: string;
  /** Gateway ID that serves this model (auto-discovery). */
  gateway_id?: string;
  /** Name of the gateway that serves this model. */
  gateway_name?: string;
  metadata: {
    api_schema: string;
    provider: string;
    model: string;
    default_base_url: string;
    api_version_prefix: string;
    endpoint: string;
    cost_per_1k_input: number;
    cost_per_1k_output: number;
    api_key_required: boolean;
    api_key_label: string;
    purchase_price?: number;
  };
}

interface MarketplaceBrowserProps {
  /** Called when the user confirms a model selection */
  onSelect: (model: MarketplaceModel) => void;
  /** Called after a successful purchase + secret save */
  onPurchaseComplete?: (secretId: string, model: MarketplaceModel) => void;
  /** ID of the currently-selected model (if any) */
  selectedModelId?: string | null;
  /** If set, fetch marketplace from this specific gateway only */
  gatewayId?: string;
}

const CAPABILITY_LABELS: Record<string, string> = {
  chat: 'Chat',
  vision: 'Vision',
  function_calling: 'Functions',
  json_mode: 'JSON',
  extended_thinking: 'Thinking',
  grounding: 'Grounding',
  reasoning: 'Reasoning',
  rag: 'RAG',
};

const MarketplaceBrowser: React.FC<MarketplaceBrowserProps> = ({
  onSelect,
  onPurchaseComplete,
  selectedModelId,
  gatewayId,
}) => {
  const [models, setModels] = useState<MarketplaceModel[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState('All');
  const [search, setSearch] = useState('');
  const [hoveredId, setHoveredId] = useState<string | null>(null);
  const [purchaseModel, setPurchaseModel] = useState<MarketplaceModel | null>(null);
  const [purchasedMap, setPurchasedMap] = useState<
    Record<string, { expires_at: string; api_key_secret_id: string }>
  >({});
  const [refreshKey, setRefreshKey] = useState(0);

  // Fetch marketplace catalog and purchased models in parallel
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    const cacheBuster = refreshKey > 0 ? `?refresh=1` : '';

    Promise.all([
      apiClient
        .get<
          any[]
        >(gatewayId ? `/gateways/${gatewayId}/marketplace${cacheBuster}` : `/marketplace/models${cacheBuster}`)
        .then(res => ({
          ...res,
          data: (res.data || []).map(
            (m: any) =>
              ({
                ...m,
                reviewCount: m.reviewCount ?? m.review_count ?? 0,
                rating: m.rating ?? 0,
                contextWindow: m.contextWindow ?? m.context_window ?? '',
                capabilities: m.capabilities ?? [],
                category: m.category ?? 'General',
                description: m.description ?? '',
                logo: m.logo ?? '',
                pricing: m.pricing ?? '',
                metadata: m.metadata ?? {},
                gateway_id: m.gateway_id,
                gateway_name: m.gateway_name,
              }) as MarketplaceModel
          ),
        })),
      apiClient.get<any[]>('/marketplace/purchased').catch(() => ({ data: [] as any[] })),
    ])
      .then(([modelsRes, purchasedRes]) => {
        if (!cancelled) {
          setModels(modelsRes.data);
          // Build a lookup: marketplace model_id → { expires_at, api_key_secret_id }
          const map: Record<string, { expires_at: string; api_key_secret_id: string }> = {};
          for (const p of purchasedRes.data || []) {
            map[p.model_id] = {
              expires_at: p.purchase?.expires_at || '',
              api_key_secret_id: p.purchase?.api_key_secret_id || '',
            };
          }
          setPurchasedMap(map);
          setLoading(false);
        }
      })
      .catch((err: any) => {
        if (!cancelled) {
          setError(`Failed to load marketplace: ${err.message}`);
          setLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [gatewayId, refreshKey]);

  const categories = ['All', ...Array.from(new Set(models.map(m => m.category))), 'Purchased'];

  const filtered = models.filter(m => {
    const matchCat =
      filter === 'All' ||
      m.category === filter ||
      (filter === 'Purchased' &&
        purchasedMap[m.id] &&
        !(new Date(purchasedMap[m.id].expires_at) < new Date()));
    const q = search.toLowerCase();
    const matchSearch =
      !q ||
      m.name.toLowerCase().includes(q) ||
      m.provider.toLowerCase().includes(q) ||
      m.description.toLowerCase().includes(q);
    return matchCat && matchSearch;
  });

  if (loading) {
    return (
      <div className="text-center py-4">
        <div className="spinner-border spinner-border-sm text-primary me-2" role="status" />
        Loading marketplace models…
      </div>
    );
  }

  if (error) {
    return (
      <div className="alert alert-warning">
        <i className="fas fa-exclamation-triangle me-2" />
        {error}
      </div>
    );
  }

  return (
    <div>
      {/* Search & category filters */}
      <div className="d-flex flex-wrap align-items-center mb-3" style={{ gap: '8px' }}>
        <div className="input-group" style={{ maxWidth: 280 }}>
          <div className="input-group-prepend">
            <span className="input-group-text">
              <i className="fas fa-search" />
            </span>
          </div>
          <input
            type="text"
            className="form-control"
            placeholder="Search models…"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        {categories.map(cat => (
          <button
            key={cat}
            type="button"
            className={`btn btn-sm ${filter === cat ? 'btn-primary' : 'btn-outline-secondary'}`}
            onClick={() => setFilter(cat)}
          >
            {cat}
          </button>
        ))}
        <button
          type="button"
          className="btn btn-sm btn-outline-primary ms-auto"
          onClick={() => setRefreshKey(k => k + 1)}
          disabled={loading}
          title="Refresh marketplace"
        >
          <i className={`fas fa-sync-alt${loading ? ' fa-spin' : ''}`} />
        </button>
      </div>

      {/* Model grid */}
      <div className="row">
        {filtered.map(model => {
          const isSelected = selectedModelId === model.id;
          const purchaseInfo = purchasedMap[model.id];
          const isPurchased = !!purchaseInfo;
          const isExpired =
            isPurchased && purchaseInfo.expires_at
              ? new Date(purchaseInfo.expires_at) < new Date()
              : false;
          const daysRemaining =
            isPurchased && purchaseInfo.expires_at
              ? Math.ceil(
                  (new Date(purchaseInfo.expires_at).getTime() - Date.now()) / (1000 * 60 * 60 * 24)
                )
              : 0;
          return (
            <div key={model.id} className="col-md-6 col-lg-4 mb-3">
              <div
                className={`card h-100 ${isSelected ? 'border-primary' : ''}`}
                style={{
                  cursor: 'pointer',
                  borderWidth: isSelected ? 2 : 1,
                  boxShadow: hoveredId === model.id ? '0 4px 12px rgba(0,0,0,0.15)' : undefined,
                  transition: 'box-shadow 0.2s, border-color 0.2s',
                  backgroundColor:
                    isPurchased && !isExpired ? 'rgba(40, 167, 69, 0.06)' : undefined,
                }}
                onClick={() => onSelect(model)}
                onMouseEnter={() => setHoveredId(model.id)}
                onMouseLeave={() => setHoveredId(null)}
              >
                <div className="card-body p-3">
                  {/* Header: logo + name */}
                  <div className="d-flex align-items-center mb-2">
                    <img
                      src={model.logo}
                      alt={model.provider}
                      style={{ width: 32, height: 32, objectFit: 'contain' }}
                      onError={e => {
                        (e.target as HTMLImageElement).style.display = 'none';
                      }}
                    />
                    <div className="ms-2" style={{ minWidth: 0 }}>
                      <h6 className="mb-0 text-truncate" style={{ fontSize: '14px' }}>
                        {model.name}
                      </h6>
                      <small className="text-muted">{model.provider}</small>
                      {model.gateway_name && !gatewayId && (
                        <div>
                          <small className="text-info" style={{ fontSize: '10px' }}>
                            <i className="fas fa-network-wired me-1" />
                            {model.gateway_name}
                          </small>
                        </div>
                      )}
                    </div>
                    {isSelected && (
                      <i
                        className="fas fa-check-circle text-primary ms-auto"
                        style={{ fontSize: '18px' }}
                      />
                    )}
                  </div>

                  {/* Category & rating */}
                  <div className="d-flex align-items-center mb-2" style={{ gap: '6px' }}>
                    <span className="badge text-bg-light">{model.category}</span>
                    <span style={{ fontSize: '12px' }}>
                      <i className="fas fa-star text-warning me-1" style={{ fontSize: '11px' }} />
                      {model.rating || 0}
                      <span className="text-muted ms-1">
                        ({(model.reviewCount || 0).toLocaleString()})
                      </span>
                    </span>
                  </div>

                  {/* Description */}
                  <p className="text-muted mb-2" style={{ fontSize: '12px', lineHeight: 1.4 }}>
                    {model.description}
                  </p>

                  {/* Pricing & context */}
                  <div className="mb-2" style={{ fontSize: '11px' }}>
                    <div>
                      <i className="fas fa-dollar-sign me-1 text-muted" />
                      {model.pricing}
                    </div>
                    <div>
                      <i className="fas fa-database me-1 text-muted" />
                      Context: {model.contextWindow}
                    </div>
                  </div>

                  {/* Capability badges */}
                  <div className="d-flex flex-wrap" style={{ gap: '4px' }}>
                    {model.capabilities.map(cap => (
                      <span
                        key={cap}
                        className="badge"
                        style={{
                          background: withAlpha(UI_COLORS.primary, 0.12),
                          color: UI_COLORS.primary,
                          fontSize: '10px',
                        }}
                      >
                        {CAPABILITY_LABELS[cap] || cap}
                      </span>
                    ))}
                  </div>

                  {/* Purchase button / owned status */}
                  {model.metadata.api_key_required && (
                    <div className="mt-2 pt-2 border-top">
                      {isPurchased && !isExpired ? (
                        <div style={{ fontSize: '11px' }}>
                          <span className="badge text-bg-success me-1">
                            <i className="fas fa-key me-1" />
                            Purchased
                          </span>
                          <span className="text-muted">
                            Expires {formatDateTime(purchaseInfo.expires_at, true)}
                            {daysRemaining <= 7 && (
                              <span className="text-warning ms-1">({daysRemaining}d left)</span>
                            )}
                          </span>
                        </div>
                      ) : (
                        <button
                          type="button"
                          className={`btn btn-sm ${isExpired ? 'btn-warning' : 'btn-outline-success'} w-100`}
                          onClick={e => {
                            e.stopPropagation();
                            setPurchaseModel(model);
                          }}
                        >
                          <i className="fas fa-credit-card me-1" />
                          {isExpired ? 'Renew Key (Expired)' : 'Purchase Key'}
                          {model.metadata.purchase_price && (
                            <small className="ms-1">
                              ({(model.metadata.purchase_price / 1e6).toFixed(2)} USDC)
                            </small>
                          )}
                        </button>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {filtered.length === 0 && (
        <div className="text-center text-muted py-3">No models match your search.</div>
      )}

      {/* Purchase Modal */}
      {purchaseModel && (
        <MarketplacePurchaseModal
          show={!!purchaseModel}
          model={purchaseModel}
          onClose={() => setPurchaseModel(null)}
          onPurchaseComplete={(secretId, purchasedModel) => {
            // Refresh the purchased map so the card shows "Owned"
            const expiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
            setPurchasedMap(prev => ({
              ...prev,
              [purchasedModel.id]: { expires_at: expiry, api_key_secret_id: secretId },
            }));
            setPurchaseModel(null);
            if (onPurchaseComplete) {
              onPurchaseComplete(secretId, purchasedModel);
            }
          }}
        />
      )}
    </div>
  );
};

export default MarketplaceBrowser;
