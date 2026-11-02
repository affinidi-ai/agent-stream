import React, { useState, useCallback } from 'react';
import { apiClient } from '../../api';
import type { MarketplaceModel } from './MarketplaceBrowser';
import { UI_COLORS } from '../../utils/uiPalette';

type PurchaseStep = 'confirm' | 'requesting' | 'success' | 'saving';

interface MarketplacePurchaseModalProps {
  show: boolean;
  model: MarketplaceModel;
  onClose: () => void;
  /** Called after the API key has been saved as a gateway secret. */
  onPurchaseComplete: (secretId: string, model: MarketplaceModel) => void;
}

const primaryButtonStyle: React.CSSProperties = {
  background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
  border: 'none',
  borderRadius: '10px',
  padding: '12px',
  fontSize: '16px',
  fontWeight: 600,
};

const MarketplacePurchaseModal: React.FC<MarketplacePurchaseModalProps> = ({
  show,
  model,
  onClose,
  onPurchaseComplete,
}) => {
  const [step, setStep] = useState<PurchaseStep>('confirm');
  const [error, setError] = useState<string | null>(null);
  const [apiKey, setApiKey] = useState<string | null>(null);
  const [purchasedAt, setPurchasedAt] = useState<string | null>(null);
  const [expiresAt, setExpiresAt] = useState<string | null>(null);
  const [savedSecretId, setSavedSecretId] = useState<string | null>(null);

  const handleRequestAccess = useCallback(async () => {
    setError(null);
    setStep('requesting');
    try {
      const qsParams = new URLSearchParams();
      if (model.marketplace_id) qsParams.set('marketplace_id', model.marketplace_id);
      if (model.gateway_id) qsParams.set('gateway_id', model.gateway_id);
      const qs = qsParams.toString() ? `?${qsParams.toString()}` : '';
      const res = await apiClient.fetch(
        `/api/v1/marketplace/purchase/${encodeURIComponent(model.id)}${qs}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
        }
      );
      if (!res.ok) {
        const body = await res.text();
        throw new Error(`Unexpected response ${res.status}: ${body}`);
      }
      const data = await res.json();
      if (!data.api_key) throw new Error('The marketplace did not return an API key');
      setApiKey(data.api_key);
      setPurchasedAt(data.purchased_at || new Date().toISOString());
      setExpiresAt(data.expires_at || null);
      setStep('success');
    } catch (e: any) {
      setError(e.message || String(e));
      setStep('confirm');
    }
  }, [model.id, model.marketplace_id, model.gateway_id]);

  const handleSaveSecret = useCallback(async () => {
    if (!apiKey) return;
    setStep('saving');
    setError(null);

    const secretId = `mp_${model.metadata.provider}_${crypto.randomUUID()}`;
    const now = purchasedAt || new Date().toISOString();
    const expiry = expiresAt || new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

    try {
      const gwLabel = model.gateway_name ? `${model.gateway_name}: ` : '';
      await apiClient.post('/secrets/new', {
        name: `${gwLabel}${model.name} (Marketplace)`,
        secret_id: secretId,
        value: apiKey,
        secret_type: 'ApiKey',
        description: `API key from the marketplace for ${model.name} (${model.provider})${model.gateway_name ? ` from ${model.gateway_name}` : ''}. Expires: ${new Date(expiry).toLocaleDateString()}`,
        tags: ['marketplace', model.metadata.provider],
      });
    } catch (e: any) {
      setError(`Failed to save secret: ${e.message || e}`);
      setStep('success');
      return;
    }

    try {
      await apiClient.post('/marketplace/purchased', {
        id: crypto.randomUUID(),
        model_id: model.id,
        name: model.name,
        provider: model.provider,
        logo: model.logo,
        category: model.category,
        description: model.description,
        pricing: model.pricing,
        context_window: model.contextWindow,
        capabilities: model.capabilities,
        gateway_name: model.gateway_name || '',
        metadata: {
          api_schema: model.metadata.api_schema,
          provider: model.metadata.provider,
          model: model.metadata.model,
          default_base_url: model.metadata.default_base_url,
          api_version_prefix: model.metadata.api_version_prefix || '',
          endpoint: model.metadata.endpoint || '',
          cost_per_1k_input: model.metadata.cost_per_1k_input || 0,
          cost_per_1k_output: model.metadata.cost_per_1k_output || 0,
          api_key_required: model.metadata.api_key_required,
          api_key_label: model.metadata.api_key_label || '',
          purchase_price: model.metadata.purchase_price || 0,
        },
        purchase: {
          purchased_at: now,
          expires_at: expiry,
          api_key_secret_id: secretId,
        },
      });
    } catch (e: any) {
      // Non-fatal — the secret was already saved
      console.warn('Failed to save marketplace model record:', e);
    }

    setSavedSecretId(secretId);
    onPurchaseComplete(secretId, model);
  }, [apiKey, model, purchasedAt, expiresAt, onPurchaseComplete]);

  const handleClose = () => {
    setStep('confirm');
    setError(null);
    setApiKey(null);
    setPurchasedAt(null);
    setExpiresAt(null);
    setSavedSecretId(null);
    onClose();
  };

  if (!show) return null;

  const isComplete = step === 'success' || step === 'saving';

  return (
    <div
      className="modal show d-block"
      tabIndex={-1}
      role="dialog"
      style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}
      onClick={e => {
        if (e.target === e.currentTarget) handleClose();
      }}
    >
      <div
        className="modal-dialog modal-dialog-centered"
        role="document"
        style={{ maxWidth: '560px' }}
      >
        <div className="modal-content" style={{ borderRadius: '15px', overflow: 'hidden' }}>
          <button
            type="button"
            className="btn-close position-absolute"
            style={{
              right: '15px',
              top: '15px',
              opacity: 0.5,
              zIndex: 1050,
              transform: 'scale(1.5)',
            }}
            aria-label="Close"
            onClick={handleClose}
          />

          {step === 'confirm' && (
            <div className="modal-body text-center pt-5 px-4 pb-4">
              <h5 className="font-weight-bold mb-2">Get access to {model.name}</h5>
              <p className="text-muted small mb-4">
                {model.provider}
                {model.gateway_name ? ` · offered by ${model.gateway_name}` : ''}
              </p>
              {error && (
                <div className="alert alert-warning text-start small mb-3" role="alert">
                  <i className="fas fa-exclamation-triangle me-2" />
                  {error}
                </div>
              )}
              <button
                type="button"
                className="btn btn-lg w-100 text-white mb-2"
                style={primaryButtonStyle}
                onClick={handleRequestAccess}
              >
                <i className="fas fa-key me-2" />
                Request API Key
              </button>
              <button
                type="button"
                className="btn btn-link btn-sm text-muted"
                onClick={handleClose}
              >
                Cancel
              </button>
            </div>
          )}

          {step === 'requesting' && (
            <div className="modal-body text-center py-5 px-4">
              <div className="mb-4">
                <div
                  className="spinner-border text-primary"
                  style={{ width: '60px', height: '60px' }}
                  role="status"
                >
                  <span className="sr-only">Requesting...</span>
                </div>
              </div>
              <h5 className="font-weight-bold mb-3">Requesting API Key</h5>
              <p className="text-muted">Contacting the marketplace…</p>
            </div>
          )}

          {isComplete && apiKey && (
            <div className="modal-body text-center py-5 px-4">
              <div className="mb-4">
                <div
                  className="rounded-circle bg-success d-inline-flex align-items-center justify-content-center"
                  style={{ width: '80px', height: '80px' }}
                >
                  <i className="fas fa-check text-white" style={{ fontSize: '40px' }} />
                </div>
              </div>
              <h5 className="font-weight-bold mb-2">API Key Ready</h5>
              <p className="text-muted small mb-4">
                Your API key for <strong>{model.name}</strong> is ready.
                {expiresAt && (
                  <span className="d-block mt-1">
                    <i className="fas fa-clock me-1" />
                    Valid for{' '}
                    {Math.max(
                      1,
                      Math.ceil(
                        (new Date(expiresAt).getTime() - Date.now()) / (1000 * 60 * 60 * 24)
                      )
                    )}{' '}
                    days
                  </span>
                )}
              </p>

              {error && (
                <div className="alert alert-warning text-start small mb-3" role="alert">
                  <i className="fas fa-exclamation-triangle me-2" />
                  {error}
                </div>
              )}

              {savedSecretId ? (
                <>
                  <div className="alert alert-success small mb-3">
                    <i className="fas fa-check-circle me-2" />
                    Saved to gateway &mdash; ready to use in your pipe.
                  </div>
                  <button
                    type="button"
                    className="btn btn-link btn-sm text-muted"
                    onClick={handleClose}
                  >
                    Done
                  </button>
                </>
              ) : step === 'saving' ? (
                <div className="py-2">
                  <div
                    className="spinner-border spinner-border-sm text-primary me-2"
                    role="status"
                  />
                  <span className="small text-muted">Saving to gateway…</span>
                </div>
              ) : (
                <>
                  <button
                    type="button"
                    className="btn btn-lg w-100 text-white mb-2"
                    style={{
                      ...primaryButtonStyle,
                      background: `linear-gradient(135deg, ${UI_COLORS.success} 0%, ${UI_COLORS.accentTeal} 100%)`,
                    }}
                    onClick={handleSaveSecret}
                  >
                    <i className="fas fa-key me-2" />
                    Save API Key to Gateway
                  </button>
                  <button
                    type="button"
                    className="btn btn-link btn-sm text-muted"
                    onClick={handleClose}
                  >
                    Skip for now
                  </button>
                </>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default MarketplacePurchaseModal;
