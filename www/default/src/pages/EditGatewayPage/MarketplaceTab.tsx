import React from 'react';
import MarketplaceBrowser, { MarketplaceModel } from '../../components/shared/MarketplaceBrowser';

interface MarketplaceTabProps {
  gatewayId: string;
}

const MarketplaceTab: React.FC<MarketplaceTabProps> = ({ gatewayId }) => {
  return (
    <div className="card shadow-sm mb-4">
      <div className="card-header bg-light">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-store"></i> Marketplace
        </h6>
      </div>
      <div className="card-body">
        <p className="text-muted mb-3">
          <i className="fas fa-info-circle me-1"></i>
          Models available from this gateway. Requesting a model provisions an API key for it.
        </p>
        <MarketplaceBrowser
          gatewayId={gatewayId}
          onSelect={() => {}}
          onPurchaseComplete={(secretId, model) => {
            // Could navigate to pipe creation with the purchased model, for now just stay
          }}
        />
      </div>
    </div>
  );
};

export default MarketplaceTab;
