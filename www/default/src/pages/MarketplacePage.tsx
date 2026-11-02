import React from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import MarketplaceBrowser from '../components/shared/MarketplaceBrowser';

const MarketplacePage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const returnTo = searchParams.get('returnTo') || '/pipes';

  const handleClose = () => {
    navigate(returnTo);
  };

  return (
    <div className="container-fluid">
      <div className="mb-3">
        <button className="btn btn-sm btn-secondary" onClick={handleClose}>
          <i className="fas fa-arrow-left"></i>
        </button>
      </div>
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <h4 className="m-0">
          <i className="fas fa-store me-2"></i>
          LLM Marketplace
        </h4>
      </div>

      <MarketplaceBrowser
        onSelect={() => {}}
        onPurchaseComplete={() => {
          // Models refresh automatically in MarketplaceBrowser after purchase
        }}
      />
    </div>
  );
};

export default MarketplacePage;
