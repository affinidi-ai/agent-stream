import React from 'react';

const IntegrationsAdminOnlyNotice: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({
  className = 'small text-muted',
  ...rest
}) => (
  <div className={className} {...rest}>
    <i className="fas fa-lock me-1" aria-hidden="true" />
    Integrations are managed by administrators.
  </div>
);

export default IntegrationsAdminOnlyNotice;
