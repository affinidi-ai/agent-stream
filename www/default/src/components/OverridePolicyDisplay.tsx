import React from 'react';

interface OverridePolicyDisplayProps {
  overridePolicy?: Record<string, string>;
  pipeId?: string;
  listenAddress?: string;
}

const OverridePolicyDisplay: React.FC<OverridePolicyDisplayProps> = ({
  overridePolicy,
  pipeId,
  listenAddress,
}) => {
  if (!overridePolicy || Object.keys(overridePolicy).length === 0) {
    return (
      <div className="alert alert-secondary">
        <i className="fas fa-info-circle me-2"></i>
        No parameter override policies configured. This pipe uses standard request forwarding.
      </div>
    );
  }

  const getPolicyBadge = (policy: string) => {
    switch (policy) {
      case 'gateway_wins':
        return <span className="badge text-bg-danger">Gateway Wins</span>;
      case 'client_wins':
        return <span className="badge text-bg-success">Client Wins</span>;
      case 'inject_if_missing':
        return <span className="badge text-bg-info">Inject If Missing</span>;
      default:
        return <span className="badge text-bg-secondary">{policy}</span>;
    }
  };

  const getPolicyDescription = (policy: string) => {
    switch (policy) {
      case 'gateway_wins':
        return 'Gateway value always used, client requests ignored';
      case 'client_wins':
        return 'Client value passed through as-is';
      case 'inject_if_missing':
        return 'Gateway value injected only when client omits parameter';
      default:
        return policy;
    }
  };

  return (
    <div className="override-policy-display">
      <div className="alert alert-info mb-3">
        <i className="fas fa-sliders-h me-2"></i>
        <strong>SDK Interception Enabled</strong>
        <p className="mb-0 mt-2">This pipe can intercept SDK requests. Configure your client:</p>
        {pipeId && (
          <code
            className="d-block mt-2"
            style={{ background: '#fff', padding: '8px', borderRadius: '4px' }}
          >
            new OpenAI({'{'} baseURL: '{listenAddress || 'https://gateway'}/llm/{pipeId}' {'}'})
          </code>
        )}
      </div>

      <h6 className="mb-3">
        <i className="fas fa-sliders-h me-2"></i>
        Configured Override Policies
      </h6>

      <table className="table table-sm table-bordered">
        <thead className="thead-light">
          <tr>
            <th style={{ width: '30%' }}>Parameter</th>
            <th style={{ width: '25%' }}>Policy</th>
            <th style={{ width: '45%' }}>Behavior</th>
          </tr>
        </thead>
        <tbody>
          {Object.entries(overridePolicy).map(([param, policy]) => (
            <tr key={param}>
              <td>
                <code>{param}</code>
              </td>
              <td>{getPolicyBadge(policy)}</td>
              <td>
                <small className="text-muted">{getPolicyDescription(policy)}</small>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className="alert alert-light mt-3">
        <strong>Policy Explanations:</strong>
        <ul className="mb-0 mt-2" style={{ fontSize: '0.9rem' }}>
          <li>
            <span className="badge text-bg-danger">Gateway Wins</span> - Enforces governance. Client
            values are always overridden.
          </li>
          <li>
            <span className="badge text-bg-success">Client Wins</span> - Passthrough. Client fully
            controls the value; the gateway never injects (no fallback).
          </li>
          <li>
            <span className="badge text-bg-info">Inject If Missing</span> - Ensures parameter is
            present. Gateway fills in gaps.
          </li>
        </ul>
      </div>
    </div>
  );
};

export default OverridePolicyDisplay;
