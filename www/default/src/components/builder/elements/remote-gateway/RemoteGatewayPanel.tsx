import React, { useEffect, useState } from 'react';
import { Form, Button } from 'react-bootstrap';
import type { ConfigPanelProps } from '../types';
import { apiClient } from '../../../../api';

interface Gateway {
  id: string;
  name: string;
  did?: string;
  gateway_type?: string;
}

/**
 * Read-only sidebar panel for the synthesised `remote-gateway` node.
 * Resolves `gateway_id` to a gateway name and links to the gateway
 * dashboard.
 */
const RemoteGatewayPanel: React.FC<ConfigPanelProps> = ({ config }) => {
  const gatewayId: string = config?.gateway_id || '';

  const [gateway, setGateway] = useState<Gateway | null>(null);

  useEffect(() => {
    if (!gatewayId) return;
    apiClient
      .get('/gateways')
      .then(res => {
        const list: Gateway[] = res.data || [];
        setGateway(list.find(g => g.id === gatewayId) ?? null);
      })
      .catch(() => setGateway(null));
  }, [gatewayId]);

  return (
    <>
      <div className="config-section">
        <label>Remote Gateway</label>
        <Form.Group className="mb-2">
          <Form.Label className="small text-muted mb-1">Gateway</Form.Label>
          <Form.Control size="sm" type="text" readOnly value={gateway?.name || gatewayId || '—'} />
        </Form.Group>
        <div className="d-flex gap-2 mt-2">
          {gatewayId && (
            <Button
              size="sm"
              variant="outline-secondary"
              onClick={() => window.open(`/gateways/${gatewayId}`, '_blank', 'noopener,noreferrer')}
            >
              <i className="fas fa-external-link-alt me-1" /> Open gateway
            </Button>
          )}
        </div>
      </div>
      <div className="config-section">
        <Form.Text className="text-muted" style={{ fontSize: '11px' }}>
          This destination is synthesised from a <code>fabric://</code> target endpoint on the
          parent target. To change it, edit that node's destination.
        </Form.Text>
      </div>
    </>
  );
};

export default RemoteGatewayPanel;
