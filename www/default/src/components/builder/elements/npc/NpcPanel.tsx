import React from 'react';
import { Form } from 'react-bootstrap';
import { registry } from '../registry';
import type { ConfigPanelProps } from '../types';

const NpcPanel: React.FC<ConfigPanelProps> = ({ node, config, updateField, allNodes }) => {
  // Inject `connected_to` default from parentId (preserves legacy behavior).
  const effectiveConfig = { ...config, connected_to: config.connected_to ?? node.parentId ?? '' };
  const currentNodeId = node.id;

  // Available connection targets: any node that isn't the current NPC or the surface
  const connectableNodes = (allNodes || []).filter(
    n => n.id !== currentNodeId && n.type !== 'surface'
  );

  return (
    <>
      <div className="config-section">
        <label>NPC Details</label>
        <Form.Group className="mb-2">
          <Form.Label className="small text-muted mb-1">URL / Endpoint (optional)</Form.Label>
          <Form.Control
            size="sm"
            type="text"
            placeholder="https://..."
            value={effectiveConfig.npc_url || ''}
            onChange={e => updateField('npc_url', e.target.value)}
          />
        </Form.Group>
      </div>
      <div className="config-section">
        <label>Connection</label>
        <Form.Group className="mb-2">
          <Form.Label className="small text-muted mb-1">Connected To</Form.Label>
          <Form.Select
            size="sm"
            value={effectiveConfig.connected_to || ''}
            onChange={e => updateField('connected_to', e.target.value)}
          >
            <option value="">None (free-floating)</option>
            {connectableNodes.map(n => (
              <option key={n.id} value={n.id}>
                {n.label || registry.get(n.type)?.label || n.type}
              </option>
            ))}
          </Form.Select>
        </Form.Group>
        <Form.Group className="mb-2">
          <Form.Label className="small text-muted mb-1">Arrow Direction</Form.Label>
          <Form.Select
            size="sm"
            value={effectiveConfig.connection_direction || 'outbound'}
            onChange={e => updateField('connection_direction', e.target.value)}
          >
            <option value="outbound">Outbound (parent → this)</option>
            <option value="inbound">Inbound (this → parent)</option>
          </Form.Select>
        </Form.Group>
      </div>
    </>
  );
};

export default NpcPanel;
