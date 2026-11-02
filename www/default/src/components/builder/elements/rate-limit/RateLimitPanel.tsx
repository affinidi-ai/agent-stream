import React from 'react';
import { Form } from 'react-bootstrap';
import type { ConfigPanelProps } from '../types';

const RateLimitPanel: React.FC<ConfigPanelProps> = ({ config, updateField }) => (
  <>
    <div className="config-section">
      <label>Requests</label>
      <Form.Group className="mb-2">
        <Form.Label className="small text-muted mb-1">Max requests per window</Form.Label>
        <Form.Control
          size="sm"
          type="number"
          min="1"
          value={config.requests ?? ''}
          onChange={e => updateField('requests', e.target.value)}
        />
      </Form.Group>
      <Form.Group className="mb-2">
        <Form.Label className="small text-muted mb-1">Window (seconds)</Form.Label>
        <Form.Control
          size="sm"
          type="number"
          min="1"
          value={config.window_secs ?? ''}
          onChange={e => updateField('window_secs', e.target.value)}
        />
      </Form.Group>
      <Form.Group className="mb-2">
        <Form.Label className="small text-muted mb-1">Burst allowance (optional)</Form.Label>
        <Form.Control
          size="sm"
          type="number"
          min="0"
          value={config.burst ?? ''}
          onChange={e => updateField('burst', e.target.value)}
        />
        <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
          Extra requests permitted in short bursts above the steady rate.
        </Form.Text>
      </Form.Group>
    </div>
  </>
);

export default RateLimitPanel;
