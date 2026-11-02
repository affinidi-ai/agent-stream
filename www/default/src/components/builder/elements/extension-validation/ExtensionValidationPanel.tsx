import React from 'react';
import { Form } from 'react-bootstrap';
import type { ConfigPanelProps } from '../types';

const ExtensionValidationPanel: React.FC<ConfigPanelProps> = ({ config, updateField }) => (
  <>
    <div className="config-section">
      <label>Required Extensions</label>
      <Form.Control
        size="sm"
        type="text"
        placeholder="https://a2a.dev/extensions/agent-identity/v1"
        value={config.required_extensions || ''}
        onChange={e => updateField('required_extensions', e.target.value)}
      />
      <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
        Comma-separated list of extension URIs that must be present
      </Form.Text>
    </div>

    <div className="config-section">
      <label>JSON Schema (optional)</label>
      <Form.Control
        as="textarea"
        rows={5}
        size="sm"
        placeholder={'{\n  "type": "object",\n  "required": ["agentIdentity"]\n}'}
        value={config.schema || ''}
        onChange={e => updateField('schema', e.target.value)}
        style={{ fontFamily: 'Monaco, Menlo, monospace', fontSize: '11px' }}
      />
    </div>
  </>
);

export default ExtensionValidationPanel;
