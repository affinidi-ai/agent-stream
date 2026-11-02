import React from 'react';
import { Form } from 'react-bootstrap';
import type { ConfigPanelProps } from '../types';

const ExtensionRulesPanel: React.FC<ConfigPanelProps> = ({ config, updateField }) => {
  const rules: Array<{ extension_uri: string; action: string; condition?: string }> =
    config.rules || [];

  return (
    <>
      <div className="config-section">
        <label>Default Behavior</label>
        <Form.Text className="d-block text-muted mb-2" style={{ fontSize: '10px' }}>
          The direction is set by the arrow this element was dropped on. Drop another Extension
          Rules element on the opposite arrow to filter the other direction.
        </Form.Text>
        <Form.Select
          size="sm"
          value={config.default_action || 'pass'}
          onChange={e => updateField('default_action', e.target.value)}
        >
          <option value="pass">Pass through (no filtering)</option>
          <option value="strip">Strip unknown extensions</option>
          <option value="reject">Reject if unknown extensions present</option>
        </Form.Select>
      </div>

      <div className="config-section">
        <label>Extension Rules</label>
        <Form.Text className="d-block text-muted mb-2" style={{ fontSize: '10px' }}>
          Per-extension URI rules override the default behavior.
        </Form.Text>

        {rules.map((rule, idx) => (
          <div
            key={idx}
            className="mb-2 p-2"
            style={{ border: '1px solid #e9ecef', borderRadius: '6px' }}
          >
            <Form.Group className="mb-1">
              <Form.Control
                size="sm"
                type="text"
                placeholder="Extension URI (e.g. https://a2a.dev/extensions/...)"
                value={rule.extension_uri}
                onChange={e => {
                  const updated = [...rules];
                  updated[idx] = { ...updated[idx], extension_uri: e.target.value };
                  updateField('rules', updated);
                }}
              />
            </Form.Group>
            <div className="d-flex gap-1">
              <Form.Select
                size="sm"
                value={rule.action}
                onChange={e => {
                  const updated = [...rules];
                  updated[idx] = { ...updated[idx], action: e.target.value };
                  updateField('rules', updated);
                }}
                style={{ flex: 1 }}
              >
                <option value="require">Require</option>
                <option value="allow">Allow</option>
                <option value="strip">Strip</option>
                <option value="reject">Reject if present</option>
              </Form.Select>
              <button
                className="btn btn-outline-danger btn-sm"
                onClick={() =>
                  updateField(
                    'rules',
                    rules.filter((_, i) => i !== idx)
                  )
                }
                style={{ padding: '2px 8px' }}
              >
                <i className="fas fa-times" />
              </button>
            </div>
          </div>
        ))}

        <button
          className="btn btn-outline-primary btn-sm w-100"
          onClick={() => updateField('rules', [...rules, { extension_uri: '', action: 'allow' }])}
        >
          <i className="fas fa-plus me-1" /> Add Rule
        </button>
      </div>
    </>
  );
};

export default ExtensionRulesPanel;
