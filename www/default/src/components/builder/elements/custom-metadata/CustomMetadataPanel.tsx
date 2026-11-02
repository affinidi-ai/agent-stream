import React, { useState, useEffect } from 'react';
import { Form } from 'react-bootstrap';
import { apiClient } from '../../../../api';
import type { ConfigPanelProps } from '../types';

const CustomMetadataPanel: React.FC<ConfigPanelProps> = ({ config, updateField }) => {
  const entries: Array<{ key: string; value: string; target?: string }> = config.entries || [];
  const [secrets, setSecrets] = useState<
    Array<{ id: string; name: string; secret_id: string; description?: string }>
  >([]);
  const [openSecretsIdx, setOpenSecretsIdx] = useState<number | null>(null);

  useEffect(() => {
    apiClient
      .fetch('/api/v1/secrets/')
      .then(r => (r.ok ? r.json() : []))
      .then((data: any[]) => setSecrets(data || []))
      .catch(() => {});
  }, []);

  const addEntry = () => {
    updateField('entries', [...entries, { key: '', value: '', target: 'header' }]);
  };

  const updateEntry = (idx: number, field: string, value: string) => {
    const updated = [...entries];
    updated[idx] = { ...updated[idx], [field]: value };
    updateField('entries', updated);
  };

  const removeEntry = (idx: number) => {
    updateField(
      'entries',
      entries.filter((_, i) => i !== idx)
    );
  };

  return (
    <>
      <div className="config-section">
        <label>Metadata Entries</label>
        <Form.Text className="d-block text-muted mb-2" style={{ fontSize: '10px' }}>
          Key-value pairs injected into this direction's traffic. The direction is determined by
          which arrow you dropped this element on — drop another Metadata element on the opposite
          arrow to inject into the other direction.
        </Form.Text>

        {entries.map((entry, idx) => (
          <div
            key={idx}
            className="mb-2 p-2"
            style={{ border: '1px solid #e9ecef', borderRadius: '6px' }}
          >
            <div className="d-flex gap-1 mb-1">
              <Form.Control
                size="sm"
                type="text"
                placeholder="Key"
                value={entry.key}
                onChange={e => updateEntry(idx, 'key', e.target.value)}
                style={{ flex: 1 }}
              />
              <Form.Control
                size="sm"
                type="text"
                placeholder="Value or $SECRET:name"
                value={entry.value}
                onChange={e => updateEntry(idx, 'value', e.target.value)}
                style={{ flex: 1 }}
              />
              <div style={{ position: 'relative' }}>
                <button
                  className="btn btn-outline-secondary btn-sm"
                  onClick={() => setOpenSecretsIdx(openSecretsIdx === idx ? null : idx)}
                  title="Select secret"
                  style={{ padding: '2px 6px' }}
                >
                  <i className="fas fa-key" />
                </button>
                {openSecretsIdx === idx && (
                  <ul
                    className="dropdown-menu dropdown-menu-end show"
                    style={{
                      position: 'absolute',
                      right: 0,
                      top: '100%',
                      zIndex: 1000,
                      minWidth: '200px',
                    }}
                  >
                    {secrets.length === 0 ? (
                      <li>
                        <span
                          className="dropdown-item-text text-muted"
                          style={{ fontSize: '12px' }}
                        >
                          No secrets available
                        </span>
                      </li>
                    ) : (
                      secrets.map(secret => (
                        <li key={secret.id}>
                          <button
                            type="button"
                            className="dropdown-item"
                            onClick={() => {
                              updateEntry(idx, 'value', `$SECRET:${secret.secret_id}`);
                              setOpenSecretsIdx(null);
                            }}
                          >
                            <div>
                              <strong style={{ fontSize: '12px' }}>{secret.name}</strong>
                              <div className="text-muted" style={{ fontSize: '10px' }}>
                                {secret.secret_id}
                              </div>
                            </div>
                          </button>
                        </li>
                      ))
                    )}
                  </ul>
                )}
              </div>
              <button
                className="btn btn-outline-danger btn-sm"
                onClick={() => removeEntry(idx)}
                style={{ padding: '2px 8px' }}
              >
                <i className="fas fa-times" />
              </button>
            </div>
            {entry.value?.startsWith('$SECRET:') && (
              <span className="badge text-bg-warning mb-1" style={{ fontSize: '9px' }}>
                <i className="fas fa-key me-1" /> Secret reference
              </span>
            )}
            <div className="d-flex gap-1">
              <Form.Select
                size="sm"
                value={entry.target || 'header'}
                onChange={e => updateEntry(idx, 'target', e.target.value)}
                style={{ flex: 1 }}
              >
                <option value="header">HTTP Header</option>
                <option value="extension">Protocol Extension</option>
                <option value="body">Body (JSON merge)</option>
                <option value="query">Query Parameter</option>
              </Form.Select>
            </div>
          </div>
        ))}

        <button className="btn btn-outline-primary btn-sm w-100" onClick={addEntry}>
          <i className="fas fa-plus me-1" /> Add Entry
        </button>
      </div>

      <div className="config-section">
        <label>Dynamic Values</label>
        <Form.Text className="d-block text-muted mb-2" style={{ fontSize: '10px' }}>
          Special placeholders resolved at runtime.
        </Form.Text>
        <div
          className="p-2 rounded"
          style={{
            background: '#f8f9fc',
            fontSize: '10px',
            fontFamily: 'Monaco, Menlo, monospace',
          }}
        >
          <div>
            <code>{'$REQUEST_ID'}</code> — unique request ID
          </div>
          <div>
            <code>{'$TIMESTAMP'}</code> — ISO 8601 timestamp
          </div>
          <div>
            <code>{'$CALLER_DID'}</code> — caller's resolved DID
          </div>
          <div>
            <code>{'$CHANNEL_ID'}</code> — channel identifier
          </div>
          <div>
            <code>{'$SECRET:id'}</code> — secret reference
          </div>
        </div>
      </div>
    </>
  );
};

export default CustomMetadataPanel;
