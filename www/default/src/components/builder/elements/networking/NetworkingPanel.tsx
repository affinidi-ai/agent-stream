import React from 'react';
import { Form } from 'react-bootstrap';
import type { ConfigPanelProps } from '../types';

const NetworkingPanel: React.FC<ConfigPanelProps> = ({ config, updateField }) => (
  <>
    <div className="config-section">
      <label>Timeouts</label>
      <Form.Group className="mb-2">
        <Form.Label className="small text-muted mb-1">Request timeout (seconds)</Form.Label>
        <Form.Control
          size="sm"
          type="number"
          min="1"
          value={config.timeout_secs ?? ''}
          onChange={e => updateField('timeout_secs', e.target.value)}
        />
      </Form.Group>
      <Form.Group className="mb-2">
        <Form.Label className="small text-muted mb-1">Connect timeout (seconds)</Form.Label>
        <Form.Control
          size="sm"
          type="number"
          min="1"
          value={config.connect_timeout_secs ?? ''}
          onChange={e => updateField('connect_timeout_secs', e.target.value)}
        />
      </Form.Group>
      <Form.Group className="mb-2">
        <Form.Label className="small text-muted mb-1">Idle timeout (seconds)</Form.Label>
        <Form.Control
          size="sm"
          type="number"
          min="1"
          value={config.idle_timeout_secs ?? ''}
          onChange={e => updateField('idle_timeout_secs', e.target.value)}
        />
      </Form.Group>
    </div>

    <div className="config-section">
      <label>Retry</label>
      <Form.Check
        type="switch"
        id="retry-enable"
        label="Enable automatic retries"
        checked={config.retry_enabled || false}
        onChange={e => updateField('retry_enabled', e.target.checked)}
      />
      {config.retry_enabled && (
        <>
          <Form.Group className="mt-2">
            <Form.Label className="small text-muted mb-1">Max attempts</Form.Label>
            <Form.Control
              size="sm"
              type="number"
              min="1"
              max="10"
              value={config.retry_max ?? ''}
              onChange={e => updateField('retry_max', e.target.value)}
            />
          </Form.Group>
          <Form.Group className="mt-2">
            <Form.Label className="small text-muted mb-1">Backoff multiplier</Form.Label>
            <Form.Control
              size="sm"
              type="number"
              step="0.1"
              min="1"
              value={config.retry_backoff_multiplier ?? ''}
              onChange={e => updateField('retry_backoff_multiplier', e.target.value)}
            />
          </Form.Group>
          <Form.Group className="mt-2">
            <Form.Label className="small text-muted mb-1">Initial backoff (ms)</Form.Label>
            <Form.Control
              size="sm"
              type="number"
              min="0"
              value={config.retry_initial_backoff_ms ?? ''}
              onChange={e => updateField('retry_initial_backoff_ms', e.target.value)}
            />
          </Form.Group>
          <Form.Group className="mt-2">
            <Form.Label className="small text-muted mb-1">Max backoff (ms)</Form.Label>
            <Form.Control
              size="sm"
              type="number"
              min="0"
              value={config.retry_max_backoff_ms ?? ''}
              onChange={e => updateField('retry_max_backoff_ms', e.target.value)}
            />
          </Form.Group>
          <Form.Group className="mt-2">
            <Form.Label className="small text-muted mb-1">Retryable status codes</Form.Label>
            <Form.Control
              size="sm"
              type="text"
              value={config.retry_status_codes ?? ''}
              onChange={e => updateField('retry_status_codes', e.target.value)}
            />
            <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
              Comma-separated HTTP status codes (e.g. 502,503,504)
            </Form.Text>
          </Form.Group>
        </>
      )}
    </div>

    <div className="config-section">
      <label>Circuit Breaker</label>
      <Form.Check
        type="switch"
        id="cb-enable"
        label="Enable circuit breaker"
        checked={config.circuit_breaker_enabled || false}
        onChange={e => updateField('circuit_breaker_enabled', e.target.checked)}
      />
      {config.circuit_breaker_enabled && (
        <>
          <Form.Group className="mt-2">
            <Form.Label className="small text-muted mb-1">Failure threshold</Form.Label>
            <Form.Control
              size="sm"
              type="number"
              min="1"
              value={config.cb_threshold ?? ''}
              onChange={e => updateField('cb_threshold', e.target.value)}
            />
          </Form.Group>
          <Form.Group className="mt-2">
            <Form.Label className="small text-muted mb-1">Success threshold (to close)</Form.Label>
            <Form.Control
              size="sm"
              type="number"
              min="1"
              value={config.cb_success_threshold ?? ''}
              onChange={e => updateField('cb_success_threshold', e.target.value)}
            />
          </Form.Group>
          <Form.Group className="mt-2">
            <Form.Label className="small text-muted mb-1">Recovery timeout (seconds)</Form.Label>
            <Form.Control
              size="sm"
              type="number"
              min="1"
              value={config.cb_recovery_secs ?? ''}
              onChange={e => updateField('cb_recovery_secs', e.target.value)}
            />
          </Form.Group>
          <Form.Group className="mt-2">
            <Form.Label className="small text-muted mb-1">Window size (seconds)</Form.Label>
            <Form.Control
              size="sm"
              type="number"
              min="1"
              value={config.cb_window_secs ?? ''}
              onChange={e => updateField('cb_window_secs', e.target.value)}
            />
          </Form.Group>
        </>
      )}
    </div>

    <div className="config-section">
      <label>Traffic Mirroring</label>
      <Form.Check
        type="switch"
        id="mirror-enable"
        label="Mirror traffic to shadow endpoint"
        checked={config.mirror_enabled || false}
        onChange={e => updateField('mirror_enabled', e.target.checked)}
      />
      {config.mirror_enabled && (
        <>
          <Form.Group className="mt-2">
            <Form.Label className="small text-muted mb-1">Mirror endpoint</Form.Label>
            <Form.Control
              size="sm"
              type="text"
              value={config.mirror_endpoint ?? ''}
              onChange={e => updateField('mirror_endpoint', e.target.value)}
            />
            <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
              Full URL of the shadow endpoint (e.g. https://shadow.internal:3001).
            </Form.Text>
          </Form.Group>
          <Form.Group className="mt-2">
            <Form.Label className="small text-muted mb-1">Traffic percentage</Form.Label>
            <Form.Control
              size="sm"
              type="number"
              min="1"
              max="100"
              value={config.mirror_percentage ?? ''}
              onChange={e => updateField('mirror_percentage', e.target.value)}
            />
          </Form.Group>
          <Form.Group className="mt-2">
            <Form.Label className="small text-muted mb-1">Mirror timeout (seconds)</Form.Label>
            <Form.Control
              size="sm"
              type="number"
              min="1"
              value={config.mirror_timeout_secs ?? ''}
              onChange={e => updateField('mirror_timeout_secs', e.target.value)}
            />
          </Form.Group>
          <Form.Check
            type="switch"
            id="mirror-async"
            label="Fire-and-forget (async)"
            className="mt-2"
            checked={config.mirror_async || false}
            onChange={e => updateField('mirror_async', e.target.checked)}
          />
        </>
      )}
    </div>
  </>
);

export default NetworkingPanel;
