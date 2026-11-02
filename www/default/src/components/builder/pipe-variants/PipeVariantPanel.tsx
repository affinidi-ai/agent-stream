import React, { useState } from 'react';
import { Button, Col, Form, Row } from 'react-bootstrap';
import { BASE_VARIANT_ID, type PipeVariantMeta } from './usePipeVariantSnapshots';

/**
 * Sidebar editor for a pipe's variant catalog — the pipe analogue of
 * the surface `TargetVariantPanel`. Variants are full snapshots of the
 * pipe addressed by a `$alias` path segment; this panel manages the
 * catalog (add / rename / set-default / remove) while the actual
 * per-variant config is edited on the canvas after switching to the
 * variant via the top-left variants widget.
 *
 * Unlike the surface panel (a canvas-node `ConfigPanel`), the pipe
 * builder has no `target-variant` canvas node, so this panel is
 * props-driven: the host page owns the catalog (`variants` /
 * `defaultVariantId`) and the snapshot manager.
 */

export interface PipeVariantPanelProps {
  /** Named variants (base is implicit, never in this list). */
  variants: PipeVariantMeta[];
  /** Default variant id, or null when base is the implicit default. */
  defaultVariantId: string | null;
  /** Currently active variant id (BASE_VARIANT_ID / null = base active). */
  activeVariantId: string | null;
  /** Pipe inbound listener, e.g. `https://host:8443` (trailing slash trimmed). */
  listenAddress: string;
  /** Pipe route, e.g. `/llm/chat`. */
  route: string;
  /** Promote the supplied catalog + default (add / rename / remove / set-default). */
  onChange: (variants: PipeVariantMeta[], defaultVariantId: string | null) => void;
  /** Switch the active variant so its config renders on the canvas. */
  onSwitchVariant: (variantId: string) => void;
}

function makeVariantId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return `v-${Math.random().toString(36).slice(2, 10)}-${Date.now().toString(36)}`;
}

const PipeVariantPanel: React.FC<PipeVariantPanelProps> = ({
  variants,
  defaultVariantId,
  activeVariantId,
  listenAddress,
  route,
  onChange,
  onSwitchVariant,
}) => {
  const defaultId = defaultVariantId || undefined;
  const isBaseActive = activeVariantId === BASE_VARIANT_ID || activeVariantId == null;

  // Per-variant URL: the alias is appended to the route as a `$alias`
  // segment (see `crate::proxy::route_variant` — pipe variant routing
  // parses `/route$alias/...`). Base variant has no suffix.
  const listen = listenAddress.replace(/\/+$/, '');
  const buildVariantUrl = (alias: string | undefined | null): string => {
    if (!listen) return '';
    const base = `${listen}${route || ''}`;
    return alias ? `${base}$${alias}` : base;
  };
  const copyUrl = (url: string) => {
    if (!url) return;
    void navigator.clipboard?.writeText(url);
  };

  const [openId, setOpenId] = useState<string | null>(() =>
    variants.length === 1 ? variants[0].id : null
  );

  const handleAdd = () => {
    const id = makeVariantId();
    const used = new Set(variants.map(v => (v.alias || '').toLowerCase()));
    let n = variants.length + 1;
    while (used.has(`alias${n}`)) n += 1;
    const alias = `alias${n}`;
    const next: PipeVariantMeta = { id, name: alias, alias, enabled: true };
    onChange([...variants, next], defaultVariantId);
    setOpenId(id);
    // Land on the new variant so its config is what the canvas edits.
    onSwitchVariant(id);
  };

  const handleRemove = (id: string) => {
    const list = variants.filter(v => v.id !== id);
    // Removing the default falls back to base, never to a sibling.
    const nextDefault = defaultId === id ? null : defaultVariantId;
    onChange(list, nextDefault);
    if (openId === id) setOpenId(null);
    if (activeVariantId === id) onSwitchVariant(BASE_VARIANT_ID);
  };

  const handleSetDefault = (id: string | null) => {
    onChange(variants, id);
  };

  const updateRow = (id: string, patch: Partial<PipeVariantMeta>) => {
    const list = variants.map(v => (v.id === id ? { ...v, ...patch } : v));
    onChange(list, defaultVariantId);
  };

  return (
    <>
      <div className="config-section">
        <p className="text-muted small mb-0">
          Variants are full snapshots of this pipe, addressed by a <code>$alias</code> path segment.
          Add one or more variants here; switch to a variant via the variants widget on the canvas
          to edit its upstream, rate limit, policies, prompt guard, judge and jury. Leave{' '}
          <strong>base</strong> as default to route alias-less requests to the unmodified pipe, or
          promote a named variant once you're ready to ship it.
        </p>
      </div>

      <div className="config-section">
        <div className="d-flex align-items-center justify-content-between mb-2">
          <strong className="small">Variants ({variants.length})</strong>
          <Button size="sm" variant="outline-primary" onClick={handleAdd}>
            <i className="fas fa-plus me-1" /> Add variant
          </Button>
        </div>

        {/* Always-present "base" row — the pipe with no overlay. Locked:
            no rename, no alias, no enable/disable. Switch to make its
            config the one the canvas edits; "Default" routes alias-less
            requests to the bare pipe (default_variant_id = null). */}
        <div className="variant-row variant-row-base rounded mb-2">
          <div className="d-flex align-items-center px-2 py-1">
            <span style={{ width: 18 }} />
            <button
              type="button"
              className="btn btn-link btn-sm text-decoration-none p-0 flex-grow-1 text-start"
              onClick={() => onSwitchVariant(BASE_VARIANT_ID)}
              style={{ minWidth: 0 }}
              title="Edit base on the canvas"
            >
              <span className="d-flex align-items-center gap-2">
                <strong className="small">base</strong>
                <span className="small text-muted fst-italic">(unmodified pipe)</span>
                {isBaseActive && (
                  <span className="badge bg-primary" style={{ fontSize: '9px' }}>
                    editing
                  </span>
                )}
                {!defaultId && (
                  <span className="badge bg-secondary" style={{ fontSize: '9px' }}>
                    default
                  </span>
                )}
              </span>
            </button>
            <Form.Check
              type="switch"
              id="pv-default-base"
              label="Default"
              checked={!defaultId}
              onChange={() => handleSetDefault(null)}
              className="me-2 small"
            />
          </div>
          <div className="px-2 pb-2">
            <div className="input-group input-group-sm">
              <span className="input-group-text small">URL</span>
              <Form.Control
                size="sm"
                type="text"
                readOnly
                value={buildVariantUrl(null) || '(route not configured)'}
                style={{ fontFamily: 'monospace' }}
              />
              <Button
                size="sm"
                variant="outline-secondary"
                title="Copy to clipboard"
                disabled={!buildVariantUrl(null)}
                onClick={() => copyUrl(buildVariantUrl(null))}
              >
                <i className="fas fa-copy" />
              </Button>
            </div>
          </div>
        </div>

        {variants.length === 0 && (
          <div className="text-muted small fst-italic">
            No named variants yet. Click <em>Add variant</em> to create one.
          </div>
        )}

        {variants.map(v => {
          const isOpen = openId === v.id;
          const isDefault = defaultId === v.id;
          const isActive = activeVariantId === v.id;
          const aliasError =
            v.alias && !/^[a-z0-9-]{1,32}$/.test(v.alias)
              ? 'Alias must be 1-32 chars: lowercase letters, digits, hyphens'
              : null;
          return (
            <div key={v.id} className="variant-row rounded mb-2">
              <div className="d-flex align-items-center px-2 py-1">
                <button
                  type="button"
                  className="btn btn-link btn-sm text-decoration-none p-0 me-2"
                  onClick={() => setOpenId(isOpen ? null : v.id)}
                  title={isOpen ? 'Collapse' : 'Expand'}
                  style={{ width: 18 }}
                >
                  <i className={`fas fa-chevron-${isOpen ? 'down' : 'right'}`} />
                </button>
                <button
                  type="button"
                  className="btn btn-link btn-sm text-decoration-none p-0 flex-grow-1 text-start"
                  onClick={() => onSwitchVariant(v.id)}
                  style={{ minWidth: 0 }}
                  title="Edit this variant on the canvas"
                >
                  <span className="d-flex align-items-center gap-2">
                    <strong className="small text-truncate">
                      {v.name || <span className="text-muted">(unnamed)</span>}
                    </strong>
                    <code className="small text-muted">{v.alias ? `$${v.alias}` : '$alias?'}</code>
                    {isActive && (
                      <span className="badge bg-primary" style={{ fontSize: '9px' }}>
                        editing
                      </span>
                    )}
                    {isDefault && (
                      <span className="badge bg-secondary" style={{ fontSize: '9px' }}>
                        default
                      </span>
                    )}
                    {v.enabled === false && (
                      <span className="badge bg-warning text-dark" style={{ fontSize: '9px' }}>
                        disabled
                      </span>
                    )}
                  </span>
                  {v.description && (
                    <span className="small text-muted text-truncate d-block">{v.description}</span>
                  )}
                </button>
                {!isDefault && (
                  <button
                    type="button"
                    className="btn btn-link btn-sm text-decoration-none p-1"
                    onClick={() => handleSetDefault(v.id)}
                    title="Make default"
                  >
                    <i className="fas fa-star text-muted" />
                  </button>
                )}
                <button
                  type="button"
                  className="btn btn-link btn-sm text-decoration-none p-1 text-danger"
                  onClick={() => handleRemove(v.id)}
                  title="Remove variant"
                >
                  <i className="fas fa-trash" />
                </button>
              </div>

              {isOpen && (
                <div className="variant-row-body p-2">
                  <div className="input-group input-group-sm mb-2">
                    <span className="input-group-text small">URL</span>
                    <Form.Control
                      size="sm"
                      type="text"
                      readOnly
                      value={buildVariantUrl(v.alias) || '(route not configured)'}
                      style={{ fontFamily: 'monospace' }}
                    />
                    <Button
                      size="sm"
                      variant="outline-secondary"
                      title="Copy to clipboard"
                      disabled={!buildVariantUrl(v.alias)}
                      onClick={() => copyUrl(buildVariantUrl(v.alias))}
                    >
                      <i className="fas fa-copy" />
                    </Button>
                  </div>

                  <Row className="g-2">
                    <Col xs={6}>
                      <Form.Group>
                        <Form.Label className="small mb-1">Name</Form.Label>
                        <Form.Control
                          size="sm"
                          type="text"
                          value={v.name || ''}
                          onChange={e => updateRow(v.id, { name: e.target.value })}
                        />
                      </Form.Group>
                    </Col>
                    <Col xs={6}>
                      <Form.Group>
                        <Form.Label className="small mb-1">Alias</Form.Label>
                        <Form.Control
                          size="sm"
                          type="text"
                          value={v.alias || ''}
                          onChange={e =>
                            updateRow(v.id, {
                              alias: e.target.value.replace(/\s+/g, '-').toLowerCase(),
                            })
                          }
                          isInvalid={!!aliasError}
                        />
                        {aliasError && (
                          <Form.Control.Feedback type="invalid">{aliasError}</Form.Control.Feedback>
                        )}
                      </Form.Group>
                    </Col>
                  </Row>

                  <Form.Group className="mt-2">
                    <Form.Label className="small mb-1">Description</Form.Label>
                    <Form.Control
                      size="sm"
                      type="text"
                      value={v.description || ''}
                      onChange={e => updateRow(v.id, { description: e.target.value })}
                    />
                  </Form.Group>

                  <div className="d-flex gap-3 mt-2">
                    <Form.Check
                      type="switch"
                      id={`pv-enabled-${v.id}`}
                      label="Enabled"
                      checked={isDefault ? true : v.enabled !== false}
                      disabled={isDefault}
                      title={
                        isDefault
                          ? 'The default variant cannot be disabled. Promote another variant to default first.'
                          : undefined
                      }
                      onChange={e => updateRow(v.id, { enabled: e.target.checked })}
                    />
                    <Form.Check
                      type="switch"
                      id={`pv-default-${v.id}`}
                      label="Default"
                      checked={isDefault}
                      onChange={() => handleSetDefault(v.id)}
                    />
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </>
  );
};

export default PipeVariantPanel;
