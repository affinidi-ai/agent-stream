import React from 'react';
import type { ConfigPanelProps } from '../types';
import { useOptionalSurfaceMeta } from '../../SurfaceMetaContext';
import { RoutingRulesControls } from '../surface/SurfacePanel';

/**
 * Full-page editor for the **Router** element. Attribute-based routing lives
 * here: ordered rules that match a request header, a top-level body field, or an
 * attachment type (modality — including the realtime WebSocket transport) and
 * route to a variant. The rules are the surface's base-pipe `routing_rules`,
 * read/written through the surface meta (shared with variant-catalog sync), so
 * they stay in lock-step with the variant catalog. The single enable toggle
 * lives on the sidebar (the node's enable flag); this editor never repeats it
 * (`hideEnableSwitch`). Mirrors the surface-config fullscreen card so the "Close
 * tab" control is consistent across editors.
 */
const RouterFullscreenPanel: React.FC<ConfigPanelProps> = ({ closeFullscreenEditor }) => {
  const meta = useOptionalSurfaceMeta();
  const setRoutingRules = meta?.setRoutingRules;
  const hasRules = (meta?.routingRules?.length ?? 0) > 0;
  // Open the editor with one editable rule so the operator can enter data
  // immediately instead of first pressing "Add routing rule". Replacing with a
  // single rule keeps this idempotent under StrictMode's double-invoke.
  React.useEffect(() => {
    if (setRoutingRules && !hasRules) {
      setRoutingRules([
        { match: { kind: 'header', name: '', equals: '' }, target: { variant: null } },
      ]);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return (
    <div className="surface-config-fullscreen">
      <div className="card shadow-sm mb-4">
        <div className="card-header bg-light d-flex justify-content-between align-items-center">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-route me-2" />
            Router — attribute-based request routing
          </h6>
          {closeFullscreenEditor && (
            <button
              type="button"
              className="btn btn-sm btn-outline-secondary"
              onClick={closeFullscreenEditor}
            >
              <i className="fas fa-times me-1" />
              Close tab
            </button>
          )}
        </div>
        <div className="card-body">
          <p className="text-muted small">
            Match a request header, a body field, or an attachment type and route it to a variant.
            Evaluated at the front door before auth, policy, and guards; an explicit{' '}
            <code>$alias</code> always wins, and anything unmatched (including plain text) goes to
            the base surface. Turn routing on or off from the Router element in the sidebar.
          </p>
          {meta && meta.setRoutingRules ? (
            <RoutingRulesControls
              value={meta.routingRules ?? []}
              variantAliases={meta.variantAliases ?? []}
              enabled={meta.routingEnabled === true}
              onEnabledChange={v => meta.setRoutingEnabled?.(v)}
              onChange={meta.setRoutingRules}
              hideEnableSwitch
            />
          ) : (
            <div className="text-muted small">Routing is unavailable in this context.</div>
          )}
        </div>
      </div>
    </div>
  );
};

export default RouterFullscreenPanel;
