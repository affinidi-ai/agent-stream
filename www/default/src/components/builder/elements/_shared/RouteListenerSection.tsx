import React, { useEffect, useMemo, useState } from 'react';
import { Form } from 'react-bootstrap';
import { fetchRoutingConfig, type RoutingConfig } from './routingConfig';
import { generateRandomPath } from '../../../../utils/stringUtils';

export interface RouteListenerSectionProps {
  config: any;
  updateField: (field: string, value: any) => void;
  updateFields: (fields: Record<string, any>) => void;
  /**
   * The wire field name this section composes (`<prefix><custom>`).
   * Access Points write `route`.
   */
  routeFieldName: 'route';
  /** Banner heading, e.g. "Channel Route" or "Listener URL". */
  bannerLabel: string;
  /**
   * Replace the top history snapshot after the seed runs so undo skips
   * past the auto-seeded defaults. Optional; only APs (auto-created on
   * canvas load) need this.
   */
  replaceCommit?: () => void;
}

const PATH_TRAVERSAL_MSG = 'Path may not contain ".." segments';

function validatePath(path: string): string | null {
  if (!path) return null;
  if (path.split('/').some(seg => seg === '..')) return PATH_TRAVERSAL_MSG;
  return null;
}

/**
 * Shared address + prefix + custom-path editor used by Access Points.
 *
 * Persists `route_prefix` + `route_suffix` alongside the composed wire
 * field so the inputs round-trip a saved surface without re-deriving
 * the split (which can drift when the prefix list changes upstream).
 *
 * Auto-seeds a two-word random custom path on first mount when the
 * node has no prior config — matches the AP behaviour callers expect.
 */
const RouteListenerSection: React.FC<RouteListenerSectionProps> = ({
  config,
  updateField,
  updateFields,
  routeFieldName,
  bannerLabel,
  replaceCommit,
}) => {
  const [routingConfig, setRoutingConfig] = useState<RoutingConfig | null>(null);

  useEffect(() => {
    if (routingConfig) return;
    let alive = true;
    fetchRoutingConfig().then(data => {
      if (alive && data) setRoutingConfig(data);
    });
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const availableAddresses: string[] = useMemo(() => {
    if (!routingConfig) return [];
    return routingConfig.available_listen_addresses;
  }, [routingConfig]);

  const selectedHostPort: string = config.listen_address || '';
  const composedRoute: string = config[routeFieldName] || '';

  const { selectedPrefix, customPath } = useMemo(() => {
    if (config.route_prefix || config.route_suffix !== undefined) {
      return {
        selectedPrefix: config.route_prefix || '',
        customPath: config.route_suffix || '',
      };
    }
    if (!composedRoute || !routingConfig) {
      return { selectedPrefix: '', customPath: '' };
    }
    const match = routingConfig.channel_path_prefix.find(
      p => composedRoute === p.prefix || composedRoute.startsWith(p.prefix + '/')
    );
    if (!match) return { selectedPrefix: '', customPath: composedRoute };
    const suffix = composedRoute.substring(match.prefix.length);
    return {
      selectedPrefix: match.prefix,
      customPath: suffix.startsWith('/') ? suffix.substring(1) : suffix,
    };
  }, [config.route_prefix, config.route_suffix, composedRoute, routingConfig]);

  // First-time seed: drop a two-word default + first available address +
  // first prefix into a brand-new node. Subsequent mounts (undo / redo,
  // restored surface) skip seeding because at least one of the route
  // fields is already populated.
  const seededRef = React.useRef(false);
  useEffect(() => {
    if (seededRef.current) return;
    if (!routingConfig) return;

    if (composedRoute || config.route_suffix) {
      seededRef.current = true;
      // Backfill missing pieces if a prior partial seed left them blank.
      const patch: Record<string, any> = {};
      if (!config.listen_address && availableAddresses[0]) {
        patch.listen_address = availableAddresses[0];
      }
      if (!config.route_prefix && routingConfig.channel_path_prefix[0]) {
        const matched = routingConfig.channel_path_prefix.find(
          p => composedRoute === p.prefix || composedRoute.startsWith(p.prefix + '/')
        );
        const prefix = matched?.prefix ?? routingConfig.channel_path_prefix[0].prefix;
        const derivedSuffix = matched ? composedRoute.substring(matched.prefix.length) : '';
        const suffix = config.route_suffix || derivedSuffix || '';
        const path = suffix ? (suffix.startsWith('/') ? suffix : `/${suffix}`) : '';
        patch.route_prefix = prefix;
        if (suffix) {
          patch.route_suffix = suffix.startsWith('/') ? suffix.substring(1) : suffix;
        }
        if (path) patch[routeFieldName] = `${prefix}${path}`;
      }
      if (Object.keys(patch).length > 0) updateFields(patch);
      return;
    }

    seededRef.current = true;
    const suffix = generateRandomPath();
    const path = suffix.startsWith('/') ? suffix : `/${suffix}`;
    const prefix = routingConfig.channel_path_prefix[0]?.prefix ?? '';
    const listen = availableAddresses[0] ?? '';
    updateFields({
      listen_address: listen,
      route_prefix: prefix,
      route_suffix: suffix,
      [routeFieldName]: prefix && path ? `${prefix}${path}` : '',
    });
    replaceCommit?.();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [routingConfig]);

  const writeRouteParts = (prefix: string, suffix: string) => {
    const trimmed = suffix.trim();
    const path = trimmed ? (trimmed.startsWith('/') ? trimmed : `/${trimmed}`) : '';
    const composed = prefix && path ? `${prefix}${path}` : '';
    updateFields({
      route_prefix: prefix,
      route_suffix: suffix,
      [routeFieldName]: composed,
    });
  };

  const pathError = useMemo(() => validatePath(customPath), [customPath]);

  const fullRouteDisplay = useMemo(() => {
    if (!selectedHostPort || !selectedPrefix) return '';
    const suffix = customPath.startsWith('/') ? customPath : `/${customPath}`;
    return `${selectedHostPort}${selectedPrefix}${suffix}`;
  }, [selectedHostPort, selectedPrefix, customPath]);

  return (
    <>
      <RouteListenerBanner
        label={bannerLabel}
        url={fullRouteDisplay}
        warning={pathError ?? undefined}
      />

      <div className="config-section">
        <label>Listener</label>
        <Form.Group className="mb-2">
          <Form.Label className="small text-muted mb-1">
            Listen Address (Host:Port) <span className="text-danger">*</span>
          </Form.Label>
          <Form.Select
            size="sm"
            value={selectedHostPort}
            onChange={e => updateField('listen_address', e.target.value)}
            disabled={!routingConfig || availableAddresses.length === 0}
          >
            {!routingConfig ? (
              <option value="">Loading...</option>
            ) : availableAddresses.length === 0 ? (
              <option value="">No addresses available</option>
            ) : (
              <>
                <option value="">-- Select listen address --</option>
                {availableAddresses.map(addr => (
                  <option key={addr} value={addr}>
                    {addr}
                  </option>
                ))}
              </>
            )}
          </Form.Select>
        </Form.Group>
        <Form.Group className="mb-2">
          <Form.Label className="small text-muted mb-1">
            Channel Prefix <span className="text-danger">*</span>
          </Form.Label>
          <Form.Select
            size="sm"
            value={selectedPrefix}
            onChange={e => writeRouteParts(e.target.value, customPath)}
            disabled={!routingConfig || routingConfig.channel_path_prefix.length === 0}
          >
            {!routingConfig ? (
              <option value="">Loading...</option>
            ) : routingConfig.channel_path_prefix.length === 0 ? (
              <option value="">No prefixes available</option>
            ) : (
              <>
                <option value="">-- Select prefix --</option>
                {routingConfig.channel_path_prefix.map(item => (
                  <option key={item.id} value={item.prefix}>
                    {item.name}
                  </option>
                ))}
              </>
            )}
          </Form.Select>
        </Form.Group>
        <Form.Group className="mb-2">
          <Form.Label className="small text-muted mb-1">
            Custom Path <span className="text-danger">*</span>
          </Form.Label>
          <Form.Control
            size="sm"
            type="text"
            placeholder="my-agent/v1"
            value={customPath.startsWith('/') ? customPath.substring(1) : customPath}
            isInvalid={!!pathError}
            onChange={e => writeRouteParts(selectedPrefix, e.target.value)}
          />
          {pathError && (
            <Form.Control.Feedback type="invalid" style={{ fontSize: '10px' }}>
              {pathError}
            </Form.Control.Feedback>
          )}
        </Form.Group>
      </div>
    </>
  );
};

export default RouteListenerSection;

export interface RouteListenerBannerProps {
  /** Heading text shown in bold before the URL. */
  label: string;
  /** Composed URL to display. Empty string renders the placeholder hint. */
  url: string;
  /** When set, the banner switches to warning style and shows this message instead of the URL. */
  warning?: string;
  /** Placeholder text when `url` is empty and there's no warning. */
  placeholder?: string;
}

/**
 * Read-only banner used by `RouteListenerSection` and by panels that
 * want to surface another node's listener URL (e.g. a Managed Agent
 * showing the Access Point's URL as a convenience). Identical look,
 * feel, and copy behaviour as the editing variant.
 */
export const RouteListenerBanner: React.FC<RouteListenerBannerProps> = ({
  label,
  url,
  warning,
  placeholder = '(select address and prefix)',
}) => {
  const hasUrl = !!url && !warning;
  const display = warning ? warning : url || placeholder;
  return (
    <div
      className={`alert ${warning ? 'alert-warning' : 'alert-success'} mb-3`}
      style={{ fontSize: '13px' }}
    >
      <i className="fas fa-info-circle me-2"></i>
      <strong>{label}:</strong> {display}
      {hasUrl && (
        <button
          type="button"
          className="btn btn-xs ms-2"
          style={{ padding: '2px 6px', fontSize: '11px', outline: 'none' }}
          onClick={e => {
            navigator.clipboard.writeText(url);
            const btn = e.currentTarget as HTMLButtonElement;
            const originalHtml = btn.innerHTML;
            btn.innerHTML = '<i class="fas fa-check"></i>';
            setTimeout(() => {
              btn.innerHTML = originalHtml;
            }, 2000);
          }}
          title="Copy to clipboard"
        >
          <i className="fas fa-copy"></i>
        </button>
      )}
    </div>
  );
};
