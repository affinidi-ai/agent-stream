import { apiClient } from '../../../../api';

export interface RoutingConfig {
  available_listen_addresses: string[];
  channel_path_prefix: Array<{ id: string; name: string; prefix: string }>;
}

let cachedRoutingConfig: RoutingConfig | null = null;
let routingConfigPromise: Promise<RoutingConfig | null> | null = null;

export function fetchRoutingConfig(): Promise<RoutingConfig | null> {
  if (cachedRoutingConfig) return Promise.resolve(cachedRoutingConfig);
  if (routingConfigPromise) return routingConfigPromise;
  routingConfigPromise = apiClient
    .fetch('/api/v1/config/surface-routing')
    .then(r => (r.ok ? r.json() : null))
    .then((data: RoutingConfig | null) => {
      if (data) cachedRoutingConfig = data;
      return data;
    })
    .catch(() => null);
  return routingConfigPromise;
}
