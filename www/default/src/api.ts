import {
  DashboardStats,
  LogEntry,
  Settings,
  Task,
  TruncateLogsResult,
  TruncateMetricsResult,
  UserSettingsOverrides,
} from './types';

// Agent Surface types
import type { SurfaceStatus } from './generated/SurfaceStatus';
import { formatApiError } from './utils/apiError';

const API_BASE = '/api/v1';

export const TERMS_ACCEPTANCE_REQUIRED_EVENT = 'terms-acceptance-required';
export const TERMS_OPERATIONAL_FAILURE_EVENT = 'terms-operational-failure';

async function signalTermsFailure(response: Response): Promise<void> {
  if ((response.status !== 403 && response.status !== 503) || typeof window === 'undefined') return;
  const body = (await response
    .clone()
    .json()
    .catch(() => null)) as { code?: string } | null;
  if (response.status === 403 && body?.code === 'TERMS_ACCEPTANCE_REQUIRED') {
    window.dispatchEvent(new Event(TERMS_ACCEPTANCE_REQUIRED_EVENT));
  } else if (response.status === 503 && body?.code === 'TERMS_OPERATIONAL_FAILURE') {
    window.dispatchEvent(new Event(TERMS_OPERATIONAL_FAILURE_EVENT));
  }
}

/** One appliance resource limit with its current live count (GET /v1/limits). */
export interface LimitItem {
  id: string;
  name: string;
  description: string;
  limit: number;
  current: number;
}

class SessionManager {
  private static readonly YES_VALUE = '1';
  private static readonly SESSION_EXPIRED_KEY = 'session_expired';

  didSessionExpire(): boolean {
    return sessionStorage.getItem(SessionManager.SESSION_EXPIRED_KEY) === SessionManager.YES_VALUE;
  }

  setSessionExpiredError(): void {
    sessionStorage.setItem(SessionManager.SESSION_EXPIRED_KEY, SessionManager.YES_VALUE);
  }

  clearSessionExpiredError(): void {
    sessionStorage.removeItem(SessionManager.SESSION_EXPIRED_KEY);
  }

  private setCookie(name: string, value: string, days: number = 365): void {
    const expires = new Date();
    expires.setTime(expires.getTime() + days * 24 * 60 * 60 * 1000);
    document.cookie = `${name}=${value};expires=${expires.toUTCString()};path=/;SameSite=Strict`;
  }

  getCookie(name: string): string | null {
    const nameEQ = name + '=';
    const ca = document.cookie.split(';');
    for (let i = 0; i < ca.length; i++) {
      let c = ca[i];
      while (c.charAt(0) === ' ') c = c.substring(1, c.length);
      if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
    }
    return null;
  }

  getSessionToken(): string | null {
    // Try sessionStorage first
    let token = sessionStorage.getItem('session_token');
    if (token) return token;

    token = this.getCookie('session_token');
    if (token) {
      // Restore to sessionStorage for future calls
      sessionStorage.setItem('session_token', token);
    }
    return token;
  }

  getAuthHeaders(): Record<string, string> {
    const sessionToken = this.getSessionToken();
    if (!sessionToken) {
      return {};
    }
    return { Authorization: `Bearer ${sessionToken}` };
  }

  login(username: string, sessionToken: string): void {
    this.setCookie('lastUsername', username);
    sessionStorage.setItem('session_token', sessionToken);
  }

  /**
   * End the dashboard session. Resolves to the identity provider's sign-out
   * address when the server gives one (OIDC sign-in), which only an explicit
   * sign-out should open: see {@link signOut}.
   */
  async logout(logoutAction: () => void = () => {}): Promise<string | undefined> {
    logoutAction();
    let endSessionUrl: string | undefined;
    try {
      const response = await fetch('/api/auth/logout', {
        method: 'POST',
        headers: this.getAuthHeaders(),
      });
      const answer = response.ok ? await response.json().catch(() => ({})) : {};
      const url = answer?.end_session_url;
      if (typeof url === 'string' && /^https?:\/\//.test(url)) {
        endSessionUrl = url;
      }
    } catch (error) {
      console.error('Logout failed:', error);
    }

    sessionStorage.removeItem('session_token');
    document.cookie = 'session_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT;';
    return endSessionUrl;
  }

  /**
   * Sign out at the person's request: end the session and, when the identity
   * provider has a sign-out address, go there so they are signed out of the
   * provider too. Resolves to true when the browser is leaving for it.
   */
  async signOut(logoutAction: () => void = () => {}): Promise<boolean> {
    const endSessionUrl = await this.logout(logoutAction);
    if (endSessionUrl) {
      window.location.assign(endSessionUrl);
      return true;
    }
    return false;
  }

  expireSession(): void {
    this.setSessionExpiredError();
    this.logout().finally(() => window.location.reload());
  }
}

export const sessionManager = new SessionManager();

class APIClient {
  private async request<T>(
    endpoint: string,
    options?: RequestInit & { timeout?: number }
  ): Promise<T> {
    const url = `${API_BASE}${endpoint}`;

    // Setup timeout using AbortController
    const controller = new AbortController();
    let timedOut = false;
    const timeoutId = options?.timeout
      ? setTimeout(() => {
          timedOut = true;
          controller.abort();
        }, options.timeout)
      : null;

    // Link an optional caller-supplied signal so callers can cancel in-flight
    // requests (the internal controller still owns the timeout).
    const externalSignal = options?.signal;
    if (externalSignal) {
      if (externalSignal.aborted) {
        controller.abort();
      } else {
        externalSignal.addEventListener('abort', () => controller.abort(), { once: true });
      }
    }

    try {
      const response = await fetch(url, {
        headers: {
          'Content-Type': 'application/json',
          ...sessionManager.getAuthHeaders(),
          ...options?.headers,
        },
        ...options,
        signal: controller.signal,
      });

      await signalTermsFailure(response);

      if (response.status === 401) {
        sessionManager.expireSession();
        throw new Error('Session expired');
      }

      if (!response.ok) {
        console.error('[API] Request failed:', endpoint, response.status, response.statusText);
        let errorBody = '';
        try {
          errorBody = await response.text();
          if (errorBody) console.error('[API] Error body:', errorBody.substring(0, 500));
        } catch (e) {
          console.error('[API] Could not read error response:', e);
        }
        throw new Error(formatApiError(response.status, errorBody, response.statusText));
      }

      // Don't try to parse JSON for 204 No Content responses
      if (response.status === 204) {
        return {} as T;
      }

      const data = await response.json();
      return data;
    } catch (error: any) {
      if (error.name === 'AbortError') {
        if (timedOut) {
          throw new Error(
            'Request timeout - the webhook endpoint did not respond within 30 seconds'
          );
        }
        // Caller cancelled via signal — preserve AbortError so it can be ignored.
        throw error;
      }
      throw error;
    } finally {
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
    }
  }

  /**
   * Authenticated fetch — drop-in replacement for `fetch()` that adds the
   * Authorization header automatically.  Returns the raw `Response` so callers
   * can inspect status, stream the body, etc.
   */
  async fetch(input: string, init?: RequestInit): Promise<Response> {
    const response = await fetch(input, {
      ...init,
      headers: {
        ...sessionManager.getAuthHeaders(),
        ...init?.headers,
      },
    });
    await signalTermsFailure(response);
    return response;
  }

  // Appliance resource limits
  async getLimits(): Promise<LimitItem[]> {
    return this.request<LimitItem[]>('/limits');
  }

  // Generic HTTP methods
  async get<T = any>(
    endpoint: string,
    options?: { timeout?: number; signal?: AbortSignal }
  ): Promise<{ data: T }> {
    const data = await this.request<T>(endpoint, options);
    return { data };
  }

  async post<T = any>(
    endpoint: string,
    body?: any,
    options?: { timeout?: number }
  ): Promise<{ data: T }> {
    const data = await this.request<T>(endpoint, {
      method: 'POST',
      body: JSON.stringify(body),
      ...options,
    });
    return { data };
  }

  async put<T = any>(
    endpoint: string,
    body?: any,
    options?: { timeout?: number }
  ): Promise<{ data: T }> {
    const data = await this.request<T>(endpoint, {
      method: 'PUT',
      body: JSON.stringify(body),
      ...options,
    });
    return { data };
  }

  async delete<T = any>(endpoint: string, options?: { timeout?: number }): Promise<{ data: T }> {
    const data = await this.request<T>(endpoint, {
      method: 'DELETE',
      ...options,
    });
    return { data };
  }

  // Dashboard Stats
  async getDashboardStats(
    bucketSeconds?: number,
    channelId?: string,
    gatewayId?: string,
    identityDid?: string,
    pipeId?: string
  ): Promise<DashboardStats> {
    const params = new URLSearchParams();
    if (bucketSeconds) params.append('bucket_seconds', bucketSeconds.toString());
    if (channelId) params.append('channel_id', channelId);
    if (gatewayId) params.append('gateway_id', gatewayId);
    if (identityDid) params.append('identity_did', identityDid);
    if (pipeId) params.append('pipe_id', pipeId);
    const queryString = params.toString() ? `?${params.toString()}` : '';
    const result = await this.request<DashboardStats>(`/dashboard/stats${queryString}`);

    return result;
  }

  async getSystemMetrics(timeRange?: string, since?: string): Promise<any> {
    const params = new URLSearchParams();
    if (since) params.set('since', since);
    else if (timeRange) params.set('time_range', timeRange);
    const qs = params.toString();
    return this.request(`/dashboard/system-metrics${qs ? `?${qs}` : ''}`);
  }

  // Identity Management
  async resolveIdentityDID(did: string): Promise<any> {
    return this.request(`/identity/resolve-did?did=${encodeURIComponent(did)}`);
  }

  async getGatewayDidDocument(): Promise<any> {
    return this.request('/identity/did-document');
  }

  // Settings Management
  async getSettings(): Promise<Settings> {
    const backendSettings = await this.request<any>('/settings');

    // Convert backend settings format to frontend format
    return {
      badge_threshold: backendSettings.badge_threshold_minutes || 5,
      metrics_retention: backendSettings.metrics_retention_minutes || 360, // Both in minutes now
      task_activity_window: backendSettings.task_activity_window_seconds || 60,
      connections_window: backendSettings.connections_window_minutes || 5,
      latency_window: backendSettings.latency_window_minutes || 5,
      onboarding_channel_ttl_seconds: backendSettings.onboarding_channel_ttl_seconds || 30,
      refresh_interval_seconds: backendSettings.refresh_interval_seconds || 5,
      log_timestamp_format: backendSettings.log_timestamp_format || 'local',
      bucket_seconds: backendSettings.bucket_seconds || 30,
      payments_min_display: backendSettings.payments_min_display || 10,
      feature_flags: backendSettings.feature_flags || {},
      prometheus_auth_enabled: backendSettings.prometheus_auth_enabled || false,
      prometheus_auth_username: backendSettings.prometheus_auth_username || '',
      audit_enabled: backendSettings.audit_enabled || false,
      audit_categories: backendSettings.audit_categories || {
        policies: false,
        trust_checks: false,
        identity: false,
      },
      appliance_id: backendSettings.appliance_id || '',
    };
  }

  async updateSettings(settings: Partial<Settings>): Promise<void> {
    // Map frontend field names to backend field names
    const backendSettings: any = {};

    if (settings.badge_threshold !== undefined) {
      backendSettings.badge_threshold_minutes = settings.badge_threshold;
    }

    if (settings.metrics_retention !== undefined) {
      backendSettings.metrics_retention_minutes = settings.metrics_retention;
    }

    if (settings.task_activity_window !== undefined) {
      backendSettings.task_activity_window_seconds = settings.task_activity_window;
    }

    if (settings.connections_window !== undefined) {
      backendSettings.connections_window_minutes = settings.connections_window;
    }

    if (settings.latency_window !== undefined) {
      backendSettings.latency_window_minutes = settings.latency_window;
    }

    if (settings.onboarding_channel_ttl_seconds !== undefined) {
      backendSettings.onboarding_channel_ttl_seconds = settings.onboarding_channel_ttl_seconds;
    }

    if (settings.refresh_interval_seconds !== undefined) {
      backendSettings.refresh_interval_seconds = settings.refresh_interval_seconds;
    }

    if (settings.log_timestamp_format !== undefined) {
      backendSettings.log_timestamp_format = settings.log_timestamp_format;
    }

    if (settings.bucket_seconds !== undefined) {
      backendSettings.bucket_seconds = settings.bucket_seconds;
    }

    if (settings.payments_min_display !== undefined) {
      backendSettings.payments_min_display = settings.payments_min_display;
    }

    if (settings.feature_flags !== undefined) {
      backendSettings.feature_flags = settings.feature_flags;
    }

    if (settings.prometheus_auth_enabled !== undefined) {
      backendSettings.prometheus_auth_enabled = settings.prometheus_auth_enabled;
    }

    if (settings.prometheus_auth_username !== undefined) {
      backendSettings.prometheus_auth_username = settings.prometheus_auth_username;
    }

    if ((settings as any).prometheus_auth_password !== undefined) {
      backendSettings.prometheus_auth_password = (settings as any).prometheus_auth_password;
    }

    if (settings.audit_enabled !== undefined) {
      backendSettings.audit_enabled = settings.audit_enabled;
    }

    if (settings.audit_categories !== undefined) {
      backendSettings.audit_categories = settings.audit_categories;
    }

    if (settings.appliance_id !== undefined) {
      backendSettings.appliance_id = settings.appliance_id;
    }

    await this.request('/settings', {
      method: 'POST',
      body: JSON.stringify(backendSettings),
    });
  }

  async resetSettings(): Promise<void> {
    await this.request('/settings', {
      method: 'DELETE',
    });
  }

  // Per-User Settings Management

  /**
   * Get effective settings for the current user (user overrides merged with system defaults).
   * Falls back to system settings if user settings endpoint is not available.
   */
  async getUserSettings(): Promise<Settings> {
    try {
      const backendSettings = await this.request<any>('/user-settings');
      return {
        badge_threshold: backendSettings.badge_threshold_minutes || 5,
        metrics_retention: backendSettings.metrics_retention_minutes || 360,
        task_activity_window: backendSettings.task_activity_window_seconds || 60,
        connections_window: backendSettings.connections_window_minutes || 5,
        latency_window: backendSettings.latency_window_minutes || 5,
        onboarding_channel_ttl_seconds: backendSettings.onboarding_channel_ttl_seconds || 30,
        refresh_interval_seconds: backendSettings.refresh_interval_seconds || 5,
        log_timestamp_format: backendSettings.log_timestamp_format || 'local',
        bucket_seconds: backendSettings.bucket_seconds || 30,
        payments_min_display: backendSettings.payments_min_display || 10,
        feature_flags: backendSettings.feature_flags || {},
        prometheus_auth_enabled: backendSettings.prometheus_auth_enabled || false,
        prometheus_auth_username: backendSettings.prometheus_auth_username || '',
      };
    } catch {
      // Fall back to system settings if user settings endpoint is unavailable
      return this.getSettings();
    }
  }

  /** Get only the user's personal overrides (without system defaults). */
  async getUserSettingsOverrides(): Promise<UserSettingsOverrides> {
    return this.request<UserSettingsOverrides>('/user-settings/overrides');
  }

  /** Update the current user's personal display preferences. */
  async updateUserSettings(settings: Partial<UserSettingsOverrides>): Promise<void> {
    await this.request('/user-settings', {
      method: 'POST',
      body: JSON.stringify(settings),
    });
  }

  /** Reset user settings to system defaults. */
  async resetUserSettings(): Promise<void> {
    await this.request('/user-settings', {
      method: 'DELETE',
    });
  }

  // Metrics Configuration Management
  async getMetricsConfig(): Promise<any> {
    return this.request('/metrics/config');
  }

  async updateMetricsConfig(config: any): Promise<{ success: boolean; message: string }> {
    return this.request('/metrics/config', {
      method: 'PUT',
      body: JSON.stringify(config),
    });
  }

  async testOtlpConnection(endpoint: string): Promise<{ success: boolean; message: string }> {
    return this.request('/metrics/test-connection', {
      method: 'POST',
      body: JSON.stringify({ endpoint }),
    });
  }

  // Agent Surfaces
  async listSurfaces(): Promise<AgentSurface[]> {
    const list = await this.request<AgentSurface[]>('/surfaces');
    return list.map(fromBackendSurface);
  }

  async getSurface(surfaceId: string): Promise<AgentSurface> {
    const s = await this.request<AgentSurface>(`/surfaces/${encodeURIComponent(surfaceId)}`);
    return fromBackendSurface(s);
  }

  async createSurface(surface: Partial<AgentSurface>): Promise<AgentSurface> {
    const s = await this.request<AgentSurface>('/surfaces', {
      method: 'POST',
      body: JSON.stringify(toBackendSurface(surface)),
    });
    return fromBackendSurface(s);
  }

  async updateSurface(surfaceId: string, surface: Partial<AgentSurface>): Promise<AgentSurface> {
    const s = await this.request<AgentSurface>(`/surfaces/${encodeURIComponent(surfaceId)}`, {
      method: 'PUT',
      body: JSON.stringify(toBackendSurface(surface)),
    });
    return fromBackendSurface(s);
  }

  async deleteSurface(surfaceId: string): Promise<void> {
    await this.request(`/surfaces/${encodeURIComponent(surfaceId)}`, {
      method: 'DELETE',
    });
  }

  // Pipe Templates
  async listPipeTemplates(): Promise<PipeTemplate[]> {
    return this.request<PipeTemplate[]>('/pipe-templates');
  }

  async getPipeTemplate(id: string): Promise<PipeTemplate> {
    return this.request<PipeTemplate>(`/pipe-templates/${encodeURIComponent(id)}`);
  }

  async createPipeTemplate(tpl: Partial<PipeTemplate>): Promise<PipeTemplate> {
    return this.request<PipeTemplate>('/pipe-templates', {
      method: 'POST',
      body: JSON.stringify(tpl),
    });
  }

  async updatePipeTemplate(id: string, tpl: Partial<PipeTemplate>): Promise<PipeTemplate> {
    return this.request<PipeTemplate>(`/pipe-templates/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(tpl),
    });
  }

  async deletePipeTemplate(id: string): Promise<void> {
    await this.request(`/pipe-templates/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  }

  /**
   * Upload an exported `*.pipe-template.json` payload. The backend
   * re-assigns a fresh id if the incoming id collides, so this is safe
   * to call repeatedly on the same file (each call produces a clone).
   */
  async importPipeTemplate(payload: unknown): Promise<PipeTemplate> {
    return this.request<PipeTemplate>('/pipe-templates/import', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  /**
   * Trigger a browser download of the template as a portable
   * `*.pipe-template.json` file. Returns the resolved filename.
   */
  async exportPipeTemplate(id: string): Promise<string> {
    const response = await this.fetch(
      `${API_BASE}/pipe-templates/${encodeURIComponent(id)}/export`
    );
    if (!response.ok) {
      const body = await response.text().catch(() => '');
      throw new Error(`Export failed: ${response.status} ${response.statusText} ${body}`);
    }
    const blob = await response.blob();
    const disposition = response.headers.get('content-disposition') ?? '';
    const match = /filename="?([^"]+)"?/i.exec(disposition);
    const filename = match?.[1] ?? `${id}.pipe-template.json`;
    const url = URL.createObjectURL(blob);
    try {
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
    } finally {
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
    return filename;
  }

  // Onboarding Management
  async createTempOnboardChannel(protocol: string): Promise<{
    config_id: string;
    channel_name: string;
    endpoint_url: string;
    message: string;
    ttl_seconds: number;
  }> {
    return this.request('/onboard/create-temp-surface', {
      method: 'POST',
      body: JSON.stringify({ protocol }),
    });
  }

  async deleteTempOnboardChannel(configId: string): Promise<void> {
    await this.request(`/onboard/delete-temp-channel/${encodeURIComponent(configId)}`, {
      method: 'DELETE',
    });
  }

  // Metrics Management
  async truncateMetrics(): Promise<TruncateMetricsResult> {
    return this.request<TruncateMetricsResult>('/metrics/truncate', {
      method: 'POST',
    });
  }

  // Tasks (if available - placeholder for future implementation)
  async getTasks(): Promise<Task[]> {
    // This might need to be implemented in the backend
    return this.request<Task[]>('/tasks');
  }

  // Logs (if available - placeholder for future implementation)
  async getLogs(limit?: number): Promise<LogEntry[]> {
    const params = limit ? `?limit=${limit}` : '';
    return this.request<LogEntry[]>(`/logs${params}`);
  }

  // Truncate old / rotated log files
  async truncateOldLogs(): Promise<TruncateLogsResult> {
    return this.request<TruncateLogsResult>('/logs/truncate', {
      method: 'POST',
    });
  }

  // Download all logs as a ZIP archive (streaming for large files)
  async downloadLogs(): Promise<Blob> {
    const response = await fetch(`${API_BASE}/logs/download`, {
      method: 'GET',
      headers: {
        ...sessionManager.getAuthHeaders(),
      },
    });

    if (!response.ok) {
      const errorBody = await response.text().catch(() => '');
      throw new Error(
        `Download failed: ${formatApiError(response.status, errorBody, response.statusText)}`
      );
    }

    return response.blob();
  }

  // Permissions
  async getPermissions(): Promise<Record<string, boolean>> {
    return this.request<Record<string, boolean>>('/permissions');
  }

  // API Keys Management
  async listAllApiKeys(): Promise<ApiKeyMeta[]> {
    return this.request<ApiKeyMeta[]>('/api-keys');
  }

  async listApiKeys(agentId: string): Promise<ApiKeyMeta[]> {
    return this.request<ApiKeyMeta[]>(`/api-keys/${encodeURIComponent(agentId)}`);
  }

  async createApiKey(
    agentId: string,
    clientId: string,
    labels?: Record<string, string>,
    expiresInSeconds?: number | null
  ): Promise<ApiKeyCreated> {
    return this.request<ApiKeyCreated>(`/api-keys/${encodeURIComponent(agentId)}`, {
      method: 'POST',
      body: JSON.stringify({
        client_id: clientId,
        labels,
        expires_in_seconds: expiresInSeconds ?? undefined,
      }),
    });
  }

  async getApiKey(agentId: string, keyId: string): Promise<ApiKeyRecord> {
    return this.request<ApiKeyRecord>(
      `/api-keys/${encodeURIComponent(agentId)}/${encodeURIComponent(keyId)}`
    );
  }

  async revokeApiKey(agentId: string, keyId: string, actor?: string): Promise<void> {
    await this.request(
      `/api-keys/${encodeURIComponent(agentId)}/${encodeURIComponent(keyId)}/revoke`,
      {
        method: 'POST',
        body: JSON.stringify({ actor: actor || 'dashboard' }),
      }
    );
  }

  async rotateApiKey(agentId: string, keyId: string, actor?: string): Promise<ApiKeyCreated> {
    return this.request<ApiKeyCreated>(
      `/api-keys/${encodeURIComponent(agentId)}/${encodeURIComponent(keyId)}/rotate`,
      {
        method: 'POST',
        body: JSON.stringify({ actor: actor || 'dashboard' }),
      }
    );
  }

  async deleteApiKey(agentId: string, keyId: string): Promise<void> {
    await this.request(`/api-keys/${encodeURIComponent(agentId)}/${encodeURIComponent(keyId)}`, {
      method: 'DELETE',
    });
  }

  // Outbound Credentials Management
  async listCredentials(agentId: string): Promise<OutboundCredentialMeta[]> {
    return this.request<OutboundCredentialMeta[]>(`/credentials/${encodeURIComponent(agentId)}`);
  }

  async createCredential(
    agentId: string,
    targetIdentifier: string,
    credentialType: CredentialType,
    credentialValue: string,
    headerName?: string,
    headerFormat?: string,
    labels?: Record<string, string>
  ): Promise<OutboundCredentialMeta> {
    return this.request<OutboundCredentialMeta>(`/credentials/${encodeURIComponent(agentId)}`, {
      method: 'POST',
      body: JSON.stringify({
        target_identifier: targetIdentifier,
        credential_type: credentialType,
        credential_value: credentialValue,
        header_name: headerName,
        header_format: headerFormat,
        labels,
        actor: 'dashboard',
      }),
    });
  }

  async getCredential(agentId: string, credentialId: string): Promise<OutboundCredentialMeta> {
    return this.request<OutboundCredentialMeta>(
      `/credentials/${encodeURIComponent(agentId)}/${encodeURIComponent(credentialId)}`
    );
  }

  async updateCredential(
    agentId: string,
    credentialId: string,
    credentialValue: string,
    targetIdentifier?: string,
    labels?: Record<string, string>
  ): Promise<OutboundCredentialMeta> {
    return this.request<OutboundCredentialMeta>(
      `/credentials/${encodeURIComponent(agentId)}/${encodeURIComponent(credentialId)}`,
      {
        method: 'PUT',
        body: JSON.stringify({
          credential_value: credentialValue,
          target_identifier: targetIdentifier,
          labels,
          actor: 'dashboard',
        }),
      }
    );
  }

  async deleteCredential(agentId: string, credentialId: string): Promise<void> {
    await this.request(
      `/credentials/${encodeURIComponent(agentId)}/${encodeURIComponent(credentialId)}`,
      {
        method: 'DELETE',
      }
    );
  }

  // DID:webvh Identity Management
  async listDidWebVhIdentities(): Promise<any> {
    const response = await this.get<any>('/identities');
    return response.data;
  }

  async getDidWebVhIdentity(id: string): Promise<any> {
    const response = await this.get<any>(`/identities/${encodeURIComponent(id)}`);
    return response.data;
  }

  async createDidWebVhIdentity(request: any): Promise<any> {
    const response = await this.post<any>('/identities', request);
    return response.data;
  }

  async updateDidWebVhIdentity(id: string, didDocument: any, updateKeys?: string[]): Promise<any> {
    const response = await this.post<any>(`/identities/${encodeURIComponent(id)}/update`, {
      did_document: didDocument,
      update_keys: updateKeys,
    });
    return response.data;
  }

  async deleteDidWebVhIdentity(id: string): Promise<void> {
    await this.delete(`/identities/${encodeURIComponent(id)}`);
  }

  async getIdentityTrustScore(id: string): Promise<any> {
    const response = await this.get<any>(`/identities/${encodeURIComponent(id)}/trust-score`);
    return response.data;
  }

  async getIdentityVersionHistory(id: string): Promise<any> {
    const response = await this.get<any>(`/identities/${encodeURIComponent(id)}/history`);
    return response.data;
  }

  async rotateIdentityKeys(id: string, params?: { pre_rotation_seconds?: number }): Promise<any> {
    const response = await this.post<any>(
      `/identities/${encodeURIComponent(id)}/rotate-keys`,
      params
    );
    return response.data;
  }

  async transferIdentityOwnership(id: string, request: any): Promise<any> {
    const response = await this.post<any>(
      `/identities/${encodeURIComponent(id)}/transfer`,
      request
    );
    return response.data;
  }

  async resolveDidWebVh(did: string, versionId?: string, versionTime?: string): Promise<any> {
    const params = new URLSearchParams({ did });
    if (versionId) params.append('versionId', versionId);
    if (versionTime) params.append('versionTime', versionTime);
    const response = await this.get<any>(`/resolve?${params.toString()}`);
    return response.data;
  }

  async verifyDidWebVh(did: string, dna?: any): Promise<any> {
    const response = await this.post<any>(
      `/verify/${encodeURIComponent(did)}`,
      dna ? { dna } : undefined
    );
    return response.data;
  }

  // Debug: Export storage with PII redaction, encrypted with Ed25519 public key
  async exportStorage(publicKeyPem: string): Promise<Blob> {
    const response = await fetch(`${API_BASE}/debug/export-storage`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...sessionManager.getAuthHeaders(),
      },
      body: JSON.stringify({ public_key_pem: publicKeyPem }),
    });

    if (!response.ok) {
      const errorBody = await response.text().catch(() => '');
      throw new Error(
        `Export failed: ${formatApiError(response.status, errorBody, response.statusText)}`
      );
    }

    return response.blob();
  }

  // Admin: Backup storage (full, with PIIs) — downloads backup.asbak
  async backupStorage(): Promise<Blob> {
    const response = await fetch(`${API_BASE}/admin/backup-storage`, {
      method: 'POST',
      headers: {
        ...sessionManager.getAuthHeaders(),
      },
    });

    if (!response.ok) {
      const errorBody = await response.text().catch(() => '');
      throw new Error(
        `Backup failed: ${formatApiError(response.status, errorBody, response.statusText)}`
      );
    }

    return response.blob();
  }

  // Admin: Restore storage from backup.asbak upload
  async restoreStorage(file: File): Promise<{ status: string; message: string }> {
    const formData = new FormData();
    formData.append('backup', file);

    const response = await fetch(`${API_BASE}/admin/restore-storage`, {
      method: 'POST',
      headers: {
        ...sessionManager.getAuthHeaders(),
      },
      body: formData,
    });

    if (!response.ok) {
      const errorBody = await response.text().catch(() => '');
      throw new Error(
        `Restore failed: ${formatApiError(response.status, errorBody, response.statusText)}`
      );
    }

    return response.json();
  }
}

// API Key types
export interface ApiKeyMeta {
  key_id: string;
  agent_id: string;
  client_id: string;
  status: 'active' | 'revoked';
  labels: Record<string, string>;
  created_at: string;
  expires_at?: string;
  revoked_at?: string;
  last_used_at?: string;
  issuer?: { actor: string; method: string };
  rotated_from?: string;
  needs_rotation: boolean;
  prefix?: string;
  created_by?: string;
  revoked_by?: string;
  use_count?: number;
}

export type ApiKeyRecord = ApiKeyMeta;

export interface ApiKeyCreated {
  key_id: string;
  agent_id: string;
  client_id: string;
  secret: string;
  created_at: string;
  expires_at?: string;
  rotated_from?: string;
}

// Outbound Credential types
export type CredentialType = 'api_key' | 'bearer_token' | 'basic_auth' | 'custom';

export interface OutboundCredentialMeta {
  credential_id: string;
  agent_id: string;
  target_identifier: string;
  credential_type: CredentialType;
  header_name: string;
  header_format: string;
  labels: Record<string, string>;
  created_at: string;
  updated_at: string;
  created_by: string;
}

export const apiClient = new APIClient();

/**
 * A reusable starting point for a pipe. Mirrors the backend
 * `PipeTemplate` in `src/pipe_templates/types.rs`. Like surface
 * templates, a pipe template is either `partial` (a bundle of
 * incremental items dropped onto an existing pipe canvas) or `full`
 * (a complete `pipe` snapshot, including `canvas` and `variants`,
 * applied by replacing the current edit form wholesale).
 */
export interface PipeTemplate {
  $schema?: string;
  /** Server-minted on create when omitted/empty. */
  id: string;
  name: string;
  /**
   * Template kind. `partial` (default) is a bundle of incremental
   * items dropped onto an existing pipe canvas. `full` carries a
   * complete pipe snapshot under `pipe` (including `canvas` and
   * `variants`) and is applied by replacing the current edit form.
   */
  kind?: 'partial' | 'full';
  /** Short one-liner shown in the template list row. */
  description?: string;
  /** Long-form explanation shown when the template row is expanded. */
  details?: string;
  /**
   * Body text for the welcome callout shown the first time the user
   * lands on a pipe created from this template. Empty falls back to a
   * generic default.
   */
  starter_hint?: string;
  /** FontAwesome icon name without the `fa-` prefix. */
  icon?: string;
  tags?: string[];
  /** `"system"` for builtins, otherwise the author DID / user id. */
  author?: string;
  created_at?: string;
  updated_at?: string;
  /** Server-set. Builtins are read-only via the REST API. */
  builtin?: boolean;
  /**
   * Display order in template lists and the create-pipe picker. Lower
   * values sort first; ties fall back to alphabetical by name.
   * Templates without this field sort last.
   */
  sort_priority?: number;
  /**
   * Item list for `kind: 'partial'` templates. Empty / omitted for
   * full templates.
   */
  items?: PipeTemplateItem[];
  /**
   * Verbatim pipe snapshot for `kind: 'full'` templates — the same flat
   * shape the edit form holds (name / route / provider / model /
   * endpoint_url / guard / judge / jury / rate-limit / cost-tracking /
   * override_policy …) plus `canvas` (node layout) and `variants`
   * (upstream-only switchable copies). May contain placeholder tokens
   * like `$SURFACE_NAME` / `$SURFACE_ROUTE` / `$SURFACE_ENDPOINT` that the apply
   * step substitutes against the current form context. Opaque
   * server-side.
   */
  pipe?: any;
}

export interface PipeTemplateItem {
  /**
   * Anchor scope. Known: `pipe`, `source`, `upstream`, `middleware`.
   * Other strings are forward-compat placeholders.
   */
  scope: string;
  /** Element kind from the frontend pipe registry (e.g. `pipe-rate-limit`). */
  kind: string;
  /** Optional address detail. Reserved for forward-compat. */
  address?: string;
  /** Partial config payload deep-merged onto the placed element. */
  config?: any;
}

export interface AgentSurface {
  surface_id: string;
  name: string;
  description: string;
  status: SurfaceStatus;
  agent_did?: string;
  tags: string[];
  variants?: any[];
  default_variant_id?: string;
  access_point: {
    name?: string;
    listen_address: string;
    route: string;
    protocol: 'a2a' | 'mcp';
    caller_context?: { mode: 'required' | 'optional' | 'anonymous' };
    identity_resolution?: any;
    inbound_policy?: { policy_definition_id: string };
    rate_limit?: { requests: number; window_secs: number };
    publish_to_did_document?: boolean;
    didwebvh_identity?: Record<string, any>;
  };
  target: {
    endpoint: string;
    auth?: any;
    policy?: { policy_definition_id: string };
    response_policy?: { policy_definition_id: string };
    payment_policy?: any;
    networking?: any;
    /**
     * Frontend-facing identity definition. The API client translates this
     * to/from the backend's `identity_injection` shape on every request —
     * the wire format and the UI model are intentionally decoupled so they
     * can evolve independently.
     */
    agent_identity?: {
      type?: 'from_payload' | 'from_api_key' | 'from_mtls' | 'static';
      api_key_id?: string;
      certificate_id?: string;
      static_did?: string;
      meta_field?: string;
      fields?: string[];
      json_schema?: any;
    };
  };
  /**
   * Opaque dashboard-owned blob persisting canvas layout (positions,
   * decorative NPC/human/caller nodes). The backend stores it verbatim;
   * the runtime never reads it.
   */
  canvas?: any;
  /**
   * When true, the dashboard runs Auto Layout the first time the surface opens
   * in the visual builder (then clears the flag on the next save). Set on a
   * machine-generated surface that has no hand-authored canvas layout. The
   * runtime never reads it.
   */
  auto_canvas?: boolean;
  last_activity?: string | null;
}

// ---------------------------------------------------------------------------
// Surface translation layer
// ---------------------------------------------------------------------------
// The frontend models the identity element as `target.agent_identity` with a
// `type` discriminator. The backend persists `target.identity_injection`
// (currently `{ inject_vp }` plus extra fields it ignores). These helpers are
// the single chokepoint that bridges the two shapes so the UI never leaks
// backend-specific names and the backend can evolve without churning the UI.

function toBackendSurface(surface: Partial<AgentSurface>): any {
  if (!surface || !surface.target) return surface;
  const target: any = { ...surface.target };
  const ai: any = (target as any).agent_identity;
  if (ai && typeof ai === 'object') {
    delete target.agent_identity;
    target.identity_injection = {
      // VP injection is not yet a first-class element in the UI; keep it on
      // by default so the backend continues to inject a presentation when
      // identity is configured. Once a dedicated VP element exists this
      // hardcoded flag should become a real frontend field.
      inject_vp: true,
      ...ai,
    };
  }
  return { ...surface, target };
}

function fromBackendSurface(surface: AgentSurface): AgentSurface {
  if (!surface || !surface.target) return surface;
  const target: any = { ...surface.target };
  const ii: any = (target as any).identity_injection;
  if (ii && typeof ii === 'object') {
    const { inject_vp, ...rest } = ii;
    void inject_vp;
    delete target.identity_injection;
    if (Object.keys(rest).length > 0) {
      target.agent_identity = rest;
    }
  }
  return { ...surface, target };
}
