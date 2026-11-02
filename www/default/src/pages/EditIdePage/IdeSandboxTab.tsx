import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { apiClient } from '../../api';
import type { CanvasNode } from '../../components/builder/SurfaceCanvas';
import { RouteListenerBanner } from '../../components/builder/elements/_shared/RouteListenerSection';
import {
  composeIdeRoute,
  readIdeClientAuth,
  readIdeSource,
} from '../../components/builder/elements/ide/ideNodesFromConfig';
import { showToast } from '../../utils/toaster';

/** Routing + presentation extension attached to each published model entry. */
interface IdeModelEntryExt {
  route: string;
  surface_id: string;
  variant_alias?: string;
  display_name: string;
  group?: string;
  order?: number;
  default?: boolean;
  model?: string;
  provider?: string;
  max_input_tokens?: number;
  max_output_tokens?: number;
  capabilities?: string[];
  description?: string;
  sunset_at?: string;
}

interface IdeModelEntry {
  id: string;
  object: string;
  created: number;
  owned_by: string;
  agent_stream: IdeModelEntryExt;
}

interface IdeModelsResponse {
  object: string;
  data: IdeModelEntry[];
  catalog_version?: string;
}

interface IdeClientAuth {
  provider: string;
  tenant_id?: string;
  client_id?: string;
  scopes?: string[];
}

interface IdeBootstrapResponse {
  auth: IdeClientAuth;
  models_path: string;
  chat_path: string;
}

/** Admin view of the public `.well-known/agent-stream` bootstrap document. */
interface IdeBootstrapPreview {
  published: boolean;
  well_known_path: string;
  bootstrap: IdeBootstrapResponse | null;
}

interface IdeSandboxTabProps {
  pipeId: string;
  /** Access Point route derived from the current (possibly unsaved) source. */
  route?: string;
  /**
   * Live canvas nodes — used to reflect **unsaved** client sign-in edits in
   * the Client bootstrap card so the sandbox visibly tracks the current
   * setting rather than only the last saved config.
   */
  nodes?: CanvasNode[];
  /** Whether the surface has unsaved changes. */
  isModified?: boolean;
}

/**
 * Sandbox for an IDE surface: shows the exact `/v1/models` catalogue an IDE
 * client (e.g. the VS Code extension) receives from this surface's Access
 * Point, and lets the operator test which member surface a given model string
 * resolves to. The preview reflects the **saved** config without per-caller
 * gates, so a real caller may see a subset.
 */
const IdeSandboxTab: React.FC<IdeSandboxTabProps> = ({
  pipeId,
  route,
  nodes,
  isModified = false,
}) => {
  const [preview, setPreview] = useState<IdeModelsResponse | null>(null);
  const [bootstrap, setBootstrap] = useState<IdeBootstrapPreview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [probe, setProbe] = useState('');

  // Whether the *live* canvas has client sign-in configured. The saved backend
  // bootstrap only refreshes on Save + tab remount, so this drives the Client
  // bootstrap card so the sandbox visibly tracks the current setting instead
  // of showing stale metadata after the operator removes client sign-in.
  const livePresent = useMemo(() => (nodes ? readIdeClientAuth(nodes).present : null), [nodes]);
  const savedPublished = bootstrap?.published === true;
  const stateMatches = livePresent === null || livePresent === savedPublished;

  // Full Access Point URL (listen_address + prefix + custom_path) derived
  // from the live canvas, so the endpoint banners below match what the user
  // is looking at right now — not the last saved route.
  const accessPointFullUrl = useMemo(() => {
    if (!nodes) return '';
    const src = readIdeSource(nodes);
    const routePath = composeIdeRoute(src.prefix, src.custom_path);
    return src.listen_address && routePath ? `${src.listen_address}${routePath}` : '';
  }, [nodes]);
  const modelsUrl = accessPointFullUrl ? `${accessPointFullUrl}/v1/models` : '';
  const bootstrapUrl = accessPointFullUrl ? `${accessPointFullUrl}/.well-known/agent-stream` : '';

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [previewRes, bootstrapRes] = await Promise.all([
        apiClient.fetch(`/api/v1/pipes/${pipeId}/ide-catalog/preview`),
        apiClient.fetch(`/api/v1/pipes/${pipeId}/ide-catalog/bootstrap`),
      ]);
      if (!previewRes.ok) {
        const body = await previewRes.json().catch(() => ({}));
        throw new Error(body.error || previewRes.statusText);
      }
      setPreview((await previewRes.json()) as IdeModelsResponse);
      setBootstrap(bootstrapRes.ok ? ((await bootstrapRes.json()) as IdeBootstrapPreview) : null);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load catalogue preview');
      setPreview(null);
      setBootstrap(null);
    } finally {
      setLoading(false);
    }
  }, [pipeId]);

  useEffect(() => {
    void load();
  }, [load]);

  const entries = useMemo(() => preview?.data ?? [], [preview]);

  const match = useMemo(() => {
    const key = probe.trim();
    if (!key) return null;
    return entries.find(e => e.id === key) ?? null;
  }, [probe, entries]);

  const copyJson = useCallback(() => {
    if (!preview) return;
    void navigator.clipboard
      .writeText(JSON.stringify(preview, null, 2))
      .then(() => showToast('success', 'Catalogue JSON copied'))
      .catch(() => showToast('error', 'Failed to copy'));
  }, [preview]);

  const copyBootstrap = useCallback(() => {
    if (!bootstrap?.bootstrap) return;
    void navigator.clipboard
      .writeText(JSON.stringify(bootstrap.bootstrap, null, 2))
      .then(() => showToast('success', 'Bootstrap JSON copied'))
      .catch(() => showToast('error', 'Failed to copy'));
  }, [bootstrap]);

  return (
    <div className="card shadow-sm mb-0 surface-fullpage-panel">
      <div className="card-header d-flex align-items-center justify-content-between">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-flask me-2" />
          Sandbox
        </h6>
        <button
          className="btn btn-sm btn-outline-secondary"
          onClick={() => void load()}
          title="Reload catalogue preview"
        >
          <i className="fas fa-rotate me-1" /> Refresh
        </button>
      </div>
      <div className="card-body surface-fullpage-panel__body p-0">
        <div className="ide-sandbox-tab">
          {livePresent === false ? (
            <div
              className="alert alert-warning mb-3 d-flex align-items-center"
              style={{ fontSize: '13px' }}
            >
              <i className="fas fa-info-circle me-2" />
              <strong className="me-2">Client bootstrap endpoint:</strong>
              <span className="badge bg-warning text-dark">Will not publish</span>
            </div>
          ) : accessPointFullUrl ? (
            <div className="alert alert-success mb-3" style={{ fontSize: '13px' }}>
              <i className="fas fa-info-circle me-2" />
              <strong>Client bootstrap endpoint:</strong> {bootstrapUrl}
              <button
                type="button"
                className="btn btn-xs ms-2"
                style={{ padding: '2px 6px', fontSize: '11px', outline: 'none' }}
                onClick={e => {
                  navigator.clipboard.writeText(bootstrapUrl);
                  const btn = e.currentTarget as HTMLButtonElement;
                  const originalHtml = btn.innerHTML;
                  btn.innerHTML = '<i class="fas fa-check"></i>';
                  setTimeout(() => {
                    btn.innerHTML = originalHtml;
                  }, 2000);
                }}
                title="Copy to clipboard"
              >
                <i className="fas fa-copy" />
              </button>
              <a
                href={bootstrapUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="btn btn-xs ms-1"
                style={{ padding: '2px 6px', fontSize: '11px', outline: 'none' }}
                title="Open bootstrap endpoint in a new tab"
              >
                <i className="fas fa-external-link-alt" />
              </a>
            </div>
          ) : null}

          {loading && (
            <div className="text-muted py-4 text-center">
              <i className="fas fa-spinner fa-spin me-2" /> Loading catalogue…
            </div>
          )}

          {!loading && error && (
            <div className="alert alert-danger" role="alert">
              <i className="fas fa-triangle-exclamation me-2" />
              {error}
            </div>
          )}

          {!loading && !error && (
            <>
              {livePresent !== false && (
                <div className="card mb-3">
                  <div className="card-body">
                    <div className="d-flex justify-content-between align-items-center mb-1">
                      <label className="form-label small fw-semibold mb-0">
                        Client bootstrap
                        {livePresent !== null && (
                          <span
                            className={`badge ms-2 ${livePresent ? 'bg-success' : 'bg-secondary'}`}
                          >
                            {livePresent ? 'Will publish' : 'Will not publish'}
                          </span>
                        )}
                      </label>
                      {livePresent === true && stateMatches && bootstrap?.bootstrap && (
                        <button
                          className="btn btn-sm btn-outline-secondary"
                          onClick={copyBootstrap}
                        >
                          <i className="fas fa-copy me-1" /> Copy
                        </button>
                      )}
                    </div>
                    {!stateMatches && (
                      <div className="alert alert-info small mb-2" role="alert">
                        <i className="fas fa-circle-info me-2" />
                        {livePresent
                          ? 'Unsaved edit: client sign-in has been added. Save the surface to publish this bootstrap; the live endpoint currently returns 404.'
                          : 'Unsaved edit: client sign-in has been removed. Save the surface to unpublish; the live endpoint currently still serves the metadata shown below.'}
                      </div>
                    )}
                    {stateMatches && isModified && livePresent === true && savedPublished && (
                      <div className="alert alert-info small mb-2" role="alert">
                        <i className="fas fa-circle-info me-2" />
                        Unsaved edits to client sign-in are not reflected below. Save the surface to
                        update the published bootstrap.
                      </div>
                    )}
                    {savedPublished && bootstrap?.bootstrap ? (
                      <pre
                        className="border rounded bg-light p-2 small mb-0"
                        style={{ maxHeight: 280, overflow: 'auto' }}
                      >
                        {JSON.stringify(bootstrap.bootstrap, null, 2)}
                      </pre>
                    ) : (
                      <div className="alert alert-warning small mb-0" role="alert">
                        <i className="fas fa-triangle-exclamation me-2" />
                        No bootstrap published yet — save the surface to publish.
                      </div>
                    )}
                  </div>
                </div>
              )}

              <div className="card mb-3">
                <div className="card-body">
                  <label className="form-label small fw-semibold mb-1">Resolve a model</label>
                  <p className="text-muted small mb-2">
                    Enter a model id (mnemonic or <code>{'{pipe_id}[$alias]'}</code>) an IDE client
                    would send. This is how dispatch selects a member surface.
                  </p>
                  <input
                    className="form-control form-control-sm mb-2"
                    placeholder="e.g. gpt-4o or 1a2b3c$fast"
                    value={probe}
                    onChange={e => setProbe(e.target.value)}
                  />
                  {probe.trim() && !match && (
                    <div className="text-danger small">
                      <i className="fas fa-xmark me-1" />
                      No match — a real request would 404 (or the model is filtered for the caller).
                    </div>
                  )}
                  {match && (
                    <div className="small">
                      <span className="badge bg-success me-2">Resolves</span>
                      <code>{match.id}</code> → <strong>{match.agent_stream.display_name}</strong>
                      <div className="text-muted mt-1">
                        surface <code>{match.agent_stream.surface_id}</code>
                        {match.agent_stream.variant_alias && (
                          <>
                            {' '}
                            · variant <code>{match.agent_stream.variant_alias}</code>
                          </>
                        )}
                        {match.agent_stream.model && (
                          <>
                            {' '}
                            · model <code>{match.agent_stream.model}</code>
                          </>
                        )}
                        {match.agent_stream.provider && (
                          <>
                            {' '}
                            · provider <code>{match.agent_stream.provider}</code>
                          </>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              <div className="mb-3">
                <div className="d-flex justify-content-between align-items-center mb-1">
                  <span className="fw-semibold small">
                    Published models <span className="text-muted">({entries.length})</span>
                  </span>
                </div>
                {entries.length === 0 ? (
                  <div className="text-muted small">
                    No models published. Add exposed, enabled LLM members to this surface.
                  </div>
                ) : (
                  <div className="table-responsive">
                    <table className="table table-sm align-middle mb-0">
                      <thead>
                        <tr>
                          <th>Model id</th>
                          <th>Display name</th>
                          <th>Surface</th>
                          <th>Variant</th>
                          <th>Upstream model</th>
                          <th>Provider</th>
                        </tr>
                      </thead>
                      <tbody>
                        {entries.map(e => (
                          <tr key={e.id}>
                            <td>
                              <code>{e.id}</code>
                              {e.agent_stream.default && (
                                <span className="badge bg-primary ms-2">default</span>
                              )}
                            </td>
                            <td>{e.agent_stream.display_name}</td>
                            <td>
                              <code>{e.agent_stream.surface_id}</code>
                            </td>
                            <td>
                              {e.agent_stream.variant_alias ? (
                                <code>{e.agent_stream.variant_alias}</code>
                              ) : (
                                <span className="text-muted">—</span>
                              )}
                            </td>
                            <td>
                              {e.agent_stream.model ? (
                                <code>{e.agent_stream.model}</code>
                              ) : (
                                <span className="text-muted">—</span>
                              )}
                            </td>
                            <td>
                              {e.agent_stream.provider ?? <span className="text-muted">—</span>}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              <div>
                <div className="d-flex justify-content-between align-items-center mb-1">
                  <span className="fw-semibold small">Raw catalogue JSON</span>
                  <button className="btn btn-sm btn-outline-secondary" onClick={copyJson}>
                    <i className="fas fa-copy me-1" /> Copy
                  </button>
                </div>
                <pre
                  className="border rounded bg-light p-2 small mb-0"
                  style={{ maxHeight: 360, overflow: 'auto' }}
                >
                  {JSON.stringify(preview, null, 2)}
                </pre>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default IdeSandboxTab;
