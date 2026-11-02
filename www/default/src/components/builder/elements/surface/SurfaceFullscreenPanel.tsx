import React from 'react';
import { Form } from 'react-bootstrap';
import type { ConfigPanelProps } from '../types';
import { useOptionalSurfaceMeta } from '../../SurfaceMetaContext';
import {
  CacheControls,
  CanaryControls,
  GovernanceRecordingControls,
  SurfaceUsageLimitControls,
  TeamAttributionControls,
  UsageAlertsControls,
  VpEvidenceControls,
} from './SurfacePanel';

/**
 * One titled sub-section inside the surface configuration card. Uses the same
 * `font-weight-bold text-primary` heading treatment as the builder's card
 * titles (legible in both light and dark themes via the shared dark-theme
 * `.text-primary` override), an icon, then the control body — so the surface
 * editor reads like the rest of the site's full-page editors.
 */
const Sub: React.FC<{ title: string; icon: string; children: React.ReactNode }> = ({
  title,
  icon,
  children,
}) => (
  <>
    <h6 className="font-weight-bold text-primary mb-3" style={{ fontSize: '13px' }}>
      <i className={`fas ${icon} me-2`} />
      {title}
    </h6>
    {children}
  </>
);

/** Canonical order of the client API formats (ingress skins) a surface answers. */
const ALL_INGRESS_FORMATS = ['openai_chat', 'anthropic_messages', 'openai_responses'];
const INGRESS_FORMAT_OPTIONS: Array<{ value: string; label: string }> = [
  { value: 'openai_chat', label: 'OpenAI Chat Completions ( /v1/chat/completions )' },
  { value: 'anthropic_messages', label: 'Anthropic Messages ( /v1/messages )' },
  { value: 'openai_responses', label: 'OpenAI Responses ( /v1/responses )' },
];

/**
 * Full-page editor for an LLM Surface's management controls. Moves the dense
 * cluster of surface-level configuration off the cramped property sidebar and
 * into a roomy full-page view laid out like the Decider configuration editor.
 * Reads/writes the same page-level meta via {@link useOptionalSurfaceMeta} the
 * sidebar summaries read, so edits here and the sidebar stay in lock-step.
 */
const SurfaceFullscreenPanel: React.FC<ConfigPanelProps> = ({ closeFullscreenEditor }) => {
  const meta = useOptionalSurfaceMeta();

  if (!meta || meta.variant !== 'pipe') {
    return (
      <div className="text-muted small p-3">No surface settings available in this context.</div>
    );
  }

  const disabled = meta.readOnly;

  return (
    <div className="surface-config-fullscreen">
      <div className="card shadow-sm mb-4">
        <div className="card-header bg-light d-flex justify-content-between align-items-center">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-sliders me-2" />
            Surface Configuration
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
          {meta.setSurfaceUsageLimit && (
            <Sub title="Surface-wide usage limit" icon="fa-gauge-high">
              {meta.hasSecondaryStages === false && (
                <div className="alert alert-info py-2 mb-3" style={{ fontSize: '12px' }}>
                  <i className="fas fa-info-circle me-1" /> Surface-wide usage limit is not
                  applicable since there is only one LLM in use in this surface — set the limit on
                  the LLM directly. Add a Judge, Jury, or Decider and this control will meter spend
                  across every stage.
                </div>
              )}
              <SurfaceUsageLimitControls
                value={meta.surfaceUsageLimit ?? null}
                onChange={meta.setSurfaceUsageLimit}
                disabled={disabled || meta.hasSecondaryStages === false}
              />
            </Sub>
          )}

          {meta.setTeamAttribution && (
            <>
              <hr className="my-4" />
              <Sub title="Team usage attribution" icon="fa-users">
                <TeamAttributionControls
                  value={meta.teamAttribution ?? null}
                  onChange={meta.setTeamAttribution}
                  disabled={disabled}
                />
              </Sub>
            </>
          )}

          {meta.setStreamingEnabled && (
            <>
              <hr className="my-4" />
              <Sub title="SSE streaming passthrough" icon="fa-wave-square">
                <div className="alert alert-info py-2 mb-3" style={{ fontSize: '12px' }}>
                  <i className="fas fa-info-circle me-1" /> When a caller requests{' '}
                  <code>"stream": true</code> Agent Stream will send the model's SSE response
                  straight back unbuffered. This would bypass all response-side review
                  (judge/jury/expert witness, response guards), so streaming responses are not
                  supported when those are configured or the base provider is not OpenAI-schema.
                </div>
                <Form.Check
                  type="switch"
                  id="surface-streaming-enabled"
                  label="Allow SSE streaming passthrough"
                  checked={meta.streamingEnabled !== false}
                  disabled={disabled}
                  onChange={e => meta.setStreamingEnabled?.(e.target.checked)}
                />
              </Sub>
            </>
          )}

          {meta.setForwardCallerToken && (
            <>
              <hr className="my-4" />
              <Sub title="Identity pass-through" icon="fa-id-badge">
                <div className="alert alert-info py-2 mb-3" style={{ fontSize: '12px' }}>
                  <i className="fas fa-info-circle me-1" /> Forward the caller's validated inbound
                  bearer token as the outbound <code>Authorization: Bearer</code> credential,
                  instead of this surface's stored API key. Requires <strong>JWT bearer</strong>{' '}
                  source auth so the token is verified first. For Bearer-accepting upstreams
                  (OpenAI-compatible, Azure OpenAI with Entra ID, or another gateway that accepts
                  the same token).
                </div>
                <Form.Check
                  type="switch"
                  id="surface-forward-caller-token"
                  label="Forward caller's token to the provider (identity pass-through)"
                  checked={meta.forwardCallerToken === true}
                  disabled={disabled}
                  onChange={e => meta.setForwardCallerToken?.(e.target.checked)}
                />
              </Sub>
            </>
          )}

          {meta.setAcceptedIngressSchemas && (
            <>
              <hr className="my-4" />
              <Sub title="Client API formats" icon="fa-plug">
                <div className="alert alert-info py-2 mb-3" style={{ fontSize: '12px' }}>
                  <i className="fas fa-info-circle me-1" /> Which client API dialects this surface
                  answers. The format is negotiated per request by path and normalized to the same
                  pipeline, so one surface serves OpenAI and Anthropic clients regardless of the
                  upstream model. Leave all enabled to accept any client; disable one to lock the
                  surface out of that dialect.
                </div>
                {INGRESS_FORMAT_OPTIONS.map(opt => {
                  const current =
                    meta.acceptedIngressSchemas && meta.acceptedIngressSchemas.length
                      ? meta.acceptedIngressSchemas
                      : ALL_INGRESS_FORMATS;
                  const checked = current.includes(opt.value);
                  return (
                    <Form.Check
                      key={opt.value}
                      type="switch"
                      id={`surface-ingress-${opt.value}`}
                      label={opt.label}
                      checked={checked}
                      disabled={disabled}
                      onChange={e => {
                        const next = e.target.checked
                          ? Array.from(new Set([...current, opt.value]))
                          : current.filter(v => v !== opt.value);
                        next.sort(
                          (a, b) => ALL_INGRESS_FORMATS.indexOf(a) - ALL_INGRESS_FORMATS.indexOf(b)
                        );
                        meta.setAcceptedIngressSchemas?.(next);
                      }}
                    />
                  );
                })}
              </Sub>
            </>
          )}

          {meta.setCache && (
            <>
              <hr className="my-4" />
              <Sub title="Response cache" icon="fa-database">
                <CacheControls
                  value={meta.cache ?? null}
                  onChange={meta.setCache}
                  disabled={disabled}
                />
              </Sub>
            </>
          )}

          {meta.setCanary && (
            <>
              <hr className="my-4" />
              <Sub title="Canary / A-B traffic split" icon="fa-code-branch">
                <CanaryControls
                  value={meta.canary ?? null}
                  variantAliases={meta.variantAliases ?? []}
                  onChange={meta.setCanary}
                  disabled={disabled}
                />
              </Sub>
            </>
          )}

          {meta.setUsageAlerts && (
            <>
              <hr className="my-4" />
              <Sub title="Breach & anomaly alerts" icon="fa-bell">
                <UsageAlertsControls
                  value={meta.usageAlerts ?? []}
                  enabled={meta.usageAlertsEnabled === true}
                  onEnabledChange={v => meta.setUsageAlertsEnabled?.(v)}
                  onChange={meta.setUsageAlerts}
                  disabled={disabled}
                />
              </Sub>
            </>
          )}

          {meta.setGovernanceRecording && (
            <>
              <hr className="my-4" />
              <Sub title="Governance recording" icon="fa-file-shield">
                <GovernanceRecordingControls
                  value={meta.governanceRecording ?? null}
                  onChange={meta.setGovernanceRecording}
                  disabled={disabled}
                />
              </Sub>
            </>
          )}

          {meta.setVpEvidence && (
            <>
              <hr className="my-4" />
              <Sub title="VP evidence" icon="fa-id-badge">
                <VpEvidenceControls
                  value={meta.vpEvidence ?? null}
                  onChange={meta.setVpEvidence}
                  disabled={disabled}
                />
              </Sub>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default SurfaceFullscreenPanel;
