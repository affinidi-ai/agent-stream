/**
 * Pure `SourceAuthConfig` ↔ caller-auth-node round-trip helpers, shared by
 * every scope that surfaces `source_auth` as a canvas element (IDE Surface,
 * LLM Surface). Both scopes edit the flat node config through the same
 * `CallerAuthPanel` / `CallerAuthFullscreen`, so both need the same wire
 * translation. This module is the single source of truth for that mapping.
 *
 * Mirrors `configFromPayload` / `buildPayload` in
 * `caller-auth/definition.ts` (the agent-surface scope) but without the
 * `access_point.caller_authentication.methods[0]` wrapper — a pipe/IDE
 * surface stores `source_auth` as a single discriminated union on the
 * surface root, not as a list under an access-point sub-object.
 */

import type { SourceAuthConfig } from '../../../../types';
import type { CanvasNode } from '../../SurfaceCanvas';

const str = (v: unknown) => (typeof v === 'string' ? v : '');

/** True when a JWT-bearer node names an audience or opts out of `aud` validation. */
export function jwtAudienceSet(c: Record<string, any>): boolean {
  return (
    (Array.isArray(c.audiences) && c.audiences.length > 0) || c.jwt_allow_missing_audience === true
  );
}

/** Why a caller-auth node cannot be saved yet, or `null` when it can. */
export function callerAuthIncompleteReason(c: Record<string, any> | undefined): string | null {
  if (!c?.method_type) return 'Authentication method must be selected';
  if (c.method_type === 'jwt_bearer' && !c.jwt_strategy_id) return 'JWT strategy must be selected';
  if (c.method_type === 'jwt_bearer' && !jwtAudienceSet(c))
    return 'At least one accepted audience is required';
  if (c.method_type === 'api_key' && !c.api_key_secret_id) return 'API key secret must be selected';
  if (c.method_type === 'mtls' && !c.mtls_certificate_id)
    return 'mTLS certificate must be selected';
  return null;
}

/**
 * Translate the wire `source_auth` object into the flat config the caller-auth
 * panel edits. Returns `null` for an unrecognisable shape so the caller can
 * skip seeding the node entirely.
 */
export function flattenSourceAuth(sa: SourceAuthConfig): Record<string, unknown> | null {
  const m = sa as Record<string, unknown>;
  const type = str(m.type);
  if (!type) return null;
  const out: Record<string, unknown> = { method_type: type };
  const extraction = m.extraction as { source?: string; field?: string } | undefined;
  if (extraction) {
    if (extraction.source) out.extraction_source = extraction.source;
    if (extraction.field) out.extraction_field = extraction.field;
  }
  if (type === 'jwt_bearer') {
    if (typeof m.jwt_verification_strategy_id === 'string')
      out.jwt_strategy_id = m.jwt_verification_strategy_id;
    if (Array.isArray(m.audiences)) out.audiences = m.audiences;
    out.jwt_allow_missing_audience = m.allow_missing_audience === true;
    out.jwt_token_header = typeof m.token_header === 'string' ? m.token_header : 'Authorization';
    out.jwt_token_scheme = typeof m.token_scheme === 'string' ? m.token_scheme : 'Bearer';
  }
  if (type === 'api_key' && typeof m.secret_id === 'string') {
    out.api_key_secret_id = m.secret_id;
  }
  if (type === 'mtls') {
    const trust = m.trust as { type?: string; certificate_ids?: unknown } | undefined;
    const ids =
      trust?.type === 'pinned' && Array.isArray(trust.certificate_ids)
        ? (trust.certificate_ids as unknown[])
        : [];
    if (ids.length > 0 && typeof ids[0] === 'string') out.mtls_certificate_id = ids[0];
  }
  return out;
}

/**
 * Read the flat caller-auth node config back into the wire `SourceAuthConfig`.
 * Returns `null` when the config is incomplete (e.g. JWT bearer with no
 * strategy selected) — the caller should then persist the surface without
 * `source_auth` so the element renders as incomplete on the canvas and the
 * surface stays open until it is configured.
 *
 * `surfaceId` is required by `api_key_provider` (which addresses the API-key
 * provider by the surface's own id) and unused by every other method.
 */
export function readSourceAuthFromNode(
  node: CanvasNode | undefined,
  surfaceId?: string
): SourceAuthConfig | null {
  if (!node) return null;
  const c = (node.config ?? {}) as Record<string, unknown>;
  const method = str(c.method_type);
  if (!method) return null;

  const extraction = {
    source: str(c.extraction_source) || 'http_header',
    ...(str(c.extraction_source) === 'http_header' || !str(c.extraction_source)
      ? { field: str(c.extraction_field) || 'Authorization' }
      : {}),
  } as { source: string; field?: string };

  switch (method) {
    case 'jwt_bearer': {
      const strategyId = str(c.jwt_strategy_id).trim();
      if (!strategyId) return null;
      const auds = Array.isArray(c.audiences) ? (c.audiences as unknown[]).map(a => String(a)) : [];
      return {
        type: 'jwt_bearer',
        jwt_verification_strategy_id: strategyId,
        audiences: auds,
        // Only meaningful with an empty list, and omitted otherwise so the
        // saved shape is unchanged unless the operator opted in.
        ...(auds.length === 0 && c.jwt_allow_missing_audience === true
          ? { allow_missing_audience: true }
          : {}),
        token_header: str(c.jwt_token_header).trim() || 'Authorization',
        token_scheme: (str(c.jwt_token_scheme) || 'Bearer').trim(),
      } as SourceAuthConfig;
    }
    case 'api_key': {
      const secretId = str(c.api_key_secret_id).trim();
      if (!secretId) return null;
      return {
        type: 'api_key',
        extraction: extraction as SourceAuthConfig extends { extraction: infer X } ? X : never,
        secret_id: secretId,
      } as unknown as SourceAuthConfig;
    }
    case 'api_key_provider': {
      const agentId = (surfaceId ?? '').trim();
      if (!agentId) return null;
      return {
        type: 'api_key_provider',
        extraction: extraction as SourceAuthConfig extends { extraction: infer X } ? X : never,
        agent_id: agentId,
      } as unknown as SourceAuthConfig;
    }
    case 'mtls': {
      const certId = str(c.mtls_certificate_id).trim();
      if (!certId) return null;
      return {
        type: 'mtls',
        trust: { type: 'pinned', certificate_ids: [certId] },
        identity_binding: { type: 'fingerprint' },
        allowed_subjects: [],
        allow_forwarded: true,
      } as SourceAuthConfig;
    }
    default:
      return null;
  }
}
