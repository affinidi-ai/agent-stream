import { integrationIntegration } from '../../components/connection-points/IntegrationsStep';
import { buildCanvasBlob } from '../../components/builder/elements';
import type { CanvasNode } from '../../components/builder/SurfaceCanvas';
import {
  composeIdeRoute,
  readIdeClientAuth,
  readIdeMembers,
  readIdeOpaPolicy,
  readIdeRateLimit,
  readIdeSource,
  readIdeSourceAuth,
} from '../../components/builder/elements/ide/ideNodesFromConfig';

export interface ComposeIdePayloadArgs {
  /** Surface id (existing pipe id, or a freshly minted UUID for a new surface). */
  id: string;
  /** Canvas nodes — the source of truth for members, source routing, governance. */
  nodes: CanvasNode[];
  /** Current canvas surface size, if known. */
  surfaceSize?: { w: number; h: number } | null;
  /** Current canvas viewport, if known. */
  view?: { x: number; y: number; k: number } | null;
  /** Current hide-disabled toolbar toggle state, if known. */
  settings?: { hide_disabled: boolean } | null;
  name: string;
  description: string;
  enabled: boolean;
  integrations: integrationIntegration[];
  createdAt: string;
}

/**
 * Build the IDE-surface wire payload from the live canvas + page state. The
 * single source of truth for the save request and the Config tab's live
 * display, so the JSON a user copies from the Config tab is byte-for-byte what
 * gets persisted. Reads members / source routing / client sign-in / governance
 * straight off the canvas via the shared `readIde*` helpers.
 */
export function composeIdePayload(args: ComposeIdePayloadArgs): Record<string, unknown> {
  const {
    id,
    nodes,
    surfaceSize,
    view,
    settings,
    name,
    description,
    enabled,
    integrations,
    createdAt,
  } = args;
  const members = readIdeMembers(nodes);
  const src = readIdeSource(nodes);
  const clientAuth = readIdeClientAuth(nodes);
  const opa = readIdeOpaPolicy(nodes);
  const rl = readIdeRateLimit(nodes);
  const sourceAuth = readIdeSourceAuth(nodes, id);
  const route = composeIdeRoute(src.prefix, src.custom_path);
  const canvas = buildCanvasBlob(nodes as Parameters<typeof buildCanvasBlob>[0], {
    surfaceSize: surfaceSize ? { width: surfaceSize.w, height: surfaceSize.h } : undefined,
    view: view ?? undefined,
    settings: settings ?? undefined,
  });

  return {
    id,
    name: name.trim(),
    description: description.trim() || undefined,
    status: enabled ? 'enabled' : 'disabled',
    listen_address: src.listen_address || undefined,
    route: route || undefined,
    pipe_type: {
      type: 'ide_catalog',
      config: {
        members: members.map(m => ({
          pipe_id: m.pipe_id,
          variant_alias: m.variant_alias ?? undefined,
          mnemonic: m.mnemonic ?? undefined,
          display_name: m.display_name ?? undefined,
          group: m.group ?? undefined,
          order: m.order,
          default: m.default,
          expose: m.expose,
          metadata: m.metadata ?? undefined,
          upstream_oauth_identifier_id: m.upstream_oauth_identifier_id ?? undefined,
          opa_policy_id: m.opa_policy_id ?? undefined,
          node_id: m.node_id,
        })),
        client_auth: clientAuth.present
          ? {
              provider: clientAuth.provider,
              tenant_id: clientAuth.tenant_id,
              client_id: clientAuth.client_id,
              scopes: clientAuth.scopes,
              oauth_identifier_id: clientAuth.oauth_identifier_id || undefined,
            }
          : undefined,
      },
    },
    opa_policy: opa.present
      ? {
          enabled: opa.enabled,
          policy_definition_id: opa.policy_definition_id,
          log_decisions: opa.log_decisions,
        }
      : undefined,
    rate_limit: rl.present
      ? {
          enabled: rl.enabled,
          requests_per_minute: rl.requests_per_minute,
          tokens_per_minute: rl.tokens_per_minute,
        }
      : undefined,
    source_auth: sourceAuth ?? undefined,
    integrations: integrations.length > 0 ? integrations : undefined,
    canvas,
    created_at: createdAt,
  };
}
