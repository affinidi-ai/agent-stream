import {
  nodesFromIde,
  type IdeConfigLike,
} from '../../../components/builder/elements/ide/ideNodesFromConfig';
import type { IdeRoutingConfig } from '../../../components/builder/elements/ide/idePanelData';
import { composeIdePayload } from '../idePayload';

const routing: IdeRoutingConfig = {
  availableListenAddresses: ['0.0.0.0:9000'],
  pathPrefixes: [{ id: 'ide', name: 'IDE', prefix: '/ide' }],
};

const sourceConfig: IdeConfigLike = {
  id: 'surf-1',
  name: 'Palette',
  description: 'central catalogue',
  listen_address: '0.0.0.0:9000',
  route: '/ide/team-palette',
  pipe_type: {
    type: 'ide_catalog',
    config: {
      members: [
        {
          pipe_id: 'llm-openai',
          mnemonic: 'fast',
          display_name: 'Fast',
          order: 0,
          default: true,
          expose: true,
        },
      ],
      client_auth: {
        provider: 'entra',
        tenant_id: 'tenant-abc',
        client_id: 'client-xyz',
        scopes: ['api://x/.default'],
      },
    },
  },
};

describe('composeIdePayload', () => {
  it('rebuilds the wire payload from the canvas, importing page name/description/status/id', () => {
    const nodes = nodesFromIde(sourceConfig, routing);
    const payload = composeIdePayload({
      id: 'surf-1',
      nodes,
      surfaceSize: { w: 840, h: 300 },
      view: null,
      name: 'Palette',
      description: 'central catalogue',
      enabled: true,
      integrations: [],
      createdAt: '2026-07-20T00:00:00.000Z',
    });

    expect(payload.id).toBe('surf-1');
    expect(payload.name).toBe('Palette');
    expect(payload.description).toBe('central catalogue');
    expect(payload.status).toBe('enabled');
    expect(payload.listen_address).toBe('0.0.0.0:9000');
    expect(payload.route).toBe('/ide/team-palette');
    expect(payload.created_at).toBe('2026-07-20T00:00:00.000Z');

    const pipeType = payload.pipe_type as {
      type: string;
      config: { members: Array<{ pipe_id: string; mnemonic?: string }>; client_auth?: unknown };
    };
    expect(pipeType.type).toBe('ide_catalog');
    expect(pipeType.config.members).toHaveLength(1);
    expect(pipeType.config.members[0].pipe_id).toBe('llm-openai');
    expect(pipeType.config.members[0].mnemonic).toBe('fast');
    expect(pipeType.config.client_auth).toEqual({
      provider: 'entra',
      tenant_id: 'tenant-abc',
      client_id: 'client-xyz',
      scopes: ['api://x/.default'],
    });
  });

  it('serialises a disabled surface as status "disabled" and omits an empty description', () => {
    const nodes = nodesFromIde({ ...sourceConfig, description: undefined }, routing);
    const payload = composeIdePayload({
      id: 'surf-1',
      nodes,
      surfaceSize: null,
      view: null,
      name: 'Palette',
      description: '   ',
      enabled: false,
      integrations: [],
      createdAt: '2026-07-20T00:00:00.000Z',
    });

    expect(payload.status).toBe('disabled');
    expect(payload.description).toBeUndefined();
  });

  it('includes source_auth when a caller-context node is present on the canvas', () => {
    const withAuth: IdeConfigLike = {
      ...sourceConfig,
      source_auth: {
        type: 'jwt_bearer',
        jwt_verification_strategy_id: 'strat-1',
        audiences: ['api://ide'],
        token_header: 'Authorization',
        token_scheme: 'Bearer',
      },
    };
    const nodes = nodesFromIde(withAuth, routing);
    const payload = composeIdePayload({
      id: 'surf-1',
      nodes,
      surfaceSize: null,
      view: null,
      name: 'Palette',
      description: 'central catalogue',
      enabled: true,
      integrations: [],
      createdAt: '2026-07-20T00:00:00.000Z',
    });
    expect(payload.source_auth).toEqual({
      type: 'jwt_bearer',
      jwt_verification_strategy_id: 'strat-1',
      audiences: ['api://ide'],
      token_header: 'Authorization',
      token_scheme: 'Bearer',
    });
  });

  it('omits source_auth when no caller-context node is present', () => {
    const nodes = nodesFromIde(sourceConfig, routing);
    const payload = composeIdePayload({
      id: 'surf-1',
      nodes,
      surfaceSize: null,
      view: null,
      name: 'Palette',
      description: 'central catalogue',
      enabled: true,
      integrations: [],
      createdAt: '2026-07-20T00:00:00.000Z',
    });
    expect(payload.source_auth).toBeUndefined();
  });
});
