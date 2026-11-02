import {
  nodesFromIde,
  readIdeMembers,
  readIdeSource,
  readIdeClientAuth,
  readIdeOpaPolicy,
  readIdeRateLimit,
  readIdeSourceAuth,
  composeIdeRoute,
  type IdeConfigLike,
} from '../ideNodesFromConfig';
import type { IdeRoutingConfig } from '../idePanelData';
import type { CanvasNode } from '../../../SurfaceCanvas';

const routing: IdeRoutingConfig = {
  availableListenAddresses: ['0.0.0.0:8080'],
  pathPrefixes: [
    { id: 'p1', name: 'API', prefix: 'api' },
    { id: 'p2', name: 'Gateway', prefix: 'gw' },
  ],
};

describe('nodesFromIde spine seeding', () => {
  it('seeds only the source + catalogue + response spine when config is null', () => {
    const nodes = nodesFromIde(null, routing);
    expect(nodes.map(n => n.id)).toEqual(['ide-source', 'ide-catalog', 'ide-response']);
    const source = nodes.find(n => n.id === 'ide-source')!;
    expect(source.configured).toBe(false);
    expect(source.config).toEqual({
      listen_address: '',
      prefix: '',
      custom_path: '',
      client_auth_provider: 'entra',
      client_auth_tenant_id: '',
      client_auth_client_id: '',
      client_auth_scopes: [],
      client_auth_oauth_identifier_id: '',
    });
    expect(nodes.find(n => n.id === 'ide-catalog')?.parentId).toBe('ide-source');
    expect(nodes.find(n => n.id === 'ide-response')?.parentId).toBe('ide-catalog');
    expect(nodes.some(n => n.type === 'ide-opa-policy')).toBe(false);
    expect(nodes.some(n => n.type === 'ide-rate-limit')).toBe(false);
  });

  it('seeds one ide-member node per config member with 1-based ids', () => {
    const config: IdeConfigLike = {
      pipe_type: {
        type: 'ide_catalog',
        config: {
          members: [{ pipe_id: 'p-alpha' }, { pipe_id: 'p-beta', variant_alias: 'fast' }],
        },
      },
    };
    const nodes = nodesFromIde(config, routing);
    const members = nodes.filter(n => n.type === 'ide-member');
    expect(members.map(n => n.id)).toEqual(['ide-member-1', 'ide-member-2']);
    expect(members[0].parentId).toBe('ide-catalog');
    expect(members[0].config).toEqual({
      pipe_id: 'p-alpha',
      variant_alias: '',
      mnemonic: '',
      display_name: '',
      group: '',
      order: 0,
      default: false,
      expose: true,
    });
    expect(members[1].config?.variant_alias).toBe('fast');
  });
});

describe('route decompose / compose round-trip', () => {
  it('decomposes a saved route into prefix + custom_path via readIdeSource', () => {
    const config: IdeConfigLike = { listen_address: '0.0.0.0:8080', route: 'api/ide-catalogue' };
    const source = readIdeSource(nodesFromIde(config, routing));
    expect(source).toEqual({
      listen_address: '0.0.0.0:8080',
      prefix: 'api',
      custom_path: 'ide-catalogue',
    });
  });

  it('marks the source configured only when listen, prefix and path all resolve', () => {
    const config: IdeConfigLike = { listen_address: '0.0.0.0:8080', route: 'api/x' };
    const nodes = nodesFromIde(config, routing);
    expect(nodes.find(n => n.id === 'ide-source')?.configured).toBe(true);
  });

  it('leaves prefix/custom_path blank when the route matches no known prefix', () => {
    const config: IdeConfigLike = { listen_address: '0.0.0.0:8080', route: 'unknown/x' };
    const source = readIdeSource(nodesFromIde(config, routing));
    expect(source.prefix).toBe('');
    expect(source.custom_path).toBe('');
  });

  it('composes prefix + custom_path back into a full route, stripping a leading slash', () => {
    expect(composeIdeRoute('api', 'ide-foo')).toBe('api/ide-foo');
    expect(composeIdeRoute('api', '/ide-foo')).toBe('api/ide-foo');
  });

  it('composes an empty route when no prefix is chosen', () => {
    expect(composeIdeRoute('', 'ide-foo')).toBe('');
  });

  it('round-trips a route through compose(readIdeSource(...))', () => {
    const config: IdeConfigLike = { listen_address: '0.0.0.0:8080', route: 'gw/team-ide' };
    const source = readIdeSource(nodesFromIde(config, routing));
    expect(composeIdeRoute(source.prefix, source.custom_path)).toBe('gw/team-ide');
  });
});

describe('readIdeMembers', () => {
  it('drops members with a blank pipe_id', () => {
    const config: IdeConfigLike = {
      pipe_type: {
        config: { members: [{ pipe_id: 'keep' }, { pipe_id: '' }, {}] },
      },
    };
    const members = readIdeMembers(nodesFromIde(config, routing));
    expect(members).toHaveLength(1);
    expect(members[0].pipe_id).toBe('keep');
  });

  it('collapses empty optional fields to null (single member is auto-default)', () => {
    const config: IdeConfigLike = {
      pipe_type: { config: { members: [{ pipe_id: 'p1' }] } },
    };
    const members = readIdeMembers(nodesFromIde(config, routing));
    expect(members[0]).toEqual({
      pipe_id: 'p1',
      variant_alias: null,
      mnemonic: null,
      display_name: null,
      group: null,
      order: 0,
      default: true,
      expose: true,
      metadata: null,
      upstream_oauth_identifier_id: null,
      opa_policy_id: null,
      node_id: 'ide-member-1',
    });
  });

  it('preserves populated optional fields and flags', () => {
    const config: IdeConfigLike = {
      pipe_type: {
        config: {
          members: [
            {
              pipe_id: 'p1',
              variant_alias: 'fast',
              display_name: 'Fast model',
              group: 'Speed',
              order: 3,
              default: true,
              expose: false,
            },
          ],
        },
      },
    };
    const members = readIdeMembers(nodesFromIde(config, routing));
    expect(members[0]).toEqual({
      pipe_id: 'p1',
      variant_alias: 'fast',
      mnemonic: null,
      display_name: 'Fast model',
      group: 'Speed',
      order: 3,
      default: true,
      expose: false,
      metadata: null,
      upstream_oauth_identifier_id: null,
      opa_policy_id: null,
      node_id: 'ide-member-1',
    });
  });

  it('sorts by order then node id so the saved list is stable', () => {
    const config: IdeConfigLike = {
      pipe_type: {
        config: {
          members: [
            { pipe_id: 'third', order: 2 },
            { pipe_id: 'first', order: 0 },
            { pipe_id: 'second', order: 1 },
          ],
        },
      },
    };
    const members = readIdeMembers(nodesFromIde(config, routing));
    expect(members.map(m => m.pipe_id)).toEqual(['first', 'second', 'third']);
  });

  it('round-trips a full member list through nodesFromIde -> readIdeMembers', () => {
    const original = [
      {
        pipe_id: 'p-alpha',
        variant_alias: null,
        mnemonic: 'fast-coder',
        display_name: 'Alpha',
        group: null,
        order: 0,
        default: true,
        expose: true,
        metadata: null,
        upstream_oauth_identifier_id: null,
        opa_policy_id: null,
        node_id: 'ide-member-stable-a',
      },
      {
        pipe_id: 'p-beta',
        variant_alias: 'cheap',
        mnemonic: null,
        display_name: null,
        group: 'Budget',
        order: 1,
        default: false,
        expose: false,
        metadata: null,
        upstream_oauth_identifier_id: null,
        opa_policy_id: null,
        node_id: 'ide-member-stable-b',
      },
    ];
    const config: IdeConfigLike = { pipe_type: { config: { members: original } } };
    expect(readIdeMembers(nodesFromIde(config, routing))).toEqual(original);
  });

  it('round-trips the advertised context window (max input/output tokens) metadata', () => {
    const config: IdeConfigLike = {
      pipe_type: {
        config: {
          members: [
            {
              pipe_id: 'p1',
              metadata: { max_input_tokens: 200000, max_output_tokens: 8192 },
            },
          ],
        },
      },
    };
    const nodes = nodesFromIde(config, routing);
    const memberNode = nodes.find(n => n.type === 'ide-member');
    expect(memberNode?.config?.max_input_tokens).toBe(200000);
    expect(memberNode?.config?.max_output_tokens).toBe(8192);
    expect(readIdeMembers(nodes)[0].metadata).toEqual({
      max_input_tokens: 200000,
      max_output_tokens: 8192,
    });
  });

  it('preserves API-authored metadata (description) while editing the context window', () => {
    const config: IdeConfigLike = {
      pipe_type: {
        config: {
          members: [
            {
              pipe_id: 'p1',
              metadata: { description: 'Great for code', capabilities: ['tools'] },
            },
          ],
        },
      },
    };
    const nodes = nodesFromIde(config, routing);
    const memberNode = nodes.find(n => n.type === 'ide-member');
    // Simulate the panel setting a context window on top of preserved metadata.
    memberNode!.config!.max_input_tokens = 128000;
    expect(readIdeMembers(nodes)[0].metadata).toEqual({
      description: 'Great for code',
      capabilities: ['tools'],
      max_input_tokens: 128000,
    });
  });

  it('seeds and reads back the per-member mnemonic (the client-facing model id)', () => {
    const config: IdeConfigLike = {
      pipe_type: {
        config: { members: [{ pipe_id: 'p1', variant_alias: 'fast', mnemonic: 'coder' }] },
      },
    };
    const nodes = nodesFromIde(config, routing);
    expect(nodes.find(n => n.type === 'ide-member')?.config?.mnemonic).toBe('coder');
    expect(readIdeMembers(nodes)[0].mnemonic).toBe('coder');
  });
});

describe('client sign-in (client_auth) round-trip', () => {
  it('reports client sign-in absent when config omits it', () => {
    const auth = readIdeClientAuth(nodesFromIde({}, routing));
    expect(auth).toEqual({
      present: false,
      provider: 'entra',
      tenant_id: '',
      client_id: '',
      scopes: [],
      oauth_identifier_id: '',
    });
  });

  it('seeds and reads back a full Entra client sign-in config', () => {
    const config: IdeConfigLike = {
      pipe_type: {
        config: {
          members: [],
          client_auth: {
            provider: 'entra',
            tenant_id: 'tenant-123',
            client_id: 'client-456',
            scopes: ['api://agent-stream/.default'],
          },
        },
      },
    };
    const auth = readIdeClientAuth(nodesFromIde(config, routing));
    expect(auth).toEqual({
      present: true,
      provider: 'entra',
      tenant_id: 'tenant-123',
      client_id: 'client-456',
      scopes: ['api://agent-stream/.default'],
      oauth_identifier_id: '',
    });
  });

  it('trims blank scope lines and marks present from any single identifier', () => {
    const config: IdeConfigLike = {
      pipe_type: {
        config: {
          members: [],
          client_auth: {
            tenant_id: 'tenant-only',
            scopes: ['  ', 'api://x/scope', ''],
          },
        },
      },
    };
    const auth = readIdeClientAuth(nodesFromIde(config, routing));
    expect(auth.present).toBe(true);
    expect(auth.provider).toBe('entra');
    expect(auth.tenant_id).toBe('tenant-only');
    expect(auth.scopes).toEqual(['api://x/scope']);
  });
});

describe('member gate chip round-trips', () => {
  it('seeds an ide-member-upstream-auth chip from a member upstream ref and reads it back', () => {
    const config: IdeConfigLike = {
      pipe_type: {
        config: {
          members: [{ pipe_id: 'p1', upstream_oauth_identifier_id: 'prof-123' }],
        },
      },
    };
    const nodes = nodesFromIde(config, routing);
    // The ref lives on a docked chip, not on the member's own config.
    const chip = nodes.find(n => n.type === 'ide-member-upstream-auth');
    expect(chip?.parentId).toBe('ide-member-1');
    expect(chip?.config?.upstream_oauth_identifier_id).toBe('prof-123');
    expect(
      nodes.find(n => n.type === 'ide-member')?.config?.upstream_oauth_identifier_id
    ).toBeUndefined();
    expect(readIdeMembers(nodes)[0].upstream_oauth_identifier_id).toBe('prof-123');
  });

  it('seeds an ide-member-opa chip from a member opa_policy_id and reads it back', () => {
    const config: IdeConfigLike = {
      pipe_type: {
        config: {
          members: [{ pipe_id: 'p1', opa_policy_id: 'ide-policy-9' }],
        },
      },
    };
    const nodes = nodesFromIde(config, routing);
    const chip = nodes.find(n => n.type === 'ide-member-opa');
    expect(chip?.parentId).toBe('ide-member-1');
    expect(chip?.config?.policy_definition_id).toBe('ide-policy-9');
    expect(readIdeMembers(nodes)[0].opa_policy_id).toBe('ide-policy-9');
  });

  it('seeds no gate chips for a plain member and collapses refs to null', () => {
    const config: IdeConfigLike = {
      pipe_type: { config: { members: [{ pipe_id: 'p1' }] } },
    };
    const nodes = nodesFromIde(config, routing);
    expect(nodes.some(n => n.type === 'ide-member-upstream-auth')).toBe(false);
    expect(nodes.some(n => n.type === 'ide-member-opa')).toBe(false);
    const member = readIdeMembers(nodes)[0];
    expect(member.upstream_oauth_identifier_id).toBeNull();
    expect(member.opa_policy_id).toBeNull();
  });
});

describe('stable node_id binding (catalogue reorder safety)', () => {
  it('uses the persisted node_id as the member node id (not a positional id)', () => {
    const config: IdeConfigLike = {
      pipe_type: {
        config: { members: [{ pipe_id: 'p1', node_id: 'ide-member-abc' }] },
      },
    };
    const nodes = nodesFromIde(config, routing);
    const member = nodes.find(n => n.type === 'ide-member');
    expect(member?.id).toBe('ide-member-abc');
  });

  it('docks a member gate chip to the member node_id, not the array index', () => {
    const config: IdeConfigLike = {
      pipe_type: {
        config: {
          members: [
            { pipe_id: 'copilot', node_id: 'ide-member-copilot' },
            { pipe_id: 'gpt', node_id: 'ide-member-gpt' },
            {
              pipe_id: 'claude',
              node_id: 'ide-member-claude',
              upstream_oauth_identifier_id: 'prof-graph',
            },
          ],
        },
      },
    };
    const nodes = nodesFromIde(config, routing);
    const chip = nodes.find(n => n.type === 'ide-member-upstream-auth');
    // The chip must dock to claude (its stable node_id), never to whichever
    // member happens to sit at array index 1/2 — the bug this guards against.
    expect(chip?.parentId).toBe('ide-member-claude');
    const claude = readIdeMembers(nodes).find(m => m.pipe_id === 'claude');
    const copilot = readIdeMembers(nodes).find(m => m.pipe_id === 'copilot');
    expect(claude?.upstream_oauth_identifier_id).toBe('prof-graph');
    expect(copilot?.upstream_oauth_identifier_id).toBeNull();
  });

  it('keeps the upstream ref on the right member after a reorder (order swap)', () => {
    // claude (order 2) carries the upstream ref. Re-persist with claude moved to
    // the top of the roster (order 0) — the array is re-sorted by readIdeMembers,
    // but because each member carries a stable node_id, the ref must still land
    // on claude, not on whatever now sits first.
    const config: IdeConfigLike = {
      pipe_type: {
        config: {
          members: [
            { pipe_id: 'copilot', node_id: 'n-copilot', order: 2 },
            { pipe_id: 'gpt', node_id: 'n-gpt', order: 1 },
            {
              pipe_id: 'claude',
              node_id: 'n-claude',
              order: 0,
              upstream_oauth_identifier_id: 'prof-graph',
            },
          ],
        },
      },
    };
    const members = readIdeMembers(nodesFromIde(config, routing));
    // Sorted by order: claude(0), gpt(1), copilot(2).
    expect(members.map(m => m.pipe_id)).toEqual(['claude', 'gpt', 'copilot']);
    expect(members[0].node_id).toBe('n-claude');
    expect(members[0].upstream_oauth_identifier_id).toBe('prof-graph');
    expect(members[2].pipe_id).toBe('copilot');
    expect(members[2].upstream_oauth_identifier_id).toBeNull();
  });
});

describe('front-door governance seeding', () => {
  it('seeds and reads back the OPA policy gate from config', () => {
    const config: IdeConfigLike = {
      opa_policy: { enabled: true, policy_definition_id: 'pol-1', log_decisions: true },
    };
    const opa = readIdeOpaPolicy(nodesFromIde(config, routing));
    expect(opa).toEqual({
      present: true,
      enabled: true,
      policy_definition_id: 'pol-1',
      log_decisions: true,
    });
  });

  it('reports the OPA gate absent when config omits it', () => {
    const opa = readIdeOpaPolicy(nodesFromIde({}, routing));
    expect(opa).toEqual({
      present: false,
      enabled: true,
      policy_definition_id: '',
      log_decisions: false,
    });
  });

  it('seeds and reads back the rate limit from config', () => {
    const config: IdeConfigLike = {
      rate_limit: { enabled: true, requests_per_minute: 120, tokens_per_minute: 50000 },
    };
    const rl = readIdeRateLimit(nodesFromIde(config, routing));
    expect(rl).toEqual({
      present: true,
      enabled: true,
      requests_per_minute: 120,
      tokens_per_minute: 50000,
    });
  });

  it('defaults rate-limit values when the config block is present but sparse', () => {
    const config: IdeConfigLike = { rate_limit: {} };
    const rl = readIdeRateLimit(nodesFromIde(config, routing));
    expect(rl).toEqual({
      present: true,
      enabled: true,
      requests_per_minute: 60,
      tokens_per_minute: 100000,
    });
  });

  it('reports the rate limit absent when config omits it', () => {
    const rl = readIdeRateLimit(nodesFromIde({}, routing));
    expect(rl.present).toBe(false);
  });
});

describe('front-door caller-context (source_auth)', () => {
  it('seeds and reads back a JWT-bearer caller-auth from config', () => {
    const config: IdeConfigLike = {
      source_auth: {
        type: 'jwt_bearer',
        jwt_verification_strategy_id: 'strat-1',
        audiences: ['api://ide'],
        token_header: 'Authorization',
        token_scheme: 'Bearer',
      },
    };
    const nodes = nodesFromIde(config, routing);
    const auth = readIdeSourceAuth(nodes, 'surface-x');
    expect(auth).toEqual({
      type: 'jwt_bearer',
      jwt_verification_strategy_id: 'strat-1',
      audiences: ['api://ide'],
      token_header: 'Authorization',
      token_scheme: 'Bearer',
    });
  });

  it('seeds and reads back an API-key caller-auth from config', () => {
    const config: IdeConfigLike = {
      source_auth: {
        type: 'api_key',
        extraction: { source: 'http_header', field: 'X-API-Key' },
        // secret_id is on the wire but not declared on the ts type
        secret_id: 'sec-1',
      } as unknown as IdeConfigLike['source_auth'],
    };
    const nodes = nodesFromIde(config, routing);
    const auth = readIdeSourceAuth(nodes, 'surface-x') as unknown as Record<string, unknown>;
    expect(auth).toMatchObject({
      type: 'api_key',
      extraction: { source: 'http_header', field: 'X-API-Key' },
      secret_id: 'sec-1',
    });
  });

  it('seeds and reads back an mTLS caller-auth from config', () => {
    const config: IdeConfigLike = {
      source_auth: {
        type: 'mtls',
        trust: { type: 'pinned', certificate_ids: ['cert-1'] },
        identity_binding: { type: 'fingerprint' },
        allowed_subjects: [],
        allow_forwarded: true,
      },
    };
    const nodes = nodesFromIde(config, routing);
    const auth = readIdeSourceAuth(nodes, 'surface-x');
    expect(auth).toEqual({
      type: 'mtls',
      trust: { type: 'pinned', certificate_ids: ['cert-1'] },
      identity_binding: { type: 'fingerprint' },
      allowed_subjects: [],
      allow_forwarded: true,
    });
  });

  it('returns null when no ide-caller-auth node is present on the canvas', () => {
    const nodes = nodesFromIde({}, routing);
    expect(readIdeSourceAuth(nodes, 'surface-x')).toBeNull();
  });

  it('returns null when JWT-bearer is picked but no strategy is selected', () => {
    const nodes: CanvasNode[] = [
      {
        id: 'ide-caller-auth',
        type: 'ide-caller-auth',
        label: 'Caller Context',
        configured: false,
        parentId: 'ide-source',
        config: { method_type: 'jwt_bearer' },
      } as CanvasNode,
    ];
    expect(readIdeSourceAuth(nodes, 'surface-x')).toBeNull();
  });
});

describe('canvas overlay', () => {
  it('overlays a saved position onto a config-derived member node', () => {
    const config: IdeConfigLike = {
      pipe_type: { config: { members: [{ pipe_id: 'p1' }] } },
      canvas: {
        version: 1,
        nodes: [{ id: 'ide-member-1', type: 'ide-member', position: { x: 12, y: 34 } }],
      },
    };
    const nodes = nodesFromIde(config, routing);
    expect(nodes.find(n => n.id === 'ide-member-1')?.position).toEqual({ x: 12, y: 34 });
  });

  it('never resurrects an ide-member node that is not backed by a config member', () => {
    const config: IdeConfigLike = {
      pipe_type: { config: { members: [] } },
      canvas: {
        version: 1,
        nodes: [{ id: 'ide-member-1', type: 'ide-member', config: { pipe_id: 'ghost' } }],
      },
    };
    const nodes = nodesFromIde(config, routing);
    expect(nodes.some(n => n.type === 'ide-member')).toBe(false);
  });

  it('restores a drag-on governance node absent from the config-derived spine', () => {
    const config: IdeConfigLike = {
      canvas: {
        version: 1,
        nodes: [
          {
            id: 'ide-rate-limit',
            type: 'ide-rate-limit',
            label: 'Rate Limit',
            position: { x: 0, y: 90 },
            config: { enabled: true, requests_per_minute: 30, tokens_per_minute: 9000 },
          },
        ],
      },
    };
    const rl = readIdeRateLimit(nodesFromIde(config, routing));
    expect(rl).toEqual({
      present: true,
      enabled: true,
      requests_per_minute: 30,
      tokens_per_minute: 9000,
    });
  });

  it('does not seed a second OPA node when the canvas already carries one with an edge-slot canonical id', () => {
    // Repro: user drops the OPA element on the source→catalogue edge, which
    // mints canonical id `ide-opa-policy-ide-source` (owned-by-source slot);
    // on save the surface persists both the canvas blob (with that id) and
    // the top-level `opa_policy` config. On reopen `nodesFromIde` must not
    // additionally seed the spine hardcoded-id `ide-opa-policy` node — that
    // would double up the OPA element on the canvas.
    const config: IdeConfigLike = {
      opa_policy: { enabled: true, policy_definition_id: 'p' },
      canvas: {
        version: 1,
        nodes: [
          {
            id: 'ide-opa-policy-ide-source',
            type: 'ide-opa-policy',
            position: { x: 10, y: 10 },
            config: { enabled: true, policy_definition_id: 'p' },
          },
        ],
      },
    };
    const nodes = nodesFromIde(config, routing);
    const opa = nodes.filter(n => n.type === 'ide-opa-policy');
    expect(opa).toHaveLength(1);
    expect(opa[0].id).toBe('ide-opa-policy-ide-source');
  });

  it('does not seed a second rate-limit node when the canvas already carries one with an edge-slot canonical id', () => {
    const config: IdeConfigLike = {
      rate_limit: { enabled: true, requests_per_minute: 30, tokens_per_minute: 9000 },
      canvas: {
        version: 1,
        nodes: [
          {
            id: 'ide-rate-limit-ide-source',
            type: 'ide-rate-limit',
            position: { x: 10, y: 10 },
            config: { enabled: true, requests_per_minute: 30, tokens_per_minute: 9000 },
          },
        ],
      },
    };
    const nodes = nodesFromIde(config, routing);
    const rl = nodes.filter(n => n.type === 'ide-rate-limit');
    expect(rl).toHaveLength(1);
    expect(rl[0].id).toBe('ide-rate-limit-ide-source');
  });
});

describe('readIdeSource on an empty canvas', () => {
  it('returns blank parts when there is no source node', () => {
    const source = readIdeSource([] as CanvasNode[]);
    expect(source).toEqual({ listen_address: '', prefix: '', custom_path: '' });
  });
});
