import type { CanvasNode } from '../../../SurfaceCanvas';
import {
  applyIdeTemplateItems,
  canSerializeIdeNode,
  serializeIdeTemplate,
} from '../ideTemplateItems';

function node(partial: Partial<CanvasNode> & { id: string; type: any }): CanvasNode {
  return {
    label: partial.label ?? partial.id,
    configured: true,
    ...partial,
  } as CanvasNode;
}

/** A minimal live IDE canvas: spine + one member + the three governance nodes. */
function ideCanvas(): CanvasNode[] {
  return [
    node({ id: 'ide-source', type: 'ide-source', label: 'Access Point' }),
    node({ id: 'ide-catalog', type: 'ide-catalog', label: 'Catalogue', parentId: 'ide-source' }),
    node({ id: 'ide-response', type: 'ide-response', label: 'Response', parentId: 'ide-catalog' }),
    node({
      id: 'member-1',
      type: 'ide-member',
      label: 'Member',
      parentId: 'ide-catalog',
      config: { pipe_id: 'llm-abc' },
      position: { x: 10, y: 20 },
    }),
    node({
      id: 'ide-opa-policy',
      type: 'ide-opa-policy',
      label: 'OPA Policy',
      parentId: 'ide-source',
      config: { enabled: true, policy_definition_id: 'pol-1', log_decisions: true },
    }),
    node({
      id: 'ide-rate-limit',
      type: 'ide-rate-limit',
      label: 'Rate Limit',
      parentId: 'ide-source',
      config: { enabled: true, requests_per_minute: 30, tokens_per_minute: 5000 },
    }),
    node({
      id: 'ide-caller-auth',
      type: 'ide-caller-auth',
      label: 'Caller Context',
      parentId: 'ide-source',
      config: {
        method_type: 'jwt_bearer',
        jwt_strategy_id: 'strat-1',
        jwt_token_header: 'Authorization',
        jwt_token_scheme: 'Bearer',
      },
    }),
  ];
}

describe('serializeIdeTemplate', () => {
  it('captures only the governance singletons', () => {
    const items = serializeIdeTemplate(ideCanvas());
    const kinds = items.map(i => i.kind).sort();
    expect(kinds).toEqual(['ide-caller-auth', 'ide-opa-policy', 'ide-rate-limit']);
    // Members and spine are never serializable.
    expect(canSerializeIdeNode(node({ id: 'member-1', type: 'ide-member' }))).toBe(false);
    expect(canSerializeIdeNode(node({ id: 'ide-catalog', type: 'ide-catalog' }))).toBe(false);
    expect(canSerializeIdeNode(node({ id: 'ide-opa-policy', type: 'ide-opa-policy' }))).toBe(true);
  });

  it('honours a node-id selection', () => {
    const items = serializeIdeTemplate(ideCanvas(), { nodeIds: ['ide-rate-limit'] });
    expect(items.map(i => i.kind)).toEqual(['ide-rate-limit']);
    expect(items[0].config).toMatchObject({
      enabled: true,
      requests_per_minute: 30,
      tokens_per_minute: 5000,
    });
  });

  it('captures the OPA policy config verbatim', () => {
    const items = serializeIdeTemplate(ideCanvas(), { nodeIds: ['ide-opa-policy'] });
    expect(items[0]).toMatchObject({
      scope: 'middleware',
      kind: 'ide-opa-policy',
      config: { enabled: true, policy_definition_id: 'pol-1', log_decisions: true },
    });
  });
});

describe('applyIdeTemplateItems', () => {
  it('merges a governance bundle onto a fresh canvas without touching members', () => {
    const items = serializeIdeTemplate(ideCanvas());
    // Target canvas: spine + member only, no governance yet.
    const target: CanvasNode[] = [
      node({ id: 'ide-source', type: 'ide-source' }),
      node({ id: 'ide-catalog', type: 'ide-catalog', parentId: 'ide-source' }),
      node({ id: 'ide-response', type: 'ide-response', parentId: 'ide-catalog' }),
      node({
        id: 'member-9',
        type: 'ide-member',
        parentId: 'ide-catalog',
        config: { pipe_id: 'llm-xyz' },
        position: { x: 5, y: 5 },
      }),
    ];
    const applied = applyIdeTemplateItems(target, items);

    // Member is preserved untouched (including its position).
    const member = applied.find(n => n.id === 'member-9');
    expect(member?.config).toEqual({ pipe_id: 'llm-xyz' });
    expect(member?.position).toEqual({ x: 5, y: 5 });

    // The three governance singletons were added.
    const opa = applied.find(n => n.type === 'ide-opa-policy');
    const rl = applied.find(n => n.type === 'ide-rate-limit');
    const auth = applied.find(n => n.type === 'ide-caller-auth');
    expect(opa?.config).toMatchObject({ policy_definition_id: 'pol-1', log_decisions: true });
    expect(rl?.config).toMatchObject({ requests_per_minute: 30, tokens_per_minute: 5000 });
    expect(auth?.config).toMatchObject({ method_type: 'jwt_bearer', jwt_strategy_id: 'strat-1' });
    // Governance nodes are parented to the source spine anchor.
    expect(opa?.parentId).toBe('ide-source');
  });

  it('replaces an existing same-type singleton instead of duplicating it', () => {
    const items = serializeIdeTemplate(ideCanvas(), { nodeIds: ['ide-rate-limit'] });
    // Target already has a rate-limit with different numbers.
    const target: CanvasNode[] = [
      node({ id: 'ide-source', type: 'ide-source' }),
      node({
        id: 'ide-rate-limit',
        type: 'ide-rate-limit',
        parentId: 'ide-source',
        config: { enabled: true, requests_per_minute: 999, tokens_per_minute: 1 },
      }),
    ];
    const applied = applyIdeTemplateItems(target, items);
    const rls = applied.filter(n => n.type === 'ide-rate-limit');
    expect(rls).toHaveLength(1);
    expect(rls[0].config).toMatchObject({ requests_per_minute: 30, tokens_per_minute: 5000 });
  });

  it('round-trips serialize → apply for every governance element', () => {
    const source = ideCanvas();
    const items = serializeIdeTemplate(source);
    const applied = applyIdeTemplateItems([node({ id: 'ide-source', type: 'ide-source' })], items);
    const reserialized = serializeIdeTemplate(applied);
    // The captured items are stable across a serialize → apply → serialize cycle.
    expect(reserialized).toEqual(items);
  });
});
