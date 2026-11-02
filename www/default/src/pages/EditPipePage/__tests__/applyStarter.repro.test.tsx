import React from 'react';
import { act, render } from '@testing-library/react';
import { resolvePipeTemplateBlob } from '../../../components/builder/pipe-templates/pipeTemplateBlob';
import type { PipeFormData, RoutingConfig } from '../types';
import { useCanvasBindings } from '../hooks/useCanvasBindings';
import { usePipeBuilder } from '../hooks/usePipeBuilder';
import { usePipeForm } from '../hooks/usePipeForm';

// A self-contained full-template `pipe` blob mirroring what the gateway
// persists for a starter template: name / route tokenized, full middleware
// (prompt guard, judge, jury) enabled, and a saved canvas blob whose nodes
// include the canvas-only decorations (rate-limit + jurors) that must survive
// being applied to a brand-new pipe.
const TEMPLATE_PIPE_BLOB: Record<string, any> = {
  name: '$SURFACE_NAME',
  route: '$SURFACE_ROUTE',
  enabled: true,
  provider: 'openai',
  model: 'gpt-4o',
  endpoint_url: '/chat/completions',
  rate_limit_enabled: true,
  requests_per_minute: 1,
  tokens_per_minute: 100000,
  cost_tracking_enabled: false,
  prompt_guard: {
    enabled: true,
    request: [{ regex: { action: 'reject', rules: [{ builtin: 'email' }] }, rejection: null }],
    response: [{ regex: { action: 'reject', rules: [{ builtin: 'email' }] }, rejection: null }],
  },
  judge: { enabled: true, mode: 'moderation' },
  jury: {
    enabled: true,
    mode: 'all',
    jurors: [
      { id: 'pipe-juror-0', name: 'Juror 0' },
      { id: 'pipe-juror-1', name: 'Juror 1' },
    ],
  },
  canvas: {
    nodes: [
      { id: 'pipe-source', type: 'pipe-source', position: { x: -490, y: 0 } },
      {
        id: 'pipe-prompt-guard-request',
        type: 'pipe-prompt-guard',
        position: { x: -245, y: 0 },
        config: { direction: 'request', enabled: true },
      },
      { id: 'pipe-judge', type: 'pipe-judge', position: { x: -120, y: 0 } },
      { id: 'pipe-upstream', type: 'pipe-upstream', position: { x: 0, y: 0 } },
      { id: 'pipe-jury', type: 'pipe-jury', position: { x: 120, y: 0 } },
      {
        id: 'pipe-juror-0',
        type: 'pipe-juror',
        parentId: 'pipe-jury',
        position: { x: 120, y: -80 },
      },
      {
        id: 'pipe-juror-1',
        type: 'pipe-juror',
        parentId: 'pipe-jury',
        position: { x: 120, y: 80 },
      },
      {
        id: 'pipe-prompt-guard-response',
        type: 'pipe-prompt-guard',
        position: { x: 245, y: 0 },
        config: { direction: 'response', enabled: true },
      },
      { id: 'pipe-response', type: 'pipe-response', position: { x: 490, y: 0 } },
      {
        id: 'pipe-rate-limit-pipe-source',
        type: 'pipe-rate-limit',
        label: 'Rate Limit',
        parentId: 'pipe-source',
        position: { x: -350, y: 0 },
        config: { enabled: true, requests_per_minute: 1, tokens_per_minute: 100000 },
      },
    ],
  },
};

const routingConfig: RoutingConfig = {
  available_listen_addresses: ['https://fabric-stream-1.example.com'],
  pipe_path_prefix: [{ prefix: '/llm' }],
} as unknown as RoutingConfig;

interface HarnessHandle {
  getFormData: () => PipeFormData;
  getNodes: () => any[];
  applyTemplate: (pipeBlob: Record<string, any>) => void;
}

const Harness = React.forwardRef<HarnessHandle, { routing: RoutingConfig | null }>(
  ({ routing }, ref) => {
    const form = usePipeForm({ pipeId: 'new', llmProviders: [], routingConfig: routing });
    const canvasViewRef = React.useRef<{ x: number; y: number; k: number } | null>(null);

    const canvas = useCanvasBindings(
      form.formData,
      form.selectedPrefix,
      form.customPath,
      form.setFormData,
      form.setSelectedPrefix,
      form.setCustomPath,
      form.setIsModified,
      [],
      form.routePrefixResolved
    );

    const pb = usePipeBuilder(
      canvas.pipeForCanvas,
      {
        onSourceChange: canvas.handleCanvasSourceChange,
        onUpstreamChange: canvas.handleCanvasUpstreamChange,
        onRateLimitChange: canvas.handleCanvasRateLimitChange,
        onOpaPolicyChange: canvas.handleCanvasOpaPolicyChange,
        onPromptGuardChange: canvas.handleCanvasPromptGuardChange,
        onJudgeChange: canvas.handleCanvasJudgeChange,
        onJuryChange: canvas.handleCanvasJuryChange,
        onDeciderChange: canvas.handleCanvasDeciderChange,
        onUsageLimitsChange: canvas.handleCanvasUsageLimitsChange,
      },
      () => form.setIsModified(true),
      true,
      canvasViewRef
    );

    React.useImperativeHandle(ref, () => ({
      getFormData: () => form.formData,
      getNodes: () => pb.builder.state.nodes,
      applyTemplate: (pipeBlob: Record<string, any>) => {
        form.setFormData(prev => {
          const resolved = resolvePipeTemplateBlob(pipeBlob, {
            name: prev.name,
            route: prev.route,
            endpoint: prev.endpoint_url,
          });
          return { ...prev, ...resolved } as PipeFormData;
        });
        form.setIsModified(true);
      },
    }));

    return null;
  }
);

const settle = async () => {
  for (let i = 0; i < 5; i++) {
    // eslint-disable-next-line no-await-in-loop
    await act(async () => {
      await Promise.resolve();
    });
  }
};

const pgNode = (nodes: any[], dir: string) =>
  nodes.find(n => n.type === 'pipe-prompt-guard' && n.config?.direction === dir);

describe('apply starter template to a new pipe', () => {
  it('routing loaded BEFORE apply: preserves flat config and reseeds canvas', async () => {
    const pipeBlob = TEMPLATE_PIPE_BLOB;

    const ref = React.createRef<HarnessHandle>();
    // eslint-disable-next-line testing-library/no-unnecessary-act
    await act(async () => {
      render(<Harness ref={ref} routing={routingConfig} />);
    });
    await settle();
    await act(async () => {
      ref.current!.applyTemplate(pipeBlob);
    });
    await settle();

    const fd = ref.current!.getFormData();
    expect(fd.prompt_guard).not.toBeNull();
    expect(fd.judge).not.toBeNull();
    expect(fd.jury).not.toBeNull();
    expect(fd.rate_limit_enabled).toBe(true);

    const nodes = ref.current!.getNodes();
    const req = pgNode(nodes, 'request');
    expect(req?.config?.enabled).toBe(true);
    expect(req?.config?.request?.length).toBeGreaterThan(0);
    expect(nodes.some(n => n.type === 'pipe-rate-limit')).toBe(true);
    expect(nodes.find(n => n.id === 'pipe-judge')?.config?.judge).not.toBeNull();
  });

  it('routing loaded AFTER apply: preserves flat config and reseeds canvas', async () => {
    const pipeBlob = TEMPLATE_PIPE_BLOB;

    const ref = React.createRef<HarnessHandle>();
    const { rerender } = render(<Harness ref={ref} routing={null} />);
    await settle();

    // Apply the starter before the routing catalogue has arrived.
    await act(async () => {
      ref.current!.applyTemplate(pipeBlob);
    });
    await settle();

    // Routing arrives.
    // eslint-disable-next-line testing-library/no-unnecessary-act
    await act(async () => {
      rerender(<Harness ref={ref} routing={routingConfig} />);
    });
    await settle();

    const fd = ref.current!.getFormData();
    expect(fd.prompt_guard).not.toBeNull();
    expect(fd.judge).not.toBeNull();
    expect(fd.jury).not.toBeNull();
    expect(fd.rate_limit_enabled).toBe(true);

    const nodes = ref.current!.getNodes();
    const req = pgNode(nodes, 'request');
    expect(req?.config?.enabled).toBe(true);
    expect(req?.config?.request?.length).toBeGreaterThan(0);
    expect(nodes.some(n => n.type === 'pipe-rate-limit')).toBe(true);
  });
});
