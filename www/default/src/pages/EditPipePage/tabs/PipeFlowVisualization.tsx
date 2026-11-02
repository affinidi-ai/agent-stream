import React, { useEffect, useRef, useMemo } from 'react';
import * as d3 from 'd3';
import { UI_COLORS } from '../../../utils/uiPalette';

// Re-use the config types from sibling tabs
import type { JudgeConfig } from './JudgeTab';
import type { JuryConfig } from './JuryTab';
import type { PromptGuardConfig } from './promptGuardTypes';

interface LLMConfig {
  provider: string;
  model: string;
}

export interface PipeFlowVisualizationProps {
  pipeName: string;
  llm?: LLMConfig | null;
  promptGuard?: PromptGuardConfig | null;
  judge?: JudgeConfig | null;
  jury?: JuryConfig | null;
}

// ── Flow graph types ────────────────────────────────────────────────

interface FlowNode {
  id: string;
  label: string;
  subtitle?: string;
  type: 'endpoint' | 'guard' | 'judge' | 'llm' | 'jury';
  enabled: boolean;
  x: number;
  y: number;
  icon: string;
  details?: string;
}

interface FlowLink {
  source: string;
  target: string;
}

// ── Helpers ─────────────────────────────────────────────────────────

/** Summarise request-side prompt guard rules */
function requestGuardSummary(pg: PromptGuardConfig | null | undefined): string | null {
  if (!pg?.request?.length) return null;
  const ruleCount = pg.request.reduce((n, g) => n + (g.regex?.rules?.length ?? 0), 0);
  if (ruleCount === 0) return null;
  const actions = Array.from(new Set(pg.request.map(g => g.regex?.action).filter(Boolean)));
  return `${ruleCount} rule${ruleCount !== 1 ? 's' : ''} (${actions.join(', ')})`;
}

/** Summarise response-side prompt guard rules */
function responseGuardSummary(pg: PromptGuardConfig | null | undefined): string | null {
  if (!pg?.response?.length) return null;
  const ruleCount = pg.response.reduce((n, g) => n + (g.regex?.rules?.length ?? 0), 0);
  if (ruleCount === 0) return null;
  const actions = Array.from(new Set(pg.response.map(g => g.regex?.action).filter(Boolean)));
  return `${ruleCount} rule${ruleCount !== 1 ? 's' : ''} (${actions.join(', ')})`;
}

// ── Component ───────────────────────────────────────────────────────

const PipeFlowVisualization: React.FC<PipeFlowVisualizationProps> = ({
  pipeName,
  llm,
  promptGuard,
  judge,
  jury,
}) => {
  const svgRef = useRef<SVGSVGElement>(null);

  // Build the node & link graph from the current pipe config
  const { nodes, links } = useMemo(() => {
    const nodes: FlowNode[] = [];
    const links: FlowLink[] = [];

    let currentX = 80;
    const centerY = 100;
    const spacing = 200;

    // ── 1. Request (origin) ──────────────────────────────────────
    nodes.push({
      id: 'request',
      label: 'Request',
      type: 'endpoint',
      enabled: true,
      x: currentX,
      y: centerY,
      icon: 'fa-paper-plane',
      details: 'Incoming API request',
    });

    let prevId = 'request';
    currentX += spacing;

    // ── 2. Prompt Guard – request side ───────────────────────────
    const reqGuard = requestGuardSummary(promptGuard);
    const hasReqGuard = !!reqGuard;
    nodes.push({
      id: 'req-guard',
      label: 'Prompt Guard',
      subtitle: hasReqGuard ? reqGuard! : 'not configured',
      type: 'guard',
      enabled: hasReqGuard,
      x: currentX,
      y: centerY,
      icon: 'fa-shield-alt',
      details: hasReqGuard
        ? `Request prompt guard: ${reqGuard}`
        : 'No request-side prompt guard rules configured',
    });
    links.push({ source: prevId, target: 'req-guard' });
    prevId = 'req-guard';
    currentX += spacing;

    // ── 3. Judge (pre-processing LLM validation) ─────────────────
    const judgeEnabled = !!judge?.enabled;
    const judgeMode = judge?.mode ?? 'llm';
    const judgeModel = judge?.llm ? `${judge.llm.provider_type}/${judge.llm.model}` : '';
    nodes.push({
      id: 'judge',
      label: 'Judge',
      subtitle: judgeEnabled ? `${judgeMode}${judgeModel ? ' · ' + judgeModel : ''}` : 'disabled',
      type: 'judge',
      enabled: judgeEnabled,
      x: currentX,
      y: centerY,
      icon: 'fa-gavel',
      details: judgeEnabled
        ? `Mode: ${judgeMode}\nProvider: ${judgeModel}\nRules: ${judge!.rules?.length ?? 0}`
        : 'Judge is disabled',
    });
    links.push({ source: prevId, target: 'judge' });
    prevId = 'judge';
    currentX += spacing;

    // ── 4. Processing LLM ────────────────────────────────────────
    const llmLabel = llm ? `${llm.provider}/${llm.model}` : 'not configured';
    nodes.push({
      id: 'llm',
      label: 'Processing LLM',
      subtitle: llmLabel,
      type: 'llm',
      enabled: !!llm,
      x: currentX,
      y: centerY,
      icon: 'fa-brain',
      details: llm
        ? `Provider: ${llm.provider}\nModel: ${llm.model}`
        : 'No LLM provider configured',
    });
    links.push({ source: prevId, target: 'llm' });
    prevId = 'llm';
    currentX += spacing;

    // ── 5. Jury (post-processing LLM validation) ─────────────────
    const juryEnabled = !!jury?.enabled;
    const juryRetries = jury?.max_retries ?? 0;
    const juryInfo = juryEnabled
      ? `${jury!.mode} · ${jury!.jurors?.length ?? 0} juror${(jury!.jurors?.length ?? 0) !== 1 ? 's' : ''}${juryRetries > 0 ? ` · ${juryRetries} retry` : ''}`
      : 'disabled';
    nodes.push({
      id: 'jury',
      label: 'Jury',
      subtitle: juryInfo,
      type: 'jury',
      enabled: juryEnabled,
      x: currentX,
      y: centerY,
      icon: 'fa-users',
      details: juryEnabled
        ? `Mode: ${jury!.mode}\nJurors: ${jury!.jurors?.length ?? 0}${juryRetries > 0 ? `\nMax retries: ${juryRetries}` : ''}`
        : 'Jury is disabled',
    });
    links.push({ source: prevId, target: 'jury' });
    prevId = 'jury';
    currentX += spacing;

    // ── 6. Prompt Guard – response side ──────────────────────────
    const resGuard = responseGuardSummary(promptGuard);
    const hasResGuard = !!resGuard;
    nodes.push({
      id: 'res-guard',
      label: 'Prompt Guard',
      subtitle: hasResGuard ? resGuard! : 'not configured',
      type: 'guard',
      enabled: hasResGuard,
      x: currentX,
      y: centerY,
      icon: 'fa-shield-alt',
      details: hasResGuard
        ? `Response prompt guard: ${resGuard}`
        : 'No response-side prompt guard rules configured',
    });
    links.push({ source: prevId, target: 'res-guard' });
    prevId = 'res-guard';
    currentX += spacing;

    // ── 7. Response (terminal) ───────────────────────────────────
    nodes.push({
      id: 'response',
      label: 'Response',
      type: 'endpoint',
      enabled: true,
      x: currentX,
      y: centerY,
      icon: 'fa-reply',
      details: 'Outgoing API response',
    });
    links.push({ source: prevId, target: 'response' });

    return { nodes, links };
  }, [pipeName, llm, promptGuard, judge, jury]);

  // ── D3 rendering ────────────────────────────────────────────────
  useEffect(() => {
    if (!svgRef.current || nodes.length === 0) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const width = svgRef.current.clientWidth;
    const g = svg.append('g');

    // Colour palette keyed by node type
    const fillColour = (n: FlowNode): string => {
      if (!n.enabled) return 'var(--gray-300)';
      switch (n.type) {
        case 'endpoint':
          return UI_COLORS.accentPurple;
        case 'guard':
          return UI_COLORS.warning;
        case 'judge':
          return UI_COLORS.danger;
        case 'llm':
          return UI_COLORS.success;
        case 'jury':
          return UI_COLORS.primary;
        default:
          return UI_COLORS.neutral;
      }
    };

    // Arrow marker
    svg
      .append('defs')
      .append('marker')
      .attr('id', 'pipe-arrow')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 42)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', 'var(--gray-400)');

    // Links (arrows)
    g.selectAll('.link')
      .data(links)
      .enter()
      .append('line')
      .attr('x1', d => nodes.find(n => n.id === d.source)!.x)
      .attr('y1', d => nodes.find(n => n.id === d.source)!.y)
      .attr('x2', d => nodes.find(n => n.id === d.target)!.x)
      .attr('y2', d => nodes.find(n => n.id === d.target)!.y)
      .attr('stroke', 'var(--gray-300)')
      .attr('stroke-width', 2)
      .attr('marker-end', 'url(#pipe-arrow)');

    // ── Jury retry loop arrow (curved arc from Jury back to LLM) ──
    const juryNode = nodes.find(n => n.id === 'jury');
    const llmNode = nodes.find(n => n.id === 'llm');
    const retries = jury?.max_retries ?? 0;
    if (juryNode && llmNode && juryNode.enabled && retries > 0) {
      // Arrow marker for the retry arc (blue, smaller refX for the arc endpoint)
      svg
        .select('defs')
        .append('marker')
        .attr('id', 'retry-arrow')
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 8)
        .attr('refY', 0)
        .attr('markerWidth', 6)
        .attr('markerHeight', 6)
        .attr('orient', 'auto')
        .append('path')
        .attr('d', 'M0,-5L10,0L0,5')
        .attr('fill', UI_COLORS.accentPurple);

      // Quadratic bezier curving above the main flow
      const x1 = juryNode.x - 20;
      const y1 = juryNode.y - 42;
      const x2 = llmNode.x + 20;
      const y2 = llmNode.y - 42;
      const cy = juryNode.y - 90; // control point above both nodes

      g.append('path')
        .attr('d', `M${x1},${y1} Q${(x1 + x2) / 2},${cy} ${x2},${y2}`)
        .attr('fill', 'none')
        .attr('stroke', UI_COLORS.accentPurple)
        .attr('stroke-width', 2)
        .attr('stroke-dasharray', '6,3')
        .attr('marker-end', 'url(#retry-arrow)');

      // Label on the retry arc
      g.append('text')
        .attr('x', (x1 + x2) / 2)
        .attr('y', cy + 14)
        .attr('text-anchor', 'middle')
        .attr('font-size', '10px')
        .attr('fill', UI_COLORS.accentPurple)
        .attr('font-weight', '600')
        .text(`retry (max ${retries})`);
    }

    // Node groups
    const nodeG = g
      .selectAll<SVGGElement, FlowNode>('.node')
      .data(nodes)
      .enter()
      .append('g')
      .attr('class', 'node')
      .attr('transform', d => `translate(${d.x},${d.y})`);

    // Circle
    nodeG
      .append('circle')
      .attr('r', 38)
      .attr('fill', d => fillColour(d))
      .attr('stroke', '#ffffff')
      .attr('stroke-width', 3)
      .attr('opacity', d => (d.enabled ? 0.92 : 0.5));

    // Icon (FontAwesome unicode)
    const faUnicode: Record<string, string> = {
      'fa-paper-plane': '\uf1d8',
      'fa-shield-alt': '\uf3ed',
      'fa-gavel': '\uf0e3',
      'fa-brain': '\uf5dc',
      'fa-users': '\uf0c0',
      'fa-reply': '\uf3e5',
    };

    nodeG
      .append('text')
      .attr('text-anchor', 'middle')
      .attr('y', 7)
      .attr('font-family', 'FontAwesome')
      .attr('font-size', '22px')
      .attr('fill', '#ffffff')
      .text(d => faUnicode[d.icon] ?? '\uf013');

    // Label (below circle)
    nodeG
      .append('text')
      .attr('text-anchor', 'middle')
      .attr('y', 56)
      .attr('font-size', '12px')
      .attr('font-weight', 'bold')
      .attr('fill', d => (d.enabled ? 'var(--gray-700)' : 'var(--gray-400)'))
      .text(d => d.label);

    // Subtitle (below label)
    nodeG.each(function (d) {
      if (!d.subtitle) return;
      const el = d3.select(this);
      const text = el
        .append('text')
        .attr('text-anchor', 'middle')
        .attr('y', 70)
        .attr('font-size', '10px')
        .attr('fill', d.enabled ? 'var(--gray-500)' : 'var(--gray-300)');

      // Truncate long subtitles
      const sub = d.subtitle.length > 30 ? d.subtitle.slice(0, 28) + '…' : d.subtitle;
      text.text(sub);
    });

    // Tooltip
    nodeG
      .append('title')
      .text(
        d =>
          `${d.label}${d.subtitle ? '\n' + d.subtitle : ''}${d.details ? '\n\n' + d.details : ''}`
      );

    // Scale to fit
    const minX = Math.min(...nodes.map(n => n.x));
    const maxX = Math.max(...nodes.map(n => n.x));
    const totalWidth = maxX - minX + 180;
    const scale = Math.min(1, width / totalWidth);
    const tx = (width - totalWidth * scale) / 2 - minX * scale + 90;
    g.attr('transform', `translate(${tx}, 10) scale(${scale})`);
  }, [nodes, links]);

  // ── Legend ──────────────────────────────────────────────────────
  const legendItems: { colour: string; label: string }[] = [
    { colour: UI_COLORS.accentPurple, label: 'Request / Response' },
    { colour: UI_COLORS.warning, label: 'Prompt Guard' },
    { colour: UI_COLORS.danger, label: 'Judge (pre-processing)' },
    { colour: UI_COLORS.success, label: 'Processing LLM' },
    { colour: UI_COLORS.primary, label: 'Jury (post-processing)' },
    { colour: 'var(--gray-300)', label: 'Disabled / Not Configured' },
  ];

  return (
    <div className="card shadow-sm mb-4">
      <div className="card-header bg-light">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-project-diagram"></i> Pipe Flow Visualization
        </h6>
      </div>
      <div className="card-body">
        <svg
          ref={svgRef}
          style={{
            width: '100%',
            height: '220px',
            border: '1px solid var(--gray-200)',
            borderRadius: '4px',
            backgroundColor: 'var(--gray-50)',
          }}
        />

        {/* Legend */}
        <div className="mt-3 d-flex flex-wrap" style={{ gap: '14px' }}>
          {legendItems.map(item => (
            <span
              key={item.label}
              className="d-flex align-items-center"
              style={{ fontSize: '12px' }}
            >
              <span
                style={{
                  display: 'inline-block',
                  width: 12,
                  height: 12,
                  borderRadius: '50%',
                  backgroundColor: item.colour,
                  marginRight: 5,
                  flexShrink: 0,
                }}
              />
              {item.label}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
};

export default PipeFlowVisualization;

// ── Mini (compact) pipe flow for Judge / Jury tabs ──────────────────

interface MiniFlowStep {
  id: string;
  label: string;
  icon: string;
  colour: string;
  enabled: boolean;
}

type StepId = 'req-guard' | 'judge' | 'llm' | 'jury' | 'res-guard';

export interface MiniPipeFlowProps {
  /** Which step id(s) to highlight as "you are here" */
  highlightId: StepId | StepId[];
  promptGuard?: PromptGuardConfig | null;
  judge?: JudgeConfig | null;
  jury?: JuryConfig | null;
}

export const MiniPipeFlow: React.FC<MiniPipeFlowProps> = ({
  highlightId,
  promptGuard,
  judge,
  jury,
}) => {
  const highlighted = Array.isArray(highlightId) ? highlightId : [highlightId];
  const reqGuard = !!requestGuardSummary(promptGuard);
  const resGuard = !!responseGuardSummary(promptGuard);
  const judgeEnabled = !!judge?.enabled;
  const juryEnabled = !!jury?.enabled;

  const steps: MiniFlowStep[] = [
    {
      id: 'request',
      label: 'Request',
      icon: 'fa-paper-plane',
      colour: UI_COLORS.accentPurple,
      enabled: true,
    },
    {
      id: 'req-guard',
      label: 'Prompt Guard',
      icon: 'fa-shield-alt',
      colour: UI_COLORS.warning,
      enabled: reqGuard,
    },
    {
      id: 'judge',
      label: 'Judge',
      icon: 'fa-gavel',
      colour: UI_COLORS.danger,
      enabled: judgeEnabled,
    },
    {
      id: 'llm',
      label: 'Processing LLM',
      icon: 'fa-brain',
      colour: UI_COLORS.success,
      enabled: true,
    },
    {
      id: 'jury',
      label: 'Jury',
      icon: 'fa-users',
      colour: UI_COLORS.primary,
      enabled: juryEnabled,
    },
    {
      id: 'res-guard',
      label: 'Prompt Guard',
      icon: 'fa-shield-alt',
      colour: UI_COLORS.warning,
      enabled: resGuard,
    },
    {
      id: 'response',
      label: 'Response',
      icon: 'fa-reply',
      colour: UI_COLORS.accentPurple,
      enabled: true,
    },
  ];

  return (
    <div
      className="d-flex align-items-center"
      style={{ width: '100%', fontSize: '12px', lineHeight: 1 }}
    >
      {steps.map((step, idx) => {
        const isHighlight = highlighted.includes(step.id as StepId);

        return (
          <React.Fragment key={step.id}>
            {idx > 0 && (
              <i
                className="fas fa-long-arrow-alt-right mini-flow-arrow"
                style={{ fontSize: '14px', flexShrink: 0, margin: '0 2px' }}
              />
            )}
            <span
              title={step.label}
              className={isHighlight ? 'mini-flow-step is-highlight' : 'mini-flow-step'}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '4px',
                padding: '4px 10px',
                borderRadius: '14px',
                backgroundColor: isHighlight ? step.colour : undefined,
                color: isHighlight ? '#ffffff' : undefined,
                fontWeight: isHighlight ? 700 : 400,
                boxShadow: isHighlight ? `0 0 0 2px ${step.colour}44` : 'none',
                whiteSpace: 'nowrap',
                flex: '1 1 0',
                minWidth: 0,
                overflow: 'hidden',
                textOverflow: 'ellipsis',
              }}
            >
              <i
                className={`fas ${step.icon} mini-flow-icon`}
                style={{ fontSize: '10px', color: isHighlight ? '#fff' : undefined, flexShrink: 0 }}
              />
              <span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{step.label}</span>
            </span>
          </React.Fragment>
        );
      })}
    </div>
  );
};
