import React from 'react';
import { render, screen, within } from '@testing-library/react';
import PipeMonitoringTab from '../PipeMonitoringTab';

jest.mock('react-chartjs-2', () => ({
  Line: () => null,
}));

jest.mock('../PipeLogsViewer', () => () => null);

// Per-stage cost + total tokens on the cards are window-scoped from the usage
// telemetry series (not from `stage_usage`, which now only supplies avg latency).
// Drive them deterministically by mocking the usage-series hook.
const mockUsage = { totals: {} };

jest.mock('../../../../components/usage/useUsageSeries', () => ({
  useUsageSeries: keys => ({
    series: keys.map(key => ({
      key,
      resolution: '1m',
      step_secs: 60,
      points: mockUsage.totals[key]
        ? [
            {
              t: 0,
              cost: mockUsage.totals[key].cost,
              tokens: mockUsage.totals[key].tokens,
              requests: 1,
            },
          ]
        : [],
    })),
    committed: { windowSecs: 3600, endOffset: 0 },
    domainSecs: 3600,
    loading: false,
  }),
}));

const buildState = (stageUsage: unknown) => ({
  activeView: 'global',
  globalState: {
    stats: {
      metrics: {
        pipe_stats: [
          {
            pipe_id: 'pipe-1',
            pipe_name: 'Pipe 1',
            total_requests: 2,
            successful_requests: 2,
            failed_requests: 0,
            avg_latency_ms: 100,
            avg_gateway_processing_ms: 0,
            avg_target_processing_ms: 0,
            total_input_tokens: 0,
            total_output_tokens: 0,
            total_cost: 0,
            stage_usage: stageUsage,
          },
        ],
        time_series: [],
        latency_time_series: [],
      },
    },
  },
  filteredState: { stats: null },
});

const renderTab = (stageUsage: unknown) =>
  render(
    <PipeMonitoringTab
      pipeId="pipe-1"
      pipeName="Pipe 1"
      state={buildState(stageUsage)}
      actions={{}}
    />
  );

describe('PipeMonitoringTab stage usage cards', () => {
  it('renders per-stage latency, windowed tokens and combined cost', () => {
    // Windowed cost + total tokens come from the usage telemetry series.
    mockUsage.totals = {
      'surface:pipe-1:stage:llm': { cost: 0.3, tokens: 70 },
      'surface:pipe-1:stage:judge': { cost: 0.02, tokens: 6 },
      'surface:pipe-1:stage:jury': { cost: 0.03, tokens: 12 },
      'surface:pipe-1:stage:decider': { cost: 0.04, tokens: 6 },
    };

    renderTab({
      llm: {
        total_input_tokens: 40,
        total_output_tokens: 30,
        total_cost: 0.3,
        avg_latency_ms: 200,
      },
      judge: {
        total_input_tokens: 4,
        total_output_tokens: 2,
        total_cost: 0.02,
        avg_latency_ms: 40,
      },
      jury: { total_input_tokens: 8, total_output_tokens: 4, total_cost: 0.03, avg_latency_ms: 40 },
      decider: {
        total_input_tokens: 5,
        total_output_tokens: 1,
        total_cost: 0.04,
        avg_latency_ms: 50,
      },
    });

    const cards = screen.getByTestId('pipe-stage-usage-cards');

    // Card value is the lifetime avg latency from stage_usage.
    expect(within(cards).getByText('Main LLM')).toBeInTheDocument();
    expect(within(cards).getByText('200 ms')).toBeInTheDocument();

    // Card meta is the window-scoped total tokens from telemetry.
    expect(within(cards).getByText(/70 tokens · selected window/)).toBeInTheDocument();

    // Total cost = 0.3 + 0.02 + 0.03 + 0.04 = 0.39 (windowed, from telemetry).
    expect(within(cards).getByText('$0.3900')).toBeInTheDocument();
    expect(within(cards).getByText(/Decider \$0\.0400/)).toBeInTheDocument();
  });

  it('falls back to zeroed latency and cost when no usage is present', () => {
    mockUsage.totals = {};
    renderTab(undefined);

    const cards = screen.getByTestId('pipe-stage-usage-cards');

    expect(within(cards).getByText('Judge')).toBeInTheDocument();
    expect(within(cards).getByText('Jury')).toBeInTheDocument();
    // All-zero combined cost (no telemetry in the window).
    expect(within(cards).getByText('$0.0000')).toBeInTheDocument();
    // Avg latency falls back to 0 when stage_usage is absent.
    expect(within(cards).getAllByText('0 ms').length).toBeGreaterThan(0);
  });
});
