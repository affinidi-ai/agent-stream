import React, { useState, useEffect, useMemo, useRef } from 'react';
import { useApp } from '../../context/AppContext';
import { usePermissions } from '../../context/PermissionsContext';
import { LogEntry } from '../../types';
import { escapeHtml } from '../../utils/escapeHtml';
import { UI_COLORS, withAlpha } from '../../utils/uiPalette';

/**
 * PipeActivityViewer — structured pipeline stage view
 *
 * Parses [STAGE:xxx] tags from pipe logs and renders a visual pipeline
 * flow instead of raw log output. Falls back to showing raw logs for
 * entries that don't have stage tags.
 */

// ── Types ──

interface StageData {
  stage: string;
  payload: Record<string, any>;
  timestamp: number;
  level: string;
  raw: string;
}

interface PipelineRun {
  id: number;
  stages: StageData[];
  rawLogs: LogEntry[];
  timestamp: number;
}

interface PipeActivityViewerProps {
  pipeId: string;
  pipeName?: string;
  height?: string;
  /**
   * When set (epoch ms), a request is in flight. An optimistic "Processing…"
   * session card is shown immediately until the real pipeline logs for this
   * request arrive, so the panel reacts the moment the user hits send rather
   * than waiting for the next stats refresh.
   */
  pendingSince?: number | null;
  /**
   * A terminal failure of the in-flight request that produced no pipeline
   * stage logs (rate limit, policy denial, network, variant resolution).
   * Rendered as a standalone error session card so the failed request is
   * shown with its reason instead of the panel reverting to the previous run.
   */
  pendingError?: {
    since: number;
    httpStatus?: number;
    message: string;
    label: string;
  } | null;
}

// ── Stage tag regex ──
// Matches: [STAGE:stage_name] {json_payload}
const STAGE_REGEX = /\[STAGE:(\w+)\]\s*(\{.*\})\s*$/;

function parseStageTag(message: string): { stage: string; payload: Record<string, any> } | null {
  const match = message.match(STAGE_REGEX);
  if (!match) return null;
  try {
    const payload = JSON.parse(match[2]);
    return { stage: match[1], payload };
  } catch {
    return null;
  }
}

// ── Stage display config ──

const STAGE_CONFIG: Record<string, { label: string; icon: string; color: string; order: number }> =
  {
    decider: { label: 'Decider (Router)', icon: 'fa-route', color: UI_COLORS.orange, order: 0 },
    prompt_guard_request: {
      label: 'Prompt Guard (Request)',
      icon: 'fa-shield-alt',
      color: UI_COLORS.primary,
      order: 1,
    },
    judge: { label: 'Judge', icon: 'fa-gavel', color: UI_COLORS.accentPurple, order: 2 },
    llm_request: { label: 'LLM Processing', icon: 'fa-brain', color: UI_COLORS.primary, order: 3 },
    llm_response: { label: 'LLM Response', icon: 'fa-reply', color: UI_COLORS.success, order: 4 },
    juror: { label: 'Juror', icon: 'fa-user-tie', color: UI_COLORS.orange, order: 5 },
    jury: { label: 'Jury', icon: 'fa-users', color: UI_COLORS.accentTeal, order: 6 },
    prompt_guard_response: {
      label: 'Prompt Guard (Response)',
      icon: 'fa-shield-alt',
      color: UI_COLORS.primary,
      order: 7,
    },
    summary: { label: 'Summary', icon: 'fa-chart-bar', color: UI_COLORS.accentTeal, order: 8 },
  };

function isFailureOutcome(outcome: string | undefined): boolean {
  return (
    outcome === 'rejected' || outcome === 'blocked' || outcome === 'error' || outcome === 'failed'
  );
}

function getOutcomeStyle(outcome: string | undefined): { bg: string; fg: string; badge: string } {
  switch (outcome) {
    case 'approved':
    case 'allowed':
    case 'success':
    case 'selected':
      return {
        bg: withAlpha(UI_COLORS.success, 0.1),
        fg: UI_COLORS.success,
        badge: 'text-bg-success',
      };
    case 'rejected':
    case 'blocked':
    case 'error':
    case 'failed':
      return {
        bg: withAlpha(UI_COLORS.danger, 0.1),
        fg: UI_COLORS.danger,
        badge: 'text-bg-danger',
      };
    case 'masked':
      return {
        bg: withAlpha(UI_COLORS.warning, 0.1),
        fg: UI_COLORS.warning,
        badge: 'text-bg-warning',
      };
    default:
      return {
        bg: withAlpha(UI_COLORS.neutralMuted, 0.1),
        fg: UI_COLORS.neutralMuted,
        badge: 'text-bg-secondary',
      };
  }
}

// The LLM Processing stage (`llm_request`) carries no outcome of its own — its
// success is reported by the paired `llm_response`. Derive an effective outcome
// so the stage reads as success/failure rather than a neutral grey.
function effectiveOutcome(stage: StageData, stages: StageData[]): string | undefined {
  if (stage.payload.outcome) return stage.payload.outcome;
  if (stage.stage === 'llm_request') {
    const response = stages.find(s => s.stage === 'llm_response');
    if (response) return response.payload.outcome;
    const failed = stages.some(s => isFailureOutcome(s.payload.outcome));
    return failed ? undefined : 'success';
  }
  return undefined;
}

// ── Stage card renderers ──

// Compact per-stage token/cost line. Judge, Jury and Juror cards each carry
// their own usage now, so their spend is visible inline rather than being
// folded silently into the summary total.
function StageUsageLine({ payload }: { payload: Record<string, any> }) {
  const hasTokens = payload.tokens !== undefined && payload.tokens !== null;
  const hasCost = payload.cost !== undefined && payload.cost !== null;
  if (!hasTokens && !hasCost) return null;
  return (
    <div
      className="mt-1 d-flex flex-wrap align-items-center"
      style={{ gap: '10px', fontSize: '11px', color: UI_COLORS.neutralMuted }}
    >
      {hasTokens && (
        <span>
          <i className="fas fa-coins me-1" style={{ color: UI_COLORS.orange }} />
          {payload.tokens} tok
          {payload.input_tokens !== undefined && (
            <span className="ms-1">
              ({payload.input_tokens}↑ {payload.output_tokens}↓)
            </span>
          )}
        </span>
      )}
      {hasCost && <span>${Number(payload.cost).toFixed(6)}</span>}
    </div>
  );
}

function renderPromptGuard(data: StageData, direction: string) {
  const outcome = data.payload.outcome || 'unknown';
  const style = getOutcomeStyle(outcome);
  return (
    <div className="d-flex align-items-center justify-content-between">
      <span>{data.payload.detail || direction}</span>
      <span className={`badge ${style.badge}`} style={{ fontSize: '11px' }}>
        {outcome.toUpperCase()}
      </span>
    </div>
  );
}

function renderDecider(data: StageData) {
  const p = data.payload;
  const routed = p.outcome === 'selected';
  const style = getOutcomeStyle(routed ? 'success' : p.outcome);
  return (
    <div>
      <div className="d-flex align-items-center justify-content-between mb-1">
        <span style={{ fontSize: '12px' }}>
          <span className="text-muted" style={{ fontSize: '11px' }}>
            Routed to:
          </span>{' '}
          <strong>{p.name || p.candidate || '—'}</strong>
        </span>
        <span className={`badge ${style.badge}`} style={{ fontSize: '11px' }}>
          {(p.outcome || 'unknown').toUpperCase()}
        </span>
      </div>
      <div style={{ fontSize: '11px', color: UI_COLORS.neutralMuted }}>
        {p.candidate && (
          <span>
            id: <code style={{ fontSize: '10px' }}>{p.candidate}</code>
          </span>
        )}
        {(p.provider || p.model) && (
          <span className="ms-2">
            {p.provider}
            {p.provider && p.model ? '/' : ''}
            {p.model}
          </span>
        )}
      </div>
      {p.reasoning && (
        <div
          className="mt-1"
          style={{ fontSize: '11px', color: UI_COLORS.neutralMuted, fontStyle: 'italic' }}
        >
          <span className="text-muted" style={{ fontStyle: 'normal' }}>
            Why:
          </span>{' '}
          {p.reasoning}
        </div>
      )}
      <StageUsageLine payload={data.payload} />
    </div>
  );
}

function renderJudge(data: StageData) {
  const outcome = data.payload.outcome || 'unknown';
  const style = getOutcomeStyle(outcome);
  return (
    <div>
      <div className="d-flex align-items-center justify-content-between mb-1">
        <span>
          <span className="text-muted" style={{ fontSize: '11px' }}>
            Mode:
          </span>{' '}
          <span style={{ fontSize: '12px' }}>{data.payload.mode || '—'}</span>
        </span>
        <span className={`badge ${style.badge}`} style={{ fontSize: '11px' }}>
          {outcome.toUpperCase()}
        </span>
      </div>
      <div style={{ fontSize: '11px', color: UI_COLORS.neutralMuted }}>
        {data.payload.provider}/{data.payload.model} &middot; {data.payload.rules} rule(s)
      </div>
      {data.payload.reason && (
        <div className="mt-1" style={{ fontSize: '11px', color: style.fg }}>
          {data.payload.reason}
        </div>
      )}
      <StageUsageLine payload={data.payload} />
    </div>
  );
}

function renderLlmRequest(data: StageData, effOutcome?: string) {
  const style = effOutcome ? getOutcomeStyle(effOutcome) : null;
  return (
    <div className="d-flex align-items-center justify-content-between">
      <div style={{ fontSize: '12px' }}>
        <span className="text-muted" style={{ fontSize: '11px' }}>
          Provider:
        </span>{' '}
        <strong>{data.payload.provider}</strong>
        <span className="mx-2 text-muted">|</span>
        <span className="text-muted" style={{ fontSize: '11px' }}>
          Model:
        </span>{' '}
        <strong>{data.payload.model}</strong>
        {data.payload.attempt !== 'initial' && (
          <>
            <span className="mx-2 text-muted">|</span>
            <span className="badge text-bg-warning" style={{ fontSize: '10px' }}>
              {data.payload.attempt}
            </span>
          </>
        )}
      </div>
      {style && (
        <span className={`badge ${style.badge}`} style={{ fontSize: '11px' }}>
          {effOutcome!.toUpperCase()}
        </span>
      )}
    </div>
  );
}

function renderLlmResponse(data: StageData) {
  const outcome = data.payload.outcome || 'unknown';
  const style = getOutcomeStyle(outcome);
  const isError = outcome === 'error' || outcome === 'failed';
  return (
    <div>
      <div className="d-flex align-items-center justify-content-between">
        <span style={{ fontSize: '12px' }}>{isError ? 'Request failed' : 'Response received'}</span>
        <span className={`badge ${style.badge}`} style={{ fontSize: '11px' }}>
          {outcome.toUpperCase()}
        </span>
      </div>
      {isError && data.payload.error && (
        <div className="mt-1" style={{ fontSize: '11px', color: style.fg }}>
          {data.payload.error}
        </div>
      )}
    </div>
  );
}

function renderJuror(data: StageData) {
  const outcome = data.payload.outcome || 'unknown';
  const style = getOutcomeStyle(outcome);
  return (
    <div>
      <div className="d-flex align-items-center justify-content-between">
        <span style={{ fontSize: '12px' }}>
          <strong>{data.payload.name}</strong>
          <span className="text-muted ms-2" style={{ fontSize: '11px' }}>
            {data.payload.provider}/{data.payload.model}
          </span>
        </span>
        <span className={`badge ${style.badge}`} style={{ fontSize: '11px' }}>
          {outcome.toUpperCase()}
        </span>
      </div>
      {(data.payload.reason || data.payload.detail) && (
        <div className="mt-1" style={{ fontSize: '11px', color: style.fg }}>
          {data.payload.reason || data.payload.detail}
        </div>
      )}
      <StageUsageLine payload={data.payload} />
    </div>
  );
}

function renderJury(data: StageData) {
  const outcome = data.payload.outcome || 'unknown';
  const style = getOutcomeStyle(outcome);
  return (
    <div>
      <div className="d-flex align-items-center justify-content-between mb-1">
        <span style={{ fontSize: '12px' }}>
          <span className="text-muted" style={{ fontSize: '11px' }}>
            Mode:
          </span>{' '}
          {data.payload.mode || '—'}
        </span>
        <span className={`badge ${style.badge}`} style={{ fontSize: '11px' }}>
          {outcome.toUpperCase()}
        </span>
      </div>
      <div style={{ fontSize: '11px', color: UI_COLORS.neutralMuted }}>
        {data.payload.approved !== undefined && (
          <span>
            {data.payload.approved}/
            {data.payload.total || data.payload.approved + (data.payload.rejected || 0)} juror(s)
            approved
          </span>
        )}
      </div>
      {data.payload.reason && (
        <div className="mt-1" style={{ fontSize: '11px', color: style.fg }}>
          {data.payload.reason}
        </div>
      )}
      <StageUsageLine payload={data.payload} />
    </div>
  );
}

function renderSummary(data: StageData) {
  const p = data.payload;
  const breakdown: Array<{ label: string; tokens?: number; cost?: number }> = [];
  // Decider routes first, so it leads the breakdown when it ran.
  if (p.decider_active || (p.decider_tokens ?? 0) > 0 || (p.decider_cost ?? 0) > 0) {
    breakdown.push({ label: 'Decider', tokens: p.decider_tokens, cost: p.decider_cost });
  }
  if (p.llm_tokens !== undefined || p.llm_cost !== undefined) {
    breakdown.push({ label: 'LLM', tokens: p.llm_tokens, cost: p.llm_cost });
  }
  // Show Judge whenever it ran — a Moderation-mode judge is free (zero
  // tokens/cost) but still a stage that executed.
  if (p.judge_active || (p.judge_tokens ?? 0) > 0 || (p.judge_cost ?? 0) > 0) {
    breakdown.push({ label: 'Judge', tokens: p.judge_tokens, cost: p.judge_cost });
  }
  if (p.jury_active || (p.jury_tokens ?? 0) > 0 || (p.jury_cost ?? 0) > 0) {
    breakdown.push({ label: 'Jury', tokens: p.jury_tokens, cost: p.jury_cost });
  }
  // Only worth a separate row once Decider/Judge/Jury actually contributed — a
  // plain LLM-only call needs no breakdown beyond the totals above.
  const hasStageBreakdown = breakdown.length > 1;
  return (
    <div>
      <div className="d-flex flex-wrap" style={{ gap: '12px', fontSize: '12px' }}>
        <div>
          <div className="text-muted" style={{ fontSize: '10px' }}>
            TOTAL TOKENS
          </div>
          <strong>{p.tokens ?? '—'}</strong>
          {p.input_tokens !== undefined && (
            <span className="text-muted ms-1" style={{ fontSize: '10px' }}>
              ({p.input_tokens}↑ {p.output_tokens}↓)
            </span>
          )}
        </div>
        <div>
          <div className="text-muted" style={{ fontSize: '10px' }}>
            TOTAL COST
          </div>
          <strong>${(p.cost ?? 0).toFixed(6)}</strong>
        </div>
        <div>
          <div className="text-muted" style={{ fontSize: '10px' }}>
            LATENCY
          </div>
          <strong>{p.latency_ms ?? '—'}ms</strong>
        </div>
        <div>
          <div className="text-muted" style={{ fontSize: '10px' }}>
            PROVIDER
          </div>
          <strong>
            {p.provider}/{p.model}
          </strong>
        </div>
      </div>
      {hasStageBreakdown && (
        <div
          className="mt-2 pt-2"
          style={{ borderTop: `1px solid ${withAlpha(UI_COLORS.neutralMuted, 0.2)}` }}
        >
          <div className="text-muted mb-1" style={{ fontSize: '10px' }}>
            BREAKDOWN BY STAGE
          </div>
          <div className="d-flex flex-wrap" style={{ gap: '14px', fontSize: '11px' }}>
            {breakdown.map(b => (
              <span key={b.label}>
                <span className="text-muted">{b.label}:</span> <strong>{b.tokens ?? 0}</strong> tok
                {b.cost !== undefined && (
                  <span className="text-muted ms-1">&middot; ${Number(b.cost).toFixed(6)}</span>
                )}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function renderStageContent(data: StageData, effOutcome?: string) {
  switch (data.stage) {
    case 'decider':
      return renderDecider(data);
    case 'prompt_guard_request':
      return renderPromptGuard(data, 'Request');
    case 'prompt_guard_response':
      return renderPromptGuard(data, 'Response');
    case 'judge':
      return renderJudge(data);
    case 'llm_request':
      return renderLlmRequest(data, effOutcome);
    case 'llm_response':
      return renderLlmResponse(data);
    case 'juror':
      return renderJuror(data);
    case 'jury':
      return renderJury(data);
    case 'summary':
      return renderSummary(data);
    default:
      return (
        <pre style={{ fontSize: '11px', margin: 0 }}>{JSON.stringify(data.payload, null, 2)}</pre>
      );
  }
}

// ── Clear-cutoff persistence ──
// The cleared-before timestamp is stored per pipe so clearing the activity
// survives a page refresh (log entries are re-fetched from a shared rolling
// log tail, so without this the cleared runs reappear).
const CLEAR_KEY_PREFIX = 'pipe-activity-clear:';

function readClearTimestamp(pipeId: string): number {
  try {
    const raw = localStorage.getItem(CLEAR_KEY_PREFIX + pipeId);
    const value = raw ? Number(raw) : 0;
    return Number.isFinite(value) ? value : 0;
  } catch {
    return 0;
  }
}

function writeClearTimestamp(pipeId: string, ts: number): void {
  try {
    localStorage.setItem(CLEAR_KEY_PREFIX + pipeId, String(ts));
  } catch {
    // Ignore storage failures (private mode / quota) — clearing still works
    // for the current session via component state.
  }
}

// The sandbox only surfaces recent activity: runs older than this window are
// hidden even though they remain in the shared rolling log tail we fetch.
const RECENT_ACTIVITY_WINDOW_MS = 15 * 60 * 1000;

// ── Main Component ──

const PipeActivityViewer: React.FC<PipeActivityViewerProps> = ({
  pipeId,
  pipeName,
  height,
  pendingSince,
  pendingError,
}) => {
  const { getCurrentStats } = useApp();
  const { hasPermission } = usePermissions();
  const mayReadLogs = hasPermission('logs.view');
  const [showRawLogs, setShowRawLogs] = useState(false);
  const [expandedRun, setExpandedRun] = useState<number | null>(null);
  const [clearTimestamp, setClearTimestamp] = useState<number>(() => readClearTimestamp(pipeId));
  // Ticks so the 15-minute recency window keeps sliding even when no new logs
  // arrive to trigger a re-render.
  const [now, setNow] = useState<number>(() => Date.now());
  const containerRef = useRef<HTMLDivElement>(null);

  // Re-read the persisted cutoff if the viewer is reused for a different pipe.
  useEffect(() => {
    setClearTimestamp(readClearTimestamp(pipeId));
  }, [pipeId]);

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(id);
  }, []);

  const handleClear = () => {
    const ts = Date.now();
    writeClearTimestamp(pipeId, ts);
    setClearTimestamp(ts);
  };

  const stats = getCurrentStats();
  const allLogEntries: LogEntry[] = useMemo(
    () => stats?.proxy_info?.log_entries || [],
    [stats?.proxy_info?.log_entries]
  );

  const filterPrefix = `[PIPE:${pipeId}]`;

  // Filter to this pipe's logs, respecting the clear cutoff and the 15-minute
  // recency window (whichever is later wins).
  const recentCutoff = Math.max(clearTimestamp, now - RECENT_ACTIVITY_WINDOW_MS);
  const pipeLogEntries = useMemo(
    () =>
      allLogEntries.filter(e => e.message.includes(filterPrefix) && e.timestamp >= recentCutoff),
    [allLogEntries, filterPrefix, recentCutoff]
  );

  // Group logs into pipeline runs (delimited by summary completion or very large time gaps)
  const runs: PipelineRun[] = useMemo(() => {
    if (pipeLogEntries.length === 0) return [];

    const result: PipelineRun[] = [];
    let currentRun: PipelineRun = { id: 0, stages: [], rawLogs: [], timestamp: 0 };
    let runId = 0;
    // Tracks whether the current run reached a terminal outcome (summary or a
    // non-jury terminal rejection). A jury rejection is NOT terminal on its own
    // because it may trigger a redrive (retry) that continues the same run.
    let currentRunCompleted = false;

    for (const entry of pipeLogEntries) {
      const cleanMsg = entry.message.replace(filterPrefix, '').trim();
      const stageMatch = parseStageTag(cleanMsg);

      // An "entry stage" is the first stage of a fresh client request: a request
      // prompt guard, a judge, or the initial (non-retry) LLM call. A redriven
      // LLM call after a jury rejection carries attempt="retry N/M" and is NOT an
      // entry stage, so it stays inside the same run/container.
      const attempt = stageMatch ? String(stageMatch.payload.attempt ?? 'initial') : 'initial';
      const isEntryStage =
        !!stageMatch &&
        (stageMatch.stage === 'prompt_guard_request' ||
          stageMatch.stage === 'judge' ||
          (stageMatch.stage === 'llm_request' && attempt === 'initial'));

      const lastStage =
        currentRun.stages.length > 0 ? currentRun.stages[currentRun.stages.length - 1] : undefined;
      // A terminal jury rejection (max retries exhausted) is not flagged by the
      // backend, but it is revealed when the next thing we see is the entry stage
      // of a brand-new request rather than a retry LLM call.
      const lastWasJuryRejection =
        !!lastStage &&
        lastStage.stage === 'jury' &&
        (lastStage.payload.outcome === 'rejected' || lastStage.payload.outcome === 'blocked');
      const veryLargeGap =
        currentRun.rawLogs.length > 0 &&
        entry.timestamp - currentRun.rawLogs[currentRun.rawLogs.length - 1].timestamp > 120_000;

      // Start a new run only at the boundary of a genuinely separate execution:
      // 1. the previous run completed (summary / terminal guard or judge rejection)
      //    and a new stage has begun, OR
      // 2. a terminal jury rejection is followed by the entry stage of a new request, OR
      // 3. a very large time gap (>120s) indicates a truly separate execution.
      const startNewRun =
        currentRun.stages.length > 0 &&
        ((!!stageMatch && currentRunCompleted) ||
          (isEntryStage && lastWasJuryRejection) ||
          veryLargeGap);

      if (startNewRun) {
        result.push(currentRun);
        runId++;
        currentRun = { id: runId, stages: [], rawLogs: [], timestamp: 0 };
        currentRunCompleted = false;
      }

      if (currentRun.timestamp === 0) {
        currentRun.timestamp = entry.timestamp;
      }

      currentRun.rawLogs.push(entry);

      if (stageMatch) {
        currentRun.stages.push({
          stage: stageMatch.stage,
          payload: stageMatch.payload,
          timestamp: entry.timestamp,
          level: entry.level,
          raw: cleanMsg,
        });

        if (stageMatch.stage === 'summary') {
          currentRunCompleted = true;
        } else if (
          (stageMatch.stage === 'prompt_guard_request' ||
            stageMatch.stage === 'prompt_guard_response' ||
            stageMatch.stage === 'judge') &&
          (stageMatch.payload.outcome === 'rejected' || stageMatch.payload.outcome === 'blocked')
        ) {
          currentRunCompleted = true;
        } else if (
          stageMatch.stage === 'llm_response' &&
          (stageMatch.payload.outcome === 'error' || stageMatch.payload.outcome === 'failed')
        ) {
          currentRunCompleted = true;
        }
      }
    }

    // Push final run
    if (currentRun.stages.length > 0) {
      result.push(currentRun);
    }

    return result;
  }, [pipeLogEntries, filterPrefix]);

  // Show the optimistic placeholder while a request is in flight, until the
  // real pipeline logs for it land (a small tolerance absorbs client/server
  // clock skew, matching the existing Date.now()-vs-log-timestamp comparisons).
  const showPending =
    !!pendingSince &&
    !pendingError &&
    !runs.some(r => r.timestamp >= (pendingSince as number) - 2000);

  // Show a terminal error card for a failure that produced no stage logs
  // (rate limit, policy denial, network, variant). It persists as a session
  // card until the next request, and is hidden once the activity is cleared.
  const showPendingError =
    !!pendingError &&
    pendingError.since >= clearTimestamp &&
    !runs.some(r => r.timestamp >= pendingError.since - 2000);

  // Auto-expand latest run. While a request is in flight, collapse the previous
  // runs so the optimistic placeholder is the focus.
  useEffect(() => {
    if (showPending || showPendingError) {
      setExpandedRun(null);
    } else if (runs.length > 0) {
      setExpandedRun(runs[runs.length - 1].id);
    }
  }, [runs.length, showPending, showPendingError]);

  // Auto-scroll to bottom so the newest run (or the pending placeholder) is in view.
  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [runs, showPending, showPendingError]);

  const formatTime = (ts: number) => {
    const d = new Date(ts);
    return d.toLocaleTimeString(undefined, {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  };

  return (
    <div className="card shadow mb-4">
      <div className="card-header sandbox-panel-header d-flex justify-content-between align-items-center">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-stream me-2"></i>LLM Activity {pipeName && `- ${pipeName}`}
        </h6>
        <div className="d-flex align-items-center">
          <button
            className="btn btn-sm btn-outline-danger me-2"
            onClick={handleClear}
            title="Clear activity history"
            disabled={runs.length === 0 && pipeLogEntries.length === 0}
          >
            <i className="fas fa-trash"></i>
          </button>
          {mayReadLogs && (
            <button
              className={`btn btn-sm ${showRawLogs ? 'btn-secondary' : 'btn-outline-secondary'} me-2`}
              onClick={() => setShowRawLogs(!showRawLogs)}
              title="Toggle raw log view"
            >
              <i className={`fas fa-${showRawLogs ? 'th-list' : 'code'} me-1`}></i>
              {showRawLogs ? 'Pipeline' : 'Raw'}
            </button>
          )}
          <small className="text-muted">
            {runs.length + (showPending || showPendingError ? 1 : 0)} run
            {runs.length + (showPending || showPendingError ? 1 : 0) !== 1 ? 's' : ''}
          </small>
        </div>
      </div>
      <div
        ref={containerRef}
        className="card-body p-3 pipe-activity-body"
        style={{
          ...(height === '100%'
            ? { flex: '1 1 auto', minHeight: 0 }
            : { height: height || '500px' }),
          overflowY: 'auto',
        }}
      >
        {!mayReadLogs ? (
          <>
            <div className="text-center text-muted py-5" data-testid="pipe-activity-logs-required">
              <i className="fas fa-lock" style={{ fontSize: '2.5rem', opacity: 0.3 }}></i>
              <p className="mt-3" style={{ fontSize: '13px' }}>
                Pipeline activity is built from the appliance log and requires the logs.view
                permission.
              </p>
            </div>
            {showPendingError && pendingError && (
              <PendingErrorCard error={pendingError} formatTime={formatTime} />
            )}
          </>
        ) : runs.length === 0 && !showPending && !showPendingError && !showRawLogs ? (
          <div className="text-center text-muted py-5">
            <i className="fas fa-stream" style={{ fontSize: '2.5rem', opacity: 0.3 }}></i>
            <p className="mt-3" style={{ fontSize: '13px' }}>
              Activity details will appear here when you type and send a message.
            </p>
            <p style={{ fontSize: '11px', opacity: 0.7 }}>
              Each stage of the Surface pipeline (Prompt Guard → Judge → LLM → Jury → Response
              Guard) is shown as a card in this list.
            </p>
          </div>
        ) : showRawLogs ? (
          <RawLogView entries={pipeLogEntries} filterPrefix={filterPrefix} />
        ) : (
          <>
            {runs.map(run => (
              <PipelineRunCard
                key={run.id}
                run={run}
                expanded={expandedRun === run.id}
                onToggle={() => setExpandedRun(expandedRun === run.id ? null : run.id)}
                formatTime={formatTime}
              />
            ))}
            {showPending && (
              <PendingRunCard since={pendingSince as number} formatTime={formatTime} />
            )}
            {showPendingError && pendingError && (
              <PendingErrorCard error={pendingError} formatTime={formatTime} />
            )}
          </>
        )}
      </div>
    </div>
  );
};

// ── Pending Run Card ──
// Optimistic placeholder shown the instant a request is sent, before any
// pipeline logs have been fetched. Replaced by the real run card once stage
// logs for the request arrive.

const PendingRunCard: React.FC<{ since: number; formatTime: (ts: number) => string }> = ({
  since,
  formatTime,
}) => (
  <div
    className="mb-3 border rounded pipe-run-card"
    style={{
      borderColor: 'var(--gray-300)',
      borderLeftWidth: '3px',
      borderLeftColor: UI_COLORS.primary,
    }}
  >
    <div
      className="d-flex align-items-center px-3 py-2"
      style={{ background: withAlpha(UI_COLORS.primary, 0.04) }}
    >
      <span
        className="spinner-border spinner-border-sm text-primary me-2"
        role="status"
        style={{ width: '12px', height: '12px', borderWidth: '2px' }}
      />
      <span style={{ fontSize: '12px', fontWeight: 600 }}>{formatTime(since)}</span>
      <span className="mx-2 text-muted">—</span>
      <span className="text-muted" style={{ fontSize: '12px' }}>
        Processing through pipeline…
      </span>
    </div>
  </div>
);

// ── Pending Error Card ──
// Terminal session card for an in-flight request that failed before any
// pipeline stage logs were emitted (rate limit, policy denial, network,
// variant resolution). Keeps the failed request visible with its reason
// instead of letting the panel revert to the previous run.

const PendingErrorCard: React.FC<{
  error: { since: number; httpStatus?: number; message: string; label: string };
  formatTime: (ts: number) => string;
}> = ({ error, formatTime }) => (
  <div
    className="mb-3 border rounded pipe-run-card"
    style={{
      borderColor: UI_COLORS.danger,
      borderLeftWidth: '3px',
      borderLeftColor: UI_COLORS.danger,
    }}
  >
    <div
      className="d-flex align-items-center px-3 py-2"
      style={{ background: withAlpha(UI_COLORS.danger, 0.04) }}
    >
      <i
        className="fas fa-exclamation-circle me-2"
        style={{ color: UI_COLORS.danger, fontSize: '13px' }}
      />
      <span style={{ fontSize: '12px', fontWeight: 600 }}>{formatTime(error.since)}</span>
      <span className="mx-2 text-muted">—</span>
      <span className="badge text-bg-danger" style={{ fontSize: '11px' }}>
        {error.label}
        {error.httpStatus ? ` · ${error.httpStatus}` : ''}
      </span>
      <span className="ms-2 text-muted" style={{ fontSize: '12px' }}>
        Request did not proceed
      </span>
    </div>
    <div
      className="px-3 py-2"
      style={{
        fontSize: '12px',
        color: UI_COLORS.danger,
        borderTop: `1px solid ${withAlpha(UI_COLORS.danger, 0.15)}`,
      }}
    >
      {error.message}
    </div>
  </div>
);

// ── Pipeline Run Card ──

// ── Duration helper ──

function formatDuration(ms: number): string {
  if (ms < 10) return '<0.01s';
  const seconds = ms / 1000;
  if (seconds < 10) return `${seconds.toFixed(2)}s`;
  return `${seconds.toFixed(1)}s`;
}

const PipelineRunCard: React.FC<{
  run: PipelineRun;
  expanded: boolean;
  onToggle: () => void;
  formatTime: (ts: number) => string;
}> = ({ run, expanded, onToggle, formatTime }) => {
  // Find summary stage for the header
  const summary = run.stages.find(s => s.stage === 'summary');
  const hasFault = run.stages.some(s => isFailureOutcome(s.payload.outcome));
  const stagesWithoutSummary = run.stages.filter(s => s.stage !== 'summary');

  // Merge consecutive juror stages into a visual group
  const groupedStages = groupJurorStages(stagesWithoutSummary);

  return (
    <div
      className="mb-3 border rounded pipe-run-card"
      style={{
        borderColor: hasFault ? UI_COLORS.danger : 'var(--gray-300)',
        borderLeftWidth: '3px',
        borderLeftColor: hasFault ? UI_COLORS.danger : UI_COLORS.success,
      }}
    >
      {/* Run header */}
      <div
        className="d-flex align-items-center justify-content-between px-3 py-2"
        style={{
          cursor: 'pointer',
          background: hasFault
            ? withAlpha(UI_COLORS.danger, 0.03)
            : withAlpha(UI_COLORS.success, 0.03),
        }}
        onClick={onToggle}
      >
        <div className="d-flex align-items-center">
          <i
            className={`fas fa-chevron-${expanded ? 'down' : 'right'} me-2 text-muted`}
            style={{ fontSize: '10px', width: '10px' }}
          ></i>
          <span style={{ fontSize: '12px', fontWeight: 600 }}>{formatTime(run.timestamp)}</span>
          <span className="mx-2 text-muted">—</span>
          {/* Stage pill indicators */}
          <div className="d-flex" style={{ gap: '3px' }}>
            {run.stages.map((s, i) => {
              const cfg = STAGE_CONFIG[s.stage];
              if (!cfg || s.stage === 'summary') return null;
              const outcome = effectiveOutcome(s, run.stages);
              const outcomeStyle = getOutcomeStyle(outcome);
              return (
                <span
                  key={i}
                  title={`${cfg.label}: ${outcome || 'ok'}`}
                  style={{
                    width: '8px',
                    height: '8px',
                    borderRadius: '50%',
                    background: outcomeStyle.fg,
                    display: 'inline-block',
                  }}
                />
              );
            })}
          </div>
        </div>
        {summary && (
          <div className="d-flex align-items-center" style={{ gap: '10px', fontSize: '11px' }}>
            <span className="text-muted">{summary.payload.tokens} tokens</span>
            <span className="text-muted">${(summary.payload.cost ?? 0).toFixed(4)}</span>
            <span className="text-muted">{summary.payload.latency_ms}ms</span>
          </div>
        )}
      </div>

      {/* Expanded stages */}
      {expanded && (
        <div className="px-3 pb-3 pt-1">
          {/* Stage pipeline */}
          <div style={{ position: 'relative' }}>
            {groupedStages.map((item, idx) => (
              <StageCard
                key={idx}
                item={item}
                isLast={idx === groupedStages.length - 1}
                runStages={run.stages}
              />
            ))}
          </div>

          {/* Summary footer */}
          {summary && (
            <div
              className="mt-2 p-2 rounded"
              style={{
                background: withAlpha(UI_COLORS.success, 0.06),
                border: `1px solid ${withAlpha(UI_COLORS.success, 0.2)}`,
              }}
            >
              {renderStageContent(summary)}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// ── Grouping helper for juror stages ──

type GroupedItem = { type: 'stage'; data: StageData } | { type: 'jurors'; data: StageData[] };

function groupJurorStages(stages: StageData[]): GroupedItem[] {
  const result: GroupedItem[] = [];
  let jurorBuffer: StageData[] = [];

  for (const s of stages) {
    if (s.stage === 'juror') {
      jurorBuffer.push(s);
    } else {
      if (jurorBuffer.length > 0) {
        result.push({ type: 'jurors', data: jurorBuffer });
        jurorBuffer = [];
      }
      result.push({ type: 'stage', data: s });
    }
  }
  if (jurorBuffer.length > 0) {
    result.push({ type: 'jurors', data: jurorBuffer });
  }
  return result;
}

// ── Stage Card ──

const StageDetails: React.FC<{ payload: Record<string, any>; raw?: string }> = ({
  payload,
  raw,
}) => {
  const [open, setOpen] = useState(false);
  const hasPayload = !!payload && Object.keys(payload).length > 0;
  if (!hasPayload && !raw) return null;
  return (
    <div className="mt-1">
      <button
        type="button"
        className="btn btn-link p-0 text-decoration-none"
        style={{ fontSize: '10px' }}
        onClick={() => setOpen(o => !o)}
      >
        <i
          className={`fas fa-chevron-${open ? 'down' : 'right'} me-1`}
          style={{ fontSize: '8px' }}
        />
        {open ? 'Hide details' : 'Details'}
      </button>
      {open && (
        <pre
          style={{
            fontSize: '10px',
            margin: '4px 0 0',
            maxHeight: '220px',
            overflow: 'auto',
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-word',
          }}
        >
          {hasPayload ? JSON.stringify(payload, null, 2) : raw}
        </pre>
      )}
    </div>
  );
};

const StageCard: React.FC<{ item: GroupedItem; isLast: boolean; runStages: StageData[] }> = ({
  item,
  isLast,
  runStages,
}) => {
  if (item.type === 'jurors') {
    // Sum up all juror durations for the group total
    const totalMs = item.data.reduce((sum, j) => sum + (j.payload.duration_ms ?? 0), 0);
    return (
      <div className="d-flex mb-2">
        {/* Connector line */}
        <div className="d-flex flex-column align-items-center me-2" style={{ width: '24px' }}>
          <div
            style={{
              width: '24px',
              height: '24px',
              borderRadius: '50%',
              background: STAGE_CONFIG.juror.color,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
            }}
          >
            <i
              className={`fas ${STAGE_CONFIG.juror.icon} text-white`}
              style={{ fontSize: '10px' }}
            ></i>
          </div>
          {!isLast && (
            <div
              style={{ width: '2px', flex: 1, background: 'var(--gray-300)', marginTop: '2px' }}
            />
          )}
        </div>
        {/* Jurors group */}
        <div className="flex-grow-1">
          <div className="d-flex align-items-center justify-content-between mb-1">
            <span
              className="font-weight-bold"
              style={{ fontSize: '11px', color: STAGE_CONFIG.juror.color }}
            >
              Jurors ({item.data.length})
            </span>
            {totalMs > 0 && (
              <span className="text-muted" style={{ fontSize: '10px', fontFamily: 'monospace' }}>
                {formatDuration(totalMs)}
              </span>
            )}
          </div>
          <div className="d-flex flex-column" style={{ gap: '4px' }}>
            {item.data.map((juror, i) => {
              const outcomeStyle = getOutcomeStyle(juror.payload.outcome);
              return (
                <div
                  key={i}
                  className="p-2 rounded border"
                  style={{
                    background: outcomeStyle.bg,
                    borderColor: outcomeStyle.fg + '33',
                    fontSize: '12px',
                  }}
                >
                  <div className="flex-grow-1">{renderJuror(juror)}</div>
                  <StageDetails payload={juror.payload} raw={juror.raw} />
                </div>
              );
            })}
          </div>
        </div>
      </div>
    );
  }

  const s = item.data;
  const cfg = STAGE_CONFIG[s.stage] || {
    label: s.stage,
    icon: 'fa-cog',
    color: UI_COLORS.neutralMuted,
    order: 99,
  };
  const effOutcome = effectiveOutcome(s, runStages);
  const outcomeStyle = getOutcomeStyle(effOutcome);
  const durationMs = s.payload.duration_ms;

  return (
    <div className="d-flex mb-2">
      {/* Connector */}
      <div className="d-flex flex-column align-items-center me-2" style={{ width: '24px' }}>
        <div
          style={{
            width: '24px',
            height: '24px',
            borderRadius: '50%',
            background: cfg.color,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0,
          }}
        >
          <i className={`fas ${cfg.icon} text-white`} style={{ fontSize: '10px' }}></i>
        </div>
        {!isLast && (
          <div style={{ width: '2px', flex: 1, background: 'var(--gray-300)', marginTop: '2px' }} />
        )}
      </div>
      {/* Content */}
      <div className="flex-grow-1">
        <div className="d-flex align-items-center justify-content-between mb-1">
          <span className="font-weight-bold" style={{ fontSize: '11px', color: cfg.color }}>
            {cfg.label}
          </span>
          {durationMs != null && (
            <span className="text-muted" style={{ fontSize: '10px', fontFamily: 'monospace' }}>
              {formatDuration(durationMs)}
            </span>
          )}
        </div>
        <div
          className="p-2 rounded border"
          style={{
            background: outcomeStyle.bg,
            borderColor: (outcomeStyle.fg || cfg.color) + '33',
          }}
        >
          {renderStageContent(s, effOutcome)}
          <StageDetails payload={s.payload} raw={s.raw} />
        </div>
      </div>
    </div>
  );
};

// ── Raw Log fallback ──

const RawLogView: React.FC<{ entries: LogEntry[]; filterPrefix: string }> = ({
  entries,
  filterPrefix,
}) => {
  const getLevelColor = (level: string) => {
    switch (level.toUpperCase()) {
      case 'ERROR':
        return '#ff6b6b';
      case 'WARN':
        return '#ffa500';
      case 'INFO':
        return '#4dabf7';
      case 'DEBUG':
        return '#51cf66';
      case 'TRACE':
        return '#868e96';
      default:
        return '#adb5bd';
    }
  };

  if (entries.length === 0) {
    return <div className="text-center text-muted py-5">No logs available</div>;
  }

  return (
    <pre
      className="log-viewer"
      style={{ height: '100%', margin: 0 }}
      dangerouslySetInnerHTML={{
        __html: entries
          .map(entry => {
            const ts = new Date(entry.timestamp).toLocaleTimeString();
            const msg = entry.message.replace(filterPrefix, '').trim();
            return `<span style="color:#888">${escapeHtml(ts)}</span> <span style="color:${getLevelColor(entry.level)};font-weight:bold">${escapeHtml(entry.level)}</span> ${escapeHtml(msg)}`;
          })
          .join('\n'),
      }}
    />
  );
};

export default PipeActivityViewer;
