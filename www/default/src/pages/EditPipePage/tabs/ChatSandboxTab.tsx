import React, { useState, useRef, useEffect } from 'react';
import { apiClient } from '../../../api';
import { useApp } from '../../../context/AppContext';
import PipeActivityViewer from '../../../components/shared/PipeActivityViewer';
import { mergeStreamedContent } from './streamMerge';
import SandboxMarkdown from './SandboxMarkdown';
import {
  type SandboxAuthConfig,
  type SandboxOAuthProfile,
  type SandboxToken,
  clearSandboxToken,
  readSandboxToken,
  sandboxAuthUsable,
  signInToTest,
} from '../../../utils/sandboxAuth';

// ── Types ──

interface ChatMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

interface ConversationEntry extends ChatMessage {
  timestamp: string;
  model?: string;
  tokens?: { prompt: number; completion: number; total: number };
  latencyMs?: number;
  cost?: number;
  error?: boolean;
  /** If the response was rejected by judge/jury/prompt-guard */
  rejected?: boolean;
  rejectedBy?: string;
  /** True while a streamed response is still being appended to this entry. */
  streaming?: boolean;
  /** Per-candidate answers when a Mirror decider ran in Collect mode. */
  mirrorCandidates?: MirrorCandidateView[];
}

/** One candidate answer from a Mirror/Collect response (`response.x_mirror.candidates`). */
interface MirrorCandidateView {
  id: string;
  name: string;
  provider?: string;
  model?: string;
  content?: string;
  error?: string | null;
  input_tokens?: number;
  output_tokens?: number;
  cost?: number;
  latency_ms?: number;
}

export interface ChatSandboxTabProps {
  pipeId: string;
  formData: {
    name: string;
    provider: string;
    model: string;
    listen_address: string;
    route: string;
    enabled: boolean;
    judge?: any;
    jury?: any;
    prompt_guard?: any;
    /**
     * Identity pass-through: when true the surface forwards the caller's
     * validated bearer token upstream, so the sandbox can only exercise it with
     * a signed-in delegated token — "no sign-in" is not a valid option.
     */
    forward_caller_token?: boolean;
  };
  /**
   * Named variants the pipe exposes (base is implicit and always selectable).
   * Lets the sandbox execute a specific `$alias` variant — the selected alias
   * is sent to the execute API, which resolves the variant before running.
   * Only saved variants resolve; selecting an unsaved one surfaces an error.
   */
  variants?: Array<{ alias: string; name: string; enabled?: boolean }>;
  /** Alias of the default variant, used as the initial dropdown selection. */
  defaultVariantAlias?: string | null;
  /**
   * Optional OAuth (PKCE) sign-in config resolved from the surface's referenced
   * OAuth Identifier profile, its inline `sandbox_auth`, or the provider catalog
   * default (in that order). When present, the sandbox shows a "Sign in to test"
   * bar and forwards the acquired delegated token as the caller identity (e.g.
   * for a Microsoft 365 Copilot surface that forwards the caller's token).
   */
  sandboxAuth?: SandboxAuthConfig | null;
  /**
   * OAuth Identifier profiles (Credentials store) selectable as this surface's
   * sandbox sign-in identity — the preferred alternative to an inline
   * `sandbox_auth` block or a provider default in `llm.json`.
   */
  oauthProfiles?: SandboxOAuthProfile[];
  /** Currently referenced OAuth Identifier profile id, or `null`. */
  sandboxOAuthIdentifierId?: string | null;
  /**
   * The profile the sandbox will actually sign in with — the explicit reference
   * if set, otherwise an auto-picked one (e.g. the only OAuth Identifier for an
   * identity-pass-through surface). Shown as the selected value in the picker so
   * the operator sees which identity a sign-in would use, even before they pin a
   * reference. `null` when nothing is referenced or auto-resolvable.
   */
  effectiveProfileId?: string | null;
  /**
   * Why `effectiveProfileId` was auto-picked (only when not an explicit
   * reference): `'tenant'` = its Entra tenant matches the surface's Caller
   * Context verification strategy; `'single'` = it is the only OAuth Identifier.
   * Drives the picker's auto-selected hint copy. `null` when not auto-picked.
   */
  autoSelectReason?: 'tenant' | 'single' | null;
  /** Persist the chosen sign-in profile id on the surface (`''` clears it). */
  onSelectSandboxProfile?: (id: string) => void;
}

// Synthetic option value for "run the base pipe with no variant overlay".
const BASE_VARIANT_VALUE = '__base__';

/**
 * Renders the per-candidate answers of a Mirror/Collect response so an operator
 * can compare every model's output side by side and choose the best one.
 */
const MirrorCandidates: React.FC<{ candidates: MirrorCandidateView[] }> = ({ candidates }) => (
  <div className="d-flex flex-column" style={{ gap: '8px' }}>
    <div className="text-muted" style={{ fontSize: '11px' }}>
      <i className="fas fa-layer-group me-1" />
      {candidates.length} candidate answers — compare and choose:
    </div>
    {candidates.map((c, i) => (
      <div
        key={c.id || i}
        className="border rounded p-2"
        style={{ background: 'rgba(0,0,0,0.02)' }}
      >
        <div
          className="d-flex justify-content-between align-items-center mb-1"
          style={{ gap: '8px' }}
        >
          <span style={{ fontSize: '12px', fontWeight: 600 }}>
            {c.name || `Candidate ${i + 1}`}
            {(c.provider || c.model) && (
              <span className="text-muted ms-2" style={{ fontSize: '11px', fontWeight: 400 }}>
                {c.provider}
                {c.provider && c.model ? '/' : ''}
                {c.model}
              </span>
            )}
          </span>
          <span className="text-muted flex-shrink-0" style={{ fontSize: '10px' }}>
            {typeof c.cost === 'number' && c.cost > 0 ? `$${c.cost.toFixed(6)}` : ''}
            {typeof c.latency_ms === 'number' ? ` · ${c.latency_ms}ms` : ''}
          </span>
        </div>
        {c.error ? (
          <div className="text-danger" style={{ fontSize: '12px' }}>
            <i className="fas fa-triangle-exclamation me-1" />
            {c.error}
          </div>
        ) : (
          <SandboxMarkdown text={c.content || ''} />
        )}
      </div>
    ))}
  </div>
);

// ── Component ──

const ChatSandboxTab: React.FC<ChatSandboxTabProps> = ({
  pipeId,
  formData,
  variants = [],
  defaultVariantAlias = null,
  sandboxAuth = null,
  oauthProfiles = [],
  sandboxOAuthIdentifierId = null,
  effectiveProfileId = null,
  autoSelectReason = null,
  onSelectSandboxProfile,
}) => {
  const [systemPrompt, setSystemPrompt] = useState('You are a helpful assistant.');
  const [systemPromptOpen, setSystemPromptOpen] = useState(false);
  const [userMessage, setUserMessage] = useState('');
  const [conversation, setConversation] = useState<ConversationEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [pendingSince, setPendingSince] = useState<number | null>(null);
  // Terminal failure of the in-flight request that produced no pipeline stage
  // logs (rate limit, policy denial, network, variant resolution). Kept as a
  // standalone session card so the activity panel shows what stopped the run
  // instead of silently reverting to the previous run.
  const [pendingError, setPendingError] = useState<{
    since: number;
    httpStatus?: number;
    message: string;
    label: string;
  } | null>(null);
  // Selected variant alias to execute, or BASE_VARIANT_VALUE for the base
  // pipe. Seeds from the pipe's default variant so the sandbox mirrors what
  // an unqualified caller would hit.
  const [selectedVariant, setSelectedVariant] = useState<string>(
    defaultVariantAlias || BASE_VARIANT_VALUE
  );
  const chatEndRef = useRef<HTMLDivElement>(null);
  const { actions } = useApp();

  // ── Sandbox sign-in (OAuth PKCE) ──
  // Delegated token used as the caller identity for surfaces that forward the
  // caller's token (e.g. Microsoft 365 Copilot). Keyed by provider so the token
  // survives tab switches within the session.
  const authEnabled = sandboxAuthUsable(sandboxAuth);
  const [callerToken, setCallerToken] = useState<SandboxToken | null>(() =>
    authEnabled ? readSandboxToken(formData.provider) : null
  );
  const [signingIn, setSigningIn] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);
  // Identity pass-through surfaces forward the caller's token upstream, so the
  // sandbox can only test them signed in — "no sign-in" isn't a valid choice.
  const requiresSignIn = formData.forward_caller_token === true;
  // The run is only ready when either sign-in isn't required, or a token exists.
  const signInReady = !requiresSignIn || !!callerToken;
  // A profile must be picked only when sign-in is required AND no config is
  // otherwise resolvable (an inline block / provider default / auto-picked
  // single profile already yields a usable sign-in, so "None" stays valid).
  const signInProfileRequired = requiresSignIn && !authEnabled;
  // The profile value shown in the picker: the resolved/auto-picked profile
  // (parent-computed) falling back to the persisted reference.
  const displayProfileId = sandboxOAuthIdentifierId ?? effectiveProfileId ?? '';
  const autoSelected = !sandboxOAuthIdentifierId && !!effectiveProfileId;
  // Prefer a live streamed response when the surface supports it. Falls back to
  // the buffered path automatically when the surface is not streaming-eligible.
  const [streamEnabled, setStreamEnabled] = useState(true);
  // 'streaming' while SSE chunks are arriving, 'buffered' for 4s after a 409
  // fallback so the user can see why the toggle had no effect.
  const [streamStatus, setStreamStatus] = useState<'idle' | 'streaming' | 'buffered'>('idle');
  // Stateful upstream conversation id (Microsoft 365 Copilot) returned by the
  // streaming endpoint. Sent back on each follow-up so the surface continues the
  // same Copilot conversation — giving native multi-turn memory instead of
  // re-opening a fresh, context-less conversation every turn. Reset on Clear and
  // whenever the executed variant changes (a different config = a new thread).
  const [conversationId, setConversationId] = useState<string | null>(null);
  useEffect(() => {
    setConversationId(null);
  }, [selectedVariant]);

  // Re-read the stored token whenever the provider changes.
  useEffect(() => {
    setCallerToken(authEnabled ? readSandboxToken(formData.provider) : null);
    setAuthError(null);
  }, [authEnabled, formData.provider]);

  const handleSignIn = async () => {
    if (!authEnabled || !sandboxAuth) return;
    setSigningIn(true);
    setAuthError(null);
    try {
      const token = await signInToTest(formData.provider, sandboxAuth);
      setCallerToken(token);
    } catch (err: any) {
      setAuthError(err?.message || 'Sign-in failed.');
    } finally {
      setSigningIn(false);
    }
  };

  const handleSignOut = () => {
    clearSandboxToken(formData.provider);
    setCallerToken(null);
    setAuthError(null);
  };

  // Keep the selection valid as the variant catalog changes (e.g. an alias is
  // renamed or removed in the builder while the sandbox is open).
  useEffect(() => {
    if (selectedVariant === BASE_VARIANT_VALUE) return;
    if (!variants.some(v => v.alias === selectedVariant)) {
      setSelectedVariant(defaultVariantAlias || BASE_VARIANT_VALUE);
    }
  }, [variants, selectedVariant, defaultVariantAlias]);

  // Scroll to bottom on new messages
  useEffect(() => {
    if (conversation.length > 0) {
      chatEndRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }, [conversation]);

  // While a request is in flight, poll dashboard stats so pipeline stage logs
  // stream into the activity panel live instead of only appearing at the end.
  useEffect(() => {
    if (!loading) return;
    const id = setInterval(() => actions.loadDashboardStats(true), 1000);
    return () => clearInterval(id);
  }, [loading, actions]);

  // Attempt a streamed response via the streaming execute endpoint. Returns
  // 'handled' when the stream ran (success, or an in-stream error rendered
  // inline), or 'fallback' when the surface is not streaming-eligible (HTTP 409)
  // so the caller uses the buffered path. Throws for pre-stream HTTP errors,
  // which the caller's catch renders like a buffered failure.
  const runStreaming = async (
    messages: ChatMessage[],
    startTime: number
  ): Promise<'handled' | 'fallback'> => {
    const reqStart = Date.now();
    // eslint-disable-next-line no-console
    console.log('[sandbox-stream] sending request at t=0');
    const resp = await apiClient.fetch(`/api/v1/pipes/${pipeId}/execute/stream`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        // Signal SSE intent so reverse proxies (e.g. affinidi-simple-proxy) take
        // the streaming path instead of buffering the full response body.
        Accept: 'text/event-stream',
      },
      body: JSON.stringify({
        request: { model: formData.model, messages, stream: true },
        ...(selectedVariant !== BASE_VARIANT_VALUE ? { variant: selectedVariant } : {}),
        ...(callerToken ? { caller_token: callerToken.accessToken } : {}),
        ...(conversationId ? { conversation_id: conversationId } : {}),
      }),
    });

    // eslint-disable-next-line no-console
    console.log(
      '[sandbox-stream] response headers received',
      resp.status,
      'content-type:',
      resp.headers.get('content-type'),
      '| t+' + (Date.now() - reqStart) + 'ms'
    );

    // Surface not streaming-eligible → let the caller fall back to buffered.
    if (resp.status === 409) {
      // eslint-disable-next-line no-console
      console.log('[sandbox-stream] 409 not streaming-eligible → buffered fallback');
      setStreamStatus('buffered');
      setTimeout(() => setStreamStatus('idle'), 4000);
      return 'fallback';
    }

    const contentType = resp.headers.get('content-type') || '';
    if (!resp.ok || !contentType.includes('text/event-stream') || !resp.body) {
      const text = await resp.text().catch(() => '');
      // eslint-disable-next-line no-console
      console.log(
        '[sandbox-stream] non-stream response, throwing',
        resp.status,
        text.slice(0, 200)
      );
      const err: any = new Error(text || `Streaming failed (HTTP ${resp.status})`);
      err.response = { status: resp.status, data: text };
      throw err;
    }

    // Append the live assistant entry we grow as chunks arrive.
    setStreamStatus('streaming');
    // Capture the upstream conversation id (Copilot) so the next turn continues
    // the same stateful conversation for native multi-turn memory.
    const returnedConversationId = resp.headers.get('x-agent-stream-conversation-id');
    if (returnedConversationId) setConversationId(returnedConversationId);
    const model = formData.model;
    setConversation(prev => [
      ...prev,
      {
        role: 'assistant',
        content: '',
        timestamp: new Date().toISOString(),
        model,
        streaming: true,
      },
    ]);

    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    let acc = '';
    let streamErr: string | null = null;
    let chunkCount = 0;
    let deltaCount = 0;
    const firstByteAt = Date.now();
    let firstDeltaAt: number | null = null;

    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        chunkCount += 1;
        // eslint-disable-next-line no-console
        console.log(
          '[sandbox-stream] read #' + chunkCount,
          (value?.length ?? 0) + ' bytes',
          '| t+' + (Date.now() - reqStart) + 'ms'
        );
        buffer += decoder.decode(value, { stream: true });
        let nl: number;
        while ((nl = buffer.indexOf('\n')) >= 0) {
          const line = buffer.slice(0, nl).trim();
          buffer = buffer.slice(nl + 1);
          if (!line.startsWith('data:')) continue;
          const payload = line.slice(5).trim();
          if (payload === '[DONE]') {
            buffer = '';
            break;
          }
          try {
            const chunk = JSON.parse(payload);
            const delta = chunk?.choices?.[0]?.delta?.content;
            if (typeof delta === 'string' && delta) {
              deltaCount += 1;
              if (firstDeltaAt === null) firstDeltaAt = Date.now();
              // Providers stream either incremental deltas (OpenAI/Anthropic)
              // or cumulative snapshots (Copilot/Entra re-send the whole
              // answer each chunk). `mergeStreamedContent` handles both so a
              // cumulative provider no longer duplicates text / jumps.
              const merged = mergeStreamedContent(acc, delta);
              if (merged !== acc) {
                acc = merged;
                const snapshot = acc;
                setConversation(prev =>
                  prev.map((m, i) => (i === prev.length - 1 ? { ...m, content: snapshot } : m))
                );
              }
            }
          } catch {
            /* ignore keepalives / non-JSON lines */
          }
        }
      }
    } catch (e: any) {
      streamErr = e?.message || 'Stream interrupted';
    }

    // eslint-disable-next-line no-console
    console.log('[sandbox-stream] done', {
      networkChunks: chunkCount,
      contentDeltas: deltaCount,
      totalChars: acc.length,
      msToFirstDelta: firstDeltaAt ? firstDeltaAt - firstByteAt : null,
      error: streamErr,
    });

    const latencyMs = Date.now() - startTime;
    setStreamStatus('idle');
    setConversation(prev =>
      prev.map((m, i) =>
        i === prev.length - 1
          ? {
              ...m,
              content: acc || (streamErr ? `Error: ${streamErr}` : ''),
              streaming: false,
              latencyMs,
              error: !!streamErr && !acc,
            }
          : m
      )
    );
    return 'handled';
  };

  const sendMessage = async () => {
    if (!userMessage.trim()) return;
    const userEntry: ConversationEntry = {
      role: 'user',
      content: userMessage.trim(),
      timestamp: new Date().toISOString(),
    };
    setConversation(prev => [...prev, userEntry]);
    setUserMessage('');
    setLoading(true);
    setPendingSince(Date.now());
    setPendingError(null);

    // Build messages array from conversation history
    const messages: ChatMessage[] = [];
    if (systemPrompt.trim()) messages.push({ role: 'system', content: systemPrompt });
    conversation
      .filter(m => !m.error && !m.rejected)
      .forEach(m => messages.push({ role: m.role, content: m.content }));
    messages.push({ role: 'user', content: userEntry.content });

    const startTime = Date.now();

    try {
      if (streamEnabled && (await runStreaming(messages, startTime)) === 'handled') {
        return;
      }
      const response = await apiClient.post(`/pipes/${pipeId}/execute`, {
        request: {
          model: formData.model,
          messages,
        },
        ...(selectedVariant !== BASE_VARIANT_VALUE ? { variant: selectedVariant } : {}),
        ...(callerToken ? { caller_token: callerToken.accessToken } : {}),
        ...(conversationId ? { conversation_id: conversationId } : {}),
      });

      const latencyMs = Date.now() - startTime;
      const data = response.data;
      const llmResponse = data.response;
      const metrics = data.metrics;
      // Continue a stateful Copilot conversation across turns on the buffered
      // path too (parity with streaming): store the returned conversation id.
      if (metrics?.conversation_id) setConversationId(metrics.conversation_id);

      const assistantContent =
        llmResponse?.choices?.[0]?.message?.content || JSON.stringify(llmResponse, null, 2);
      const usage = llmResponse?.usage;
      // Mirror/Collect responses carry every candidate answer under `x_mirror`.
      const mirrorCandidates = Array.isArray(llmResponse?.x_mirror?.candidates)
        ? (llmResponse.x_mirror.candidates as MirrorCandidateView[])
        : undefined;

      const assistantEntry: ConversationEntry = {
        role: 'assistant',
        content: assistantContent,
        timestamp: new Date().toISOString(),
        model: metrics?.model || llmResponse?.model,
        // Prefer the gateway metrics: they are grand totals across the main
        // LLM (every attempt) plus Judge and Jury, so the per-message count
        // matches the grand cost below. The upstream `usage` object only
        // reports the final LLM call and omits Judge/Jury spend.
        tokens: metrics
          ? {
              prompt: metrics.input_tokens,
              completion: metrics.output_tokens,
              total: metrics.total_tokens,
            }
          : usage
            ? {
                prompt: usage.prompt_tokens,
                completion: usage.completion_tokens,
                total: usage.total_tokens,
              }
            : undefined,
        latencyMs: metrics?.latency_ms || latencyMs,
        cost: metrics?.cost,
        mirrorCandidates,
      };
      setConversation(prev => [...prev, assistantEntry]);
    } catch (err: any) {
      const latencyMs = Date.now() - startTime;
      let errorMsg: string;
      let rejectedBy: string | undefined;

      // Extract error details from axios error response
      const errorData = err?.response?.data;
      const httpStatus = err?.response?.status;

      if (errorData) {
        const errorText = typeof errorData === 'string' ? errorData : JSON.stringify(errorData);
        try {
          const errorJson = typeof errorData === 'object' ? errorData : JSON.parse(errorText);
          if (
            errorJson?.error?.type === 'judge_violation' ||
            errorJson?.type === 'judge_violation'
          ) {
            rejectedBy = 'Judge';
            errorMsg = errorJson.error?.message || errorJson.message || 'Request rejected by Judge';
          } else if (
            errorJson?.error?.type === 'jury_violation' ||
            errorJson?.type === 'jury_violation'
          ) {
            rejectedBy = 'Jury';
            errorMsg = errorJson.error?.message || errorJson.message || 'Request rejected by Jury';
          } else if (
            errorJson?.error?.type === 'prompt_guard_violation' ||
            errorJson?.type === 'prompt_guard_violation'
          ) {
            rejectedBy = 'Prompt Guard';
            errorMsg =
              errorJson.error?.message || errorJson.message || 'Request blocked by Prompt Guard';
          } else {
            errorMsg =
              errorJson?.error?.message || errorJson?.error || errorJson?.message || errorText;
          }
        } catch {
          // Check for common rejection patterns in plain text
          if (errorText.includes('content_policy_violation') || errorText.includes('judge')) {
            rejectedBy = 'Judge';
          } else if (errorText.includes('jury')) {
            rejectedBy = 'Jury';
          } else if (errorText.includes('prompt_guard') || errorText.includes('Prompt guard')) {
            rejectedBy = 'Prompt Guard';
          }
          errorMsg = errorText;
        }
      } else {
        errorMsg = err?.message || 'Network error';
      }

      // Stage-based rejections (Judge/Jury/Prompt Guard) emit pipeline stage
      // logs and render their own run card in the activity panel. Everything
      // else short-circuits before any stage logs (rate limit, policy denial,
      // network, variant resolution), so surface it as a terminal error card
      // — otherwise the in-flight session card vanishes and the previous run
      // is shown, giving the wrong impression.
      if (!rejectedBy) {
        let label = 'Error';
        if (httpStatus === 429) label = 'Rate Limited';
        else if (httpStatus === 403) label = 'Policy Denied';
        else if (httpStatus === 503) label = 'Unavailable';
        setPendingError({ since: startTime, httpStatus, message: errorMsg, label });
      }

      const errorEntry: ConversationEntry = {
        role: 'assistant',
        content: rejectedBy
          ? `**${rejectedBy} Rejection** (HTTP ${httpStatus || '?'})\n\n${errorMsg}`
          : `Error${httpStatus ? ` ${httpStatus}` : ''}: ${errorMsg}`,
        timestamp: new Date().toISOString(),
        latencyMs,
        error: !rejectedBy,
        rejected: !!rejectedBy,
        rejectedBy,
      };
      // Mark the triggering user message so it's excluded from future context
      setConversation(prev => [
        ...prev.map((m, i) => (i === prev.length - 1 ? { ...m, error: true } : m)),
        errorEntry,
      ]);
    } finally {
      setLoading(false);
      // Refresh dashboard stats to pick up all pipeline stage logs, then drop the
      // optimistic placeholder once the real run is in. Small delay to let the
      // backend flush the final log entries.
      setTimeout(() => {
        actions.loadDashboardStats(true);
        setPendingSince(null);
      }, 600);
    }
  };

  const clearConversation = () => {
    setConversation([]);
    setConversationId(null);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  const isDisabled = !formData.enabled;

  return (
    <div className="card shadow-sm mb-0 surface-fullpage-panel">
      <div className="card-header d-flex align-items-center justify-content-between">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-flask me-2" />
          Sandbox
        </h6>
        <div
          className="d-flex align-items-center justify-content-end flex-wrap"
          style={{ gap: 10 }}
        >
          {onSelectSandboxProfile &&
            (requiresSignIn || oauthProfiles.length > 0 || sandboxOAuthIdentifierId) && (
              <div className="d-flex align-items-center" style={{ gap: 6 }}>
                <i
                  className="fas fa-lock text-muted"
                  title="Sandbox sign-in profile — used to test surfaces that forward the caller's identity (e.g. Microsoft 365 Copilot or Azure OpenAI with Entra). Manage profiles under Credentials → OAuth Identifiers."
                />{' '}
                Sandbox Sign-in:{' '}
                <select
                  className="form-select form-select-sm"
                  data-testid="sandbox-oauth-profile"
                  style={{ width: 240 }}
                  value={displayProfileId}
                  onChange={e => onSelectSandboxProfile(e.target.value)}
                >
                  <option value="" disabled={signInProfileRequired}>
                    {signInProfileRequired
                      ? 'Select a sign-in profile (required)'
                      : 'No Sandbox Sign-In Profile'}
                  </option>
                  {oauthProfiles.map(p => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                      {p.provider ? ` (${p.provider})` : ''}
                    </option>
                  ))}
                  {sandboxOAuthIdentifierId &&
                    !oauthProfiles.some(p => p.id === sandboxOAuthIdentifierId) && (
                      <option value={sandboxOAuthIdentifierId}>
                        {sandboxOAuthIdentifierId} (not found)
                      </option>
                    )}
                </select>
              </div>
            )}
          {authEnabled && (
            <div className="d-flex align-items-center" style={{ gap: 6 }}>
              {authError && (
                <span className="text-danger small" title={authError}>
                  <i className="fas fa-triangle-exclamation" />
                </span>
              )}
              {callerToken ? (
                <>
                  <span
                    className="small text-success"
                    title={
                      callerToken.expiresAt
                        ? `Signed in — requests run as you (expires ${new Date(callerToken.expiresAt).toLocaleTimeString()})`
                        : 'Signed in — requests run as you'
                    }
                  >
                    <i className="fas fa-user-check me-1"></i>Signed in
                  </span>
                  <button className="btn btn-sm btn-outline-secondary" onClick={handleSignOut}>
                    <i className="fas fa-sign-out-alt me-1"></i>Sign out
                  </button>
                </>
              ) : (
                <button
                  className="btn btn-sm btn-primary"
                  onClick={handleSignIn}
                  disabled={signingIn}
                  title="This surface forwards the caller's identity. Sign in to test it as yourself."
                >
                  {signingIn ? (
                    <>
                      <span className="spinner-border spinner-border-sm me-1" role="status"></span>
                      Signing in…
                    </>
                  ) : (
                    <>
                      <i className="fab fa-microsoft me-1"></i>Sign in to test
                    </>
                  )}
                </button>
              )}
            </div>
          )}
        </div>
      </div>
      <div className="card-body surface-fullpage-panel__body p-0">
        <div className="pipe-sandbox">
          <style>{`
        @keyframes sandbox-dot { 0%, 80%, 100% { transform: translateY(0); opacity: 0.25; } 40% { transform: translateY(-4px); opacity: 1; } }
        .sandbox-stream-cursor { display: inline-flex; align-items: center; gap: 4px; vertical-align: middle; }
        .sandbox-stream-cursor.is-trailing { display: flex; margin-top: 8px; }
        .sandbox-stream-cursor span {
          width: 7px; height: 7px; border-radius: 50%;
          background: currentColor; opacity: 0.25;
          animation: sandbox-dot 1.3s infinite both;
        }
        .sandbox-stream-cursor span:nth-child(2) { animation-delay: 0.18s; }
        .sandbox-stream-cursor span:nth-child(3) { animation-delay: 0.36s; }
        .sandbox-md > :first-child { margin-top: 0; }
        .sandbox-md > :last-child { margin-bottom: 0; }
        .sandbox-md-p { margin: 0 0 8px; line-height: 1.5; }
        .sandbox-md-h { font-weight: 700; line-height: 1.3; margin: 12px 0 6px; }
        .sandbox-md-h1 { font-size: 1.35em; }
        .sandbox-md-h2 { font-size: 1.2em; }
        .sandbox-md-h3 { font-size: 1.08em; }
        .sandbox-md-h4, .sandbox-md-h5, .sandbox-md-h6 { font-size: 1em; }
        .sandbox-md-list { margin: 0 0 8px; padding-left: 20px; }
        .sandbox-md-list li { margin: 2px 0; line-height: 1.5; }
        .sandbox-md-code {
          background: rgba(135, 131, 120, 0.2); padding: 1px 4px; border-radius: 4px;
          font-size: 0.88em; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
        }
        .sandbox-md-pre {
          background: rgba(135, 131, 120, 0.16); padding: 8px 10px; border-radius: 6px;
          overflow-x: auto; margin: 0 0 8px;
        }
        .sandbox-md-pre code {
          background: none; padding: 0; font-size: 0.85em; white-space: pre;
          font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
        }
        .sandbox-md-quote {
          border-left: 3px solid rgba(135, 131, 120, 0.4); margin: 0 0 8px;
          padding: 2px 0 2px 10px; opacity: 0.85;
        }
        .sandbox-md-hr { border: none; border-top: 1px solid rgba(135, 131, 120, 0.3); margin: 10px 0; }
        .sandbox-md a { color: inherit; text-decoration: underline; text-underline-offset: 2px; }
      `}</style>
          {isDisabled && (
            <div className="alert alert-warning mb-3" style={{ fontSize: '13px' }}>
              <i className="fas fa-exclamation-triangle me-2"></i>
              This pipe is <strong>disabled</strong>. Enable it to use the sandbox.
            </div>
          )}

          {/* Sandbox sign-in profile picker and sign-in control now live in the
          Sandbox card header (right-justified); this keeps only the
          supplementary guidance for those controls. */}
          {onSelectSandboxProfile &&
            (requiresSignIn || oauthProfiles.length > 0 || sandboxOAuthIdentifierId) &&
            (autoSelected ||
              (signInProfileRequired && oauthProfiles.length > 1) ||
              oauthProfiles.length === 0) && (
              <div className="mb-3" style={{ maxWidth: 520 }}>
                {autoSelected && (
                  <div className="form-text">
                    {autoSelectReason === 'tenant' ? (
                      <>
                        <i className="fas fa-wand-magic-sparkles me-1" />
                        Auto-matched to your Caller Context&apos;s verification tenant. Choose it
                        explicitly to pin it to the surface.
                      </>
                    ) : (
                      <>
                        Auto-selected the only OAuth Identifier for this identity-pass-through
                        surface. Choose it explicitly to pin it to the surface.
                      </>
                    )}
                  </div>
                )}
                {signInProfileRequired && oauthProfiles.length > 1 && (
                  <div className="form-text text-warning">
                    Pick the profile whose tenant issues the tokens this surface&apos;s Caller
                    Context accepts.
                  </div>
                )}
                {oauthProfiles.length === 0 && (
                  <div className="form-text">
                    No OAuth Identifiers yet — create one under{' '}
                    <strong>Credentials → OAuth Identifiers</strong>.
                  </div>
                )}
              </div>
            )}

          {/* Identity pass-through requires a signed-in delegated token; when no
          sign-in config is resolvable yet, prompt the operator to pick a profile
          (the sign-in control in the header above only appears once a usable
          config exists). */}
          {requiresSignIn && !authEnabled && (
            <div
              className="alert alert-warning d-flex align-items-center mb-3"
              style={{ fontSize: '13px', gap: 8 }}
            >
              <i className="fas fa-user-lock"></i>
              <span>
                This surface uses <strong>identity pass-through</strong>, so testing it requires
                signing in as yourself.{' '}
                {oauthProfiles.length === 0 ? (
                  <>
                    Create an OAuth Identifier under{' '}
                    <strong>Credentials → OAuth Identifiers</strong>, then select it above.
                  </>
                ) : (
                  <>
                    Select a <strong>sandbox sign-in profile</strong> above to enable sign-in.
                  </>
                )}
              </span>
            </div>
          )}

          {/* System prompt card (collapsible, default collapsed) */}
          <div className="card shadow mb-2">
            <div
              className="card-header sandbox-panel-header d-flex justify-content-between align-items-center"
              role="button"
              onClick={() => setSystemPromptOpen(open => !open)}
            >
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-cog me-2"></i>System Prompt
              </h6>
              <button
                type="button"
                className="sandbox-twister"
                aria-expanded={systemPromptOpen}
                aria-label={systemPromptOpen ? 'Collapse system prompt' : 'Expand system prompt'}
                onClick={e => {
                  e.stopPropagation();
                  setSystemPromptOpen(open => !open);
                }}
              >
                <i className={`fas fa-chevron-${systemPromptOpen ? 'down' : 'right'}`}></i>
              </button>
            </div>
            {systemPromptOpen && (
              <div className="card-body py-2 px-3">
                <textarea
                  className="form-control"
                  rows={2}
                  value={systemPrompt}
                  onChange={e => setSystemPrompt(e.target.value)}
                  placeholder="You are a helpful assistant."
                  style={{ fontSize: '13px' }}
                />
              </div>
            )}
          </div>

          {/* Split: Conversation (left) + Logs (right) */}
          <div className="row sandbox-panels-row">
            {/* Left: Conversation */}
            <div className="col-md-6">
              <div className="card shadow mb-4">
                <div className="card-header sandbox-panel-header d-flex justify-content-between align-items-center">
                  <h6 className="m-0 font-weight-bold text-primary">
                    <i className="fas fa-comments me-2"></i>Conversation
                  </h6>
                  <div className="d-flex align-items-center gap-2">
                    <div
                      className="form-check form-switch m-0 sandbox-stream-switch"
                      title="Stream the response live when the surface supports it (falls back to buffered otherwise)"
                    >
                      <input
                        className="form-check-input"
                        type="checkbox"
                        role="switch"
                        id="sandbox-stream-toggle"
                        checked={streamEnabled}
                        onChange={e => setStreamEnabled(e.target.checked)}
                        disabled={loading}
                      />
                      <label
                        className="form-check-label text-muted"
                        htmlFor="sandbox-stream-toggle"
                        style={{ fontSize: '12px' }}
                      >
                        Stream
                      </label>
                      {streamStatus === 'streaming' && (
                        <span
                          style={{ color: '#28a745', fontSize: '11px' }}
                          title="Streaming live — tokens arriving progressively"
                        >
                          ● live
                        </span>
                      )}
                      {streamStatus === 'buffered' && (
                        <span
                          style={{ color: '#fd7e14', fontSize: '11px' }}
                          title="Surface is not streaming-eligible (Judge/Jury/response guard enabled, or toggle is off) — using buffered path"
                        >
                          ⚠ buffered
                        </span>
                      )}
                    </div>
                    {variants.length > 0 && (
                      <div className="d-flex align-items-center gap-1">
                        <i
                          className="fas fa-code-branch text-muted"
                          title="Variant to test"
                          style={{ fontSize: '12px' }}
                        ></i>
                        <select
                          className="form-select form-select-sm sandbox-variant-select"
                          value={selectedVariant}
                          onChange={e => setSelectedVariant(e.target.value)}
                          disabled={loading}
                          title="Select which variant to send the request through"
                          style={{ fontSize: '12px', width: 'auto' }}
                        >
                          <option value={BASE_VARIANT_VALUE}>Base</option>
                          {variants.map(v => (
                            <option key={v.alias} value={v.alias} disabled={v.enabled === false}>
                              {v.name || v.alias}
                              {v.enabled === false ? ' (disabled)' : ''}
                            </option>
                          ))}
                        </select>
                      </div>
                    )}
                    <button
                      className="btn btn-sm btn-outline-danger"
                      onClick={clearConversation}
                      disabled={conversation.length === 0}
                      title="Clear conversation"
                    >
                      <i className="fas fa-trash"></i>
                    </button>
                  </div>
                </div>
                <div className="card-body p-0 d-flex flex-column">
                  {/* Messages area */}
                  <div
                    className="flex-grow-1 sandbox-chat-scroll"
                    style={{
                      overflowY: 'auto',
                      padding: '1rem',
                    }}
                  >
                    {conversation.length === 0 ? (
                      <div className="text-center text-muted py-5">
                        <i className="fas fa-flask" style={{ fontSize: '3rem', opacity: 0.3 }}></i>
                        <p className="mt-3" style={{ fontSize: '13px' }}>
                          Send a message to test the Surface's full pipeline.
                        </p>
                      </div>
                    ) : (
                      conversation.map((msg, idx) => (
                        <div
                          key={idx}
                          className={`mb-3 d-flex ${msg.role === 'user' ? 'justify-content-end' : 'justify-content-start'}`}
                        >
                          <div
                            className={`p-3 rounded shadow-sm ${
                              msg.rejected
                                ? 'border'
                                : msg.error
                                  ? 'bg-danger text-white'
                                  : msg.role === 'user'
                                    ? 'bg-primary text-white'
                                    : 'sandbox-bubble border'
                            }`}
                            style={{
                              maxWidth: '85%',
                              minWidth: '120px',
                              ...(msg.rejected
                                ? {
                                    background: 'rgba(245, 158, 11, 0.12)',
                                    borderColor: 'var(--warning)',
                                  }
                                : {}),
                            }}
                          >
                            <div className="small font-weight-bold mb-1">
                              {msg.role === 'user' ? (
                                'You'
                              ) : msg.rejected ? (
                                <>
                                  <i className="fas fa-ban me-1 text-danger"></i>
                                  {msg.rejectedBy || 'Rejected'}
                                </>
                              ) : msg.error ? (
                                'Error'
                              ) : (
                                'Assistant'
                              )}
                            </div>
                            <div
                              style={{
                                wordBreak: 'break-word',
                                fontSize: '13px',
                                // Markdown blocks own their own spacing; plain
                                // text needs pre-wrap to keep the model's
                                // whitespace/newlines.
                                ...(msg.role === 'assistant' && !msg.error && !msg.rejected
                                  ? {}
                                  : { whiteSpace: 'pre-wrap' }),
                              }}
                            >
                              {msg.role === 'assistant' && !msg.error && !msg.rejected ? (
                                msg.mirrorCandidates && msg.mirrorCandidates.length > 0 ? (
                                  <MirrorCandidates candidates={msg.mirrorCandidates} />
                                ) : (
                                  <SandboxMarkdown text={msg.content} />
                                )
                              ) : (
                                msg.content
                              )}
                              {msg.streaming &&
                                (msg.content ? (
                                  <span className="sandbox-stream-cursor is-trailing">
                                    <span />
                                    <span />
                                    <span />
                                  </span>
                                ) : (
                                  <span className="sandbox-stream-cursor text-muted">
                                    <span />
                                    <span />
                                    <span />
                                  </span>
                                ))}
                            </div>
                            <div
                              className="d-flex justify-content-between mt-2 flex-wrap"
                              style={{ fontSize: '0.68rem', opacity: 0.7, gap: '4px' }}
                            >
                              <span>{new Date(msg.timestamp).toLocaleTimeString()}</span>
                              {msg.latencyMs !== undefined && <span>{msg.latencyMs}ms</span>}
                              {msg.tokens && (
                                <span
                                  title={`Prompt: ${msg.tokens.prompt} | Completion: ${msg.tokens.completion}`}
                                >
                                  {msg.tokens.total} tokens
                                </span>
                              )}
                              {msg.cost !== undefined && msg.cost > 0 && (
                                <span>${msg.cost.toFixed(6)}</span>
                              )}
                              {msg.model && <span>{msg.model}</span>}
                            </div>
                          </div>
                        </div>
                      ))
                    )}
                    {loading && streamStatus !== 'streaming' && (
                      <div className="d-flex justify-content-start mb-3">
                        <div
                          className="p-3 rounded shadow-sm sandbox-bubble border"
                          style={{ minWidth: '120px' }}
                        >
                          <div className="small font-weight-bold mb-1">Assistant</div>
                          <div className="d-flex align-items-center">
                            <div
                              className="spinner-border spinner-border-sm text-primary me-2"
                              role="status"
                            />
                            <span className="text-muted" style={{ fontSize: '13px' }}>
                              Processing through pipeline…
                            </span>
                          </div>
                        </div>
                      </div>
                    )}
                    <div ref={chatEndRef} />
                  </div>

                  {/* Input area */}
                  <div className="sandbox-input-area">
                    <div className="input-group sandbox-input-group">
                      <textarea
                        className="form-control sandbox-input"
                        rows={2}
                        value={userMessage}
                        onChange={e => setUserMessage(e.target.value)}
                        onKeyDown={handleKeyDown}
                        placeholder="Type a message… (Enter to send, Shift+Enter for new line)"
                        disabled={loading || isDisabled}
                        style={{ fontSize: '13px' }}
                      />
                      <div className="input-group-append">
                        <button
                          className="btn btn-primary sandbox-send-btn"
                          onClick={sendMessage}
                          disabled={loading || !userMessage.trim() || isDisabled || !signInReady}
                          title={
                            !signInReady
                              ? 'Sign in to test this identity-pass-through surface'
                              : 'Send message through the pipe pipeline'
                          }
                        >
                          {loading ? (
                            <span className="spinner-border spinner-border-sm" />
                          ) : (
                            <i className="fas fa-paper-plane"></i>
                          )}
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Right: Pipeline Activity */}
            <div className="col-md-6">
              <PipeActivityViewer
                pipeId={pipeId}
                pipeName={formData.name}
                height="100%"
                pendingSince={pendingSince}
                pendingError={pendingError}
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ChatSandboxTab;
