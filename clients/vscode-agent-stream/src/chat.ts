import * as vscode from 'vscode';

import { log } from './log';
import { assertSameEndpointTarget, secureFetch, validateEndpointBase } from './security';
import { resolveToolCallId } from './tool_call_id';
import { serializeToolResult } from './tool_result_security';

/** An OpenAI tool/function call on an assistant message. */
export interface OpenAIToolCall {
  id: string;
  type: 'function';
  function: { name: string; arguments: string };
}

/** A minimal OpenAI-style chat message (chat-completions schema). */
export interface OpenAIMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string | null;
  tool_calls?: OpenAIToolCall[];
  tool_call_id?: string;
}

/** An OpenAI tool (function) definition. */
export interface OpenAITool {
  type: 'function';
  function: { name: string; description: string; parameters: object };
}

/**
 * Convert VS Code chat messages into OpenAI chat-completion messages,
 * preserving tool calls (assistant) and tool results (user) so agentic modes
 * (Agent / Plan / coding agent) round-trip correctly.
 */
export function toOpenAIMessages(
  messages: readonly vscode.LanguageModelChatRequestMessage[],
): OpenAIMessage[] {
  const out: OpenAIMessage[] = [];

  for (const message of messages) {
    const isAssistant = message.role === vscode.LanguageModelChatMessageRole.Assistant;
    const text = extractText(message.content);
    const toolCalls = extractToolCalls(message.content);
    const toolResults = extractToolResults(message.content);

    // Tool results become standalone `tool` role messages (one per call id).
    for (const result of toolResults) {
      out.push({ role: 'tool', tool_call_id: result.callId, content: result.content });
    }

    if (isAssistant) {
      if (toolCalls.length > 0) {
        out.push({
          role: 'assistant',
          content: text.length > 0 ? text : null,
          tool_calls: toolCalls,
        });
      } else if (text.length > 0) {
        out.push({ role: 'assistant', content: text });
      }
    } else if (text.length > 0) {
      out.push({ role: 'user', content: text });
    }
  }

  return out;
}

function extractText(parts: readonly unknown[]): string {
  const chunks: string[] = [];
  for (const part of parts) {
    if (part instanceof vscode.LanguageModelTextPart) {
      chunks.push(part.value);
    } else if (
      part &&
      typeof part === 'object' &&
      !(part instanceof vscode.LanguageModelToolCallPart) &&
      !(part instanceof vscode.LanguageModelToolResultPart) &&
      'value' in part &&
      typeof (part as { value: unknown }).value === 'string'
    ) {
      chunks.push((part as { value: string }).value);
    }
  }
  return chunks.join('');
}

function extractToolCalls(parts: readonly unknown[]): OpenAIToolCall[] {
  const calls: OpenAIToolCall[] = [];
  for (const part of parts) {
    if (part instanceof vscode.LanguageModelToolCallPart) {
      calls.push({
        id: part.callId,
        type: 'function',
        function: { name: part.name, arguments: JSON.stringify(part.input ?? {}) },
      });
    }
  }
  return calls;
}

function extractToolResults(parts: readonly unknown[]): Array<{ callId: string; content: string }> {
  const results: Array<{ callId: string; content: string }> = [];
  for (const part of parts) {
    if (part instanceof vscode.LanguageModelToolResultPart) {
      results.push({ callId: part.callId, content: stringifyToolResult(part.content) });
    }
  }
  return results;
}

function stringifyToolResult(content: readonly unknown[]): string {
  return serializeToolResult(content);
}

/** A completed tool call parsed from the streamed response. */
export interface ParsedToolCall {
  callId: string;
  name: string;
  input: object;
}

export interface StreamCallbacks {
  onText: (text: string) => void;
  onToolCall: (call: ParsedToolCall) => void;
}

export interface StreamParams {
  url: string;
  expectedBaseUrl: string;
  allowLocalDevelopment: boolean;
  accessToken: string;
  /**
   * Optional distinct **upstream** bearer, forwarded as
   * `X-Agent-Stream-Upstream-Authorization`. Used when the selected model's
   * catalogue entry names an upstream sign-in slot (e.g. a Graph-audience token
   * for Microsoft 365 Copilot) that differs from the front-door token. When
   * absent, the surface forwards the front-door token as today.
   */
  upstreamAccessToken?: string;
  body: unknown;
  callbacks: StreamCallbacks;
  abortSignal: AbortSignal;
}

const CHAT_TIMEOUT_MS = 300000;

interface ToolCallAccumulator {
  id: string;
  name: string;
  args: string;
}

/**
 * POST an OpenAI-compatible chat completion to the Agent Stream surface.
 *
 * Handles both transports transparently: a `text/event-stream` (SSE) response is
 * streamed chunk-by-chunk, while a buffered `application/json` response (which
 * the surface returns when response-side governance such as a Judge/Jury/guard
 * forces the non-streaming path) is parsed as a single completion. Text is
 * emitted via `onText`; completed tool calls via `onToolCall`.
 */
export async function streamChatCompletion(params: StreamParams): Promise<void> {
  const expectedBase = await validateEndpointBase(params.expectedBaseUrl, {
    allowLocalDevelopment: params.allowLocalDevelopment,
  });
  assertSameEndpointTarget(expectedBase, params.url);

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'text/event-stream',
    Authorization: `Bearer ${params.accessToken}`,
  };
  if (params.upstreamAccessToken) {
    headers['X-Agent-Stream-Upstream-Authorization'] = `Bearer ${params.upstreamAccessToken}`;
  }
  const response = await secureFetch(params.url, {
    method: 'POST',
    headers,
    body: JSON.stringify(params.body),
  }, CHAT_TIMEOUT_MS, params.abortSignal, { allowLocalDevelopment: params.allowLocalDevelopment });

  if (!response.ok || !response.body) {
    const detail = await safeReadText(response);
    log(`Response HTTP ${response.status} (error): ${detail}`);
    throw new Error(`Agent Stream request failed (HTTP ${response.status}): ${detail}`);
  }

  const contentType = response.headers.get('content-type') ?? '';
  log(`Response HTTP ${response.status} (${contentType || 'no content-type'}).`);
  if (!contentType.includes('text/event-stream')) {
    await handleBufferedResponse(response, params.callbacks);
    return;
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const toolAcc = new Map<number, ToolCallAccumulator>();
  let buffer = '';

  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    buffer += decoder.decode(value, { stream: true });

    let newlineIndex: number;
    while ((newlineIndex = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, newlineIndex).trim();
      buffer = buffer.slice(newlineIndex + 1);
      if (!line.startsWith('data:')) {
        continue;
      }
      const data = line.slice('data:'.length).trim();
      if (data === '[DONE]') {
        flushToolCalls(toolAcc, params.callbacks);
        return;
      }
      consumeChunk(data, toolAcc, params.callbacks);
    }
  }

  flushToolCalls(toolAcc, params.callbacks);
}

interface BufferedResponse {
  choices?: Array<{
    message?: {
      content?: unknown;
      tool_calls?: Array<{ id?: string; function?: { name?: string; arguments?: string } }>;
    };
  }>;
}

/** Parse a non-streaming (buffered) chat completion into text + tool calls. */
async function handleBufferedResponse(
  response: Response,
  callbacks: StreamCallbacks,
): Promise<void> {
  const raw = await response.text();
  let parsed: BufferedResponse;
  try {
    parsed = JSON.parse(raw) as BufferedResponse;
  } catch {
    throw new Error(`Agent Stream returned an unparseable response: ${raw.slice(0, 500)}`);
  }

  const message = parsed.choices?.[0]?.message;
  if (!message) {
    log('WARNING: Buffered response had no choices[0].message — nothing to emit.');
    return;
  }

  if (typeof message.content === 'string' && message.content.length > 0) {
    callbacks.onText(message.content);
  }

  for (const call of message.tool_calls ?? []) {
    if (!call.function?.name) {
      continue;
    }
    callbacks.onToolCall({
      callId: resolveToolCallId(call.id),
      name: call.function.name,
      input: parseArguments(call.function.arguments ?? ''),
    });
  }
}

interface StreamChunk {
  choices?: Array<{
    delta?: {
      content?: unknown;
      tool_calls?: Array<{
        index?: number;
        id?: string;
        function?: { name?: string; arguments?: string };
      }>;
    };
  }>;
}

function consumeChunk(
  data: string,
  toolAcc: Map<number, ToolCallAccumulator>,
  callbacks: StreamCallbacks,
): void {
  let parsed: StreamChunk;
  try {
    parsed = JSON.parse(data) as StreamChunk;
  } catch {
    // Ignore keep-alive comments and partial frames.
    return;
  }

  const delta = parsed.choices?.[0]?.delta;
  if (!delta) {
    return;
  }

  if (typeof delta.content === 'string' && delta.content.length > 0) {
    callbacks.onText(delta.content);
  }

  if (Array.isArray(delta.tool_calls)) {
    for (const entry of delta.tool_calls) {
      const index = typeof entry.index === 'number' ? entry.index : toolAcc.size;
      const current = toolAcc.get(index) ?? { id: '', name: '', args: '' };
      if (entry.id) {
        current.id = entry.id;
      }
      if (entry.function?.name) {
        current.name = entry.function.name;
      }
      if (entry.function?.arguments) {
        current.args += entry.function.arguments;
      }
      toolAcc.set(index, current);
    }
  }
}

function flushToolCalls(
  toolAcc: Map<number, ToolCallAccumulator>,
  callbacks: StreamCallbacks,
): void {
  for (const acc of toolAcc.values()) {
    if (!acc.name) {
      continue;
    }
    callbacks.onToolCall({
      callId: resolveToolCallId(acc.id),
      name: acc.name,
      input: parseArguments(acc.args),
    });
  }
  toolAcc.clear();
}

function parseArguments(raw: string): object {
  if (!raw.trim()) {
    return {};
  }
  try {
    const value = JSON.parse(raw);
    return value && typeof value === 'object' ? (value as object) : {};
  } catch {
    return {};
  }
}

async function safeReadText(response: Response): Promise<string> {
  try {
    const text = (await response.text()).trim();
    return text.length > 0 ? text.slice(0, 500) : response.statusText;
  } catch {
    return response.statusText;
  }
}
