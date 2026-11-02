import * as vscode from 'vscode';

import { sanitizeLogMessage } from './log_sanitizer';

/**
 * Shared "Agent Stream" output channel so failures (mis-placed config, empty
 * completions, sign-in errors) are visible instead of failing silently. The
 * channel is created once at activation; log calls before that are no-ops.
 */

let channel: vscode.OutputChannel | undefined;

/** Create the output channel and register it for disposal. Idempotent. */
export function initLog(context: vscode.ExtensionContext): vscode.OutputChannel {
  if (!channel) {
    channel = vscode.window.createOutputChannel('Agent Stream');
    context.subscriptions.push(channel);
  }
  return channel;
}

/** Append a timestamped, single-line-safe message to the output channel. */
export function log(message: string): void {
  channel?.appendLine(`[${new Date().toISOString()}] ${sanitizeLogMessage(message)}`);
}

/**
 * Measure an async phase and log its elapsed wall-clock time. Used to localise
 * the pre-request latency (bootstrap fetch, Entra token acquisition, upstream
 * request) so the output channel shows exactly where a slow message spends its
 * time. Logs the elapsed time even when `fn` throws, so a failed phase is still
 * timed.
 */
export async function timed<T>(label: string, fn: () => Promise<T>): Promise<T> {
  const start = Date.now();
  try {
    return await fn();
  } finally {
    log(`${label} took ${Date.now() - start}ms.`);
  }
}

/** Append an error line, including the stack/message when available. */
export function logError(message: string, error?: unknown): void {
  const detail =
    error instanceof Error
      ? (error.stack ?? error.message)
      : error !== undefined
        ? String(error)
        : '';
  log(detail ? `ERROR: ${message} — ${detail}` : `ERROR: ${message}`);
}

/** Reveal the output channel (without stealing editor focus). */
export function showLog(): void {
  channel?.show(true);
}
