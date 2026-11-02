"use strict";

const readline = require("readline");
const { info, sleep } = require("./log");

// Live, in-place console feedback so a long phase visibly *moves* instead of
// "just sitting there". On a TTY it draws a single spinner line that updates in
// place; when output is piped (CI / docker logs) it degrades to a throttled
// plain progress line so the same information still lands in the log without
// control characters. Also owns an optional `q` keypress watcher that asks the
// run to wrap up after the current round.

const isTTY = !!(process.stdout && process.stdout.isTTY);
const FRAMES = ["\u280b", "\u2819", "\u2839", "\u2838", "\u283c", "\u2834", "\u2826", "\u2827", "\u2807", "\u280f"];
const PLAIN_INTERVAL_MS = 5000;

function fmtDuration(ms) {
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  const sec = s % 60;
  return m > 0 ? `${m}m${String(sec).padStart(2, "0")}s` : `${sec}s`;
}

class Spinner {
  constructor(label) {
    this.label = label;
    this.fields = {};
    this.start = Date.now();
    this.frame = 0;
    this.timer = null;
    this.lastPlain = 0;
    this._render = this._render.bind(this);
    this._startTimer();
  }

  set(fields) {
    Object.assign(this.fields, fields);
    return this;
  }

  _body() {
    const parts = Object.entries(this.fields).map(([k, v]) => `${k}=${v}`);
    const tail = parts.length ? `  ${parts.join("  ")}` : "";
    return `${this.label}${tail}  (${fmtDuration(Date.now() - this.start)})`;
  }

  _render() {
    if (isTTY) {
      this.frame = (this.frame + 1) % FRAMES.length;
      let line = `${FRAMES[this.frame]} ${this._body()}`;
      const width = (process.stdout.columns || 80) - 1;
      if (line.length > width) line = line.slice(0, width);
      process.stdout.write(`\r\x1b[K${line}`);
    } else {
      const now = Date.now();
      if (now - this.lastPlain < PLAIN_INTERVAL_MS) return;
      this.lastPlain = now;
      info(`\u2026 ${this._body()}`);
    }
  }

  _startTimer() {
    if (this.timer) return;
    this.timer = setInterval(this._render, isTTY ? 90 : 1000);
    if (this.timer.unref) this.timer.unref();
    this._render();
  }

  // Erase the current TTY line so a regular log line can be printed cleanly.
  clear() {
    if (isTTY) process.stdout.write("\r\x1b[K");
    return this;
  }

  stop(finalMsg) {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.clear();
    if (finalMsg) info(finalMsg);
    return this;
  }
}

function spinner(label) {
  return new Spinner(label);
}

// A visible, interruptible wait — shows a countdown so an intentional pause
// (telemetry settle, inter-wave bucket gap) never looks like a hang. Resolves
// early if a stop has been requested.
async function waitWithCountdown(label, seconds) {
  if (!seconds || seconds <= 0) return;
  const sp = spinner(label);
  const end = Date.now() + seconds * 1000;
  try {
    while (Date.now() < end && !stopRequested) {
      const remaining = Math.max(0, Math.ceil((end - Date.now()) / 1000));
      sp.set({ remaining: `${remaining}s` });
      await sleep(Math.min(250, end - Date.now()));
    }
  } finally {
    sp.stop();
  }
}

// ---- graceful stop (`q`) -------------------------------------------------
let stopRequested = false;
let listening = false;
let keypressHandler = null;

function isStopRequested() {
  return stopRequested;
}

function resetStop() {
  stopRequested = false;
}

function restoreRawMode(on) {
  try {
    if (process.stdin.isTTY) process.stdin.setRawMode(on);
  } catch (_) {
    /* not a TTY / unsupported — ignore */
  }
}

// Begin watching for `q` (request wrap-up) / Ctrl-C (immediate abort). No-op
// when stdin is not a TTY (piped/CI), where there are no interactive keys.
function startStopListener() {
  if (listening || !process.stdin.isTTY) return;
  listening = true;
  readline.emitKeypressEvents(process.stdin);
  restoreRawMode(true);
  process.stdin.resume();
  keypressHandler = (_str, key) => {
    if (!key) return;
    if (key.ctrl && key.name === "c") {
      restoreRawMode(false);
      process.exit(130);
    }
    if (key.name === "q") stopRequested = true;
  };
  process.stdin.on("keypress", keypressHandler);
}

// Stop watching and hand stdin back to normal line mode so the interactive
// menu prompt (readline) works afterwards.
function stopStopListener() {
  if (!listening) return;
  listening = false;
  if (keypressHandler) {
    process.stdin.removeListener("keypress", keypressHandler);
    keypressHandler = null;
  }
  restoreRawMode(false);
  process.stdin.pause();
}

module.exports = {
  spinner,
  waitWithCountdown,
  isStopRequested,
  resetStop,
  startStopListener,
  stopStopListener,
};
