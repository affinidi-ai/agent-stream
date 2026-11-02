"use strict";

const { sleep } = require("./log");

// A minimal async worker pool that bounds the number of in-flight tasks
// (`concurrency`), optionally paces new dispatches to a target rate (`rps`), and
// stops either after a fixed count (`total`) or once a wall-clock budget elapses
// (`durationMs`). Reconciliation stays exact at any concurrency because each task
// carries its own correlation nonce — the pool itself does not interleave state.
//
// taskFactory(index) is invoked per dispatch and may be sync or async; its
// rejection is routed to `onError(err, index)` (if given) and otherwise swallowed
// so one failing request never aborts the whole pool.
//
// `shouldStop()` (optional) lets a caller end dispatch early — in-flight tasks
// still drain — so a graceful `q` wrap-up stops launching new work immediately.
async function runPool({ concurrency, total, durationMs, rps, onError, shouldStop }, taskFactory) {
  const cap = Math.max(1, concurrency || 1);
  const minInterval = rps > 0 ? 1000 / rps : 0;
  const start = Date.now();
  let nextAt = start;
  let dispatched = 0;
  const inFlight = new Set();

  const shouldDispatch = () => {
    if (shouldStop && shouldStop()) return false;
    if (durationMs > 0) return Date.now() - start < durationMs;
    return dispatched < total;
  };

  while (shouldDispatch()) {
    if (inFlight.size >= cap) {
      await Promise.race(inFlight);
      continue;
    }
    if (minInterval > 0) {
      const wait = nextAt - Date.now();
      if (wait > 0) await sleep(wait);
      nextAt += minInterval;
    }
    const index = dispatched;
    dispatched += 1;
    const p = Promise.resolve()
      .then(() => taskFactory(index))
      .catch((e) => {
        if (onError) onError(e, index);
      })
      .finally(() => inFlight.delete(p));
    inFlight.add(p);
  }

  await Promise.all(inFlight);
  return dispatched;
}

module.exports = { runPool };
