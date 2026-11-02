// Mock OpenAI-protocol LLM server for the agent-stream testkit.
//
// It is deliberately dumb: it does NOT call any real model. For every
// POST /v1/chat/completions it sleeps a random short time, returns a fixed
// assistant message, and emits a *variable* `usage` block so that token counts
// (and therefore cost) vary per call exactly the way a real provider would.
//
// Every served completion is appended to an in-memory, monotonically-indexed
// call log, tagged with the correlation nonce the runner embeds in each prompt.
// The runner reads `GET /__mock/by-nonce?nonce=...` after a surface execution
// completes, so it knows precisely how many upstream calls that one execution
// produced (1 for a plain LLM, 2 with a judge, 1+N with an N-juror jury) and the
// exact tokens each consumed — accurately even under high concurrency. That log
// is the ground truth the runner reconciles the appliance's telemetry against.

const http = require("http");

const PORT = Number(process.env.MOCK_LLM_PORT || 9000);

// Simulated upstream think time (ms). Real providers take far longer than the
// old 10-250ms band, which made every surface call resolve almost instantly and
// hid latency/concurrency behaviour. Defaults to a realistic 400-2500ms; tune
// via MOCK_LLM_MIN_MS / MOCK_LLM_MAX_MS (clamped so min <= max, both >= 0).
const LATENCY_MIN_MS = Math.max(0, Number(process.env.MOCK_LLM_MIN_MS || 400));
const LATENCY_MAX_MS = Math.max(
  LATENCY_MIN_MS,
  Number(process.env.MOCK_LLM_MAX_MS || 2500),
);

// Ordered log of every completion served. Index is the array position.
const callLog = [];

// A correlation nonce the runner embeds in every prompt (`[[tkid:<id>]]`) so it
// can attribute upstream calls (main LLM + judge + each juror) to a single
// surface execution even when many requests are in flight concurrently. The
// reject trigger (`[[reject]]`) makes this mock emit content a judge/jury rule
// will block, so the runner can exercise (and reconcile) rejection telemetry.
const NONCE_RE = /\[\[tkid:([0-9a-zA-Z_-]+)\]\]/;
const REJECT_TRIGGER = "[[reject]]";

// A clean response contains the literal APPROVED (jurors approve on it) and never
// contains BLOCKED (the judge rule keys on BLOCKED). A triggered response flips
// both, so the same prompt marker drives both judge and jury rejections.
const APPROVED_CONTENT = "APPROVED: deterministic mock completion produced by the testkit.";
const BLOCKED_CONTENT = "BLOCKED: mock flagged this content for the testkit rejection drill.";

function randInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

// Deterministic, content-dependent embedding vector: different inputs yield
// different (unit-normalised) vectors, so the drift semantic-distance dimension
// sees a real distance between an answer and its reference instead of a flat 0.
function embedVector(s) {
  const dims = 16;
  const v = new Array(dims).fill(0);
  for (let i = 0; i < s.length; i += 1) v[i % dims] += s.charCodeAt(i);
  const norm = Math.sqrt(v.reduce((a, x) => a + x * x, 0)) || 1;
  return v.map((x) => x / norm);
}

// Concatenate every message's text so the nonce / reject trigger can be found
// regardless of which message carries it (the judge/jury forward the user text).
function concatContent(body) {
  const messages = Array.isArray(body && body.messages) ? body.messages : [];
  let out = "";
  for (const m of messages) {
    if (typeof m?.content === "string") out += m.content + "\n";
    else if (Array.isArray(m?.content)) {
      for (const part of m.content) if (typeof part?.text === "string") out += part.text + "\n";
    }
  }
  return out;
}

function extractNonce(text) {
  const m = NONCE_RE.exec(text || "");
  return m ? m[1] : null;
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => {
      data += chunk;
      if (data.length > 5_000_000) {
        reject(new Error("body too large"));
        req.destroy();
      }
    });
    req.on("end", () => {
      if (!data) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch (err) {
        reject(err);
      }
    });
    req.on("error", reject);
  });
}

// Approximate prompt tokens from the request so usage tracks payload size, then
// add jitter. Completion tokens are random within a band. Both are variable so
// the cost the appliance computes is variable too.
function computeUsage(body) {
  let promptChars = 0;
  const messages = Array.isArray(body && body.messages) ? body.messages : [];
  for (const m of messages) {
    if (typeof m?.content === "string") promptChars += m.content.length;
    else if (Array.isArray(m?.content)) {
      for (const part of m.content) {
        if (typeof part?.text === "string") promptChars += part.text.length;
      }
    }
  }
  const promptTokens = Math.max(8, Math.round(promptChars / 4) + randInt(5, 40));
  const completionTokens = randInt(20, 220);
  return {
    prompt_tokens: promptTokens,
    completion_tokens: completionTokens,
    total_tokens: promptTokens + completionTokens,
  };
}

function buildCompletion(model, usage, content) {
  const now = Math.floor(Date.now() / 1000);
  return {
    id: `chatcmpl-mock-${now}-${randInt(1000, 9999)}`,
    object: "chat.completion",
    created: now,
    model: model || "mock-small",
    choices: [
      {
        index: 0,
        message: { role: "assistant", content },
        finish_reason: "stop",
      },
    ],
    usage,
  };
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  // Inspect / reset the call log (testkit control plane).
  if (req.method === "GET" && url.pathname === "/__mock/calls") {
    const since = Number(url.searchParams.get("since") || 0);
    const slice = callLog.slice(Math.max(0, since));
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ count: callLog.length, calls: slice }));
    return;
  }
  if (req.method === "GET" && url.pathname === "/__mock/count") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ count: callLog.length }));
    return;
  }
  // Every call recorded for a given correlation nonce — the concurrency-safe
  // replacement for the call-count delta (which only works under serial load).
  if (req.method === "GET" && url.pathname === "/__mock/by-nonce") {
    const nonce = url.searchParams.get("nonce") || "";
    const calls = callLog.filter((c) => c.nonce === nonce);
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ nonce, count: calls.length, calls }));
    return;
  }
  if (req.method === "POST" && url.pathname === "/__mock/reset") {
    callLog.length = 0;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
    return;
  }
  if (req.method === "GET" && (url.pathname === "/health" || url.pathname === "/__mock/health")) {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ status: "ok", served: callLog.length }));
    return;
  }

  // Batch API — create (POST) rides the normal buffered path; retrieve/list
  // (GET) are proxied by the gateway's guarded GET-proxy. All JSON, no usage.
  if (req.method === "POST" && url.pathname === "/v1/batches") {
    await readJsonBody(req).catch(() => ({}));
    callLog.push({ index: callLog.length, at: Date.now(), endpoint: "batches.create" });
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ id: "batch_mock_1", object: "batch", status: "validating", endpoint: "/v1/chat/completions" }));
    return;
  }
  if (req.method === "GET" && url.pathname.startsWith("/v1/batches")) {
    callLog.push({ index: callLog.length, at: Date.now(), endpoint: "batches.get" });
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ id: "batch_mock_1", object: "batch", status: "completed", output_file_id: "file_mock_out" }));
    return;
  }
  // Files API — upload (multipart/form-data) returns the created file object.
  if (req.method === "POST" && url.pathname === "/v1/files") {
    // Drain the raw multipart body without JSON-parsing it.
    await new Promise((resolve) => {
      req.on("data", () => {});
      req.on("end", resolve);
      req.on("error", resolve);
    });
    callLog.push({
      index: callLog.length,
      at: Date.now(),
      endpoint: "files.upload",
      contentType: req.headers["content-type"] || "",
    });
    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify({ id: "file_mock_in", object: "file", bytes: 123, purpose: "batch", filename: "input.jsonl", status: "processed" })
    );
    return;
  }
  // Files API — retrieve metadata (JSON) or content (binary/JSONL).
  if (req.method === "GET" && url.pathname.startsWith("/v1/files")) {
    if (url.pathname.endsWith("/content")) {
      callLog.push({ index: callLog.length, at: Date.now(), endpoint: "files.content" });
      res.writeHead(200, { "content-type": "application/octet-stream" });
      res.end(Buffer.from('{"custom_id":"a","response":{"body":{"choices":[]}}}\n'));
      return;
    }
    callLog.push({ index: callLog.length, at: Date.now(), endpoint: "files.get" });
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ id: "file_mock_out", object: "file", bytes: 52, purpose: "batch_output" }));
    return;
  }

  // OpenAI chat completions.
  if (req.method === "POST" && url.pathname === "/v1/chat/completions") {
    let body;
    try {
      body = await readJsonBody(req);
    } catch {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { message: "invalid json", type: "invalid_request_error" } }));
      return;
    }

    // Random think time so the appliance experiences realistic latency.
    await sleep(randInt(LATENCY_MIN_MS, LATENCY_MAX_MS));

    const model = typeof body.model === "string" ? body.model : "mock-small";
    const usage = computeUsage(body);
    const text = concatContent(body);
    const nonce = extractNonce(text);
    const blocked = text.includes(REJECT_TRIGGER);
    // Echo the correlation nonce (and, when blocked, the reject trigger) back in
    // the assistant content. Jurors review the *serialized main response* (not
    // the user message), so without this the nonce never reaches juror upstream
    // calls (their tokens go uncounted) and a triggered response carries no
    // reject signal (a moderated jury would wrongly approve). The judge already
    // sees the user text directly, so this only affects the jury path.
    const parts = [blocked ? BLOCKED_CONTENT : APPROVED_CONTENT];
    if (blocked) parts.push(REJECT_TRIGGER);
    if (nonce) parts.push(`[[tkid:${nonce}]]`);
    const content = parts.join(" ");
    // Structured-output requests (the surface asked for json_schema, which the
    // gateway downgrades to json_object for this mock) get a JSON object so the
    // gateway's schema validation passes — populating the drift schema-validity
    // dimension. The APPROVED/BLOCKED keyword and the nonce stay inside the string
    // value, so judge/jury regex and nonce correlation are unaffected.
    const rf = body && body.response_format;
    const wantsJson =
      rf && typeof rf === "object" && (rf.type === "json_object" || rf.type === "json_schema");
    const responseContent = wantsJson ? JSON.stringify({ result: content }) : content;
    const completion = buildCompletion(model, usage, responseContent);

    callLog.push({
      index: callLog.length,
      at: Date.now(),
      model,
      nonce,
      blocked,
      prompt_tokens: usage.prompt_tokens,
      completion_tokens: usage.completion_tokens,
      total_tokens: usage.total_tokens,
    });

    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(completion));
    return;
  }

  // OpenAI embeddings. Embeddings responses carry input-only usage
  // (`prompt_tokens` + `total_tokens`, no `completion_tokens`) so the appliance
  // meters them as input-only spend. Deterministic vectors keep tests stable.
  if (req.method === "POST" && url.pathname === "/v1/embeddings") {
    let body;
    try {
      body = await readJsonBody(req);
    } catch {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { message: "invalid json", type: "invalid_request_error" } }));
      return;
    }

    await sleep(randInt(LATENCY_MIN_MS, LATENCY_MAX_MS));

    const model = typeof body.model === "string" ? body.model : "mock-embed";
    // Normalise `input` to an array of strings (OpenAI accepts string | string[]).
    const inputs = Array.isArray(body.input) ? body.input : [body.input];
    let promptChars = 0;
    for (const item of inputs) if (typeof item === "string") promptChars += item.length;
    const promptTokens = Math.max(1, Math.round(promptChars / 4) + randInt(1, 8));
    const data = inputs.map((item, index) => ({
      object: "embedding",
      index,
      embedding: embedVector(typeof item === "string" ? item : String(item)),
    }));
    const usage = { prompt_tokens: promptTokens, total_tokens: promptTokens };

    callLog.push({
      index: callLog.length,
      at: Date.now(),
      model,
      endpoint: "embeddings",
      prompt_tokens: usage.prompt_tokens,
      completion_tokens: 0,
      total_tokens: usage.total_tokens,
    });

    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ object: "list", data, model, usage }));
    return;
  }

  // OpenAI moderations. Returns a results array with NO usage block, exercising
  // the gateway's tolerance for non-chat responses that carry no token usage
  // (metered as zero tokens instead of failing the request). Flags content that
  // contains the reject trigger so guardrail-style flows can be tested.
  if (req.method === "POST" && url.pathname === "/v1/moderations") {
    let body;
    try {
      body = await readJsonBody(req);
    } catch {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { message: "invalid json", type: "invalid_request_error" } }));
      return;
    }

    await sleep(randInt(LATENCY_MIN_MS, LATENCY_MAX_MS));

    const model = typeof body.model === "string" ? body.model : "text-moderation-latest";
    const text = typeof body.input === "string" ? body.input : JSON.stringify(body.input ?? "");
    const flagged = text.includes(REJECT_TRIGGER);
    callLog.push({ index: callLog.length, at: Date.now(), model, endpoint: "moderations", flagged });
    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        id: `modr-mock-${Math.floor(Date.now() / 1000)}`,
        model,
        results: [
          {
            flagged,
            categories: { harassment: flagged, violence: false },
            category_scores: { harassment: flagged ? 0.97 : 0.01, violence: 0.0 },
          },
        ],
      }),
    );
    return;
  }

  // Cohere/OpenAI-style rerank. Scores each document against the query and
  // returns them sorted; no token usage block.
  if (req.method === "POST" && url.pathname === "/v1/rerank") {
    let body;
    try {
      body = await readJsonBody(req);
    } catch {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { message: "invalid json", type: "invalid_request_error" } }));
      return;
    }

    await sleep(randInt(LATENCY_MIN_MS, LATENCY_MAX_MS));

    const model = typeof body.model === "string" ? body.model : "mock-rerank";
    const documents = Array.isArray(body.documents) ? body.documents : [];
    const results = documents
      .map((_, index) => ({ index, relevance_score: 1 / (index + 1) }))
      .sort((a, b) => b.relevance_score - a.relevance_score);
    callLog.push({ index: callLog.length, at: Date.now(), model, endpoint: "rerank" });
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ id: `rrnk-mock-${Math.floor(Date.now() / 1000)}`, model, results }));
    return;
  }

  // Image generation — returns JSON (b64/url), so it rides the normal buffered
  // path with the zero-usage tolerance.
  if (req.method === "POST" && url.pathname === "/v1/images/generations") {
    let body;
    try {
      body = await readJsonBody(req);
    } catch {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { message: "invalid json", type: "invalid_request_error" } }));
      return;
    }
    await sleep(randInt(LATENCY_MIN_MS, LATENCY_MAX_MS));
    const count = Number.isInteger(body.n) ? body.n : 1;
    const data = Array.from({ length: Math.max(1, count) }, () => ({ b64_json: "aGVsbG8=" }));
    callLog.push({ index: callLog.length, at: Date.now(), endpoint: "images", model: body.model || "mock-image" });
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ created: Math.floor(Date.now() / 1000), data }));
    return;
  }

  // Speech-to-text (transcription) — returns JSON text, buffered path.
  if (req.method === "POST" && url.pathname === "/v1/audio/transcriptions") {
    await sleep(randInt(LATENCY_MIN_MS, LATENCY_MAX_MS));
    callLog.push({ index: callLog.length, at: Date.now(), endpoint: "transcriptions" });
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ text: "mock transcription" }));
    return;
  }

  // Text-to-speech — returns BINARY audio, exercising the gateway's binary
  // passthrough (raw bytes proxied verbatim with the upstream content type).
  if (req.method === "POST" && url.pathname === "/v1/audio/speech") {
    await sleep(randInt(LATENCY_MIN_MS, LATENCY_MAX_MS));
    callLog.push({ index: callLog.length, at: Date.now(), endpoint: "speech" });
    // A tiny deterministic binary blob standing in for audio bytes.
    const audio = Buffer.from([0x49, 0x44, 0x33, 0x00, 0x00, 0x00]);
    res.writeHead(200, { "content-type": "audio/mpeg" });
    res.end(audio);
    return;
  }

  res.writeHead(404, { "content-type": "application/json" });
  res.end(JSON.stringify({ error: { message: `no route for ${req.method} ${url.pathname}`, type: "invalid_request_error" } }));
});

server.listen(PORT, "0.0.0.0", () => {
  // eslint-disable-next-line no-console
  console.log(
    `[mock-llm] listening on 0.0.0.0:${PORT} (think time ${LATENCY_MIN_MS}-${LATENCY_MAX_MS}ms)`,
  );
});
