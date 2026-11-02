"use strict";

// Real-API conformance suite for the LLM Surface ingress dialects.
//
// Unlike the mock-LLM load/reconciliation harness (which never touches a real
// provider), this exercises the appliance against the REAL OpenAI and Anthropic
// APIs to prove that a Surface conforms to every client dialect it now accepts —
// OpenAI Chat Completions (/v1/chat/completions), Anthropic Messages
// (/v1/messages), and OpenAI Responses (/v1/responses) — plus /v1/models and
// /v1/embeddings. The whole point of the feature is that the client dialect is
// independent of the upstream model, so every dialect is driven against BOTH an
// OpenAI-backed and an Anthropic-backed surface (a cross-product), using the
// operator's provider keys resolved by tag (`test-suite-openai` /
// `test-suite-anthropic`).
//
// This is a CONFORMANCE test (shape correctness), not a load test: one call per
// case, small token budgets. It creates its own `test_surface`-tagged surfaces
// and tears them down at the end.

const zlib = require("zlib");
const fs = require("fs");
const path = require("path");

const { makeJwtSigner } = require("./identities");

// ── tiny valid PNG (generated, no deps) for the vision cases ──
function crc32(buf) {
  let c = ~0;
  for (let i = 0; i < buf.length; i += 1) {
    c ^= buf[i];
    for (let k = 0; k < 8; k += 1) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
  }
  return (~c) >>> 0;
}
function pngChunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, "ascii");
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([len, typeBuf, data, crc]);
}
// A solid NxN RGB PNG, big enough that both OpenAI and Anthropic accept it.
function makePngBase64(size = 48) {
  const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 2; // color type: RGB
  const row = Buffer.alloc(1 + size * 3);
  for (let x = 0; x < size; x += 1) {
    row[1 + x * 3] = 200;
    row[2 + x * 3] = 40;
    row[3 + x * 3] = 40;
  }
  const raw = Buffer.concat(Array.from({ length: size }, () => row));
  const idat = zlib.deflateSync(raw);
  const png = Buffer.concat([
    sig,
    pngChunk("IHDR", ihdr),
    pngChunk("IDAT", idat),
    pngChunk("IEND", Buffer.alloc(0)),
  ]);
  return png.toString("base64");
}
const TINY_PNG_B64 = makePngBase64(48);

// ── minimal document builders (DOCX / PDF / text) for the ingestion cases ──
// A tiny single-entry ZIP writer (STORE method, no compression) — enough for a
// DOCX whose only meaningful part is word/document.xml. Reuses crc32 above.
function zipStore(entries) {
  const chunks = [];
  const central = [];
  let offset = 0;
  for (const { name, data } of entries) {
    const nameBuf = Buffer.from(name, "utf8");
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(0, 6); // flags
    local.writeUInt16LE(0, 8); // method: store
    local.writeUInt16LE(0, 10); // mod time
    local.writeUInt16LE(0, 12); // mod date
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18); // compressed size
    local.writeUInt32LE(data.length, 22); // uncompressed size
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28); // extra len
    chunks.push(local, nameBuf, data);

    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(20, 4); // version made by
    cd.writeUInt16LE(20, 6); // version needed
    cd.writeUInt16LE(0, 8); // flags
    cd.writeUInt16LE(0, 10); // method
    cd.writeUInt16LE(0, 12); // time
    cd.writeUInt16LE(0, 14); // date
    cd.writeUInt32LE(crc, 16);
    cd.writeUInt32LE(data.length, 20);
    cd.writeUInt32LE(data.length, 24);
    cd.writeUInt16LE(nameBuf.length, 28);
    cd.writeUInt16LE(0, 30); // extra len
    cd.writeUInt16LE(0, 32); // comment len
    cd.writeUInt16LE(0, 34); // disk number
    cd.writeUInt16LE(0, 36); // internal attrs
    cd.writeUInt32LE(0, 38); // external attrs
    cd.writeUInt32LE(offset, 42); // local header offset
    central.push(cd, nameBuf);

    offset += local.length + nameBuf.length + data.length;
  }
  const cdBuf = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4); // disk number
  eocd.writeUInt16LE(0, 6); // disk with CD
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(offset, 16); // CD offset
  eocd.writeUInt16LE(0, 20); // comment len
  return Buffer.concat([...chunks, cdBuf, eocd]);
}
function xmlEscape(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
// A one-paragraph DOCX carrying `text`, base64-encoded.
function makeDocxBase64(text) {
  const xml =
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">' +
    `<w:body><w:p><w:r><w:t>${xmlEscape(text)}</w:t></w:r></w:p></w:body></w:document>`;
  return zipStore([{ name: "word/document.xml", data: Buffer.from(xml, "utf8") }]).toString("base64");
}
// A minimal, structurally-valid single-page PDF carrying `text`. PDF is
// forwarded (not yet extracted), so this only needs to be a valid PDF blob.
function makePdfBase64(text) {
  const content = `BT /F1 24 Tf 72 700 Td (${text.replace(/[()\\]/g, "")}) Tj ET`;
  const objs = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
    `<< /Length ${content.length} >>\nstream\n${content}\nendstream`,
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
  ];
  let pdf = "%PDF-1.4\n";
  const offsets = [];
  objs.forEach((body, i) => {
    offsets.push(Buffer.byteLength(pdf, "latin1"));
    pdf += `${i + 1} 0 obj\n${body}\nendobj\n`;
  });
  const xrefOffset = Buffer.byteLength(pdf, "latin1");
  pdf += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n`;
  offsets.forEach((off) => {
    pdf += `${String(off).padStart(10, "0")} 00000 n \n`;
  });
  pdf += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`;
  return Buffer.from(pdf, "latin1").toString("base64");
}
function textDataUrl(mime, text) {
  return `data:${mime};base64,${Buffer.from(text, "utf8").toString("base64")}`;
}

// ── assertions ──
function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}
// A soft assertion records a non-fatal issue (reported, but does not fail the
// suite) — used for behaviours that depend on the upstream provider rather than
// our dialect conformance (e.g. usage in a streamed response).
function assertSoft(cond, msg) {
  if (!cond) {
    const e = new Error(msg);
    e.soft = true;
    throw e;
  }
}
function isStr(v) {
  return typeof v === "string" && v.length > 0;
}
function isNum(v) {
  return typeof v === "number" && Number.isFinite(v);
}
function isInt(v) {
  return isNum(v) && Number.isInteger(v);
}

// ── SSE parsers ──
// OpenAI stream: `data: {chunk}` lines + a terminal `data: [DONE]`.
function parseOpenAiSse(lines) {
  const out = [];
  for (const line of lines) {
    if (!line.startsWith("data:")) continue;
    const payload = line.slice(5).trim();
    if (!payload) continue;
    if (payload === "[DONE]") {
      out.push("[DONE]");
      continue;
    }
    try {
      out.push(JSON.parse(payload));
    } catch {
      /* ignore malformed */
    }
  }
  return out;
}
// Anthropic / Responses stream: `event: <type>` + `data: {json}` pairs.
function parseEventSse(lines) {
  const out = [];
  let event = null;
  for (const line of lines) {
    if (line.startsWith("event:")) {
      event = line.slice(6).trim();
      continue;
    }
    if (line.startsWith("data:")) {
      const payload = line.slice(5).trim();
      if (!payload || payload === "[DONE]") {
        event = null;
        continue;
      }
      try {
        out.push({ event, data: JSON.parse(payload) });
      } catch {
        /* ignore malformed */
      }
      event = null;
    }
  }
  return out;
}

// ── tool schemas per dialect ──
const WEATHER_PARAMS = {
  type: "object",
  properties: { location: { type: "string", description: "City name" } },
  required: ["location"],
};
const OPENAI_WEATHER_TOOL = {
  type: "function",
  function: { name: "get_weather", description: "Get the current weather for a location", parameters: WEATHER_PARAMS },
};
const ANTHROPIC_WEATHER_TOOL = {
  name: "get_weather",
  description: "Get the current weather for a location",
  input_schema: WEATHER_PARAMS,
};
const RESPONSES_WEATHER_TOOL = {
  type: "function",
  name: "get_weather",
  description: "Get the current weather for a location",
  parameters: WEATHER_PARAMS,
};

// ────────────────────────────────────────────────────────────────────────────
// OpenAI Chat Completions dialect  ( POST {route}/v1/chat/completions )
// ────────────────────────────────────────────────────────────────────────────
function openAiChatCases(model) {
  const P = "/v1/chat/completions";
  return [
    {
      name: "chat: simple message",
      async run(app, s) {
        const r = await app.callSurface(s.route, P, {
          body: { model, messages: [{ role: "user", content: "Say hello in one short word." }], max_tokens: 16 },
        });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        const j = r.json;
        assert(isStr(j.id), "missing id");
        assert(j.object === "chat.completion", `object=${j.object}`);
        assert(isStr(j.model), "missing model");
        assert(Array.isArray(j.choices) && j.choices.length >= 1, "missing choices");
        assert(j.choices[0].message.role === "assistant", "role not assistant");
        assert(isStr(j.choices[0].message.content), "empty content");
        assert(isStr(j.choices[0].finish_reason), "missing finish_reason");
        assert(j.usage && isInt(j.usage.prompt_tokens) && isInt(j.usage.completion_tokens), "bad usage");
        assert(isInt(j.usage.total_tokens), "missing total_tokens");
      },
    },
    {
      name: "chat: system message",
      async run(app, s) {
        const r = await app.callSurface(s.route, P, {
          body: {
            model,
            messages: [
              { role: "system", content: "You are a terse assistant." },
              { role: "user", content: "Say hello." },
            ],
            max_tokens: 16,
          },
        });
        assert(r.status === 200, `status ${r.status}`);
        assert(r.json.choices[0].message.role === "assistant", "role not assistant");
        assert(isStr(r.json.choices[0].message.content), "empty content");
      },
    },
    {
      name: "chat: multi-turn",
      async run(app, s) {
        const r = await app.callSurface(s.route, P, {
          body: {
            model,
            messages: [
              { role: "user", content: "My name is Alice." },
              { role: "assistant", content: "Hello Alice!" },
              { role: "user", content: "What is my name? One word." },
            ],
            max_tokens: 16,
          },
        });
        assert(r.status === 200, `status ${r.status}`);
        assert(isStr(r.json.choices[0].message.content), "empty content");
      },
    },
    {
      name: "chat: content as array parts",
      async run(app, s) {
        const r = await app.callSurface(s.route, P, {
          body: {
            model,
            messages: [{ role: "user", content: [{ type: "text", text: "Say hello." }] }],
            max_tokens: 16,
          },
        });
        assert(r.status === 200, `status ${r.status}`);
        assert(isStr(r.json.choices[0].message.content), "empty content");
      },
    },
    {
      name: "chat: temperature + stop",
      async run(app, s) {
        const r = await app.callSurface(s.route, P, {
          body: {
            model,
            messages: [{ role: "user", content: "Count: 1 2 3 4 5 6" }],
            temperature: 0.0,
            stop: ["4"],
            max_tokens: 24,
          },
        });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
      },
    },
    {
      name: "chat: streaming chunks + [DONE]",
      async run(app, s) {
        const r = await app.streamSurface(s.route, P, {
          body: { model, messages: [{ role: "user", content: "Say hello." }], stream: true, max_tokens: 24 },
        });
        assert(r.status === 200, `status ${r.status}`);
        assert(r.contentType.includes("text/event-stream"), `content-type ${r.contentType}`);
        const chunks = parseOpenAiSse(r.lines);
        assert(chunks.length >= 1, "no chunks");
        assert(chunks[chunks.length - 1] === "[DONE]", "missing terminal [DONE]");
        let sawRole = false;
        let sawFinish = false;
        let text = "";
        for (const c of chunks) {
          if (c === "[DONE]") continue;
          assert(c.object === "chat.completion.chunk", `chunk object=${c.object}`);
          const d = c.choices && c.choices[0] && c.choices[0].delta;
          if (d && d.role === "assistant") sawRole = true;
          if (d && isStr(d.content)) text += d.content;
          if (c.choices && c.choices[0] && isStr(c.choices[0].finish_reason)) sawFinish = true;
        }
        assert(sawRole, "no role delta");
        assert(text.length > 0, "no content delta");
        assert(sawFinish, "no finish_reason");
      },
    },
    {
      name: "chat: streaming usage (include_usage)",
      async run(app, s) {
        const r = await app.streamSurface(s.route, P, {
          body: {
            model,
            messages: [{ role: "user", content: "Say hi." }],
            stream: true,
            stream_options: { include_usage: true },
            max_tokens: 16,
          },
        });
        assert(r.status === 200, `status ${r.status}`);
        const chunks = parseOpenAiSse(r.lines).filter((c) => c !== "[DONE]");
        const withUsage = chunks.find((c) => c.usage && isInt(c.usage.total_tokens));
        assertSoft(!!withUsage, "no usage chunk (upstream may not echo stream usage)");
      },
    },
    {
      name: "chat: tool call",
      capability: "tools",
      async run(app, s) {
        const r = await app.callSurface(s.route, P, {
          body: {
            model,
            messages: [{ role: "user", content: "What's the weather in Tokyo? Use the tool." }],
            tools: [OPENAI_WEATHER_TOOL],
            max_tokens: 128,
          },
        });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        const msg = r.json.choices[0].message;
        const fr = r.json.choices[0].finish_reason;
        if (fr === "tool_calls" || (msg.tool_calls && msg.tool_calls.length)) {
          const tc = msg.tool_calls[0];
          assert(isStr(tc.id), "tool_call missing id");
          assert(tc.type === "function", "tool_call type not function");
          assert(tc.function.name === "get_weather", `tool name ${tc.function.name}`);
          const args = JSON.parse(tc.function.arguments);
          assert("location" in args, "tool args missing location");
        } else {
          assert(isStr(msg.content), "no tool call and no content");
        }
      },
    },
    {
      name: "chat: tool result round-trip",
      capability: "tools",
      async run(app, s) {
        const first = await app.callSurface(s.route, P, {
          body: {
            model,
            messages: [{ role: "user", content: "What's the weather in Tokyo? Use the tool." }],
            tools: [OPENAI_WEATHER_TOOL],
            max_tokens: 128,
          },
        });
        assert(first.status === 200, `first status ${first.status}`);
        const msg = first.json.choices[0].message;
        if (!msg.tool_calls || !msg.tool_calls.length) {
          return; // model answered directly; round-trip not applicable this run
        }
        const tc = msg.tool_calls[0];
        const second = await app.callSurface(s.route, P, {
          body: {
            model,
            messages: [
              { role: "user", content: "What's the weather in Tokyo? Use the tool." },
              { role: "assistant", content: null, tool_calls: [tc] },
              { role: "tool", tool_call_id: tc.id, content: '{"temperature":"22C","condition":"sunny"}' },
            ],
            tools: [OPENAI_WEATHER_TOOL],
            max_tokens: 64,
          },
        });
        assert(second.status === 200, `second status ${second.status}: ${second.text.slice(0, 200)}`);
        assert(isStr(second.json.choices[0].message.content), "no final answer after tool result");
      },
    },
    {
      name: "chat: vision (image_url data URL)",
      capability: "vision",
      async run(app, s) {
        const r = await app.callSurface(s.route, P, {
          body: {
            model,
            messages: [
              {
                role: "user",
                content: [
                  { type: "text", text: "What color dominates this image? One word." },
                  { type: "image_url", image_url: { url: `data:image/png;base64,${TINY_PNG_B64}` } },
                ],
              },
            ],
            max_tokens: 24,
          },
        });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        assert(isStr(r.json.choices[0].message.content), "empty vision content");
      },
    },
    {
      name: "chat: json_schema structured output",
      async run(app, s) {
        const schema = {
          type: "object",
          properties: { city: { type: "string" }, population: { type: "integer" } },
          required: ["city", "population"],
          additionalProperties: false,
        };
        const r = await app.callSurface(s.route, P, {
          body: {
            model,
            messages: [{ role: "user", content: "Return JSON for Tokyo with its name and approximate population." }],
            response_format: { type: "json_schema", json_schema: { name: "city_info", strict: true, schema } },
            max_tokens: 128,
          },
        });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        const content = r.json.choices[0].message.content;
        assert(isStr(content) && content.length > 0, "empty content");
        // The gateway validates structured output on every provider and reports
        // conformance via the schema-valid header — proving validation ran.
        assert(
          r.headers["x-agent-stream-schema-valid"] === "true" || r.headers["x-agent-stream-schema-valid"] === "false",
          `missing x-agent-stream-schema-valid header (got ${r.headers["x-agent-stream-schema-valid"]})`,
        );
        // Native (OpenAI) enforces the schema; steered (Anthropic) providers can
        // occasionally deviate, so a parse/shape miss is soft, not a hard fail.
        try {
          const obj = JSON.parse(content);
          assert(typeof obj.city === "string" && Number.isInteger(obj.population), "shape mismatch");
          assert(r.headers["x-agent-stream-schema-valid"] === "true", "schema-valid header should be true for conforming output");
        } catch (e) {
          const err = new Error(`structured output not schema-conforming: ${e.message}`);
          err.soft = true;
          throw err;
        }
      },
    },
    {
      name: "chat: reasoning object surfaces message.reasoning",
      capability: "reasoning",
      async run(app, s) {
        const r = await app.callSurface(s.route, P, {
          body: {
            model,
            messages: [{ role: "user", content: "What is 27 * 34? Think briefly, then answer." }],
            reasoning: { effort: "low" },
            max_tokens: 2048,
          },
        });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        const msg = r.json.choices[0].message;
        assert(isStr(msg.content) && msg.content.length > 0, "empty answer content");
        // A reasoning-capable upstream returns reasoning, normalized to the
        // OpenAI-canonical `message.reasoning` (+ round-trippable details).
        assert(isStr(msg.reasoning) && msg.reasoning.length > 0, "expected message.reasoning");
        assert(Array.isArray(msg.reasoning_details) && msg.reasoning_details.length >= 1, "expected reasoning_details");
        // The reasoning-tokens meter header is always emitted (0 for Anthropic,
        // which folds thinking into output).
        assert(r.headers["x-agent-stream-reasoning-tokens"] !== undefined, "missing x-agent-stream-reasoning-tokens header");
      },
    },
    {
      name: "chat: prompt-cache breakpoint passthrough",
      capability: "caching",
      async run(app, s) {
        // A cache_control breakpoint on a large system prefix must survive to the
        // provider so it can cache it. Send twice: the first writes the cache,
        // the second should read it. The prefix must exceed the provider's cache
        // minimum (~2048 tokens for Claude Haiku) for caching to engage.
        const bigContext = "Reference material for the prompt cache conformance test. ".repeat(500);
        const body = (q) => ({
          model,
          max_tokens: 32,
          messages: [
            {
              role: "system",
              content: [{ type: "text", text: bigContext, cache_control: { type: "ephemeral" } }],
            },
            { role: "user", content: q },
          ],
        });
        const first = await app.callSurface(s.route, P, { body: body("Reply with the word ready.") });
        assert(first.status === 200, `first status ${first.status}: ${first.text.slice(0, 200)}`);
        const second = await app.callSurface(s.route, P, { body: body("Reply with the word set.") });
        assert(second.status === 200, `second status ${second.status}: ${second.text.slice(0, 200)}`);
        // Provider prompt caching is timing/TTL-dependent, so a zero count is
        // soft, but the breakpoint being accepted (200 above) proves passthrough.
        const write = Number(first.headers["x-agent-stream-cache-write-tokens"] || 0);
        const read = Number(second.headers["x-agent-stream-cached-tokens"] || 0);
        if (write === 0 && read === 0) {
          const err = new Error("no cache write/read tokens observed (provider cache may be cold)");
          err.soft = true;
          throw err;
        }
      },
    },
  ];
}

// ────────────────────────────────────────────────────────────────────────────
// Anthropic Messages dialect  ( POST {route}/v1/messages )
// ────────────────────────────────────────────────────────────────────────────
const ANTHROPIC_HEADERS = { "x-api-key": "conformance-test", "anthropic-version": "2023-06-01" };

function anthropicMessagesCases(model) {
  const P = "/v1/messages";
  const H = ANTHROPIC_HEADERS;
  return [
    {
      name: "messages: simple message",
      async run(app, s) {
        const r = await app.callSurface(s.route, P, {
          headers: H,
          body: { model, max_tokens: 32, messages: [{ role: "user", content: "Say hello." }] },
        });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        const j = r.json;
        assert(isStr(j.id) && j.id.startsWith("msg"), `id=${j.id}`);
        assert(j.type === "message", `type=${j.type}`);
        assert(j.role === "assistant", `role=${j.role}`);
        assert(isStr(j.model), "missing model");
        assert(Array.isArray(j.content) && j.content.length >= 1, "missing content");
        assert(j.content[0].type === "text", `content[0].type=${j.content[0].type}`);
        assert(isStr(j.content[0].text), "empty text");
        assert(["end_turn", "max_tokens", "stop_sequence", "tool_use"].includes(j.stop_reason), `stop_reason=${j.stop_reason}`);
        assert(j.usage && isInt(j.usage.input_tokens) && isInt(j.usage.output_tokens), "bad usage");
      },
    },
    {
      name: "messages: system + top_p + top_k + temperature",
      async run(app, s) {
        const r = await app.callSurface(s.route, P, {
          headers: H,
          body: {
            model,
            max_tokens: 32,
            system: "You are a terse assistant.",
            temperature: 0.0,
            top_p: 0.9,
            top_k: 40,
            messages: [{ role: "user", content: "Say hello." }],
          },
        });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        assert(r.json.content[0].type === "text", "content not text");
        assert(isStr(r.json.content[0].text), "empty text");
      },
    },
    {
      name: "messages: multi-turn",
      async run(app, s) {
        const r = await app.callSurface(s.route, P, {
          headers: H,
          body: {
            model,
            max_tokens: 32,
            messages: [
              { role: "user", content: "My name is Alice." },
              { role: "assistant", content: "Hello Alice!" },
              { role: "user", content: "What is my name? One word." },
            ],
          },
        });
        assert(r.status === 200, `status ${r.status}`);
        assert(isStr(r.json.content[0].text), "empty text");
      },
    },
    {
      name: "messages: max_tokens + stop_sequences",
      async run(app, s) {
        const r = await app.callSurface(s.route, P, {
          headers: H,
          body: {
            model,
            max_tokens: 8,
            stop_sequences: ["4"],
            messages: [{ role: "user", content: "Count from 1 to 10." }],
          },
        });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        assert(["end_turn", "max_tokens", "stop_sequence"].includes(r.json.stop_reason), `stop_reason=${r.json.stop_reason}`);
      },
    },
    {
      name: "messages: streaming events",
      async run(app, s) {
        const r = await app.streamSurface(s.route, P, {
          headers: H,
          body: { model, max_tokens: 32, messages: [{ role: "user", content: "Say hello." }], stream: true },
        });
        assert(r.status === 200, `status ${r.status}`);
        assert(r.contentType.includes("text/event-stream"), `content-type ${r.contentType}`);
        const events = parseEventSse(r.lines);
        const types = events.map((e) => e.event);
        assert(types.includes("message_start"), "no message_start");
        assert(types.includes("message_stop"), "no message_stop");
        const start = events.find((e) => e.event === "message_start");
        assert(start.data.type === "message_start", "message_start data.type");
        assert(isStr(start.data.message.id), "message_start missing id");
        assert(start.data.message.role === "assistant", "message_start role");
        let text = "";
        for (const e of events) {
          if (e.event === "content_block_delta" && e.data.delta && e.data.delta.type === "text_delta") {
            text += e.data.delta.text || "";
          }
        }
        assert(text.length > 0, "no text_delta content");
        assert(types.includes("message_delta"), "no message_delta");
      },
    },
    {
      name: "messages: tool_use",
      capability: "tools",
      async run(app, s) {
        const r = await app.callSurface(s.route, P, {
          headers: H,
          body: {
            model,
            max_tokens: 256,
            messages: [{ role: "user", content: "What's the weather in Tokyo? Use the tool." }],
            tools: [ANTHROPIC_WEATHER_TOOL],
          },
        });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        if (r.json.stop_reason === "tool_use") {
          const block = r.json.content.find((b) => b.type === "tool_use");
          assert(block, "no tool_use block");
          assert(isStr(block.id), "tool_use missing id");
          assert(block.name === "get_weather", `tool name ${block.name}`);
          assert(block.input && typeof block.input === "object", "tool_use missing input");
        } else {
          assert(r.json.content.some((b) => b.type === "text" && isStr(b.text)), "no tool_use and no text");
        }
      },
    },
    {
      name: "messages: forced tool_choice (structured output)",
      capability: "tools",
      async run(app, s) {
        const tool = {
          name: "record_city_info",
          description: "Record structured info about a city.",
          input_schema: {
            type: "object",
            properties: { city: { type: "string" }, population: { type: "integer" } },
            required: ["city", "population"],
          },
        };
        const r = await app.callSurface(s.route, P, {
          headers: H,
          body: {
            model,
            max_tokens: 256,
            messages: [{ role: "user", content: "Record data for Tokyo." }],
            tools: [tool],
            tool_choice: { type: "tool", name: "record_city_info" },
          },
        });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        const block = r.json.content.find((b) => b.type === "tool_use");
        assert(block, "forced tool did not produce a tool_use block");
        assert(block.name === "record_city_info", `tool name ${block.name}`);
        assert(block.input && isStr(block.input.city), "missing input.city");
      },
    },
    {
      name: "messages: vision (base64 image source)",
      capability: "vision",
      async run(app, s) {
        const r = await app.callSurface(s.route, P, {
          headers: H,
          body: {
            model,
            max_tokens: 32,
            messages: [
              {
                role: "user",
                content: [
                  { type: "image", source: { type: "base64", media_type: "image/png", data: TINY_PNG_B64 } },
                  { type: "text", text: "What color dominates this image? One word." },
                ],
              },
            ],
          },
        });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        assert(r.json.content.some((b) => b.type === "text" && isStr(b.text)), "empty vision content");
      },
    },
    {
      name: "messages: extended thinking round-trip",
      capability: "reasoning",
      async run(app, s) {
        const r = await app.callSurface(s.route, P, {
          headers: H,
          body: {
            model,
            max_tokens: 2048,
            thinking: { type: "enabled", budget_tokens: 1024 },
            messages: [{ role: "user", content: "What is 27 * 34? Think step by step, then answer." }],
          },
        });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        const types = r.json.content.map((b) => b.type);
        // Thinking is re-skinned to a native Anthropic thinking block, ahead of
        // the text answer.
        assert(types.includes("thinking") || types.includes("redacted_thinking"), `expected a thinking block, got: ${types.join(",")}`);
        assert(r.json.content.some((b) => b.type === "text" && isStr(b.text)), "expected a text answer block");
      },
    },
    {
      name: "messages: cache_control breakpoint round-trip",
      capability: "caching",
      async run(app, s) {
        // A native Anthropic client's cache_control on the system prompt must
        // survive normalization and re-shape back to the Anthropic wire. The
        // prefix must exceed the provider cache minimum (~2048 tokens for Haiku).
        const bigContext = "Reference material for the prompt cache conformance test. ".repeat(500);
        const body = (q) => ({
          model,
          max_tokens: 32,
          system: [{ type: "text", text: bigContext, cache_control: { type: "ephemeral" } }],
          messages: [{ role: "user", content: q }],
        });
        const first = await app.callSurface(s.route, P, { headers: H, body: body("Reply with the word ready.") });
        assert(first.status === 200, `first status ${first.status}: ${first.text.slice(0, 200)}`);
        const second = await app.callSurface(s.route, P, { headers: H, body: body("Reply with the word set.") });
        assert(second.status === 200, `second status ${second.status}: ${second.text.slice(0, 200)}`);
        // Anthropic reports cache creation/read in the message usage block.
        const write = Number(first.json.usage?.cache_creation_input_tokens || 0);
        const read = Number(second.json.usage?.cache_read_input_tokens || 0);
        if (write === 0 && read === 0) {
          const err = new Error("no cache tokens in Anthropic usage (provider cache may be cold)");
          err.soft = true;
          throw err;
        }
      },
    },
  ];
}

// ────────────────────────────────────────────────────────────────────────────
// OpenAI Responses dialect  ( POST {route}/v1/responses )
// ────────────────────────────────────────────────────────────────────────────
function responsesCases(model) {
  const P = "/v1/responses";
  const outputText = (j) => {
    if (isStr(j.output_text)) return j.output_text;
    const msg = (j.output || []).find((i) => i.type === "message");
    const part = msg && (msg.content || []).find((c) => c.type === "output_text");
    return part ? part.text : "";
  };
  return [
    {
      name: "responses: simple input",
      async run(app, s) {
        const r = await app.callSurface(s.route, P, {
          body: { model, input: "Say hello in one short word.", max_output_tokens: 32 },
        });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        const j = r.json;
        assert(isStr(j.id) && j.id.startsWith("resp"), `id=${j.id}`);
        assert(j.object === "response", `object=${j.object}`);
        assert(["completed", "incomplete"].includes(j.status), `status field=${j.status}`);
        assert(Array.isArray(j.output), "missing output array");
        assert(isStr(outputText(j)), "empty output text");
        assert(j.usage && isInt(j.usage.input_tokens) && isInt(j.usage.output_tokens), "bad usage");
      },
    },
    {
      name: "responses: instructions + input",
      async run(app, s) {
        const r = await app.callSurface(s.route, P, {
          body: { model, instructions: "You are terse.", input: "Say hello.", max_output_tokens: 32 },
        });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        assert(isStr(outputText(r.json)), "empty output text");
      },
    },
    {
      name: "responses: input item array",
      async run(app, s) {
        const r = await app.callSurface(s.route, P, {
          body: {
            model,
            input: [{ type: "message", role: "user", content: [{ type: "input_text", text: "Say hello." }] }],
            max_output_tokens: 32,
          },
        });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        assert(isStr(outputText(r.json)), "empty output text");
      },
    },
    {
      name: "responses: streaming events",
      async run(app, s) {
        const r = await app.streamSurface(s.route, P, {
          body: { model, input: "Say hello.", stream: true, max_output_tokens: 32 },
        });
        assert(r.status === 200, `status ${r.status}`);
        assert(r.contentType.includes("text/event-stream"), `content-type ${r.contentType}`);
        const events = parseEventSse(r.lines);
        const types = events.map((e) => e.event);
        assert(types.includes("response.created"), "no response.created");
        assert(types.includes("response.completed"), "no response.completed");
        let text = "";
        for (const e of events) {
          if (e.event === "response.output_text.delta") text += e.data.delta || "";
        }
        assert(text.length > 0, "no output_text.delta content");
        const done = events.find((e) => e.event === "response.completed");
        assert(done.data.response && isStr(done.data.response.status), "completed missing response.status");
      },
    },
    {
      name: "responses: tool (function_call)",
      capability: "tools",
      async run(app, s) {
        const r = await app.callSurface(s.route, P, {
          body: {
            model,
            input: "What's the weather in Tokyo? Use the tool.",
            tools: [RESPONSES_WEATHER_TOOL],
            max_output_tokens: 256,
          },
        });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        const fc = (r.json.output || []).find((i) => i.type === "function_call");
        if (fc) {
          assert(fc.name === "get_weather", `fn name ${fc.name}`);
          assert(isStr(fc.call_id), "function_call missing call_id");
          assert(typeof fc.arguments === "string", "function_call arguments not string");
        } else {
          assert(isStr(outputText(r.json)), "no function_call and no output text");
        }
      },
    },
    {
      name: "responses: vision (input_image)",
      capability: "vision",
      async run(app, s) {
        const r = await app.callSurface(s.route, P, {
          body: {
            model,
            input: [
              {
                type: "message",
                role: "user",
                content: [
                  { type: "input_text", text: "What color dominates this image? One word." },
                  { type: "input_image", image_url: `data:image/png;base64,${TINY_PNG_B64}` },
                ],
              },
            ],
            max_output_tokens: 24,
          },
        });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        assert(isStr(outputText(r.json)), "empty vision output text");
      },
    },
  ];
}

// ── endpoint (non-dialect) cases ──
function modelsCase() {
  return {
    name: "models: discovery",
    async run(app, s) {
      const r = await app.getSurface(s.route, "/v1/models", {});
      assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
      const data = Array.isArray(r.json) ? r.json : r.json.data;
      assert(Array.isArray(data) && data.length >= 1, "no models listed");
      assert(data.every((m) => isStr(m.id)), "a model is missing an id");
    },
  };
}
function embeddingsCases(model) {
  const P = "/v1/embeddings";
  return [
    {
      name: "embeddings: single input",
      async run(app, s) {
        const r = await app.callSurface(s.route, P, { body: { model, input: "Hello world" } });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        const j = r.json;
        assert(j.object === "list", `object=${j.object}`);
        assert(Array.isArray(j.data) && j.data.length >= 1, "no data");
        assert(j.data[0].object === "embedding", "data[0].object");
        assert(Array.isArray(j.data[0].embedding) && j.data[0].embedding.length > 0, "empty embedding");
        assert(j.data[0].embedding.every(isNum), "non-numeric embedding");
        assert(j.data[0].index === 0, "index != 0");
        assert(j.usage && isInt(j.usage.prompt_tokens), "missing usage.prompt_tokens");
      },
    },
    {
      name: "embeddings: batch input",
      async run(app, s) {
        const r = await app.callSurface(s.route, P, { body: { model, input: ["Hello", "World"] } });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        assert(r.json.data.length === 2, `expected 2 embeddings, got ${r.json.data.length}`);
        assert(r.json.data[0].index === 0 && r.json.data[1].index === 1, "bad indices");
      },
    },
  ];
}

// ── surface builders ──
function baseSurface(id, route, listenAddress, description, provider, sourceAuth) {
  const surface = {
    id,
    name: `Conformance ${id}`,
    description,
    pipe_type: { type: "llm", provider },
    listen_address: listenAddress || undefined,
    route,
    cost_tracking: { enabled: true },
    enable_metrics: true,
    metrics_enabled: true,
    created_at: new Date().toISOString(),
    // Debug-only bulk cleanup can find and tombstone it.
    test_surface: true,
  };
  if (sourceAuth) surface.source_auth = sourceAuth;
  return surface;
}

// Security regression guard: assert the new ingress dialects are gated by the
// surface's source auth exactly like /v1/chat/completions — an unauthenticated
// request is rejected (401) on every dialect, and a valid bearer is accepted.
function authEnforcementCases(model, signer) {
  const bearer = `Bearer ${signer.sign("conformance-auth-tester")}`;
  return [
    {
      name: "auth: chat/completions rejects a missing bearer (401)",
      async run(app, s) {
        const r = await app.callSurface(s.route, "/v1/chat/completions", {
          body: { model, messages: [{ role: "user", content: "hi" }], max_tokens: 8 },
        });
        assert(r.status === 401, `expected 401, got ${r.status}: ${r.text.slice(0, 160)}`);
      },
    },
    {
      name: "auth: messages rejects a missing/invalid bearer (401)",
      async run(app, s) {
        // Anthropic clients send x-api-key; our front door maps it to Bearer, but
        // an invalid value is still rejected by source auth — proving the mapping
        // never bypasses authentication.
        const r = await app.callSurface(s.route, "/v1/messages", {
          headers: ANTHROPIC_HEADERS,
          body: { model, max_tokens: 8, messages: [{ role: "user", content: "hi" }] },
        });
        assert(r.status === 401, `expected 401, got ${r.status}: ${r.text.slice(0, 160)}`);
      },
    },
    {
      name: "auth: responses rejects a missing bearer (401)",
      async run(app, s) {
        const r = await app.callSurface(s.route, "/v1/responses", {
          body: { model, input: "hi", max_output_tokens: 8 },
        });
        assert(r.status === 401, `expected 401, got ${r.status}: ${r.text.slice(0, 160)}`);
      },
    },
    {
      name: "auth: chat/completions accepts a valid bearer (200)",
      async run(app, s) {
        const r = await app.callSurface(s.route, "/v1/chat/completions", {
          headers: { authorization: bearer },
          body: { model, messages: [{ role: "user", content: "Say hi." }], max_tokens: 8 },
        });
        assert(r.status === 200, `expected 200 with a valid bearer, got ${r.status}: ${r.text.slice(0, 200)}`);
      },
    },
  ];
}

// Per-request routing preferences (models[] / provider{}) filter and reorder the
// surface's own candidate pool. Run against a surface whose pool is an OpenAI
// primary + an Anthropic failover target; the x-agent-stream-provider response
// header proves which pool member actually answered.
function routingCases(openaiModel, anthropicModel) {
  const P = "/v1/chat/completions";
  const body = (extra) => ({
    model: openaiModel,
    messages: [{ role: "user", content: "Say hi in one short word." }],
    max_tokens: 16,
    ...extra,
  });
  return [
    {
      name: "routing: provider.only steers to the anthropic pool member",
      async run(app, s) {
        const r = await app.callSurface(s.route, P, { body: body({ provider: { only: ["anthropic"] } }) });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        assert(r.headers["x-agent-stream-provider"] === "anthropic", `expected anthropic, got ${r.headers["x-agent-stream-provider"]}`);
      },
    },
    {
      name: "routing: provider.only keeps the primary openai member",
      async run(app, s) {
        const r = await app.callSurface(s.route, P, { body: body({ provider: { only: ["openai"] } }) });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        assert(r.headers["x-agent-stream-provider"] === "openai", `expected openai, got ${r.headers["x-agent-stream-provider"]}`);
      },
    },
    {
      name: "routing: models[] selects the anthropic member",
      async run(app, s) {
        const r = await app.callSurface(s.route, P, { body: body({ models: [anthropicModel] }) });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        assert(r.headers["x-agent-stream-provider"] === "anthropic", `expected anthropic, got ${r.headers["x-agent-stream-provider"]}`);
      },
    },
    {
      name: "routing: an unmatched provider preference is rejected",
      async run(app, s) {
        const r = await app.callSurface(s.route, P, { body: body({ provider: { only: ["cohere"] } }) });
        assert(r.status >= 400, `expected an error status for an empty candidate set, got ${r.status}`);
      },
    },
  ];
}

// Governed server tools (web_fetch / web_search): the gateway executes the tool
// inside the request (agentic loop) under policy + SSRF + domain rules, feeds
// the result back, and cites sources. Whether the model actually calls the tool
// is provider-dependent, so tool-use assertions are soft; the surface accepting
// the request and completing the loop (200) is the hard guarantee. The SSRF
// case is a hard security guard.
function serverToolsCases(model) {
  const P = "/v1/chat/completions";
  return [
    {
      name: "web_fetch: gateway fetches an allowed URL and cites it",
      capability: "web_fetch",
      async run(app, s) {
        const r = await app.callSurface(s.route, P, {
          body: {
            model,
            messages: [
              {
                role: "user",
                content:
                  "Use the web_fetch tool to fetch https://example.com and tell me the page's main heading. Cite the URL.",
              },
            ],
            max_tokens: 200,
          },
        });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        const msg = (r.json && r.json.choices && r.json.choices[0] && r.json.choices[0].message) || {};
        const ann = Array.isArray(msg.annotations) ? msg.annotations : [];
        const cited = ann.some((a) => a && a.url_citation && String(a.url_citation.url).includes("example.com"));
        const mentioned = typeof msg.content === "string" && /example/i.test(msg.content);
        assertSoft(
          cited || mentioned,
          `expected a web_fetch citation or example.com content; annotations=${JSON.stringify(ann).slice(0, 160)}`,
        );
      },
    },
    {
      name: "web_fetch: an SSRF/private target is refused by the guard",
      capability: "web_fetch",
      async run(app, s) {
        // Steer the model at the cloud link-local metadata address. Even if it
        // calls the tool, the gateway SSRF guard must refuse it — the request
        // still completes (200) and must never yield a metadata citation.
        const r = await app.callSurface(s.route, P, {
          body: {
            model,
            messages: [
              {
                role: "user",
                content:
                  "Fetch http://169.254.169.254/latest/meta-data/ using web_fetch and report what you got. If it failed, say 'fetch blocked'.",
              },
            ],
            max_tokens: 150,
          },
        });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        const msg = (r.json && r.json.choices && r.json.choices[0] && r.json.choices[0].message) || {};
        const ann = Array.isArray(msg.annotations) ? msg.annotations : [];
        const leaked = ann.some((a) => a && a.url_citation && String(a.url_citation.url).includes("169.254"));
        assert(!leaked, "SSRF guard must not produce a link-local metadata citation");
      },
    },
    {
      name: "web_search: gateway searches the web and cites results",
      capability: "web_search",
      async run(app, s) {
        const r = await app.callSurface(s.route, P, {
          body: {
            model,
            messages: [
              {
                role: "user",
                content:
                  "Use the web_search tool to find the official Rust programming language website, then tell me its URL and cite your source.",
              },
            ],
            max_tokens: 250,
          },
        });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        const msg = (r.json && r.json.choices && r.json.choices[0] && r.json.choices[0].message) || {};
        const ann = Array.isArray(msg.annotations) ? msg.annotations : [];
        assertSoft(ann.length > 0, `expected at least one web_search citation; annotations=${JSON.stringify(ann).slice(0, 160)}`);
      },
    },
  ];
}

// Context-window guard: middle-out compression. The gateway trims an
// over-window prompt before the upstream call — deterministic (no dependence on
// the model), so these are hard assertions on the x-agent-stream-context-transform
// header. The surface is configured with a tiny window so a modest prompt overflows.
function contextTransformCases(model) {
  const P = "/v1/chat/completions";
  const filler = () => {
    const messages = [{ role: "system", content: "You are a terse assistant. Answer in one word." }];
    for (let i = 0; i < 30; i++) {
      messages.push({
        role: i % 2 === 0 ? "user" : "assistant",
        content: `Filler message number ${i} with several extra words added to raise the token count.`,
      });
    }
    messages.push({ role: "user", content: "Say hi." });
    return messages;
  };
  return [
    {
      name: "context: middle-out compresses an over-window prompt",
      async run(app, s) {
        const r = await app.callSurface(s.route, P, {
          body: { model, messages: filler(), transforms: ["middle-out"], max_tokens: 16 },
        });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        const h = r.headers["x-agent-stream-context-transform"];
        assert(
          typeof h === "string" && h.includes("middle-out"),
          `missing x-agent-stream-context-transform header (got ${h})`,
        );
        const m = /elided=(\d+)/.exec(h || "");
        assert(m && parseInt(m[1], 10) >= 1, `expected elided>=1 in the transform header, got ${h}`);
      },
    },
    {
      name: "context: transforms:[] opts out of compression",
      async run(app, s) {
        const r = await app.callSurface(s.route, P, {
          body: { model, messages: filler(), transforms: [], max_tokens: 16 },
        });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        assert(
          r.headers["x-agent-stream-context-transform"] === undefined,
          `expected no transform header when opted out, got ${r.headers["x-agent-stream-context-transform"]}`,
        );
      },
    },
  ];
}

// Document ingestion: an attached document (text / docx / pdf) is recognized
// and — when the gateway can parse it — extracted to prompt text before the
// upstream call. The gateway-side behaviour is deterministic and asserted via
// the `x-agent-stream-documents` header; whether the model then echoes the
// extracted content is provider-dependent (soft). PDF is forwarded (not yet
// extracted), so its positive case only proves the gateway accepted the upload.
// The surface is configured with a small `max_file_bytes` so the size guard can
// be exercised deterministically. Runs against the OpenAI-backed docs surface.
function documentCases(model) {
  const docsHeader = (r) => r.headers["x-agent-stream-documents"];
  const hasType = (h, t) => typeof h === "string" && new RegExp(`types=[a-z0-9,]*${t}`).test(h);
  const gatewayRejectedDoc = (r) =>
    r.status === 400 &&
    /not permitted on this surface|byte size limit|could not be decoded|cannot extract/i.test(r.text);
  return [
    {
      name: "docs: text upload is extracted to prompt text (openai_chat)",
      async run(app, s) {
        const token = "ZORBLAX-42";
        const r = await app.callSurface(s.route, "/v1/chat/completions", {
          body: {
            model,
            max_tokens: 24,
            messages: [
              {
                role: "user",
                content: [
                  { type: "text", text: "Read the attached document and reply with only the confidential token." },
                  { type: "file", file: { filename: "note.txt", file_data: textDataUrl("text/plain", `The confidential token is ${token}.`) } },
                ],
              },
            ],
          },
        });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        const h = docsHeader(r);
        assert(/extracted=[1-9]/.test(h || ""), `expected an extracted document, got header ${h}`);
        assert(hasType(h, "text"), `expected types to include text, got ${h}`);
        assertSoft(
          new RegExp(token).test((r.json.choices[0].message.content || "")),
          `model did not echo the extracted token (got: ${(r.json.choices[0].message.content || "").slice(0, 80)})`,
        );
      },
    },
    {
      name: "docs: docx upload is extracted to prompt text (openai_chat)",
      async run(app, s) {
        const token = "QUOKKA-7";
        const data = `data:application/vnd.openxmlformats-officedocument.wordprocessingml.document;base64,${makeDocxBase64(`The confidential token is ${token}.`)}`;
        const r = await app.callSurface(s.route, "/v1/chat/completions", {
          body: {
            model,
            max_tokens: 24,
            messages: [
              {
                role: "user",
                content: [
                  { type: "text", text: "Read the attached Word document and reply with only the confidential token." },
                  { type: "file", file: { filename: "note.docx", file_data: data } },
                ],
              },
            ],
          },
        });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        const h = docsHeader(r);
        assert(/extracted=[1-9]/.test(h || ""), `expected an extracted document, got header ${h}`);
        assert(hasType(h, "docx"), `expected types to include docx, got ${h}`);
        assertSoft(
          new RegExp(token).test((r.json.choices[0].message.content || "")),
          `model did not echo the docx token (got: ${(r.json.choices[0].message.content || "").slice(0, 80)})`,
        );
      },
    },
    {
      name: "docs: pdf upload is accepted and forwarded (openai_chat)",
      async run(app, s) {
        const r = await app.callSurface(s.route, "/v1/chat/completions", {
          body: {
            model,
            max_tokens: 24,
            messages: [
              {
                role: "user",
                content: [
                  { type: "text", text: "A PDF is attached." },
                  { type: "file", file: { filename: "doc.pdf", file_data: `data:application/pdf;base64,${makePdfBase64("Conformance PDF body.")}` } },
                ],
              },
            ],
          },
        });
        // Hard: the gateway must ACCEPT the upload (pdf is on the allow-list),
        // not reject it at the ingestion stage. PDF extraction is a follow-up.
        assert(!gatewayRejectedDoc(r), `gateway rejected the pdf upload: ${r.text.slice(0, 200)}`);
        if (r.status === 200) {
          assert(hasType(docsHeader(r), "pdf"), `expected types to include pdf, got ${docsHeader(r)}`);
        } else {
          // The forwarded PDF reached the upstream, which declined it — a
          // provider capability, not a gateway conformance failure.
          assertSoft(false, `pdf forwarded; upstream returned ${r.status}: ${r.text.slice(0, 160)}`);
        }
      },
    },
    {
      name: "docs: an over-size document is rejected (400)",
      async run(app, s) {
        const r = await app.callSurface(s.route, "/v1/chat/completions", {
          body: {
            model,
            max_tokens: 8,
            messages: [
              {
                role: "user",
                content: [
                  { type: "text", text: "read this" },
                  { type: "file", file: { filename: "big.txt", file_data: textDataUrl("text/plain", "x".repeat(12000)) } },
                ],
              },
            ],
          },
        });
        assert(r.status === 400, `expected 400 for an over-size document, got ${r.status}: ${r.text.slice(0, 160)}`);
        assert(/size limit/i.test(r.text), `expected a size-limit error, got ${r.text.slice(0, 160)}`);
      },
    },
    {
      name: "docs: anthropic document block is extracted (anthropic_messages ingress)",
      async run(app, s) {
        const token = "NARWHAL-3";
        const r = await app.callSurface(s.route, "/v1/messages", {
          body: {
            model,
            max_tokens: 24,
            messages: [
              {
                role: "user",
                content: [
                  { type: "text", text: "Reply with only the secret code from the document." },
                  { type: "document", source: { type: "base64", media_type: "text/plain", data: Buffer.from(`The secret code is ${token}.`, "utf8").toString("base64") } },
                ],
              },
            ],
          },
        });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        assert(/extracted=[1-9]/.test(docsHeader(r) || ""), `expected extraction via the anthropic document block, got ${docsHeader(r)}`);
        assertSoft(new RegExp(token).test(JSON.stringify(r.json || {})), `model did not echo the token from the anthropic document`);
      },
    },
    {
      name: "docs: responses input_file is extracted (openai_responses ingress)",
      async run(app, s) {
        const token = "PANGOLIN-5";
        const r = await app.callSurface(s.route, "/v1/responses", {
          body: {
            model,
            max_output_tokens: 24,
            input: [
              {
                type: "message",
                role: "user",
                content: [
                  { type: "input_text", text: "Reply with only the passphrase from the file." },
                  { type: "input_file", filename: "p.txt", file_data: textDataUrl("text/plain", `The passphrase is ${token}.`) },
                ],
              },
            ],
          },
        });
        assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
        assert(/extracted=[1-9]/.test(docsHeader(r) || ""), `expected extraction via the responses input_file, got ${docsHeader(r)}`);
        assertSoft(new RegExp(token).test(JSON.stringify(r.json || {})), `model did not echo the token from the responses input_file`);
      },
    },
  ];
}

// Recognized document extensions → the canonical type the gateway detects, the
// data-URL MIME to send, and whether the appliance extracts it (pdf is forwarded, not
// extracted). Drives the folder-iterating real-document cases below.
const REAL_DOC_TYPES = {
  txt: { type: "text", mime: "text/plain", extract: true },
  text: { type: "text", mime: "text/plain", extract: true },
  log: { type: "text", mime: "text/plain", extract: true },
  md: { type: "markdown", mime: "text/markdown", extract: true },
  markdown: { type: "markdown", mime: "text/markdown", extract: true },
  csv: { type: "csv", mime: "text/csv", extract: true },
  json: { type: "json", mime: "application/json", extract: true },
  docx: {
    type: "docx",
    mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    extract: true,
  },
  pdf: { type: "pdf", mime: "application/pdf", extract: false },
};

// Real-world document uploads: iterate every file in tests/appliance/test-docs and drive a
// case per recognized document type, so an operator can drop in more fixtures
// and they are picked up automatically. Extractable types (text/markdown/csv/
// json/docx) are asserted extracted via the `x-agent-stream-documents` header;
// pdf is accepted and forwarded (the appliance does not extract it). Files whose extension
// the gateway does not recognize are skipped, so an unsupported type does not
// fail the suite. Returns an empty list when the folder is absent or empty.
function realDocumentCases(model, docsDir) {
  const docsHeader = (r) => r.headers["x-agent-stream-documents"];
  const hasType = (h, t) => typeof h === "string" && new RegExp(`types=[a-z0-9,]*${t}`).test(h);
  const gatewayRejectedDoc = (r) =>
    r.status === 400 &&
    /not permitted on this surface|byte size limit|could not be decoded|cannot extract/i.test(r.text);

  let entries = [];
  try {
    entries = fs.readdirSync(docsDir).filter((n) => !n.startsWith("."));
  } catch {
    return [];
  }
  entries.sort();

  const cases = [];
  for (const name of entries) {
    const full = path.join(docsDir, name);
    try {
      if (!fs.statSync(full).isFile()) continue;
    } catch {
      continue;
    }
    const ext = name.split(".").pop().toLowerCase();
    const spec = REAL_DOC_TYPES[ext];
    if (!spec) continue; // Unrecognized type — the gateway would reject it; skip.

    cases.push({
      name: `docs(real): "${name}" ${spec.extract ? "is extracted" : "is accepted and forwarded"} (openai_chat)`,
      async run(app, s) {
        const data = `data:${spec.mime};base64,${fs.readFileSync(full).toString("base64")}`;
        const r = await app.callSurface(s.route, "/v1/chat/completions", {
          body: {
            model,
            max_tokens: 32,
            messages: [
              {
                role: "user",
                content: [
                  { type: "text", text: `A document named "${name}" is attached. In one short sentence, what is it about?` },
                  { type: "file", file: { filename: name, file_data: data } },
                ],
              },
            ],
          },
        });
        if (spec.extract) {
          assert(r.status === 200, `status ${r.status}: ${r.text.slice(0, 200)}`);
          const h = docsHeader(r);
          assert(/extracted=[1-9]/.test(h || ""), `expected "${name}" to be extracted, got header ${h}`);
          assert(hasType(h, spec.type), `expected types to include ${spec.type}, got ${h}`);
          assertSoft(isStr(r.json.choices[0].message.content), `expected a non-empty answer for ${name}`);
        } else {
          assert(!gatewayRejectedDoc(r), `gateway rejected "${name}": ${r.text.slice(0, 200)}`);
          if (r.status === 200) {
            assert(hasType(docsHeader(r), spec.type), `expected types to include ${spec.type}, got ${docsHeader(r)}`);
            assertSoft(isStr(r.json.choices[0].message.content), `expected a non-empty answer for ${name}`);
          } else {
            assertSoft(false, `"${name}" forwarded; upstream returned ${r.status}: ${r.text.slice(0, 160)}`);
          }
        }
      },
    });
  }
  return cases;
}

// ── orchestrator ──
async function resolveSecretId(appliance, tag) {
  let list;
  try {
    list = await appliance.findSecretsByTag(tag);
  } catch (e) {
    throw new Error(`could not query secrets by tag '${tag}': ${e.message || e}`);
  }
  const arr = Array.isArray(list) ? list : [];
  if (arr.length === 0) {
    throw new Error(
      `no secret tagged '${tag}' found on the appliance. Create a provider API key and tag it '${tag}'.`,
    );
  }
  return arr[0].id;
}

async function runDialect(appliance, surface, caps, cases, dialect, results, log) {
  for (const c of cases) {
    const meta = { surface: surface.id, dialect, name: c.name };
    if (c.capability && !caps[c.capability]) {
      results.push({ ...meta, ok: true, skipped: true, detail: `capability '${c.capability}' off` });
      continue;
    }
    try {
      await c.run(appliance, surface);
      results.push({ ...meta, ok: true });
      log(`  ✓ [${surface.id}/${dialect}] ${c.name}`);
    } catch (e) {
      const soft = !!(e && e.soft);
      results.push({ ...meta, ok: soft, soft, error: String((e && e.message) || e) });
      log(`  ${soft ? "~" : "✗"} [${surface.id}/${dialect}] ${c.name}${soft ? " (soft)" : ""}: ${e.message || e}`);
    }
  }
}

// Drive the full conformance matrix. `opts` carries the resolved provider tags,
// models, and routing (listen address + path prefix). Returns
// { pass, results, surfaces } where `pass` is false only on a HARD failure.
async function runConformance(appliance, opts, log) {
  const info = log || (() => {});
  const results = [];
  const created = [];

  const openaiSecret = await resolveSecretId(appliance, opts.openaiTag);
  const anthropicSecret = await resolveSecretId(appliance, opts.anthropicTag);
  info(`resolved secrets: openai=${openaiSecret} anthropic=${anthropicSecret}`);

  // Optional web-search engine key (Tavily), resolved by tag. When absent the
  // web_search conformance case is capability-gated off (web_fetch needs no
  // key and always runs).
  let tavilySecret = null;
  try {
    tavilySecret = await resolveSecretId(appliance, opts.tavilyTag || "test-suite-tavily");
    info(`resolved web-search secret: tavily=${tavilySecret}`);
  } catch (e) {
    info(`web_search case disabled (no secret tagged 'test-suite-tavily'): ${e.message || e}`);
  }

  // A bearer-protected surface backs the auth-enforcement (security) checks.
  // Best-effort: if the JWT strategy can't be created, those checks are skipped
  // rather than failing the whole run.
  let jwtStrategyId = null;
  let signer = null;
  try {
    signer = makeJwtSigner();
    const strategy = await appliance.createJwtStrategy({
      name: `conformance-rs256-${Date.now()}`,
      expected_issuer: signer.issuer,
      jwks_source: { type: "static", jwks: [signer.publicJwk] },
    });
    jwtStrategyId = strategy.id;
    info(`created JWT strategy ${jwtStrategyId} for auth-enforcement checks`);
  } catch (e) {
    signer = null;
    info(`auth-enforcement checks skipped (could not create JWT strategy): ${e.message || e}`);
  }

  const route = (name) => {
    const suffix = `/${name}`;
    const p = String(opts.pathPrefix || "").replace(/\/+$/, "");
    return p && !suffix.startsWith(`${p}/`) ? `${p}${suffix}` : suffix;
  };

  const openaiSurface = {
    id: "tk-conf-openai",
    route: route("conformance-openai"),
    model: opts.openaiModel,
    caps: { tools: true, vision: true },
  };
  const anthropicSurface = {
    id: "tk-conf-anthropic",
    route: route("conformance-anthropic"),
    model: opts.anthropicModel,
    caps: { tools: true, vision: true, reasoning: true, caching: true },
  };
  const embedSurface = {
    id: "tk-conf-embeddings",
    route: route("conformance-embeddings"),
    model: opts.embeddingsModel,
    caps: {},
  };
  const authSurface = {
    id: "tk-conf-auth",
    route: route("conformance-auth"),
    model: opts.openaiModel,
    caps: {},
  };
  const routingSurface = {
    id: "tk-conf-routing",
    route: route("conformance-routing"),
    model: opts.openaiModel,
    caps: {},
  };
  const webToolsSurface = {
    id: "tk-conf-web-tools",
    route: route("conformance-web-tools"),
    model: opts.openaiModel,
    caps: { web_fetch: true, web_search: !!tavilySecret },
  };
  const contextSurface = {
    id: "tk-conf-context",
    route: route("conformance-context"),
    model: opts.openaiModel,
    caps: {},
  };
  const docsSurface = {
    id: "tk-conf-docs",
    route: route("conformance-docs"),
    model: opts.openaiModel,
    caps: {},
  };
  const realDocsSurface = {
    id: "tk-conf-docs-real",
    route: route("conformance-docs-real"),
    model: opts.openaiModel,
    caps: {},
  };
  // Real fixtures dropped into tests/appliance/test-docs (resolved relative to this file).
  const docsDir = path.resolve(__dirname, "../../test-docs");
  const realDocs = realDocumentCases(opts.openaiModel, docsDir);

  const pipes = [
    baseSurface(openaiSurface.id, openaiSurface.route, opts.listenAddress, "Conformance (OpenAI-backed)", {
      provider_type: "openai",
      model: openaiSurface.model,
      api_key_secret: openaiSecret,
    }),
    baseSurface(anthropicSurface.id, anthropicSurface.route, opts.listenAddress, "Conformance (Anthropic-backed)", {
      provider_type: "anthropic",
      model: anthropicSurface.model,
      api_key_secret: anthropicSecret,
    }),
    baseSurface(embedSurface.id, embedSurface.route, opts.listenAddress, "Conformance (OpenAI embeddings)", {
      provider_type: "openai",
      model: embedSurface.model,
      api_key_secret: openaiSecret,
    }),
  ];
  // Inline images are now strict opt-in per surface (see docs/MODALITIES.md):
  // the vision surfaces must enable `image_input` or the PNG vision cases are
  // rejected (400 image_not_supported). Applied to every vision-capable surface.
  for (const p of pipes) {
    if (p.id === openaiSurface.id || p.id === anthropicSurface.id) {
      p.image_input = {
        enabled: true,
        allowed_formats: ["png", "jpeg", "gif", "webp"],
        max_bytes: 20 * 1024 * 1024,
      };
    }
  }
  // Routing pool: OpenAI primary + an Anthropic failover target, so per-request
  // provider/model preferences have more than one pool member to choose from.
  {
    const routingPipe = baseSurface(
      routingSurface.id,
      routingSurface.route,
      opts.listenAddress,
      "Conformance (routing pool)",
      { provider_type: "openai", model: opts.openaiModel, api_key_secret: openaiSecret },
    );
    routingPipe.failover = {
      enabled: true,
      targets: [
        {
          llm: {
            provider_type: "anthropic",
            model: opts.anthropicModel,
            endpoint_url: "https://api.anthropic.com/v1/messages",
            api_key_secret: anthropicSecret,
            api_schema: "anthropic",
          },
        },
      ],
    };
    pipes.push(routingPipe);
  }
  // Governed server-tools surface: OpenAI-backed (tool-calling capable) with
  // web_fetch always on and web_search on only when a Tavily key is available.
  {
    const webToolsPipe = baseSurface(
      webToolsSurface.id,
      webToolsSurface.route,
      opts.listenAddress,
      "Conformance (server tools)",
      { provider_type: "openai", model: opts.openaiModel, api_key_secret: openaiSecret },
    );
    webToolsPipe.server_tools = {
      enabled: true,
      max_iterations: 3,
      web_fetch: { enabled: true, max_content_bytes: 40000 },
      web_search: tavilySecret
        ? { enabled: true, engine: "tavily", engine_secret: tavilySecret, max_results: 3 }
        : undefined,
    };
    pipes.push(webToolsPipe);
  }
  // Context-window surface: a deliberately tiny window so a modest prompt
  // overflows and middle-out compression engages deterministically.
  {
    const contextPipe = baseSurface(
      contextSurface.id,
      contextSurface.route,
      opts.listenAddress,
      "Conformance (context window)",
      { provider_type: "openai", model: opts.openaiModel, api_key_secret: openaiSecret },
    );
    contextPipe.context_management = {
      enabled: true,
      context_window_tokens: 300,
      keep_recent_messages: 2,
      reserve_output_tokens: 50,
    };
    pipes.push(contextPipe);
  }
  // Document-ingestion surface: attached documents are recognized, extracted
  // (text/markdown/csv/json/docx) or forwarded (pdf), and gated by a small
  // size cap so the size guard fires deterministically.
  {
    const docsPipe = baseSurface(
      docsSurface.id,
      docsSurface.route,
      opts.listenAddress,
      "Conformance (document ingestion)",
      { provider_type: "openai", model: opts.openaiModel, api_key_secret: openaiSecret },
    );
    docsPipe.document_ingestion = {
      enabled: true,
      allowed_types: ["text", "markdown", "csv", "json", "docx", "pdf"],
      max_file_bytes: 8192,
      max_extracted_chars: 20000,
      mode: "auto",
    };
    pipes.push(docsPipe);
  }
  // Real-document surface: a generous size cap so genuine fixtures (and larger
  // ones an operator drops in later) fit under the 32 MiB transport limit. Only
  // created when at least one recognized fixture is present.
  if (realDocs.length) {
    const realPipe = baseSurface(
      realDocsSurface.id,
      realDocsSurface.route,
      opts.listenAddress,
      "Conformance (real documents)",
      { provider_type: "openai", model: opts.openaiModel, api_key_secret: openaiSecret },
    );
    realPipe.document_ingestion = {
      enabled: true,
      allowed_types: ["text", "markdown", "csv", "json", "docx", "pdf"],
      max_file_bytes: 16 * 1024 * 1024,
      max_extracted_chars: 20000,
      mode: "auto",
    };
    pipes.push(realPipe);
  }
  if (jwtStrategyId) {
    pipes.push(
      baseSurface(
        authSurface.id,
        authSurface.route,
        opts.listenAddress,
        "Conformance (bearer-protected)",
        { provider_type: "openai", model: authSurface.model, api_key_secret: openaiSecret },
        {
          type: "jwt_bearer",
          jwt_verification_strategy_id: jwtStrategyId,
          audiences: [signer.audience],
          token_header: "Authorization",
          token_scheme: "Bearer",
        },
      ),
    );
  }

  try {
    for (const p of pipes) {
      await appliance.createPipe(p);
      created.push(p.id);
      info(`created surface ${p.id} at ${p.route}`);
    }

    // Cross-product: every chat dialect against both the OpenAI- and
    // Anthropic-backed surface (proving dialect ⊥ upstream model).
    for (const s of [openaiSurface, anthropicSurface]) {
      await runDialect(appliance, s, s.caps, openAiChatCases(s.model), "openai_chat", results, info);
      await runDialect(appliance, s, s.caps, anthropicMessagesCases(s.model), "anthropic_messages", results, info);
      await runDialect(appliance, s, s.caps, responsesCases(s.model), "openai_responses", results, info);
      await runDialect(appliance, s, s.caps, [modelsCase()], "models", results, info);
    }

    // Embeddings only makes sense on an embeddings-capable upstream (OpenAI).
    await runDialect(appliance, embedSurface, {}, embeddingsCases(embedSurface.model), "embeddings", results, info);

    // Per-request routing over a real pool (OpenAI primary + Anthropic failover).
    await runDialect(
      appliance,
      routingSurface,
      {},
      routingCases(opts.openaiModel, opts.anthropicModel),
      "routing",
      results,
      info,
    );

    // Governed server tools: web_fetch (self-contained) always; web_search only
    // when a Tavily key is present (capability-gated per surface caps).
    await runDialect(
      appliance,
      webToolsSurface,
      webToolsSurface.caps,
      serverToolsCases(opts.openaiModel),
      "server_tools",
      results,
      info,
    );

    // Context-window guard: middle-out compression (deterministic, hard checks).
    await runDialect(
      appliance,
      contextSurface,
      {},
      contextTransformCases(opts.openaiModel),
      "context",
      results,
      info,
    );

    // Document ingestion: attached text/docx are extracted, pdf is accepted and
    // forwarded, and the size guard rejects an over-size upload. Deterministic
    // gateway checks (the `x-agent-stream-documents` header) are hard; whether
    // the model echoes the extracted content is provider-dependent (soft).
    await runDialect(
      appliance,
      docsSurface,
      {},
      documentCases(opts.openaiModel),
      "documents",
      results,
      info,
    );

    // Real fixtures from tests/appliance/test-docs (a genuine .docx + .pdf), when present.
    if (realDocs.length) {
      await runDialect(appliance, realDocsSurface, {}, realDocs, "documents-real", results, info);
    }

    // Security: prove the new ingress dialects are bearer-protected like chat.
    if (jwtStrategyId && signer) {
      await runDialect(
        appliance,
        authSurface,
        {},
        authEnforcementCases(authSurface.model, signer),
        "auth",
        results,
        info,
      );
    }
  } catch (e) {
    // Unexpected error mid-run — best-effort cleanup, then rethrow.
    await teardownAll(appliance, created, jwtStrategyId, info);
    throw e;
  }

  const hardFailures = results.filter((r) => r.ok === false && !r.skipped);
  // Teardown is deferred to the caller so surfaces (and their traffic) stay
  // reviewable in the dashboard until the operator chooses to clean up.
  return {
    pass: hardFailures.length === 0,
    results,
    created,
    teardown: () => teardownAll(appliance, created, jwtStrategyId, info),
  };
}

// Delete everything a run created (surfaces + the auth JWT strategy). Best-effort.
async function teardownAll(appliance, surfaceIds, jwtStrategyId, log) {
  await teardownSurfaces(appliance, surfaceIds, log);
  if (jwtStrategyId) {
    try {
      await appliance.deleteJwtStrategy(jwtStrategyId);
    } catch (e) {
      log(`warning: could not delete JWT strategy ${jwtStrategyId}: ${e.message || e}`);
    }
  }
}

// Delete every surface the run created (best-effort; a failure is logged, not fatal).
async function teardownSurfaces(appliance, ids, log) {
  for (const id of ids) {
    try {
      await appliance.deletePipe(id);
    } catch (e) {
      log(`warning: could not delete surface ${id}: ${e.message || e}`);
    }
  }
}

module.exports = { runConformance, TINY_PNG_B64, makeDocxBase64, makePdfBase64, textDataUrl, parseOpenAiSse, parseEventSse };
