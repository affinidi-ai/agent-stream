#!/usr/bin/env node
// @ts-check
/**
 * Audio-stream clip generator.
 *
 * Turns the text in an `audio_streams.json` catalog into the WAV clips the
 * realtime relay streams during a Gated voice-safety pause. Each clip is written
 * as PCM16 / 24 kHz / mono — the exact shape of the realtime audio channel — so
 * the appliance streams it back with zero transcoding.
 *
 * Providers:
 *   - openai  (default)  POST /v1/audio/speech, response_format=pcm  -> 24 kHz PCM16 mono
 *   - gemini             models/<tts>:generateContent, AUDIO modality -> L16 24 kHz mono
 *
 * The catalog is the single source of truth: authoring text lives beside each
 * clip id, and this script materialises the WAV bytes next to the appliance.
 *
 * Usage:
 *   OPENAI_API_KEY=sk-... node tools/audio_streams/generate.mjs \
 *     --catalog envs/local/AS1/config/audio_streams.json \
 *     --out     envs/local/AS1/_storage/audio_streams
 *
 * See tools/audio_streams/README.md for the full reference.
 */

import { readFileSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

const CLIP_SAMPLE_RATE = 24_000;
const CLIP_CHANNELS = 1;
const CLIP_BITS = 16;

const DEFAULTS = {
  catalog: "envs/local/AS1/config/audio_streams.json",
  out: "envs/local/AS1/_storage/audio_streams",
  provider: "openai",
  openaiModel: "gpt-4o-mini-tts",
  openaiVoice: "alloy",
  geminiModel: "gemini-2.5-flash-preview-tts",
  geminiVoice: "Kore",
};

function parseArgs(argv) {
  const args = {
    catalog: DEFAULTS.catalog,
    out: DEFAULTS.out,
    provider: DEFAULTS.provider,
    model: null,
    voice: null,
    force: false,
    dryRun: false,
    only: null,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => argv[(i += 1)];
    switch (arg) {
      case "--catalog":
        args.catalog = next();
        break;
      case "--out":
        args.out = next();
        break;
      case "--provider":
        args.provider = next();
        break;
      case "--model":
        args.model = next();
        break;
      case "--voice":
        args.voice = next();
        break;
      case "--only":
        args.only = next();
        break;
      case "--force":
        args.force = true;
        break;
      case "--dry-run":
        args.dryRun = true;
        break;
      case "-h":
      case "--help":
        printHelp();
        process.exit(0);
        break;
      default:
        fail(`unknown argument: ${arg}`);
    }
  }
  if (args.provider !== "openai" && args.provider !== "gemini") {
    fail(`--provider must be "openai" or "gemini" (got "${args.provider}")`);
  }
  return args;
}

function printHelp() {
  process.stdout.write(
    [
      "Generate realtime voice-safety filler clips from an audio_streams.json catalog.",
      "",
      "Options:",
      "  --catalog <path>   Catalog JSON (default: envs/local/AS1/config/audio_streams.json)",
      "  --out <dir>        Output clip directory (default: envs/local/AS1/_storage/audio_streams)",
      "  --provider <name>  openai | gemini (default: openai)",
      "  --model <name>     TTS model (default: gpt-4o-mini-tts / gemini-2.5-flash-preview-tts)",
      "  --voice <name>     Default voice; per-clip catalog `voice` overrides it",
      "  --only <id>        Generate only the clip with this id (repeatable via comma)",
      "  --force            Regenerate clips whose WAV already exists",
      "  --dry-run          List what would be generated without calling the API",
      "  -h, --help         Show this help",
      "",
      "Environment:",
      "  OPENAI_API_KEY     Required for --provider openai",
      "  GEMINI_API_KEY     Required for --provider gemini",
      "",
    ].join("\n"),
  );
}

function fail(message) {
  process.stderr.write(`error: ${message}\n`);
  process.exit(1);
}

/** Wrap raw PCM16 LE mono @ 24 kHz bytes in a canonical WAV container. */
function wavPcm16Mono24k(pcm) {
  const byteRate = CLIP_SAMPLE_RATE * CLIP_CHANNELS * (CLIP_BITS / 8);
  const blockAlign = CLIP_CHANNELS * (CLIP_BITS / 8);
  const header = Buffer.alloc(44);
  header.write("RIFF", 0);
  header.writeUInt32LE(36 + pcm.length, 4);
  header.write("WAVE", 8);
  header.write("fmt ", 12);
  header.writeUInt32LE(16, 16);
  header.writeUInt16LE(1, 20); // PCM
  header.writeUInt16LE(CLIP_CHANNELS, 22);
  header.writeUInt32LE(CLIP_SAMPLE_RATE, 24);
  header.writeUInt32LE(byteRate, 28);
  header.writeUInt16LE(blockAlign, 32);
  header.writeUInt16LE(CLIP_BITS, 34);
  header.write("data", 36);
  header.writeUInt32LE(pcm.length, 40);
  return Buffer.concat([header, pcm]);
}

/** OpenAI: text -> raw 24 kHz PCM16 mono. */
async function synthOpenai(text, model, voice) {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) fail("OPENAI_API_KEY is required for --provider openai");
  const res = await fetch("https://api.openai.com/v1/audio/speech", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model,
      voice,
      input: text,
      response_format: "pcm", // raw 24 kHz, 16-bit, mono, little-endian
    }),
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new Error(`OpenAI TTS ${res.status}: ${detail.slice(0, 300)}`);
  }
  return Buffer.from(await res.arrayBuffer());
}

/** Gemini: text -> raw 24 kHz PCM16 (L16) mono. */
async function synthGemini(text, model, voice) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) fail("GEMINI_API_KEY is required for --provider gemini");
  const url =
    `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent` +
    `?key=${encodeURIComponent(apiKey)}`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      contents: [{ parts: [{ text }] }],
      generationConfig: {
        responseModalities: ["AUDIO"],
        speechConfig: {
          voiceConfig: { prebuiltVoiceConfig: { voiceName: voice } },
        },
      },
    }),
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new Error(`Gemini TTS ${res.status}: ${detail.slice(0, 300)}`);
  }
  const body = await res.json();
  const part = body?.candidates?.[0]?.content?.parts?.find((p) => p?.inlineData?.data);
  if (!part) throw new Error("Gemini response carried no inline audio data");
  const mime = String(part.inlineData.mimeType ?? "");
  const rate = Number(/rate=(\d+)/.exec(mime)?.[1] ?? CLIP_SAMPLE_RATE);
  if (rate !== CLIP_SAMPLE_RATE) {
    throw new Error(
      `Gemini returned ${rate} Hz audio; expected ${CLIP_SAMPLE_RATE} Hz (mime: ${mime})`,
    );
  }
  return Buffer.from(part.inlineData.data, "base64");
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const catalogPath = resolve(args.catalog);
  if (!existsSync(catalogPath)) fail(`catalog not found: ${catalogPath}`);

  let catalog;
  try {
    catalog = JSON.parse(readFileSync(catalogPath, "utf8"));
  } catch (err) {
    fail(`catalog is not valid JSON: ${err.message}`);
  }
  const clips = Array.isArray(catalog?.clips) ? catalog.clips : [];
  if (clips.length === 0) fail("catalog has no `clips`");

  const outDir = resolve(args.out);
  const onlyIds = args.only ? new Set(args.only.split(",").map((s) => s.trim())) : null;
  const defaultModel =
    args.model ?? (args.provider === "gemini" ? DEFAULTS.geminiModel : DEFAULTS.openaiModel);
  const defaultVoice =
    args.voice ?? (args.provider === "gemini" ? DEFAULTS.geminiVoice : DEFAULTS.openaiVoice);

  process.stdout.write(
    `Provider: ${args.provider}  model: ${defaultModel}  voice: ${defaultVoice}\n` +
      `Catalog:  ${catalogPath}\n` +
      `Output:   ${outDir}\n\n`,
  );

  let generated = 0;
  let skipped = 0;
  let failed = 0;

  for (const clip of clips) {
    if (!clip?.id || !clip?.file) {
      process.stderr.write(`  ! skipping malformed entry: ${JSON.stringify(clip)}\n`);
      failed += 1;
      continue;
    }
    if (onlyIds && !onlyIds.has(clip.id)) continue;
    if (!clip.text) {
      process.stderr.write(`  ! ${clip.id}: no text to synthesise; skipping\n`);
      skipped += 1;
      continue;
    }

    const target = join(outDir, clip.file);
    if (existsSync(target) && !args.force) {
      process.stdout.write(`  = ${clip.id}: exists, skipping (use --force to regenerate)\n`);
      skipped += 1;
      continue;
    }

    const voice = clip.voice ?? defaultVoice;
    if (args.dryRun) {
      process.stdout.write(`  ~ ${clip.id}: would synthesise (${voice}) -> ${clip.file}\n`);
      continue;
    }

    try {
      const pcm =
        args.provider === "gemini"
          ? await synthGemini(clip.text, defaultModel, voice)
          : await synthOpenai(clip.text, defaultModel, voice);
      const wav = wavPcm16Mono24k(pcm);
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, wav);
      const ms = Math.round((pcm.length / 2 / CLIP_SAMPLE_RATE) * 1000);
      process.stdout.write(`  + ${clip.id}: ${clip.file} (${wav.length} bytes, ~${ms} ms)\n`);
      generated += 1;
    } catch (err) {
      process.stderr.write(`  ! ${clip.id}: ${err.message}\n`);
      failed += 1;
    }
  }

  process.stdout.write(`\nDone. generated=${generated} skipped=${skipped} failed=${failed}\n`);
  if (failed > 0) process.exit(1);
}

main().catch((err) => fail(err.stack ?? String(err)));
