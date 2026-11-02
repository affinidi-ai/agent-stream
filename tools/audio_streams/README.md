# Audio-stream clip generator

Generates the short **voice-safety filler clips** the realtime relay streams to a
caller while a reply is being vetted (Gated voice safety) instead of leaving dead
air on the line. It reads an `audio_streams.json` catalog, synthesises each clip's
text with a TTS provider, and writes the result as a WAV the appliance can stream
back with **zero transcoding**.

## Why this exists

When an [LLM Surface](../../docs/MODALITIES.md) runs realtime voice with **Gated** voice
safety, the model's spoken reply is held while the Judge/Jury vet it. That vet
takes a moment, so instead of silence the gateway can stream a pre-generated
filler clip ("Okay, give me a second…"). Escalating tiers cover longer vets
("still working on that…", "nearly done…"). Those clips are what this tool
produces.

The clips live in a **shared appliance store** (not per-surface): every surface
draws from the same catalogue by clip id.

## The exact audio format

Every clip **must** be:

| Property     | Value                          |
| ------------ | ------------------------------ |
| Encoding     | PCM, signed 16-bit, little-endian |
| Sample rate  | 24 000 Hz                      |
| Channels     | 1 (mono)                       |
| Container    | WAV (RIFF/WAVE, `fmt ` + `data`) |

This is the exact shape of the realtime audio channel (`response.audio.delta`),
so a matching clip streams straight through with no resampling. The appliance
**rejects** any clip that is not PCM16 / 24 kHz / mono at load time and logs why.

## Where things live (config wiring)

Two `config.toml` entries define the feature:

```toml
[config_files]
# Catalog of available clips (id -> text/label/tags). Resolved relative to the
# config directory.
audio_streams = "audio_streams.json"

[storage_paths]
# Shared directory holding the clip WAV bytes.
audio_streams = "../_storage/audio_streams"
```

- **Catalog** (`config_files.audio_streams`) — the authoring source of truth: the
  list of clips, each with an `id`, a `file` name, the spoken `text`, and
  optional `label`/`voice`/`tags`.
- **Store** (`storage_paths.audio_streams`) — the directory the WAV `file`s are
  written to and the appliance reads at startup.

The appliance loads and validates the catalog + clips once at boot
(`src/pipes/audio_streams.rs`). A missing catalog simply disables filler; a bad
clip is skipped with a warning rather than blocking startup.

## Catalog format

```jsonc
{
  "clips": [
    {
      "id": "tier1-give-me-a-second",       // stable id referenced by surfaces
      "file": "tier1-give-me-a-second.wav",  // filename inside the store dir
      "text": "Okay, give me a second.",     // synthesised by this tool
      "label": "Tier 1 — quick acknowledgement", // optional, for the dashboard
      "voice": "alloy",                       // optional per-clip voice override
      "tags": ["tier1", "ack"]               // optional, for authoring/filtering
    }
  ]
}
```

`tags` such as `tier1` / `tier2` / `tier3` are a convention for grouping clips by
how long the caller has been waiting — a surface's escalating filler groups
reference clip ids by tier. The catalog itself is just the flat set of available
clips; the escalation policy is per-surface configuration.

A starter catalog ships at
[`config/examples/audio_streams.example.json`](../../config/examples/audio_streams.example.json).
Copy it to `<env>/config/audio_streams.json` for the environment you run (for example
`envs/local/config/`); environment setup does not copy it. The script's default `--catalog`
and `--out` paths point at `envs/local/AS1/`, so pass both for any other environment.

## Prerequisites

- **Node.js 18+** (uses the built-in `fetch`; no npm dependencies).
- A TTS API key in the environment:
  - `OPENAI_API_KEY` for `--provider openai` (default)
  - `GEMINI_API_KEY` for `--provider gemini`

## Usage

From the repo root:

```bash
# OpenAI (default): generate any missing clips for the dev appliance
OPENAI_API_KEY=sk-... node tools/audio_streams/generate.mjs

# Explicit catalog + output directory
OPENAI_API_KEY=sk-... node tools/audio_streams/generate.mjs \
  --catalog envs/local/AS1/config/audio_streams.json \
  --out     envs/local/AS1/_storage/audio_streams

# Regenerate everything with a specific voice
OPENAI_API_KEY=sk-... node tools/audio_streams/generate.mjs --force --voice nova

# Google Gemini TTS instead
GEMINI_API_KEY=... node tools/audio_streams/generate.mjs --provider gemini

# Preview without calling the API
node tools/audio_streams/generate.mjs --dry-run

# Just one (or a few) clips by id
OPENAI_API_KEY=sk-... node tools/audio_streams/generate.mjs \
  --only tier1-one-moment,tier2-still-working --force
```

### Options

| Flag                | Default                                    | Meaning                                              |
| ------------------- | ------------------------------------------ | ---------------------------------------------------- |
| `--catalog <path>`  | `envs/local/AS1/config/audio_streams.json` | Catalog JSON to read                                 |
| `--out <dir>`       | `envs/local/AS1/_storage/audio_streams`    | Directory to write WAV clips into                    |
| `--provider <name>` | `openai`                                   | `openai` or `gemini`                                 |
| `--model <name>`    | `gpt-4o-mini-tts` / `gemini-2.5-flash-preview-tts` | TTS model                                    |
| `--voice <name>`    | `alloy` / `Kore`                           | Default voice (a clip's `voice` field overrides it)  |
| `--only <ids>`      | —                                          | Comma-separated clip ids to generate                 |
| `--force`           | off                                        | Regenerate clips whose WAV already exists            |
| `--dry-run`         | off                                        | List planned work without calling the API            |

By default an existing WAV is **left untouched** (idempotent reruns are cheap);
pass `--force` to overwrite.

## Voices

- **OpenAI** (`/v1/audio/speech`): `alloy`, `ash`, `ballad`, `coral`, `echo`,
  `fable`, `nova`, `onyx`, `sage`, `shimmer`, `verse`. The tool requests
  `response_format: "pcm"`, which OpenAI returns as 24 kHz / 16-bit / mono — the
  exact clip format — and this tool wraps it in a WAV header.
- **Gemini** (`…:generateContent` with the AUDIO modality): `Kore`, `Puck`,
  `Charon`, `Fenrir`, `Aoede`, … Gemini returns L16 PCM at 24 kHz mono, wrapped
  the same way. The tool errors out if a provider ever returns a non-24 kHz rate.

## Adding your own clips

1. Add an entry to `audio_streams.json` with a new `id`, `file`, and `text`.
2. Run the generator (optionally `--only <id>`).
3. Restart the appliance so the store re-reads the catalog; the catalog and clip
   bytes are loaded only at startup.

The dashboard is expected to build this catalog interactively in a later
iteration; until then the catalog file is the interface.
