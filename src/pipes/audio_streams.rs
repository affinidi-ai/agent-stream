//! Shared audio-stream clip store.
//!
//! Short pre-generated voice clips the realtime relay streams to a caller while a
//! reply is being vetted (Gated voice safety) instead of dead air. The clips are
//! catalogued by id in the `audio_streams` config file (`config_files.audio_streams`)
//! and their WAV bytes live under the shared appliance store at
//! `storage_paths.audio_streams`.
//!
//! Every clip must be PCM16 / 24 kHz / mono — the exact shape of the realtime
//! audio channel — so a clip streams straight through as `response.audio.delta`
//! frames with zero transcoding. The store loads and validates every catalogued
//! clip once at startup, decoding it to raw PCM16 the relay can chunk on demand.
//! Generate clips with `tools/audio_streams/generate.mjs` (text → TTS → WAV).

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{info, warn};

/// Sample rate every clip must use (Hz). Matches the realtime audio channel.
pub const CLIP_SAMPLE_RATE: u32 = 24_000;
/// Channel count every clip must use (mono).
pub const CLIP_CHANNELS: u16 = 1;
/// Bit depth every clip must use (signed 16-bit PCM).
pub const CLIP_BITS_PER_SAMPLE: u16 = 16;

/// One catalogued clip as authored in `audio_streams.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AudioClipEntry {
    /// Stable id referenced by a surface's filler groups.
    pub id: String,
    /// WAV filename inside the audio-stream storage directory.
    pub file: String,
    /// The spoken text — source of truth for regeneration and UI display.
    #[serde(default)]
    pub text: String,
    /// Optional human-friendly label for the dashboard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Optional TTS voice used to generate the clip (authoring metadata, so a
    /// regeneration is reproducible). Ignored by the store; used by the generator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub voice: Option<String>,
    /// Optional free-form tags (e.g. `"ack"`, `"short"`) for authoring/filtering.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// The `audio_streams.json` catalog: the set of clips available to every surface.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AudioStreamCatalog {
    #[serde(default)]
    pub clips: Vec<AudioClipEntry>,
}

/// A loaded, validated clip: its catalog metadata plus decoded PCM16 samples.
#[derive(Debug, Clone)]
pub struct AudioStreamClip {
    pub id: String,
    pub text: String,
    pub label: Option<String>,
    pub tags: Vec<String>,
    /// Raw PCM16 little-endian mono samples at 24 kHz (WAV header stripped).
    pub pcm: Arc<Vec<u8>>,
}

impl AudioStreamClip {
    /// Approximate playback duration in milliseconds (PCM16 mono @ 24 kHz).
    pub fn duration_ms(&self) -> u64 {
        let samples = (self.pcm.len() / 2) as u64;
        samples * 1000 / CLIP_SAMPLE_RATE as u64
    }

    /// Split the PCM into base64-encoded frames of at most `frame_bytes` bytes,
    /// ready to emit as realtime `response.audio.delta` chunks. `frame_bytes` is
    /// rounded down to a whole sample (2 bytes) so a frame never splits a sample.
    pub fn base64_frames(
        &self,
        frame_bytes: usize,
    ) -> Vec<String> {
        let frame = frame_bytes.max(2) & !1;
        self.pcm
            .chunks(frame)
            .map(|c| BASE64.encode(c))
            .collect()
    }
}

/// Published, byte-free view of a clip for the pipes-config document, so the
/// surface builder can offer real clip ids (with their text/label/duration) when
/// authoring escalating filler groups instead of a hardcoded list.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AudioStreamClipInfo {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub text: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    pub duration_ms: u64,
}

/// Shared, read-only store of every catalogued clip, keyed by id.
#[derive(Debug, Default)]
pub struct AudioStreamStore {
    clips: BTreeMap<String, Arc<AudioStreamClip>>,
}

impl AudioStreamStore {
    /// Load the catalog at `catalog_path` and every clip WAV it references from
    /// `clips_dir`, validating each is PCM16 / 24 kHz / mono.
    ///
    /// A missing catalog yields an empty store (the feature is simply unused). A
    /// clip that is missing or fails validation is logged and skipped so one bad
    /// clip never blocks startup.
    pub fn load(
        catalog_path: &Path,
        clips_dir: &Path,
    ) -> Self {
        let catalog = match std::fs::read(catalog_path) {
            Ok(bytes) => match serde_json::from_slice::<AudioStreamCatalog>(&bytes) {
                Ok(catalog) => catalog,
                Err(error) => {
                    warn!(
                        path = %catalog_path.display(),
                        %error,
                        "audio-stream catalog is invalid JSON; starting with no clips"
                    );
                    return Self::default();
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                info!(
                    path = %catalog_path.display(),
                    "no audio-stream catalog present; realtime filler clips disabled"
                );
                return Self::default();
            }
            Err(error) => {
                warn!(
                    path = %catalog_path.display(),
                    %error,
                    "failed to read audio-stream catalog; starting with no clips"
                );
                return Self::default();
            }
        };

        let mut clips = BTreeMap::new();
        for entry in &catalog.clips {
            let wav_path = clips_dir.join(&entry.file);
            let decoded = std::fs::read(&wav_path)
                .map_err(|error| error.to_string())
                .and_then(|bytes| decode_wav_pcm16_mono_24k(&bytes).map_err(|error| error.to_string()));
            match decoded {
                Ok(pcm) => {
                    let clip = AudioStreamClip {
                        id: entry.id.clone(),
                        text: entry.text.clone(),
                        label: entry.label.clone(),
                        tags: entry.tags.clone(),
                        pcm: Arc::new(pcm),
                    };
                    clips.insert(entry.id.clone(), Arc::new(clip));
                }
                Err(error) => {
                    warn!(
                        id = %entry.id,
                        path = %wav_path.display(),
                        %error,
                        "skipping audio-stream clip that failed to load/validate"
                    );
                }
            }
        }

        if !clips.is_empty() {
            info!(count = clips.len(), "loaded audio-stream filler clips");
        }
        Self { clips }
    }

    /// The catalogued clips as byte-free descriptors for the pipes-config
    /// document (id, label, text, tags, duration).
    pub fn entries(&self) -> Vec<AudioStreamClipInfo> {
        self.clips
            .values()
            .map(|clip| AudioStreamClipInfo {
                id: clip.id.clone(),
                label: clip.label.clone(),
                text: clip.text.clone(),
                tags: clip.tags.clone(),
                duration_ms: clip.duration_ms(),
            })
            .collect()
    }

    /// The loaded clip with the given id, if present.
    pub fn clip(
        &self,
        id: &str,
    ) -> Option<Arc<AudioStreamClip>> {
        self.clips.get(id).cloned()
    }
}

/// Per-surface plan for streaming pre-recorded clips during a realtime session:
/// escalating filler while a Gated reply is vetted, a refusal when a turn is
/// blocked (bucketed by rejection category), and an "on fail" clip when the
/// upstream model errors. All clip ids reference the shared catalog; an unknown
/// or unconfigured id is simply skipped (the caller falls back to a spoken
/// message), so this never fails a session.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealtimeAudioStreamsConfig {
    /// Minimum spacing after a filler clip before the held model reply is
    /// released. This prevents a filler clip and the real reply from playing
    /// back-to-back in the caller's client.
    #[serde(default = "default_filler_guard_band_ms")]
    pub filler_guard_band_ms: u64,
    /// Escalating filler groups played during a Gated safety hold, ordered by
    /// how long the caller has been waiting. Each tier plays one round-robin
    /// clip once its `after_ms` threshold passes.
    #[serde(default)]
    pub filler_tiers: Vec<AudioStreamTier>,
    /// Refusal clips played when a turn is blocked, keyed by the canonical
    /// rejection category. A bucket with an empty/`default` category is the
    /// fallback for any uncategorised or unmatched block.
    #[serde(default)]
    pub refusal_buckets: Vec<RefusalBucket>,
    /// Clips played (round-robin) when the upstream model fails mid-session.
    #[serde(default)]
    pub on_fail: Vec<String>,
}

fn default_filler_guard_band_ms() -> u64 {
    2_000
}

/// One escalating filler group: a set of clip ids played round-robin once the
/// caller has been waiting at least `after_ms`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AudioStreamTier {
    /// Elapsed milliseconds since the hold began before this tier plays.
    #[serde(default)]
    pub after_ms: u64,
    /// Clip ids played round-robin for this tier.
    #[serde(default)]
    pub clips: Vec<String>,
}

/// A refusal clip bucket for one rejection category (round-robin).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefusalBucket {
    /// Canonical rejection category id this bucket serves. Empty or `default`
    /// makes it the fallback bucket.
    #[serde(default)]
    pub category: String,
    /// Clip ids played round-robin when a turn is blocked in this category.
    #[serde(default)]
    pub clips: Vec<String>,
}

impl RealtimeAudioStreamsConfig {
    /// The refusal clip ids for a rejection `category`, falling back to the
    /// `default` (or unlabelled) bucket when the category has no dedicated one.
    pub fn refusal_clips(
        &self,
        category: Option<&str>,
    ) -> &[String] {
        let is_default = |c: &str| c.is_empty() || c.eq_ignore_ascii_case("default");
        if let Some(cat) = category.filter(|c| !c.is_empty())
            && let Some(bucket) = self
                .refusal_buckets
                .iter()
                .find(|b| {
                    b.category
                        .eq_ignore_ascii_case(cat)
                        && !b.clips.is_empty()
                })
        {
            return &bucket.clips;
        }
        self.refusal_buckets
            .iter()
            .find(|b| is_default(&b.category) && !b.clips.is_empty())
            .map(|b| b.clips.as_slice())
            .unwrap_or(&[])
    }
}

/// Pick the next clip id from a round-robin list, advancing `counter`. Returns
/// `None` for an empty list. `counter` is the caller's per-list rotation state.
pub fn next_round_robin<'a>(
    clips: &'a [String],
    counter: &mut usize,
) -> Option<&'a str> {
    if clips.is_empty() {
        return None;
    }
    let idx = *counter % clips.len();
    *counter = counter.wrapping_add(1);
    Some(clips[idx].as_str())
}

static AUDIO_STREAM_STORE: OnceLock<Arc<AudioStreamStore>> = OnceLock::new();

/// Install the process-wide audio-stream store. Idempotent — a second call is a
/// no-op (with a warning).
pub fn init_audio_stream_store(store: AudioStreamStore) {
    if AUDIO_STREAM_STORE
        .set(Arc::new(store))
        .is_err()
    {
        warn!("audio-stream store already initialized");
    }
}

/// The process-wide audio-stream store, if installed.
pub fn global_audio_stream_store() -> Option<Arc<AudioStreamStore>> {
    AUDIO_STREAM_STORE
        .get()
        .cloned()
}

/// The available filler clips as a JSON object for the `GET /pipes/config`
/// document (`{ "clips": […] }`), so the surface builder can author escalation
/// groups against real clip ids. Empty when no store or catalog is present.
pub fn published_catalog() -> Value {
    let clips = global_audio_stream_store()
        .map(|store| store.entries())
        .unwrap_or_default();
    json!({ "clips": clips })
}

/// Why a WAV file was rejected by [`decode_wav_pcm16_mono_24k`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WavError {
    TooShort,
    NotRiff,
    NotWave,
    MissingFmt,
    MissingData,
    Truncated,
    UnsupportedFormat { code: u16 },
    UnsupportedChannels { channels: u16 },
    UnsupportedSampleRate { sample_rate: u32 },
    UnsupportedBits { bits: u16 },
}

impl fmt::Display for WavError {
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        match self {
            WavError::TooShort => write!(f, "file too short to be a WAV"),
            WavError::NotRiff => write!(f, "missing RIFF header"),
            WavError::NotWave => write!(f, "not a WAVE container"),
            WavError::MissingFmt => write!(f, "missing or truncated fmt chunk"),
            WavError::MissingData => write!(f, "missing data chunk"),
            WavError::Truncated => write!(f, "chunk extends past end of file"),
            WavError::UnsupportedFormat { code } => {
                write!(f, "unsupported audio format {code} (expected PCM = 1)")
            }
            WavError::UnsupportedChannels { channels } => {
                write!(f, "unsupported channel count {channels} (expected mono = 1)")
            }
            WavError::UnsupportedSampleRate { sample_rate } => {
                write!(f, "unsupported sample rate {sample_rate} Hz (expected {CLIP_SAMPLE_RATE})")
            }
            WavError::UnsupportedBits { bits } => {
                write!(f, "unsupported bit depth {bits} (expected {CLIP_BITS_PER_SAMPLE})")
            }
        }
    }
}

impl std::error::Error for WavError {}

/// Decode a WAV file, requiring PCM16 / 24 kHz / mono, and return the raw PCM16
/// little-endian sample bytes (header stripped). Iterates the RIFF chunk list so
/// optional `LIST`/`fact`/other chunks before `data` are tolerated.
pub fn decode_wav_pcm16_mono_24k(bytes: &[u8]) -> Result<Vec<u8>, WavError> {
    if bytes.len() < 12 {
        return Err(WavError::TooShort);
    }
    if &bytes[0..4] != b"RIFF" {
        return Err(WavError::NotRiff);
    }
    if &bytes[8..12] != b"WAVE" {
        return Err(WavError::NotWave);
    }

    let mut pos = 12;
    let mut fmt_seen = false;
    let mut data: Option<Vec<u8>> = None;
    while pos + 8 <= bytes.len() {
        let chunk_id = &bytes[pos..pos + 4];
        let size = u32::from_le_bytes([bytes[pos + 4], bytes[pos + 5], bytes[pos + 6], bytes[pos + 7]]) as usize;
        let body_start = pos + 8;
        let body_end = body_start
            .checked_add(size)
            .ok_or(WavError::Truncated)?;
        if body_end > bytes.len() {
            return Err(WavError::Truncated);
        }

        match chunk_id {
            b"fmt " => {
                if size < 16 {
                    return Err(WavError::MissingFmt);
                }
                let b = &bytes[body_start..body_start + 16];
                let audio_format = u16::from_le_bytes([b[0], b[1]]);
                let channels = u16::from_le_bytes([b[2], b[3]]);
                let sample_rate = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
                let bits = u16::from_le_bytes([b[14], b[15]]);
                if audio_format != 1 {
                    return Err(WavError::UnsupportedFormat { code: audio_format });
                }
                if channels != CLIP_CHANNELS {
                    return Err(WavError::UnsupportedChannels { channels });
                }
                if sample_rate != CLIP_SAMPLE_RATE {
                    return Err(WavError::UnsupportedSampleRate { sample_rate });
                }
                if bits != CLIP_BITS_PER_SAMPLE {
                    return Err(WavError::UnsupportedBits { bits });
                }
                fmt_seen = true;
            }
            b"data" => {
                data = Some(bytes[body_start..body_end].to_vec());
            }
            _ => {}
        }

        // RIFF chunks are word-aligned: an odd-sized body is followed by a pad byte.
        pos = body_end + (size & 1);
    }

    if !fmt_seen {
        return Err(WavError::MissingFmt);
    }
    data.ok_or(WavError::MissingData)
}

/// Encode raw PCM16 LE mono @ 24 kHz sample bytes into a canonical WAV file.
/// Documents (and, in tests, exercises) the exact byte layout the store accepts.
#[cfg(test)]
pub fn encode_wav_pcm16_mono_24k(pcm: &[u8]) -> Vec<u8> {
    let data_len = pcm.len() as u32;
    let byte_rate = CLIP_SAMPLE_RATE * CLIP_CHANNELS as u32 * (CLIP_BITS_PER_SAMPLE as u32 / 8);
    let block_align = CLIP_CHANNELS * (CLIP_BITS_PER_SAMPLE / 8);

    let mut out = Vec::with_capacity(44 + pcm.len());
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&(36 + data_len).to_le_bytes());
    out.extend_from_slice(b"WAVE");
    out.extend_from_slice(b"fmt ");
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&CLIP_CHANNELS.to_le_bytes());
    out.extend_from_slice(&CLIP_SAMPLE_RATE.to_le_bytes());
    out.extend_from_slice(&byte_rate.to_le_bytes());
    out.extend_from_slice(&block_align.to_le_bytes());
    out.extend_from_slice(&CLIP_BITS_PER_SAMPLE.to_le_bytes());
    out.extend_from_slice(b"data");
    out.extend_from_slice(&data_len.to_le_bytes());
    out.extend_from_slice(pcm);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pcm(sample_count: usize) -> Vec<u8> {
        (0..sample_count)
            .flat_map(|i| ((i as i16).wrapping_mul(31)).to_le_bytes())
            .collect()
    }

    #[test]
    fn wav_round_trips_through_encode_decode() {
        let pcm = sample_pcm(240);
        let wav = encode_wav_pcm16_mono_24k(&pcm);
        let decoded = decode_wav_pcm16_mono_24k(&wav).expect("valid WAV should decode");
        assert_eq!(decoded, pcm);
    }

    #[test]
    fn decode_tolerates_extra_chunk_before_data() {
        let pcm = sample_pcm(48);
        let mut wav = encode_wav_pcm16_mono_24k(&pcm);
        // Splice a LIST chunk (odd size, so it exercises the pad-byte handling)
        // between fmt and data at byte 36.
        let list = {
            let body = b"INFOxx"; // 6 bytes
            let mut c = Vec::new();
            c.extend_from_slice(b"LIST");
            c.extend_from_slice(&(body.len() as u32).to_le_bytes());
            c.extend_from_slice(body);
            c
        };
        wav.splice(36..36, list);
        let decoded = decode_wav_pcm16_mono_24k(&wav).expect("WAV with LIST should decode");
        assert_eq!(decoded, pcm);
    }

    #[test]
    fn decode_rejects_non_riff() {
        let mut wav = encode_wav_pcm16_mono_24k(&sample_pcm(8));
        wav[0] = b'X';
        assert_eq!(decode_wav_pcm16_mono_24k(&wav), Err(WavError::NotRiff));
    }

    #[test]
    fn decode_rejects_wrong_sample_rate() {
        let mut wav = encode_wav_pcm16_mono_24k(&sample_pcm(8));
        // fmt sample-rate field lives at byte 24 (12 RIFF + 8 fmt header + 4).
        wav[24..28].copy_from_slice(&16_000u32.to_le_bytes());
        assert_eq!(decode_wav_pcm16_mono_24k(&wav), Err(WavError::UnsupportedSampleRate { sample_rate: 16_000 }));
    }

    #[test]
    fn decode_rejects_stereo() {
        let mut wav = encode_wav_pcm16_mono_24k(&sample_pcm(8));
        // fmt channel-count field lives at byte 22.
        wav[22..24].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(decode_wav_pcm16_mono_24k(&wav), Err(WavError::UnsupportedChannels { channels: 2 }));
    }

    #[test]
    fn clip_duration_ms_reflects_sample_count() {
        // 2400 samples @ 24 kHz == 100 ms.
        let clip = AudioStreamClip {
            id: "x".into(),
            text: String::new(),
            label: None,
            tags: vec![],
            pcm: Arc::new(sample_pcm(2400)),
        };
        assert_eq!(clip.duration_ms(), 100);
    }

    #[test]
    fn base64_frames_reconstruct_pcm() {
        let clip = AudioStreamClip {
            id: "x".into(),
            text: String::new(),
            label: None,
            tags: vec![],
            pcm: Arc::new(sample_pcm(2400)),
        };
        // 4800 bytes into 1000-byte (even) frames => 5 frames that rebuild the PCM.
        let frames = clip.base64_frames(1000);
        assert_eq!(frames.len(), 5);
        let mut rebuilt = Vec::new();
        for f in &frames {
            rebuilt.extend_from_slice(
                &BASE64
                    .decode(f)
                    .expect("valid base64"),
            );
        }
        assert_eq!(&rebuilt, clip.pcm.as_ref());
    }

    #[test]
    fn round_robin_cycles_and_wraps() {
        let clips = vec!["a".to_string(), "b".to_string()];
        let mut c = 0;
        assert_eq!(next_round_robin(&clips, &mut c), Some("a"));
        assert_eq!(next_round_robin(&clips, &mut c), Some("b"));
        assert_eq!(next_round_robin(&clips, &mut c), Some("a"));
        assert_eq!(next_round_robin(&[], &mut c), None);
    }

    #[test]
    fn refusal_bucket_matches_category_then_falls_back_to_default() {
        let cfg = RealtimeAudioStreamsConfig {
            filler_guard_band_ms: 2_000,
            filler_tiers: vec![AudioStreamTier {
                after_ms: 1000,
                clips: vec!["f1".into()],
            }],
            refusal_buckets: vec![
                RefusalBucket {
                    category: "weather".into(),
                    clips: vec!["w1".into()],
                },
                RefusalBucket {
                    category: "default".into(),
                    clips: vec!["d1".into()],
                },
            ],
            on_fail: vec!["oops".into()],
        };
        assert_eq!(cfg.refusal_clips(Some("weather")), &["w1".to_string()]);
        assert_eq!(cfg.refusal_clips(Some("unknown")), &["d1".to_string()]);
        assert_eq!(cfg.refusal_clips(None), &["d1".to_string()]);

        let empty = RealtimeAudioStreamsConfig::default();
        assert!(
            empty
                .refusal_clips(Some("weather"))
                .is_empty()
        );
    }

    #[test]
    fn catalog_deserializes_with_optional_fields() {
        let json = r#"{ "clips": [
            { "id": "a", "file": "a.wav", "text": "hi", "label": "Greeting", "tags": ["ack"] },
            { "id": "b", "file": "b.wav" }
        ] }"#;
        let catalog: AudioStreamCatalog = serde_json::from_str(json).expect("valid catalog");
        assert_eq!(catalog.clips.len(), 2);
        assert_eq!(
            catalog.clips[0]
                .label
                .as_deref(),
            Some("Greeting")
        );
        assert!(
            catalog.clips[1]
                .text
                .is_empty()
        );
        assert!(
            catalog.clips[1]
                .tags
                .is_empty()
        );
    }

    #[test]
    fn store_loads_catalogued_clips_and_skips_bad_ones() {
        let dir = std::env::temp_dir().join(format!("as-audio-streams-{}", std::process::id()));
        let clips_dir = dir.join("clips");
        std::fs::create_dir_all(&clips_dir).unwrap();

        let good = encode_wav_pcm16_mono_24k(&sample_pcm(240));
        std::fs::write(clips_dir.join("good.wav"), &good).unwrap();
        // A stereo clip that must be rejected at load.
        let mut bad = encode_wav_pcm16_mono_24k(&sample_pcm(240));
        bad[22..24].copy_from_slice(&2u16.to_le_bytes());
        std::fs::write(clips_dir.join("bad.wav"), &bad).unwrap();

        let catalog = AudioStreamCatalog {
            clips: vec![
                AudioClipEntry {
                    id: "good".into(),
                    file: "good.wav".into(),
                    text: "ok".into(),
                    label: None,
                    voice: None,
                    tags: vec![],
                },
                AudioClipEntry {
                    id: "bad".into(),
                    file: "bad.wav".into(),
                    text: String::new(),
                    label: None,
                    voice: None,
                    tags: vec![],
                },
                AudioClipEntry {
                    id: "missing".into(),
                    file: "nope.wav".into(),
                    text: String::new(),
                    label: None,
                    voice: None,
                    tags: vec![],
                },
            ],
        };
        let catalog_path = dir.join("audio_streams.json");
        std::fs::write(&catalog_path, serde_json::to_vec(&catalog).unwrap()).unwrap();

        let store = AudioStreamStore::load(&catalog_path, &clips_dir);
        let entries = store.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "good");
        assert_eq!(entries[0].text, "ok");
        // 240 samples @ 24 kHz == 10 ms.
        assert_eq!(entries[0].duration_ms, 10);
        // The published descriptor carries no bytes.
        let info_json = serde_json::to_value(&entries[0]).unwrap();
        assert_eq!(info_json["id"], "good");
        assert!(info_json.get("pcm").is_none());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn store_load_missing_catalog_is_empty() {
        let store = AudioStreamStore::load(Path::new("/nonexistent/audio_streams.json"), Path::new("/nonexistent"));
        assert!(store.entries().is_empty());
    }
}
