import React from 'react';
import type { ConfigPanelProps } from '../types';
import { usePipePanelData, type AudioStreamClipInfo } from './pipePanelData';

/**
 * Full-page editor for the **Audio Stream** element (realtime voice, Mode C).
 * The sidebar keeps only the enable switch and a "Configure…" button; the bulk
 * of the realtime configuration lives here:
 *
 *  - **Realtime voice** (Mode C) — session length + default voice.
 *  - **Realtime response safety** — Gated/Barge-in enforcement + refusal.
 *  - **Audio streams** — pre-recorded clips the gateway streams during a session:
 *    escalating **filler** while a Gated reply is vetted, a **refusal** clip on a
 *    blocked turn (bucketed by rejection category), and an **on-fail** clip when
 *    the upstream model errors. Clip ids come from the backend-published catalog.
 *
 * All of this round-trips through the `pipe-audio-stream` node config
 * (`realtimeFromCanvas` / `reconcilePipeCanvasGuards`).
 */

type TierCfg = { after_ms?: number; clips?: string[] };
type BucketCfg = { category?: string; clips?: string[] };
const DEFAULT_FILLER_GUARD_BAND_MS = 2000;

const asStringArray = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];

const toPositiveInt = (raw: string, fallback: number): number => {
  const n = parseInt(raw, 10);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
};

/** Mirrors the backend `model_supports_realtime` gate, for a config-time warning. */
const modelSupportsRealtime = (model: string, apiSchema: string): boolean => {
  const m = (model || '').toLowerCase();
  if (apiSchema === 'openai' || apiSchema === 'azure') return m.includes('realtime');
  if (apiSchema === 'gemini')
    return m.includes('live') || m.includes('native-audio') || m.includes('realtime');
  return false;
};

const Switch: React.FC<{
  id: string;
  label: string;
  enabled: boolean;
  onChange: (v: boolean) => void;
}> = ({ id, label, enabled, onChange }) => (
  <div className="form-check form-switch mb-3">
    <input
      className="form-check-input"
      type="checkbox"
      role="switch"
      id={id}
      checked={enabled}
      onChange={e => onChange(e.target.checked)}
    />
    <label className="form-check-label" htmlFor={id}>
      {label}
    </label>
  </div>
);

/** A checklist of catalogued clips (id + label + duration), backend-driven. */
const ClipPicker: React.FC<{
  idPrefix: string;
  clips: AudioStreamClipInfo[];
  selected: string[];
  onChange: (ids: string[]) => void;
}> = ({ idPrefix, clips, selected, onChange }) => {
  if (clips.length === 0) {
    return (
      <div className="text-muted small">
        No clips in the catalog. Generate them with <code>tools/audio_streams/generate.mjs</code>{' '}
        and reload the surface.
      </div>
    );
  }
  const toggle = (id: string) =>
    onChange(selected.includes(id) ? selected.filter(x => x !== id) : [...selected, id]);
  // Surface any selected id no longer in the catalog so it isn't silently lost.
  const orphans = selected.filter(id => !clips.some(c => c.id === id));
  return (
    <div>
      <div className="d-flex flex-wrap" style={{ gap: '0.25rem 1rem' }}>
        {clips.map(c => (
          <div className="form-check" key={c.id}>
            <input
              className="form-check-input"
              type="checkbox"
              id={`${idPrefix}-${c.id}`}
              checked={selected.includes(c.id)}
              onChange={() => toggle(c.id)}
            />
            <label
              className="form-check-label small"
              htmlFor={`${idPrefix}-${c.id}`}
              title={c.text}
            >
              {c.label || c.id}
              {typeof c.duration_ms === 'number' && c.duration_ms > 0 ? (
                <span className="text-muted"> ({(c.duration_ms / 1000).toFixed(1)}s)</span>
              ) : null}
            </label>
          </div>
        ))}
      </div>
      {orphans.map(id => (
        <div className="form-check" key={id}>
          <input
            className="form-check-input"
            type="checkbox"
            id={`${idPrefix}-orphan-${id}`}
            checked
            onChange={() => toggle(id)}
          />
          <label
            className="form-check-label small text-warning"
            htmlFor={`${idPrefix}-orphan-${id}`}
          >
            {id} <span className="text-muted">(not in catalog)</span>
          </label>
        </div>
      ))}
    </div>
  );
};

const AudioStreamFullscreenPanel: React.FC<ConfigPanelProps> = ({
  config,
  updateFields,
  allNodes,
  closeFullscreenEditor,
}) => {
  const { audioStreams, llmProviders } = usePipePanelData();
  const clips = audioStreams.clips;

  const rt = (config ?? {}) as {
    enabled?: boolean;
    max_session_secs?: number;
    voice?: string;
    safety?: {
      enabled?: boolean;
      mode?: string;
      refusal_message?: string;
    };
    audio_streams?: {
      filler_guard_band_ms?: number;
      filler_tiers?: TierCfg[];
      refusal_buckets?: BucketCfg[];
      on_fail?: string[];
    };
  };
  const rtOn = rt.enabled === true;
  const maxSecs =
    typeof rt.max_session_secs === 'number' && rt.max_session_secs > 0 ? rt.max_session_secs : 600;
  const updateRealtime = (patch: Record<string, unknown>) => updateFields(patch);

  const safety = rt.safety ?? {};
  const safetyOn = safety.enabled === true;
  const safetyMode = safety.mode === 'barge_in' ? 'barge_in' : 'gated';
  const updateSafety = (patch: Record<string, unknown>) =>
    updateFields({ safety: { ...safety, ...patch } });

  const streams = rt.audio_streams ?? {};
  const fillerGuardBandMs =
    typeof streams.filler_guard_band_ms === 'number'
      ? streams.filler_guard_band_ms
      : DEFAULT_FILLER_GUARD_BAND_MS;
  const fillerTiers: TierCfg[] = Array.isArray(streams.filler_tiers) ? streams.filler_tiers : [];
  const refusalBuckets: BucketCfg[] = Array.isArray(streams.refusal_buckets)
    ? streams.refusal_buckets
    : [];
  const onFail = asStringArray(streams.on_fail);
  const updateAudioStreams = (patch: Record<string, unknown>) =>
    updateFields({ audio_streams: { ...streams, ...patch } });
  const setTiers = (tiers: TierCfg[]) => updateAudioStreams({ filler_tiers: tiers });
  const setBuckets = (buckets: BucketCfg[]) => updateAudioStreams({ refusal_buckets: buckets });

  // Capability check against the surface's selected model (config-time warning).
  const llm = (allNodes ?? []).find(n => n.type === 'pipe-upstream');
  const model = String((llm?.config as any)?.model ?? '');
  const providerEnum = String((llm?.config as any)?.provider ?? '');
  const apiSchema =
    llmProviders.find(p => p.enum_value === providerEnum)?.api_schema ??
    (providerEnum === 'openai' ? 'openai' : '');
  const realtimeCapable = modelSupportsRealtime(model, apiSchema);

  return (
    <div className="container-fluid py-4">
      <div className="d-flex justify-content-between align-items-center mb-4">
        <div>
          <h4 className="mb-1">
            <i className="fas fa-microphone-lines me-2 text-primary" />
            Audio Stream — realtime, safety &amp; audio streams
          </h4>
          <div className="text-muted small">
            Configure the realtime voice session, its per-turn safety, and the pre-recorded clips
            the gateway streams during filler pauses, refusals, and upstream failures.
          </div>
        </div>
        <button
          type="button"
          className="btn btn-outline-secondary btn-sm"
          onClick={() => closeFullscreenEditor?.()}
          disabled={!closeFullscreenEditor}
        >
          <i className="fas fa-times me-1" />
          Close
        </button>
      </div>

      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-wifi me-2" />
            Realtime voice
          </h6>
        </div>
        <div className="card-body">
          <Switch
            id="rt-enabled-full"
            label="Realtime voice (streaming)"
            enabled={rtOn}
            onChange={v => updateRealtime({ enabled: v, max_session_secs: maxSecs })}
          />
          <p className="text-muted small">
            Opens a governed bidirectional WebSocket at <code>/v1/realtime</code> and relays live
            audio to the model, segmented into per-turn governance records. Needs a realtime-capable
            model — an OpenAI realtime model (e.g. <code>gpt-realtime</code>) or a Gemini Live model
            (e.g. <code>gemini-2.5-flash-native-audio-latest</code>).
          </p>
          {rtOn && (
            <>
              {model && !realtimeCapable && (
                <div className="alert alert-warning py-2 small">
                  <i className="fas fa-exclamation-triangle me-1" />
                  The selected model <code>{model}</code> is not realtime-capable. The surface will
                  reject a <code>/v1/realtime</code> session with{' '}
                  <code>realtime_not_supported</code>.
                </div>
              )}
              <div className="row">
                <div className="col-md-6 mb-3">
                  <label className="form-label">Max session length (seconds)</label>
                  <input
                    type="number"
                    min={30}
                    className="form-control"
                    value={maxSecs}
                    onChange={e =>
                      updateRealtime({ max_session_secs: toPositiveInt(e.target.value, 600) })
                    }
                  />
                </div>
                <div className="col-md-6 mb-3">
                  <label className="form-label">
                    Voice <small className="text-muted">(optional)</small>
                  </label>
                  <input
                    type="text"
                    className="form-control"
                    placeholder="e.g. alloy, verse, cedar"
                    value={typeof rt.voice === 'string' ? rt.voice : ''}
                    onChange={e => updateRealtime({ voice: e.target.value })}
                  />
                </div>
              </div>
            </>
          )}
        </div>
      </div>

      {rtOn && (
        <div className="card shadow mb-4">
          <div className="card-header py-3">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-shield-halved me-2" />
              Realtime response safety
            </h6>
          </div>
          <div className="card-body">
            <Switch
              id="rt-safety-enabled-full"
              label="Review realtime model replies"
              enabled={safetyOn}
              onChange={v =>
                updateSafety({
                  enabled: v,
                  mode: safetyMode,
                })
              }
            />
            <p className="text-muted small">
              When this surface's <strong>Jury</strong> is enabled, realtime model replies are
              reviewed with that Jury. This does not run the surface Judge on caller audio; live
              audio reaches the realtime model before a caller transcript exists. Blocked turns are
              recorded as governance <strong>Block</strong> records.
            </p>
            {safetyOn && (
              <>
                <div className="mb-3">
                  <label className="form-label">Enforcement</label>
                  <select
                    className="form-select"
                    value={safetyMode}
                    onChange={e => updateSafety({ mode: e.target.value })}
                  >
                    <option value="gated">
                      Gated — hold each reply, release only if it passes (guaranteed)
                    </option>
                    <option value="barge_in">
                      Barge-in — stream live, cut off on a violation (best-effort)
                    </option>
                  </select>
                  <small className="form-text text-muted d-block">
                    Gated guarantees no unsafe audio reaches the caller but adds a short per-turn
                    delay (filled by the audio-stream clips below); barge-in is low-latency but a
                    fragment may play before the cut-off.
                  </small>
                </div>
                <div className="mb-1 mt-2">
                  <label className="form-label">
                    Refusal message{' '}
                    <small className="text-muted">
                      (shown on a block; spoken only when no refusal clip plays)
                    </small>
                  </label>
                  <input
                    type="text"
                    className="form-control"
                    placeholder="I'm sorry, but I can't help with that."
                    value={typeof safety.refusal_message === 'string' ? safety.refusal_message : ''}
                    onChange={e => updateSafety({ refusal_message: e.target.value })}
                  />
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {rtOn && (
        <div className="card shadow mb-4">
          <div className="card-header py-3 d-flex justify-content-between align-items-center">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-music me-2" />
              Audio streams
            </h6>
            <span className="text-muted small">{clips.length} clip(s) in catalog</span>
          </div>
          <div className="card-body">
            <p className="text-muted small">
              Pre-recorded clips the gateway streams to the caller. All clips must be generated into
              the appliance's audio-stream store; pick them by id below.
            </p>

            {/* Filler tiers */}
            <h6 className="mt-2">Filler (Gated pauses)</h6>
            <p className="text-muted small">
              While a Gated reply is generated and vetted, the caller waits in silence. Add
              escalating tiers: once the wait passes a tier's threshold, one clip from that tier
              plays (round-robin). A guard band keeps the released reply from playing immediately
              after a filler clip.
            </p>
            <div className="mb-3">
              <label className="form-label">Minimum gap after filler (seconds)</label>
              <input
                type="number"
                min={0}
                step={0.5}
                className="form-control form-control-sm"
                style={{ width: '8rem' }}
                value={fillerGuardBandMs / 1000}
                onChange={e =>
                  updateAudioStreams({
                    filler_guard_band_ms: Math.round((parseFloat(e.target.value) || 0) * 1000),
                  })
                }
              />
              <small className="form-text text-muted d-block">
                After a filler clip is queued, the held model reply waits at least this long after
                that clip's playback duration before release.
              </small>
            </div>
            {fillerTiers.length === 0 && (
              <div className="text-muted small mb-2">
                No filler tiers — a Gated pause will be silent.
              </div>
            )}
            {fillerTiers.map((tier, i) => (
              <div className="border rounded p-3 mb-2" key={i}>
                <div className="d-flex justify-content-between align-items-center mb-2">
                  <div className="d-flex align-items-center">
                    <span className="me-2">After</span>
                    <input
                      type="number"
                      min={0}
                      step={0.5}
                      className="form-control form-control-sm"
                      style={{ width: '6rem' }}
                      value={typeof tier.after_ms === 'number' ? tier.after_ms / 1000 : 0}
                      onChange={e =>
                        setTiers(
                          fillerTiers.map((t, idx) =>
                            idx === i
                              ? {
                                  ...t,
                                  after_ms: Math.round((parseFloat(e.target.value) || 0) * 1000),
                                }
                              : t
                          )
                        )
                      }
                    />
                    <span className="ms-2">seconds of waiting</span>
                  </div>
                  <button
                    type="button"
                    className="btn btn-outline-danger btn-sm"
                    onClick={() => setTiers(fillerTiers.filter((_, idx) => idx !== i))}
                  >
                    <i className="fas fa-trash" />
                  </button>
                </div>
                <ClipPicker
                  idPrefix={`filler-${i}`}
                  clips={clips}
                  selected={asStringArray(tier.clips)}
                  onChange={ids =>
                    setTiers(fillerTiers.map((t, idx) => (idx === i ? { ...t, clips: ids } : t)))
                  }
                />
              </div>
            ))}
            <button
              type="button"
              className="btn btn-outline-primary btn-sm mb-3"
              onClick={() =>
                setTiers([...fillerTiers, { after_ms: (fillerTiers.length + 1) * 2000, clips: [] }])
              }
            >
              <i className="fas fa-plus me-1" />
              Add filler tier
            </button>

            <hr />

            {/* Refusal buckets */}
            <h6>Refusal (blocked turns)</h6>
            <p className="text-muted small">
              When Voice safety blocks a turn, a clip from the matching bucket plays (round-robin).
              Buckets are keyed by the canonical rejection category; leave the category as{' '}
              <code>default</code> for a catch-all. If no bucket matches, the refusal message is
              spoken by the browser instead.
            </p>
            {refusalBuckets.length === 0 && (
              <div className="text-muted small mb-2">
                No refusal clips — a block will be spoken by the browser.
              </div>
            )}
            {refusalBuckets.map((bucket, i) => (
              <div className="border rounded p-3 mb-2" key={i}>
                <div className="d-flex justify-content-between align-items-center mb-2">
                  <div className="d-flex align-items-center">
                    <span className="me-2">Category</span>
                    <input
                      type="text"
                      className="form-control form-control-sm"
                      style={{ width: '14rem' }}
                      placeholder="default"
                      value={typeof bucket.category === 'string' ? bucket.category : ''}
                      onChange={e =>
                        setBuckets(
                          refusalBuckets.map((b, idx) =>
                            idx === i ? { ...b, category: e.target.value } : b
                          )
                        )
                      }
                    />
                  </div>
                  <button
                    type="button"
                    className="btn btn-outline-danger btn-sm"
                    onClick={() => setBuckets(refusalBuckets.filter((_, idx) => idx !== i))}
                  >
                    <i className="fas fa-trash" />
                  </button>
                </div>
                <ClipPicker
                  idPrefix={`refusal-${i}`}
                  clips={clips}
                  selected={asStringArray(bucket.clips)}
                  onChange={ids =>
                    setBuckets(
                      refusalBuckets.map((b, idx) => (idx === i ? { ...b, clips: ids } : b))
                    )
                  }
                />
              </div>
            ))}
            <button
              type="button"
              className="btn btn-outline-primary btn-sm mb-3"
              onClick={() =>
                setBuckets([
                  ...refusalBuckets,
                  { category: refusalBuckets.length === 0 ? 'default' : '', clips: [] },
                ])
              }
            >
              <i className="fas fa-plus me-1" />
              Add refusal bucket
            </button>

            <hr />

            {/* On-fail */}
            <h6>On upstream failure</h6>
            <p className="text-muted small">
              Played (round-robin) when the upstream model errors mid-session, so the caller hears
              something instead of a silent drop.
            </p>
            <ClipPicker
              idPrefix="on-fail"
              clips={clips}
              selected={onFail}
              onChange={ids => updateAudioStreams({ on_fail: ids })}
            />
          </div>
        </div>
      )}
    </div>
  );
};

export default AudioStreamFullscreenPanel;
