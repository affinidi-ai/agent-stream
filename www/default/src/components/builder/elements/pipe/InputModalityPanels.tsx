import React from 'react';
import type { ConfigPanelProps } from '../types';
import { DEFAULT_INPUT_MODALITIES, usePipePanelData } from './pipePanelData';

/**
 * Sidebar panels for the Inputs-palette nodes (`pipe-audio-input` "Audio File",
 * `pipe-audio-stream` "Audio Stream", `pipe-image-input` "Image File",
 * `pipe-document-input` "Document File"). Dropping a node onto the LLM
 * **enables** that inbound modality on the surface (strict opt-in); its config
 * is assembled into the surface's `audio_input` / `realtime` / `image_input` /
 * `document_ingestion` block on save. The accepted type/format checklists are
 * **backend-driven** — sourced from the published modality support via
 * {@link usePipePanelData} — so new formats/parsers appear automatically.
 */

const toPositiveInt = (raw: string, fallback: number): number => {
  const n = parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
};

const asStringArray = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];

/** A reusable enabled toggle. */
const EnabledSwitch: React.FC<{
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

/** A reusable inline checklist of accepted types/formats. */
const TypeChecklist: React.FC<{
  idPrefix: string;
  options: { id: string; label: string; hint?: string }[];
  selected: string[];
  onToggle: (id: string) => void;
}> = ({ idPrefix, options, selected, onToggle }) => (
  <div className="mb-3">
    {options.map(o => (
      <div className="form-check form-check-inline" key={o.id}>
        <input
          className="form-check-input"
          type="checkbox"
          id={`${idPrefix}-${o.id}`}
          checked={selected.includes(o.id)}
          onChange={() => onToggle(o.id)}
        />
        <label className="form-check-label" htmlFor={`${idPrefix}-${o.id}`}>
          {o.label}
          {o.hint ? <small className="text-muted"> ({o.hint})</small> : null}
        </label>
      </div>
    ))}
  </div>
);

const MegaBytes: React.FC<{
  label: string;
  bytes: number;
  fallbackMb: number;
  onChange: (bytes: number) => void;
}> = ({ label, bytes, fallbackMb, onChange }) => {
  const mb = Math.max(1, Math.round((bytes || fallbackMb * 1024 * 1024) / (1024 * 1024)));
  return (
    <div className="mb-3">
      <label className="form-label">{label}</label>
      <input
        type="number"
        min={1}
        step={1}
        className="form-control"
        value={mb}
        onChange={e => onChange(toPositiveInt(e.target.value, fallbackMb) * 1024 * 1024)}
      />
    </div>
  );
};

export const PipeAudioInputPanel: React.FC<ConfigPanelProps> = ({ config, updateField }) => {
  const { inputModalities = DEFAULT_INPUT_MODALITIES } = usePipePanelData();
  const enabled = config?.enabled !== false;
  const selected = asStringArray(config?.allowed_formats);
  const options = inputModalities.audio.formats.map(f => ({ id: f, label: f.toUpperCase() }));
  const toggle = (f: string) =>
    updateField(
      'allowed_formats',
      selected.includes(f) ? selected.filter(x => x !== f) : [...selected, f]
    );

  return (
    <div className="surface-config-panel">
      <p className="text-muted small">
        Accept an attached audio file (an <code>input_audio</code> part, wav/mp3) for an
        audio-capable model. Delete this node to reject audio files. The target model must support
        audio input. For live bidirectional voice, use the <strong>Audio Stream</strong> element.
      </p>
      <EnabledSwitch
        id="audio-input-enabled"
        label="Accept audio files"
        enabled={enabled}
        onChange={v => updateField('enabled', v)}
      />
      <label className="d-block">Accepted formats</label>
      <TypeChecklist idPrefix="audio-fmt" options={options} selected={selected} onToggle={toggle} />
      <MegaBytes
        label="Max total audio (MB)"
        bytes={config?.max_bytes}
        fallbackMb={25}
        onChange={b => updateField('max_bytes', b)}
      />
      <small className="form-text text-muted d-block">
        Detected formats are exposed to policy as <code>input.resource.audio_formats</code>.
      </small>
    </div>
  );
};

export const PipeAudioStreamPanel: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  openFullscreenEditor,
}) => {
  const enabled = config?.enabled !== false;
  const safetyOn = (config?.safety as { enabled?: boolean } | undefined)?.enabled === true;

  return (
    <div className="surface-config-panel">
      <p className="text-muted small">
        Realtime voice (Mode C): a governed bidirectional WebSocket at <code>/v1/realtime</code>{' '}
        that relays live audio to the model, segmented into per-turn governance records. Delete this
        node to refuse realtime sessions.
      </p>
      <EnabledSwitch
        id="audio-stream-enabled"
        label="Enable realtime voice"
        enabled={enabled}
        onChange={v => updateField('enabled', v)}
      />
      <p className="text-muted small">
        Needs a realtime-capable model — an OpenAI realtime model or a Gemini Live model. Configure
        the session, per-turn voice safety, and the pre-recorded audio-stream clips (filler,
        refusal, on-fail) in the full editor.
      </p>
      {enabled && (
        <>
          {safetyOn && (
            <div className="mb-2">
              <span className="badge bg-info-subtle text-info-emphasis">
                Realtime response safety on
              </span>
            </div>
          )}
          <button
            type="button"
            className="btn btn-outline-primary btn-sm w-100"
            onClick={() => openFullscreenEditor?.()}
            disabled={!openFullscreenEditor}
          >
            <i className="fas fa-sliders me-1" />
            Configure session, safety &amp; audio streams…
          </button>
        </>
      )}
    </div>
  );
};

export const PipeImageInputPanel: React.FC<ConfigPanelProps> = ({ config, updateField }) => {
  const { inputModalities = DEFAULT_INPUT_MODALITIES } = usePipePanelData();
  const enabled = config?.enabled !== false;
  const selected = asStringArray(config?.allowed_formats);
  const options = inputModalities.image.formats.map(f => ({ id: f, label: f.toUpperCase() }));
  const toggle = (f: string) =>
    updateField(
      'allowed_formats',
      selected.includes(f) ? selected.filter(x => x !== f) : [...selected, f]
    );
  return (
    <div className="surface-config-panel">
      <p className="text-muted small">
        Accept inline images (an <code>image_url</code> part) for a vision-capable model. Delete
        this node to reject images. Remote image URLs are forwarded; inline data images are format-
        and size-checked.
      </p>
      <EnabledSwitch
        id="image-input-enabled"
        label="Accept image files"
        enabled={enabled}
        onChange={v => updateField('enabled', v)}
      />
      <label className="d-block">Accepted inline formats</label>
      <TypeChecklist idPrefix="image-fmt" options={options} selected={selected} onToggle={toggle} />
      <MegaBytes
        label="Max total inline images (MB)"
        bytes={config?.max_bytes}
        fallbackMb={20}
        onChange={b => updateField('max_bytes', b)}
      />
      <small className="form-text text-muted d-block">
        Detected formats are exposed to policy as <code>input.resource.image_formats</code>.
      </small>
    </div>
  );
};

export const PipeDocumentInputPanel: React.FC<ConfigPanelProps> = ({ config, updateField }) => {
  const { inputModalities = DEFAULT_INPUT_MODALITIES } = usePipePanelData();
  const enabled = config?.enabled !== false;
  const mode = config?.mode === 'extract' || config?.mode === 'passthrough' ? config.mode : 'auto';
  const selected = asStringArray(config?.allowed_types);
  const options = [
    ...inputModalities.document.extractable.map(t => ({ id: t, label: t.toUpperCase() })),
    ...inputModalities.document.forward_only.map(t => ({
      id: t,
      label: t.toUpperCase(),
      hint: 'forwarded, not yet parsed',
    })),
  ];
  const toggle = (t: string) =>
    updateField(
      'allowed_types',
      selected.includes(t) ? selected.filter(x => x !== t) : [...selected, t]
    );
  const chars =
    typeof config?.max_extracted_chars === 'number' ? config.max_extracted_chars : 100000;
  return (
    <div className="surface-config-panel">
      <p className="text-muted small">
        Accept an attached document (a <code>file</code> part) and, per the mode, extract it to
        prompt text so any model can read it. Delete this node to reject documents.
      </p>
      <EnabledSwitch
        id="document-input-enabled"
        label="Accept and extract attached documents"
        enabled={enabled}
        onChange={v => updateField('enabled', v)}
      />
      <div className="mb-3">
        <label className="form-label">Mode</label>
        <select
          className="form-select"
          value={mode}
          onChange={e => updateField('mode', e.target.value)}
        >
          <option value="auto">Auto — extract parseable types, forward the rest</option>
          <option value="extract">Extract — extract all allowed types (error if unable)</option>
          <option value="passthrough">Passthrough — forward to a document-native model</option>
        </select>
      </div>
      <label className="d-block">Allowed document types</label>
      <TypeChecklist idPrefix="doc-type" options={options} selected={selected} onToggle={toggle} />
      <MegaBytes
        label="Max file size (MB)"
        bytes={config?.max_file_bytes}
        fallbackMb={5}
        onChange={b => updateField('max_file_bytes', b)}
      />
      <div className="mb-0">
        <label className="form-label">Max extracted characters</label>
        <input
          type="number"
          min={1000}
          step={1000}
          className="form-control"
          value={chars}
          onChange={e =>
            updateField(
              'max_extracted_chars',
              Math.max(1000, parseInt(e.target.value, 10) || 100000)
            )
          }
        />
      </div>
      <small className="form-text text-muted d-block mt-2">
        Detected types are exposed to policy as <code>input.resource.document_types</code>.
      </small>
    </div>
  );
};
