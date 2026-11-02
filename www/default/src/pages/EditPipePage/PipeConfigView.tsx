import React, { useState } from 'react';

interface PipeConfigViewProps {
  /** Canonical surface configuration rendered as pretty-printed JSON. */
  config: unknown;
  /**
   * Apply an edited/pasted configuration into the editor. Return `null` on
   * success or an error string surfaced inline. When omitted the JSON is
   * read-only (copy still works).
   */
  onApply?: (parsed: unknown) => string | null;
  /** Heading shown above the editor. */
  title?: string;
}

/**
 * JSON view of a surface's configuration with a copy affordance. When an
 * `onApply` handler is supplied the JSON becomes editable: parse the buffered
 * text, hand the parsed payload to the host so the canvas re-hydrates to match,
 * and surface parse/semantic errors inline (the canvas keeps the last accepted
 * payload). Copying a payload here and pasting it into another surface's Config
 * tab is how a configuration is duplicated across surfaces.
 */
export const PipeConfigView: React.FC<PipeConfigViewProps> = ({
  config,
  onApply,
  title = 'Surface configuration (JSON)',
}) => {
  const canonical = JSON.stringify(config, null, 2);
  // Non-null only while the user is mid-edit; dropped on a successful apply so
  // the textarea re-syncs to the canonical payload built from the canvas.
  const [draft, setDraft] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const editable = !!onApply;
  const value = draft ?? canonical;

  const handleChange = (raw: string) => {
    setDraft(raw);
    if (!onApply) return;
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Invalid JSON');
      return;
    }
    const semanticError = onApply(parsed);
    if (semanticError) {
      setError(semanticError);
      return;
    }
    setError(null);
    setDraft(null);
  };

  return (
    <div className="card shadow-sm mb-0 surface-fullpage-panel">
      <div className="card-header d-flex align-items-center justify-content-between">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-code me-2" />
          {title}
        </h6>
        <button
          type="button"
          className="btn btn-sm btn-outline-secondary"
          onClick={() => navigator.clipboard?.writeText(value)}
          title="Copy configuration JSON"
        >
          <i className="fas fa-copy me-1" />
          Copy
        </button>
      </div>
      <div className="card-body surface-fullpage-panel__body d-flex flex-column">
        {editable &&
          (error ? (
            <div className="alert alert-danger py-2 px-3 mb-2 d-flex align-items-start">
              <i className="fas fa-times-circle me-2 mt-1" />
              <div className="flex-grow-1">
                <strong>Invalid configuration.</strong> Fix the error below — the canvas is showing
                the last accepted payload.
                <div className="small mt-1">{error}</div>
              </div>
              <button
                type="button"
                className="btn btn-sm btn-outline-secondary ms-2"
                onClick={() => {
                  setDraft(null);
                  setError(null);
                }}
              >
                Discard edits
              </button>
            </div>
          ) : (
            <p className="text-muted small mb-2">
              Complete surface configuration. Edit directly, or paste a payload from another surface
              — the canvas refreshes to match. The name and description are imported; this
              surface&apos;s id and listener details are preserved.
            </p>
          ))}
        <textarea
          className={`form-control font-monospace ${error ? 'is-invalid' : ''}`}
          spellCheck={false}
          readOnly={!editable}
          value={value}
          onChange={editable ? e => handleChange(e.target.value) : undefined}
          style={{ flex: '1 1 auto', minHeight: 0, resize: 'none' }}
        />
      </div>
    </div>
  );
};

export default PipeConfigView;
