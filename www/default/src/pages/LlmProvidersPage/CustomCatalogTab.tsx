import React, { useEffect, useMemo, useRef, useState } from 'react';
import { apiClient } from '../../api';
import { AppButton } from '../../components/shared/AppButton';
import { validateCustomCatalog } from './customValidation';

interface CustomCatalogTabProps {
  /** Lower-cased built-in provider ids, to reject collisions client-side. */
  builtInEnumValues: Set<string>;
  /** Called after a successful save so the Custom list tab can refresh. */
  onSaved: () => void;
  /**
   * Whether this tab is the active one. The ⌘S / Ctrl+S save shortcut is only
   * bound while active, because react-bootstrap keeps every tab pane mounted —
   * an ungated global listener would hijack the shortcut on the other tabs.
   */
  active?: boolean;
}

const extractError = (message: string): string => {
  // The api client throws `API Error: 400 Bad Request - {"error":"..."}`.
  const dash = message.indexOf(' - ');
  const tail = dash >= 0 ? message.slice(dash + 3) : message;
  try {
    const parsed = JSON.parse(tail);
    if (parsed && typeof parsed.error === 'string') return parsed.error;
  } catch {
    /* not JSON — fall through */
  }
  return tail || message;
};

/**
 * The **Custom** JSON editor: edit the custom provider catalog as raw JSON,
 * validate it (client-side, mirroring the authoritative backend checks), and
 * push it to the backend. Modelled on the surface Config tab. On save the
 * backend merges the custom providers into the runtime catalog so they appear
 * in every LLM / judge / jury picker as if they were built in.
 */
const CustomCatalogTab: React.FC<CustomCatalogTabProps> = ({
  builtInEnumValues,
  onSaved,
  active = true,
}) => {
  const [saved, setSaved] = useState('');
  const [text, setText] = useState('');
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [savedFlash, setSavedFlash] = useState(false);

  useEffect(() => {
    let active = true;
    (async () => {
      setLoading(true);
      setLoadError(null);
      try {
        const res = await apiClient.get<{ raw: string }>('/llm-providers/custom');
        if (!active) return;
        const raw = res.data.raw ?? '{\n  "providers": []\n}\n';
        setSaved(raw);
        setText(raw);
      } catch (e) {
        if (active) setLoadError(e instanceof Error ? e.message : 'Failed to load custom catalog');
      } finally {
        if (active) setLoading(false);
      }
    })();
    return () => {
      active = false;
    };
  }, []);

  // Client-side validation of the current draft, mirroring the backend.
  const clientError = useMemo(() => {
    if (loading) return null;
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      return e instanceof Error ? `Invalid JSON: ${e.message}` : 'Invalid JSON';
    }
    return validateCustomCatalog(parsed, builtInEnumValues);
  }, [text, builtInEnumValues, loading]);

  const dirty = text !== saved;
  const canSave = !loading && !saving && dirty && !clientError;

  const handleSave = async () => {
    if (!canSave) return;
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return;
    }
    setSaving(true);
    setSaveError(null);
    setSavedFlash(false);
    try {
      await apiClient.put('/llm-providers/custom', parsed);
      setSaved(text);
      setSavedFlash(true);
      onSaved();
      window.setTimeout(() => setSavedFlash(false), 2500);
    } catch (e) {
      setSaveError(e instanceof Error ? extractError(e.message) : 'Failed to save custom catalog');
    } finally {
      setSaving(false);
    }
  };

  // ⌘S / Ctrl+S saves the catalog. A ref holds the latest guarded save action so
  // the listener binds once (per active period) without re-running each render.
  const attemptSaveRef = useRef<() => void>(() => {});
  attemptSaveRef.current = () => {
    if (canSave) void handleSave();
  };
  useEffect(() => {
    if (!active) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 's') {
        e.preventDefault();
        attemptSaveRef.current();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [active]);

  if (loading) {
    return (
      <div className="text-center py-4">
        <div className="spinner-border text-primary" role="status" />
      </div>
    );
  }

  if (loadError) {
    return (
      <div className="alert alert-danger" data-testid="llm-custom-load-error">
        <i className="fas fa-exclamation-triangle me-2"></i>
        {loadError}
      </div>
    );
  }

  return (
    <div className="d-flex flex-column" data-testid="llm-custom-editor">
      <div className="alert alert-info py-2 px-3 mb-3" style={{ fontSize: '13px' }}>
        <i className="fas fa-info-circle me-2"></i>
        Define your own providers and models as JSON. On save they are validated and merged into the
        runtime catalog — appearing in every LLM, judge and jury picker exactly like the built-in
        providers — without ever modifying the shipped <code>llm.json</code>. A provider must have a
        unique <code>enum_value</code> (it cannot reuse a built-in one) and a <code>name</code>;
        each model needs a <code>name</code> and <code>value</code>.
      </div>

      <div className="small text-muted mb-2">
        {clientError ? (
          <span className="text-danger">
            <i className="fas fa-times-circle me-1"></i>
            {clientError}
          </span>
        ) : dirty ? (
          <span>
            <i className="fas fa-pen me-1"></i>Unsaved changes
          </span>
        ) : (
          <span>
            <i className="fas fa-check me-1 text-success"></i>Configuration is valid
          </span>
        )}
      </div>

      {saveError && (
        <div className="alert alert-danger py-2 px-3 mb-2" data-testid="llm-custom-save-error">
          <i className="fas fa-times-circle me-2"></i>
          {saveError}
        </div>
      )}
      {savedFlash && (
        <div className="alert alert-success py-2 px-3 mb-2" data-testid="llm-custom-saved">
          <i className="fas fa-check-circle me-2"></i>
          Custom catalog saved — providers are now available across the appliance.
        </div>
      )}

      <textarea
        className={`form-control font-monospace ${clientError ? 'is-invalid' : ''}`}
        spellCheck={false}
        value={text}
        onChange={e => setText(e.target.value)}
        style={{ minHeight: '55vh', resize: 'vertical' }}
        data-testid="llm-custom-textarea"
      />

      <hr />

      <div className="d-flex justify-content-end">
        <div className="d-flex gap-2">
          <AppButton
            type="button"
            variant="outline-secondary"
            onClick={() => navigator.clipboard?.writeText(text)}
            title="Copy JSON"
            iconStart={<i className="fas fa-copy me-1" aria-hidden="true" />}
          >
            Copy
          </AppButton>
          <AppButton
            type="button"
            variant="primary"
            disabled={!canSave}
            loading={saving}
            loadingLabel="Saving…"
            onClick={handleSave}
            data-testid="llm-custom-save"
            iconStart={<i className="fas fa-save me-1" aria-hidden="true" />}
          >
            Save
          </AppButton>
        </div>
      </div>
    </div>
  );
};

export default CustomCatalogTab;
