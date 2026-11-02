/**
 * CreatePipeTemplateForm — used both for creating a new pipe template
 * (full snapshot of the current pipe form) and for editing an existing
 * user template's metadata. Mirrors the surface `CreateTemplateForm`
 * but without the partial/full distinction — a pipe template always
 * carries a complete `pipe` snapshot.
 */

import React, { useMemo, useState } from 'react';
import type { PipeTemplate, PipeTemplateItem } from '../../../api';
import type { CanvasNode } from '../SurfaceCanvas';
import { pipeFormToTemplateBlob } from './pipeTemplateBlob';
import {
  serializePipeTemplate,
  canSerializePipeNode,
  describePipeNode,
} from './serializePipeTemplate';

/**
 * Pluggable canvas-node serializer for partial templates. Defaults to the
 * LLM-pipe node serializer; the IDE editor supplies its own (governance
 * singletons) so partial IDE templates capture `ide-*` nodes.
 */
export interface TemplateNodeSerializer {
  canSerialize: (node: CanvasNode) => boolean;
  serialize: (nodes: CanvasNode[], opts: { nodeIds?: Iterable<string> }) => PipeTemplateItem[];
  describe: (node: CanvasNode) => string;
}

const DEFAULT_SERIALIZER: TemplateNodeSerializer = {
  canSerialize: canSerializePipeNode,
  serialize: serializePipeTemplate,
  describe: describePipeNode,
};

const ICON_CHOICES: ReadonlyArray<{ value: string; label: string }> = [
  { value: 'diagram-project', label: 'Diagram' },
  { value: 'brain', label: 'Brain' },
  { value: 'robot', label: 'Robot' },
  { value: 'bolt', label: 'Bolt' },
  { value: 'server', label: 'Server' },
  { value: 'shield-halved', label: 'Shield' },
  { value: 'gauge', label: 'Gauge' },
  { value: 'rocket', label: 'Rocket' },
  { value: 'plug', label: 'Plug' },
  { value: 'microchip', label: 'Microchip' },
  { value: 'comments', label: 'Comments' },
  { value: 'gear', label: 'Gear' },
];

export interface CreatePipeTemplateFormProps {
  mode: 'create' | 'edit';
  /** Required in edit mode; ignored in create mode. */
  template?: PipeTemplate;
  /**
   * Current pipe form data. Required in create mode — the whole pipe is
   * snapshotted into the new template's `pipe` blob. Ignored in edit
   * mode.
   */
  currentPipe?: Record<string, any>;
  /**
   * Live canvas nodes. When present in create mode, the author can
   * capture a partial template (a bundle of selected elements) instead
   * of a full pipe snapshot.
   */
  nodes?: CanvasNode[];
  /**
   * Snapshot the live builder canvas (node positions / decorations) for
   * the full-pipe template blob, so a captured template preserves layout.
   */
  getCanvasBlob?: () => unknown;
  /**
   * Build the full-template `pipe` blob from `currentPipe`. Defaults to the
   * LLM-pipe form serializer (`pipeFormToTemplateBlob`); the IDE editor passes
   * a builder that snapshots the composed IDE config (stripping identity
   * fields) since IDE templates carry a wire-config blob, not a flat form.
   */
  buildFullBlob?: (currentPipe: Record<string, any>) => Record<string, any>;
  /**
   * Tags always stamped onto a created template (e.g. `['ide']` so an
   * IDE-authored template shows up in the IDE editor's filtered list).
   */
  requiredTags?: string[];
  /**
   * Serializer used to capture partial-template items from the canvas. Defaults
   * to the LLM-pipe node serializer; the IDE editor passes its own so partial
   * IDE templates capture governance `ide-*` nodes.
   */
  serializer?: TemplateNodeSerializer;
  /**
   * Pre-seed the partial capture with these node ids (from a canvas selection),
   * opening the form in "partial" scope. Omitted = default to a full capture.
   */
  initialSelectedNodeIds?: string[];
  onCancel: () => void;
  onSave: (payload: Partial<PipeTemplate>) => Promise<void>;
}

const CreatePipeTemplateForm: React.FC<CreatePipeTemplateFormProps> = ({
  mode,
  template,
  currentPipe,
  nodes,
  getCanvasBlob,
  buildFullBlob,
  requiredTags,
  serializer,
  initialSelectedNodeIds,
  onCancel,
  onSave,
}) => {
  const ser = serializer ?? DEFAULT_SERIALIZER;
  const [name, setName] = useState(template?.name ?? '');
  const [description, setDescription] = useState(template?.description ?? '');
  const [details, setDetails] = useState(template?.details ?? '');
  const [starterHint, setStarterHint] = useState(template?.starter_hint ?? '');
  const [icon, setIcon] = useState(template?.icon ?? ICON_CHOICES[0].value);
  const [tagsCsv, setTagsCsv] = useState(
    (template?.tags ?? (mode === 'create' ? (requiredTags ?? []) : [])).join(', ')
  );
  const [showInStarter, setShowInStarter] = useState(true);
  const [priority, setPriority] = useState<'high' | 'normal' | 'low'>(() => {
    const p = template?.sort_priority;
    if (p === undefined || p === null) return 'normal';
    if (p <= 2500) return 'high';
    if (p >= 3500) return 'low';
    return 'normal';
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const serializableNodes = useMemo(() => (nodes ?? []).filter(ser.canSerialize), [nodes, ser]);
  const canCapturePartial = mode === 'create' && serializableNodes.length > 0;

  const [scope, setScope] = useState<'full' | 'partial'>(
    initialSelectedNodeIds && initialSelectedNodeIds.length > 0 ? 'partial' : 'full'
  );
  const [selectedNodeIds, setSelectedNodeIds] = useState<Set<string>>(new Set());

  // Seed the partial selection from an explicit canvas selection when provided
  // (Create Template from Selection), else default to every serializable node.
  React.useEffect(() => {
    const allow = new Set(serializableNodes.map(n => n.id));
    const seed =
      initialSelectedNodeIds && initialSelectedNodeIds.length > 0
        ? initialSelectedNodeIds.filter(id => allow.has(id))
        : [...allow];
    setSelectedNodeIds(new Set(seed));
  }, [serializableNodes, initialSelectedNodeIds]);

  const toggleNode = (id: string) =>
    setSelectedNodeIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const pipeBlob = useMemo(() => {
    if (mode !== 'create' || !currentPipe) return null;
    const blob = (buildFullBlob ?? pipeFormToTemplateBlob)(currentPipe);
    // Prefer the live canvas snapshot so node positions / decorations
    // captured into the template match what the author sees right now.
    const liveCanvas = getCanvasBlob?.();
    if (liveCanvas) blob.canvas = liveCanvas;
    return blob;
  }, [mode, currentPipe, getCanvasBlob, buildFullBlob]);

  const partialItems = useMemo(() => {
    if (!canCapturePartial || scope !== 'partial') return [];
    return ser.serialize(serializableNodes, { nodeIds: selectedNodeIds });
  }, [canCapturePartial, scope, serializableNodes, selectedNodeIds, ser]);

  const canSave =
    name.trim().length > 0 &&
    !saving &&
    (mode === 'edit' || (scope === 'partial' ? partialItems.length > 0 : !!pipeBlob));

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSave) return;
    setError(null);
    setSaving(true);
    try {
      const payload: Partial<PipeTemplate> = {
        name: name.trim(),
        description: description.trim() || undefined,
        details: details.trim() || undefined,
        starter_hint: starterHint.trim() || undefined,
        icon: icon.trim() || undefined,
        tags: (() => {
          const list = tagsCsv
            .split(',')
            .map(s => s.trim())
            .filter(Boolean);
          // Only full-pipe templates seed the New Pipe starter picker;
          // partial bundles are applied to an existing pipe.
          if (mode === 'create' && scope === 'full' && showInStarter && !list.includes('starter')) {
            list.push('starter');
          }
          // Always stamp the caller's required tags (e.g. `ide`) so the
          // template is discoverable in the editor that created it.
          for (const t of requiredTags ?? []) {
            if (!list.includes(t)) list.push(t);
          }
          return list;
        })(),
        sort_priority: priority === 'high' ? 2000 : priority === 'low' ? 4000 : 3000,
      };
      if (mode === 'create') {
        if (scope === 'partial') {
          if (partialItems.length === 0) {
            setError('Select at least one element to capture.');
            setSaving(false);
            return;
          }
          // A partial template is an additive bundle of the selected
          // canvas elements — it merges onto an existing pipe rather than
          // replacing it.
          payload.kind = 'partial';
          payload.items = partialItems;
        } else {
          if (!pipeBlob) {
            setError('No current pipe to snapshot.');
            setSaving(false);
            return;
          }
          // A full pipe template carries the whole pipe blob (including
          // canvas layout and upstream variants).
          payload.kind = 'full';
          payload.pipe = pipeBlob;
        }
      }
      await onSave(payload);
    } catch (e: any) {
      setError(e?.message ?? 'Failed to save template');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="card shadow-sm mb-0 surface-fullpage-panel">
      <div className="card-header">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className={`fas fa-${mode === 'create' ? 'plus' : 'pen'} me-2`} />
          {mode === 'create' ? 'Create Pipe Template' : 'Edit Pipe Template'}
        </h6>
      </div>
      <form
        onSubmit={handleSubmit}
        style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}
      >
        <div className="card-body" style={{ overflowY: 'auto', minHeight: 0, flex: 1 }}>
          {canCapturePartial && (
            <div className="mb-3">
              <label className="form-label small text-muted mb-1">Capture</label>
              <div className="btn-group btn-group-sm w-100" role="group">
                <button
                  type="button"
                  className={`btn ${scope === 'full' ? 'btn-primary' : 'btn-outline-secondary'}`}
                  onClick={() => setScope('full')}
                >
                  <i className="fas fa-clone me-1" />
                  Full pipe
                </button>
                <button
                  type="button"
                  className={`btn ${scope === 'partial' ? 'btn-primary' : 'btn-outline-secondary'}`}
                  onClick={() => setScope('partial')}
                >
                  <i className="fas fa-object-group me-1" />
                  Selected elements
                </button>
              </div>
              <small className="form-text text-muted d-block">
                {scope === 'full'
                  ? 'Snapshot the whole pipe — upstream, variants, and canvas layout.'
                  : 'Capture a reusable bundle of canvas elements that merges onto an existing pipe.'}
              </small>
            </div>
          )}

          {canCapturePartial && scope === 'partial' && (
            <div className="mb-3">
              <label className="form-label small text-muted mb-1">Elements to capture</label>
              <div className="list-group list-group-flush border rounded">
                {serializableNodes.map(node => (
                  <label
                    key={node.id}
                    className="list-group-item d-flex align-items-center gap-2 py-1 px-2 small"
                    style={{ cursor: 'pointer' }}
                  >
                    <input
                      type="checkbox"
                      className="form-check-input m-0"
                      checked={selectedNodeIds.has(node.id)}
                      onChange={() => toggleNode(node.id)}
                    />
                    {ser.describe(node)}
                  </label>
                ))}
              </div>
              <small className="form-text text-muted">
                {partialItems.length} element{partialItems.length === 1 ? '' : 's'} selected.
              </small>
            </div>
          )}

          <div className="mb-3">
            <label className="form-label small text-muted mb-1">Name</label>
            <input
              type="text"
              className="form-control form-control-sm"
              value={name}
              onChange={e => setName(e.target.value)}
              autoFocus
              required
            />
            <small className="form-text text-muted">
              Short, descriptive label shown in the template list (e.g. “OpenAI Chat”).
            </small>
          </div>

          <div className="mb-3">
            <label className="form-label small text-muted mb-1">Description</label>
            <input
              type="text"
              className="form-control form-control-sm"
              value={description}
              onChange={e => setDescription(e.target.value)}
            />
            <small className="form-text text-muted">
              One-line summary shown beneath the name in the template list.
            </small>
          </div>

          <div className="mb-3">
            <label className="form-label small text-muted mb-1">Details</label>
            <textarea
              className="form-control form-control-sm"
              rows={2}
              value={details}
              onChange={e => setDetails(e.target.value)}
            />
            <small className="form-text text-muted">
              Long-form explanation shown when the template row is expanded.
            </small>
          </div>

          <div className="mb-3">
            <label className="form-label small text-muted mb-1">Starter Hint</label>
            <textarea
              className="form-control form-control-sm"
              rows={3}
              value={starterHint}
              onChange={e => setStarterHint(e.target.value)}
            />
            <small className="form-text text-muted">
              Body text for the welcome balloon shown the first time a user creates a pipe from this
              template. Leave blank to skip it.
            </small>
          </div>

          <div className="row g-2 mb-3">
            <div className="col-6">
              <label className="form-label small text-muted mb-1">Icon</label>
              <div className="input-group input-group-sm">
                <span className="input-group-text">
                  <i className={`fas fa-${icon || 'diagram-project'}`} />
                </span>
                <select
                  className="form-select form-select-sm"
                  value={icon}
                  onChange={e => setIcon(e.target.value)}
                >
                  {ICON_CHOICES.map(opt => (
                    <option key={opt.value} value={opt.value}>
                      {opt.label}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <div className="col-6">
              <label className="form-label small text-muted mb-1">Sort priority</label>
              <select
                className="form-select form-select-sm"
                value={priority}
                onChange={e => setPriority(e.target.value as 'high' | 'normal' | 'low')}
              >
                <option value="high">High</option>
                <option value="normal">Normal</option>
                <option value="low">Low</option>
              </select>
              <small className="form-text text-muted">
                Higher priority shows first in the list.
              </small>
            </div>
          </div>

          <div className="mb-3">
            <label className="form-label small text-muted mb-1">Tags</label>
            <input
              type="text"
              className="form-control form-control-sm"
              value={tagsCsv}
              onChange={e => setTagsCsv(e.target.value)}
            />
            <small className="form-text text-muted">
              Comma-separated tags to help identify your templates.
            </small>
          </div>

          {mode === 'create' && scope === 'full' && (
            <div className="mb-3 form-check">
              <input
                type="checkbox"
                className="form-check-input"
                id="pipe-template-show-in-starter"
                checked={showInStarter}
                onChange={e => setShowInStarter(e.target.checked)}
              />
              <label className="form-check-label small" htmlFor="pipe-template-show-in-starter">
                Show in New Pipe list
              </label>
              <small className="form-text text-muted d-block">
                Uncheck to hide this template from the starter picker on the New Pipe page. You can
                still apply it from the template list.
              </small>
            </div>
          )}

          {mode === 'edit' && (
            <div className="alert alert-info py-2 px-3 small mb-3">
              <i className="fas fa-circle-info me-1" />
              Editing metadata only. The pipe snapshot is preserved as-is. To change the body, apply
              it to a pipe, edit, and re-save as a new template.
            </div>
          )}

          {error && (
            <div className="alert alert-danger py-2 px-3 small mb-3">
              <i className="fas fa-times-circle me-1" />
              {error}
            </div>
          )}
        </div>
        <div className="card-footer d-flex justify-content-end gap-2" style={{ flexShrink: 0 }}>
          <button
            type="button"
            className="btn btn-sm btn-outline-secondary"
            onClick={onCancel}
            disabled={saving}
          >
            Cancel
          </button>
          <button type="submit" className="btn btn-sm btn-primary" disabled={!canSave}>
            {saving ? (
              <>
                <span className="spinner-border spinner-border-sm me-1" />
                Saving…
              </>
            ) : (
              <>
                <i className="fas fa-save me-1" />
                Save Template
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
};

export default CreatePipeTemplateForm;
