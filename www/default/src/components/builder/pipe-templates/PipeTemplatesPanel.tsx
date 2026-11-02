/**
 * PipeTemplatesPanel — the sidebar view that lists pipe templates,
 * applies them to the current pipe form, and lets the user create /
 * edit / delete their own templates. Mirrors the surface
 * `TemplatesPanel`, including the Partials / Full Surfaces kind tabs
 * that split the list by `kind` so each tab shows its own count.
 */

import React, { useState } from 'react';
import type { PipeTemplate } from '../../../api';
import { Badge } from '../../shared/Badge';
import { DeleteButton } from '../../shared/DeleteButton';
import type { CanvasNode } from '../SurfaceCanvas';
import CreatePipeTemplateForm, { type TemplateNodeSerializer } from './CreatePipeTemplateForm';
import { sortPipeTemplatesForDisplay, usePipeTemplates } from './usePipeTemplates';

interface PipeTemplatesPanelProps {
  /** Called when the user applies a template to the current pipe. */
  onApplyTemplate: (template: PipeTemplate) => void;
  /**
   * Current pipe form data — snapshotted into a new template when the
   * user saves the current pipe as a template.
   */
  currentPipe: Record<string, any>;
  /**
   * Live canvas nodes — let the author capture a partial template from
   * selected canvas elements instead of the whole pipe.
   */
  nodes?: CanvasNode[];
  /** Snapshot the live canvas layout for a full-pipe template blob. */
  getCanvasBlob?: () => unknown;
  /** Whether the panel opens in create mode (driven by the [+] button). */
  createMode: boolean;
  /** Asks the shell to leave create mode. */
  onExitCreateMode: () => void;
  /**
   * Optional predicate to scope the listed templates (e.g. the IDE editor
   * shows only IDE-tagged templates). Omitted = show every template.
   */
  templateFilter?: (template: PipeTemplate) => boolean;
  /**
   * Override how a full-template `pipe` blob is built from `currentPipe`
   * (the IDE editor snapshots its composed wire config instead of a form).
   */
  buildFullBlob?: (currentPipe: Record<string, any>) => Record<string, any>;
  /** Tags always stamped onto a created template (e.g. `['ide']`). */
  requiredTags?: string[];
  /**
   * Serializer used to capture partial-template items from the canvas (the IDE
   * editor passes its own so partial IDE templates capture `ide-*` nodes).
   */
  serializer?: TemplateNodeSerializer;
  /** Pre-seed the partial capture with these node ids (a canvas selection). */
  initialSelectedNodeIds?: string[];
}

const PipeTemplatesPanel: React.FC<PipeTemplatesPanelProps> = ({
  onApplyTemplate,
  currentPipe,
  nodes,
  getCanvasBlob,
  createMode,
  onExitCreateMode,
  templateFilter,
  buildFullBlob,
  requiredTags,
  serializer,
  initialSelectedNodeIds,
}) => {
  const { templates, loading, error, refresh, create, update, remove, importTemplate } =
    usePipeTemplates();
  const [filter, setFilter] = useState('');
  const [kindTab, setKindTab] = useState<'full' | 'partial'>('partial');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [editing, setEditing] = useState<PipeTemplate | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [importing, setImporting] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const fileInputRef = React.useRef<HTMLInputElement | null>(null);

  React.useEffect(() => {
    if (createMode) setEditing(null);
  }, [createMode]);

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await refresh();
    } finally {
      setRefreshing(false);
    }
  };

  if (createMode) {
    return (
      <CreatePipeTemplateForm
        mode="create"
        currentPipe={currentPipe}
        nodes={nodes}
        getCanvasBlob={getCanvasBlob}
        buildFullBlob={buildFullBlob}
        requiredTags={requiredTags}
        serializer={serializer}
        initialSelectedNodeIds={initialSelectedNodeIds}
        onCancel={onExitCreateMode}
        onSave={async payload => {
          await create(payload);
          onExitCreateMode();
        }}
      />
    );
  }

  if (editing) {
    return (
      <CreatePipeTemplateForm
        mode="edit"
        template={editing}
        onCancel={() => setEditing(null)}
        onSave={async payload => {
          await update(editing.id, { ...editing, ...payload });
          setEditing(null);
        }}
      />
    );
  }

  // Split by kind first so each tab shows its own count; then apply
  // the free-text filter to whichever tab is active.
  const scopedTemplates = templateFilter ? templates.filter(templateFilter) : templates;
  const fullTemplates = sortPipeTemplatesForDisplay(scopedTemplates.filter(t => t.kind === 'full'));
  const partialTemplates = sortPipeTemplatesForDisplay(
    scopedTemplates.filter(t => t.kind !== 'full')
  );
  const visibleTemplates = kindTab === 'full' ? fullTemplates : partialTemplates;
  const lowered = filter.trim().toLowerCase();
  const filtered = lowered
    ? visibleTemplates.filter(
        t =>
          t.name.toLowerCase().includes(lowered) ||
          (t.description ?? '').toLowerCase().includes(lowered) ||
          (t.details ?? '').toLowerCase().includes(lowered) ||
          (t.tags ?? []).some(tag => tag.toLowerCase().includes(lowered))
      )
    : visibleTemplates;

  const handleDelete = async (tpl: PipeTemplate) => {
    setDeletingId(tpl.id);
    try {
      await remove(tpl.id);
      if (expandedId === tpl.id) setExpandedId(null);
    } finally {
      setDeletingId(null);
    }
  };

  const handleImportClick = () => {
    setImportError(null);
    fileInputRef.current?.click();
  };

  const handleImportFile = async (file: File) => {
    setImporting(true);
    setImportError(null);
    try {
      const text = await file.text();
      let payload: unknown;
      try {
        payload = JSON.parse(text);
      } catch {
        throw new Error('File is not valid JSON');
      }
      await importTemplate(payload);
    } catch (e: any) {
      setImportError(e?.message ?? 'Import failed');
    } finally {
      setImporting(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  return (
    <div className="card shadow-sm mb-0 surface-fullpage-panel">
      <div className="card-header d-flex align-items-center justify-content-between">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-layer-group me-2" />
          Surface Templates
        </h6>
        <div className="d-flex gap-1">
          <button
            type="button"
            className="btn btn-sm btn-outline-secondary"
            onClick={handleImportClick}
            disabled={importing}
            title="Import a Surface Template JSON file"
          >
            {importing ? (
              <span className="spinner-border spinner-border-sm" />
            ) : (
              <i className="fas fa-file-import" />
            )}
          </button>
          <button
            type="button"
            className="btn btn-sm btn-outline-secondary"
            onClick={() => void handleRefresh()}
            disabled={refreshing}
            title="Reload templates"
          >
            <i className={`fas fa-rotate-right${refreshing ? ' fa-spin' : ''}`} />
          </button>
        </div>
      </div>
      <input
        ref={fileInputRef}
        type="file"
        accept="application/json,.json"
        style={{ display: 'none' }}
        onChange={e => {
          const f = e.target.files?.[0];
          if (f) void handleImportFile(f);
        }}
      />
      <div className="card-body surface-fullpage-panel__body">
        <ul className="nav nav-tabs surface-fullpage-panel__tabs mb-2" role="tablist">
          <li className="nav-item" role="presentation">
            <button
              type="button"
              className={`nav-link ${kindTab === 'partial' ? 'active' : ''}`}
              role="tab"
              aria-selected={kindTab === 'partial'}
              onClick={() => {
                setKindTab('partial');
                setExpandedId(null);
              }}
            >
              Partials
              <Badge value={partialTemplates.length} tone="secondary" size="sm" className="ms-2" />
            </button>
          </li>
          <li className="nav-item" role="presentation">
            <button
              type="button"
              className={`nav-link ${kindTab === 'full' ? 'active' : ''}`}
              role="tab"
              aria-selected={kindTab === 'full'}
              onClick={() => {
                setKindTab('full');
                setExpandedId(null);
              }}
            >
              Full Surfaces
              <Badge value={fullTemplates.length} tone="secondary" size="sm" className="ms-2" />
            </button>
          </li>
        </ul>
        <input
          type="search"
          className="form-control form-control-sm mb-3"
          placeholder="Search templates…"
          value={filter}
          onChange={e => setFilter(e.target.value)}
        />

        {loading && !refreshing && (
          <div className="text-muted small d-flex align-items-center">
            <span className="spinner-border spinner-border-sm me-2" />
            Loading templates…
          </div>
        )}

        {error && (
          <div className="alert alert-danger py-2 px-3 small mb-2">
            <i className="fas fa-times-circle me-1" />
            {error}
          </div>
        )}

        {importError && (
          <div className="alert alert-danger py-2 px-3 small mb-2">
            <i className="fas fa-times-circle me-1" />
            Import failed: {importError}
          </div>
        )}

        {!loading && !error && filtered.length === 0 && (
          <div className="text-muted small">No templates match.</div>
        )}

        <ul className="list-unstyled mb-0">
          {filtered.map(tpl => (
            <PipeTemplateRow
              key={tpl.id}
              template={tpl}
              expanded={expandedId === tpl.id}
              deleting={deletingId === tpl.id}
              onToggle={() => setExpandedId(prev => (prev === tpl.id ? null : tpl.id))}
              onApply={() => onApplyTemplate(tpl)}
              onEdit={() => setEditing(tpl)}
              onDelete={() => void handleDelete(tpl)}
            />
          ))}
        </ul>
      </div>
    </div>
  );
};

interface PipeTemplateRowProps {
  template: PipeTemplate;
  expanded: boolean;
  deleting: boolean;
  onToggle: () => void;
  onApply: () => void;
  onEdit: () => void;
  onDelete: () => void;
}

const PipeTemplateRow: React.FC<PipeTemplateRowProps> = ({
  template,
  expanded,
  deleting,
  onToggle,
  onApply,
  onEdit,
  onDelete,
}) => {
  const icon = template.icon ? `fa-${template.icon}` : 'fa-diagram-project';
  const editable = !template.builtin;
  return (
    <li className="surface-template-row">
      <div
        className="surface-template-row__header"
        role="button"
        tabIndex={0}
        aria-expanded={expanded}
        onClick={onToggle}
        onKeyDown={e => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            onToggle();
          }
        }}
      >
        <i className={`fas ${icon} surface-template-row__icon`} />
        <div className="flex-grow-1" style={{ minWidth: 0 }}>
          <div className="surface-template-row__title text-truncate">{template.name}</div>
          {template.description && (
            <div className="surface-template-row__description">{template.description}</div>
          )}
        </div>
        <div className="surface-template-row__meta">
          {template.kind === 'partial' && (
            <span
              className="badge text-bg-warning text-dark"
              title="Adds elements to the current Surface"
            >
              partial
            </span>
          )}
          {template.builtin ? (
            <span className="badge text-bg-secondary" title="Shipped with Agent Stream">
              system
            </span>
          ) : (
            <span className="badge text-bg-info" title="User-authored template">
              custom
            </span>
          )}
          {editable && (
            <>
              <button
                type="button"
                className="btn btn-sm btn-outline-secondary surface-template-row__action"
                title="Edit template"
                aria-label="Edit template"
                disabled={deleting}
                onClick={e => {
                  e.stopPropagation();
                  onEdit();
                }}
              >
                <i className="fas fa-pen" />
              </button>
              <span onClick={e => e.stopPropagation()} onKeyDown={e => e.stopPropagation()}>
                <DeleteButton
                  onDelete={onDelete}
                  disabled={deleting}
                  variant="danger"
                  size="sm"
                  className="surface-template-row__action"
                  title="Delete template"
                />
              </span>
            </>
          )}
          <button
            type="button"
            className="btn btn-sm btn-primary surface-template-row__action"
            title="Apply this template to the current Surface"
            aria-label="Apply this template to the current Surface"
            onClick={e => {
              e.stopPropagation();
              onApply();
            }}
          >
            <i className="fas fa-arrow-right" />
          </button>
          <i
            className={`fas fa-chevron-${expanded ? 'up' : 'down'} text-muted`}
            style={{ fontSize: 11 }}
          />
        </div>
      </div>

      {expanded && (
        <div className="surface-template-row__body">
          {template.details ? (
            <div className="surface-template-row__details">{template.details}</div>
          ) : (
            <div className="text-muted small fst-italic">No additional details.</div>
          )}
        </div>
      )}
    </li>
  );
};

export default PipeTemplatesPanel;
