import React from 'react';
import { useSidebarResize } from './hooks/useSidebarResize';

/** A selectable view in the pipe shell's left sidebar. */
export interface PipeShellView {
  key: string;
  label: string;
  /** FontAwesome icon id without the `fa-` prefix. */
  icon: string;
  /** Hide the view entirely (e.g. edit-only views on a new pipe). */
  available?: boolean;
  /** Optional badge / indicator rendered at the end of the row. */
  badge?: React.ReactNode;
  /**
   * When set, the row renders a trailing × that closes the view. Used by
   * transient tabs (e.g. a node's full-page editor) that appear in the
   * left cluster only while open and disappear once closed.
   */
  onClose?: () => void;
}

export interface PipeFormShellProps {
  /** Title shown in the sidebar header. */
  pipeName: string;
  /** Optional badges rendered next to the title (enabled / provider …). */
  headerBadges?: React.ReactNode;
  views: PipeShellView[];
  activeView: string;
  onSelectView: (key: string) => void;
  /** Which view key shows the always-mounted canvas. */
  canvasViewKey: string;
  /**
   * The canvas node. Rendered once and shown / hidden via CSS so its
   * internal d3 layout survives view switches.
   */
  canvas: React.ReactNode;
  /**
   * Optional overlay rendered on top of the canvas (e.g. a welcome
   * callout). Mounted only while the canvas view is active.
   */
  canvasOverlay?: React.ReactNode;
  /** Content for the active non-canvas view. */
  children?: React.ReactNode;
  /**
   * Page-specific Save / Delete buttons rendered as a 'Manage' section
   * at the bottom of the sidebar.
   */
  manageActions?: React.ReactNode;
  /**
   * Invoked by the inline [+] affordance next to the row whose key
   * matches `templateViewKey`. Used to jump straight into "save current
   * pipe as a template".
   */
  onCreateTemplate?: () => void;
  /** Row key that gets the inline [+] create-template affordance. */
  templateViewKey?: string;
  /** Optional banner rendered above the main column. */
  topBanner?: React.ReactNode;
  /**
   * Optional element palette rendered as a 'Palette' sidebar section
   * below the Views list. Mirrors the surface shell so users can drag
   * optional pipe elements onto the canvas.
   */
  paletteSlot?: React.ReactNode;
}

const SIDEBAR_WIDTH_KEY = 'pipe-builder-sidebar-width';
const SIDEBAR_MIN = 220;
const SIDEBAR_MAX = 480;

/**
 * Lean layout shell for the pipe editor. Reuses the surface builder's
 * sidebar CSS (`.surface-form-shell` / `.surface-form-sidebar` …) so the
 * two editors share one visual language: a collapsible, resizable left
 * sidebar of vertical view tabs plus a Manage section, and a single main
 * column that hosts the canvas and the active view.
 */
const PipeFormShell: React.FC<PipeFormShellProps> = ({
  pipeName,
  headerBadges,
  views,
  activeView,
  onSelectView,
  canvasViewKey,
  canvas,
  canvasOverlay,
  children,
  manageActions,
  onCreateTemplate,
  templateViewKey,
  topBanner,
  paletteSlot,
}) => {
  const [sidebarCollapsed, setSidebarCollapsed] = React.useState(false);
  const { sidebarWidth, isResizingSidebar, handleSidebarResizeStart } = useSidebarResize(
    SIDEBAR_WIDTH_KEY,
    { min: SIDEBAR_MIN, max: SIDEBAR_MAX, defaultWidth: 260 }
  );

  const visibleViews = views.filter(v => v.available !== false);

  return (
    <div className="card shadow mb-4 channel-editor-card">
      <div className="card-body p-0">
        <div
          className={`surface-form-shell${sidebarCollapsed ? ' sidebar-collapsed' : ''}`}
          style={
            !sidebarCollapsed
              ? ({
                  gridTemplateColumns: `${sidebarWidth}px minmax(0, 1fr)`,
                } as React.CSSProperties)
              : undefined
          }
        >
          <aside className="surface-form-sidebar">
            {!sidebarCollapsed && (
              <div
                className={`surface-form-sidebar-resize${isResizingSidebar ? ' active' : ''}`}
                onMouseDown={handleSidebarResizeStart}
                title="Drag to resize"
              />
            )}
            <div className="surface-form-sidebar-toolbar">
              <button
                type="button"
                className="surface-form-sidebar-iconbtn"
                onClick={() => setSidebarCollapsed(c => !c)}
                title={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
              >
                <i className={`fas fa-chevron-${sidebarCollapsed ? 'right' : 'left'}`} />
              </button>
              {!sidebarCollapsed && (
                <span className="surface-form-sidebar-title" title={pipeName || 'Pipe'}>
                  {pipeName || 'Pipe'}
                  {headerBadges}
                </span>
              )}
            </div>
            {!sidebarCollapsed && (
              <>
                <div className="surface-form-sidebar-scroll">
                  <div className="surface-form-sidebar-section">
                    <div className="surface-form-sidebar-heading">Views</div>
                    {visibleViews.map(v => (
                      <div
                        key={v.key}
                        className={`surface-form-sidebar-item${activeView === v.key ? ' active' : ''}`}
                        style={{ display: 'flex', alignItems: 'center' }}
                      >
                        <button
                          type="button"
                          className="surface-form-sidebar-item-main"
                          onClick={() => onSelectView(v.key)}
                          style={{
                            flex: 1,
                            display: 'flex',
                            alignItems: 'center',
                            background: 'transparent',
                            border: 0,
                            padding: 0,
                            color: 'inherit',
                            minWidth: 0,
                          }}
                        >
                          <i className={`fas fa-${v.icon} me-2`} />
                          <span>{v.label}</span>
                          {v.badge && <span className="ms-auto">{v.badge}</span>}
                        </button>
                        {templateViewKey && v.key === templateViewKey && onCreateTemplate && (
                          <button
                            type="button"
                            className="surface-form-sidebar-inline-action"
                            title="Save current pipe as a template"
                            onClick={e => {
                              e.stopPropagation();
                              onCreateTemplate();
                            }}
                            style={{
                              background: 'transparent',
                              border: 0,
                              color: 'inherit',
                              opacity: 0.7,
                              padding: '0 4px',
                              marginLeft: 6,
                            }}
                          >
                            <i className="fas fa-plus" />
                          </button>
                        )}
                        {v.onClose && (
                          <button
                            type="button"
                            className="surface-form-sidebar-inline-action"
                            title={`Close ${v.label}`}
                            aria-label={`Close ${v.label}`}
                            onClick={e => {
                              e.stopPropagation();
                              v.onClose?.();
                            }}
                            style={{
                              background: 'transparent',
                              border: 0,
                              color: 'inherit',
                              opacity: 0.7,
                              padding: '0 4px',
                              marginLeft: 6,
                            }}
                          >
                            <i className="fas fa-times" />
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                  {paletteSlot && (
                    <div className="surface-form-sidebar-section surface-form-sidebar-palette">
                      <div className="surface-form-sidebar-heading">Palette</div>
                      {paletteSlot}
                    </div>
                  )}
                </div>
                {manageActions && (
                  <div className="surface-form-sidebar-section surface-form-sidebar-manage">
                    <div className="surface-form-sidebar-heading">Manage</div>
                    {manageActions}
                  </div>
                )}
              </>
            )}
          </aside>
          <div className="surface-form-main">
            {topBanner}
            <div
              className="surface-form-canvas-wrap"
              style={activeView === canvasViewKey ? undefined : { display: 'none' }}
            >
              {canvas}
              {activeView === canvasViewKey && canvasOverlay}
            </div>
            {activeView !== canvasViewKey && children}
          </div>
        </div>
      </div>
    </div>
  );
};

export default PipeFormShell;
