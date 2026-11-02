/**
 * Common toaster utility for displaying notifications across the application
 */
import { UI_COLORS } from './uiPalette';

export type ToastType = 'success' | 'error' | 'warning' | 'info' | 'loading';

export interface ToastAction {
  label: string;
  onClick: () => void;
}

export interface ToastOptions {
  autoRemove?: boolean;
  duration?: number; // in milliseconds
  /** Optional inline action rendered as a link inside the toast body. */
  action?: ToastAction;
}

const element = <K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  cssText?: string
): HTMLElementTagNameMap[K] => {
  const node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  if (cssText) {
    node.style.cssText = cssText;
  }
  return node;
};

export const showToast = (
  type: ToastType,
  text: string,
  options: ToastOptions = { autoRemove: true, duration: 3000 }
) => {
  // Remove any existing toast
  const existingToast = document.getElementById('app-toast');
  if (existingToast) {
    existingToast.remove();
  }

  // Create new toast element
  const toast = document.createElement('div');
  toast.id = 'app-toast';

  // Set class based on type
  let alertClass = 'alert-info'; // Default for loading
  let borderColor: string = UI_COLORS.primary;
  let icon = 'fa-spinner fa-spin';
  let label = 'Loading...';

  if (type === 'success') {
    alertClass = 'alert-success';
    borderColor = UI_COLORS.success;
    icon = 'fa-check-circle';
    label = 'Success!';
  } else if (type === 'error') {
    alertClass = 'alert-danger';
    borderColor = UI_COLORS.danger;
    icon = 'fa-exclamation-circle';
    label = 'Error!';
  } else if (type === 'warning') {
    alertClass = 'alert-warning';
    borderColor = UI_COLORS.warning;
    icon = 'fa-triangle-exclamation';
    label = 'Heads up';
  } else if (type === 'info') {
    alertClass = 'alert-info';
    borderColor = UI_COLORS.primary;
    icon = 'fa-circle-info';
    label = 'Info';
  }

  const isDark = document.body.classList.contains('dark-theme');
  const bgColor = isDark ? 'rgba(15, 23, 42, 0.85)' : 'rgba(255, 255, 255, 0.95)';
  const borderRing = isDark
    ? '1px solid rgba(255, 255, 255, 0.08)'
    : '1px solid rgba(0, 0, 0, 0.06)';
  const textColor = isDark ? '#f1f5f9' : 'inherit';
  const closeColor = isDark ? '#94a3b8' : UI_COLORS.neutralMuted;

  // Built with DOM APIs so caller text (often a server error message or a
  // resource name) is only ever set as textContent, never parsed as HTML.
  const alert = element(
    'div',
    `alert ${alertClass} alert-dismissible fade show`,
    `position: fixed; top: 20px; right: 20px; z-index: 9999; min-width: 350px; max-width: 500px;
     border-left: 4px solid ${borderColor}; border-top: ${borderRing}; border-right: ${borderRing};
     border-bottom: ${borderRing}; box-shadow: 0 4px 15px rgba(0,0,0,0.2);
     backdrop-filter: blur(10px); background: ${bgColor}; color: ${textColor};`
  );

  const row = element('div', 'd-flex align-items-center');
  const iconWrap = element('div', 'me-3');
  iconWrap.append(element('i', `fas ${icon}`, `font-size: 1.2em; color: ${borderColor};`));

  const body = element('div', 'flex-grow-1');
  const title = element('strong');
  title.textContent = label;
  const message = element('span', undefined, 'font-size: 0.9em;');
  message.textContent = text;
  body.append(title, element('br'), message);

  // Attach via mousedown as well as click so the action fires before any
  // auto-remove timer or focus-loss handler can swallow the click.
  if (options.action) {
    const action = options.action;
    const actionWrap = element('div', undefined, 'margin-top: 6px;');
    const link = element(
      'a',
      undefined,
      `font-size: 0.9em; color: ${borderColor}; font-weight: 600; text-decoration: underline;
       cursor: pointer; position: relative; z-index: 1100;`
    );
    link.id = 'app-toast-action';
    link.href = '#';
    link.textContent = action.label;
    const fire = (e: Event) => {
      e.preventDefault();
      e.stopPropagation();
      try {
        action.onClick();
      } finally {
        toast.remove();
      }
    };
    link.addEventListener('click', fire);
    link.addEventListener('mousedown', fire);
    actionWrap.append(link);
    body.append(actionWrap);
  }

  row.append(iconWrap, body);

  const close = element(
    'button',
    'close',
    'position: absolute; top: 10px; right: 15px; z-index: 1000; background: transparent; border: none;'
  );
  close.type = 'button';
  close.title = 'Close notification';
  close.addEventListener('click', () => toast.remove());
  const closeGlyph = element('span', undefined, `font-size: 1.2em; color: ${closeColor};`);
  closeGlyph.textContent = '×';
  close.append(closeGlyph);

  alert.append(row, close);
  toast.append(alert);
  document.body.appendChild(toast);

  // Auto-remove with different timers based on type and options
  if (options.autoRemove && type !== 'loading') {
    const duration = type === 'error' ? options.duration || 5000 : options.duration || 3000;
    setTimeout(() => toast.remove(), duration);
  }
};

export const removeToast = () => {
  document.getElementById('app-toast')?.remove();
};
