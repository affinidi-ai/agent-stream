import { useEffect } from 'react';

const DEFAULT_MESSAGE =
  'You have unsaved changes to this surface. Leave anyway and lose your edits?';

/**
 * Warn the user before closing / refreshing the tab while `dirty` is
 * true by attaching a `beforeunload` listener. The browser shows its
 * built-in "Leave site?" dialog.
 *
 * In-app SPA navigation cannot be intercepted globally without
 * react-router's data router, so pages render their navigation buttons
 * with `confirmDiscardIfDirty(dirty)` to surface the same prompt for
 * Cancel / Back / sidebar links they own.
 */
export function useUnsavedChangesPrompt(dirty: boolean): void {
  useEffect(() => {
    if (!dirty) return;
    const handler = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = '';
    };
    window.addEventListener('beforeunload', handler);
    return () => window.removeEventListener('beforeunload', handler);
  }, [dirty]);
}

/**
 * Helper for in-app navigation buttons. Returns true when navigation
 * should proceed, false when the user cancelled.
 */
export function confirmDiscardIfDirty(dirty: boolean, message: string = DEFAULT_MESSAGE): boolean {
  if (!dirty) return true;
  return window.confirm(message);
}
