import React from 'react';

interface SidebarResizeOptions {
  min: number;
  max: number;
  defaultWidth: number;
}

interface SidebarResize {
  sidebarWidth: number;
  isResizingSidebar: boolean;
  handleSidebarResizeStart: (e: React.MouseEvent) => void;
}

/**
 * Drag-to-resize behaviour for a form shell's left sidebar. Persists the
 * width to `localStorage[storageKey]` and clamps it between `min` and `max`.
 */
export function useSidebarResize(storageKey: string, opts: SidebarResizeOptions): SidebarResize {
  const { min, max, defaultWidth } = opts;
  const [sidebarWidth, setSidebarWidth] = React.useState<number>(() => {
    try {
      const stored = localStorage.getItem(storageKey);
      if (stored) {
        const n = parseInt(stored, 10);
        if (Number.isFinite(n)) return Math.min(Math.max(n, min), max);
      }
    } catch {
      /* ignore */
    }
    return defaultWidth;
  });
  const sidebarWidthRef = React.useRef(sidebarWidth);
  React.useEffect(() => {
    sidebarWidthRef.current = sidebarWidth;
  }, [sidebarWidth]);
  const [isResizingSidebar, setIsResizingSidebar] = React.useState(false);

  const handleSidebarResizeStart = (e: React.MouseEvent) => {
    e.preventDefault();
    setIsResizingSidebar(true);
    const startX = e.clientX;
    const startWidth = sidebarWidthRef.current;
    const onMove = (ev: MouseEvent) => {
      const delta = ev.clientX - startX;
      setSidebarWidth(Math.min(Math.max(startWidth + delta, min), max));
    };
    const onUp = () => {
      setIsResizingSidebar(false);
      try {
        localStorage.setItem(storageKey, String(sidebarWidthRef.current));
      } catch {
        /* ignore */
      }
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
    };
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  };

  return { sidebarWidth, isResizingSidebar, handleSidebarResizeStart };
}
