import React, { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';

interface LoadingOverlayProps {
  /** When true the overlay fades in; when false it fades out (after the minimum). */
  active: boolean;
  /** Minimum time the overlay stays visible once shown, so a quick refetch doesn't flash. */
  minVisibleMs?: number;
  /** Accessible label for the spinner. */
  label?: string;
  /**
   * `panel` (default): a soft translucent scrim centered in its container.
   * `page`: paints the page background colour and pins the spinner to the
   * viewport centre so it stays visible no matter where the tall region is
   * scrolled. Used by the dashboard chart grid.
   */
  variant?: 'panel' | 'page';
}

/**
 * Soft, centered loading overlay. Fades in when `active` turns true and fades
 * out once it clears, but stays visible for at least `minVisibleMs` so a quick
 * window/resolution change doesn't flash. Sits over a `position: relative`
 * container and masks the content swap underneath instead of blanking it.
 */
const LoadingOverlay: React.FC<LoadingOverlayProps> = ({
  active,
  minVisibleMs = 500,
  label = 'Loading…',
  variant = 'panel',
}) => {
  const [visible, setVisible] = useState(active);
  const shownAtRef = useRef(0);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const clearTimer = () => {
      if (timerRef.current) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
    };
    if (active) {
      clearTimer();
      if (!visible) {
        shownAtRef.current = Date.now();
        setVisible(true);
      }
    } else if (visible && !timerRef.current) {
      const remaining = Math.max(0, minVisibleMs - (Date.now() - shownAtRef.current));
      timerRef.current = setTimeout(() => {
        timerRef.current = null;
        setVisible(false);
      }, remaining);
    }
    return clearTimer;
  }, [active, visible, minVisibleMs]);

  const isPage = variant === 'page';

  // Fade in fast so the scrim is established before the (often sub-second) data
  // swap shows through, then fade out slowly for a gentle reveal. Symmetric
  // timing let a quick API response render the new data mid fade-in.
  const fade = visible ? 'opacity 0.12s ease-out' : 'opacity 0.5s ease-in-out';

  const spinner = (
    <div
      className="usage-loading-overlay__spinner spinner-border"
      role="status"
      style={{ width: '3rem', height: '3rem' }}
    >
      <span className="visually-hidden">{label}</span>
    </div>
  );

  if (isPage) {
    // The scrim dulls the charts in place; the spinner is fixed to the viewport
    // centre so it stays visible no matter where the tall grid is scrolled. The
    // spinner is portaled to <body> so any transformed/animated page-wrapper
    // ancestor (which would otherwise become the containing block for a fixed
    // child and pin it to that box) can't pull it off the viewport centre.
    return (
      <>
        <div
          className="usage-loading-overlay usage-loading-overlay--page"
          aria-hidden={!visible}
          style={{
            position: 'absolute',
            inset: 0,
            opacity: visible ? 1 : 0,
            transition: fade,
            pointerEvents: visible ? 'auto' : 'none',
            zIndex: 20,
            borderRadius: 'inherit',
          }}
        />
        {typeof document !== 'undefined' &&
          createPortal(
            <div
              aria-hidden={!visible}
              style={{
                position: 'fixed',
                inset: 0,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                opacity: visible ? 1 : 0,
                transition: fade,
                pointerEvents: 'none',
                zIndex: 1080,
              }}
            >
              {spinner}
            </div>,
            document.body
          )}
      </>
    );
  }

  return (
    <div
      className="usage-loading-overlay"
      aria-hidden={!visible}
      style={{
        position: 'absolute',
        inset: 0,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        backdropFilter: 'blur(1px)',
        WebkitBackdropFilter: 'blur(1px)',
        opacity: visible ? 1 : 0,
        transition: fade,
        pointerEvents: visible ? 'auto' : 'none',
        zIndex: 20,
        borderRadius: 'inherit',
      }}
    >
      {spinner}
    </div>
  );
};

export default LoadingOverlay;
