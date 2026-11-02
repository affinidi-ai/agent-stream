import React, { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';

interface HelpBalloonProps {
  anchorRect: DOMRect;
  title?: string;
  bodyHtml: string;
  onClose: () => void;
}

const BALLOON_WIDTH = 320;
const GAP = 14;

/**
 * Balloon that floats to the right of a palette item, with a small tail
 * pointing left at the anchor. Position is recomputed against window size
 * so the balloon stays on-screen even when the anchor sits near the right
 * edge (in which case it flips to the left of the anchor).
 */
const HelpBalloon: React.FC<HelpBalloonProps> = ({ anchorRect, title, bodyHtml, onClose }) => {
  const ref = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState<{ left: number; top: number; flipped: boolean }>(() => {
    const wantLeft = anchorRect.right + GAP;
    const flipped = wantLeft + BALLOON_WIDTH > window.innerWidth - 8;
    const left = flipped ? anchorRect.left - GAP - BALLOON_WIDTH : wantLeft;
    return { left, top: anchorRect.top + anchorRect.height / 2, flipped };
  });

  // Click anywhere outside the balloon dismisses it. Uses capture phase
  // so d3-drag (which calls stopPropagation on mousedown for canvas
  // nodes) can't swallow the event before we see it. Clicks on a
  // palette item are excluded — the palette owns the open/close
  // toggle for those (clicking the same item closes; clicking another
  // opens). Drag start anywhere on the page also dismisses, so the
  // balloon doesn't linger while the user is dragging an element onto
  // the canvas.
  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      if (!ref.current) return;
      if (ref.current.contains(e.target as Node)) return;
      const target = e.target as Element | null;
      if (target && target.closest && target.closest('.palette-item')) return;
      onClose();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    const onDrag = () => onClose();
    document.addEventListener('mousedown', onDoc, true);
    document.addEventListener('keydown', onKey);
    document.addEventListener('dragstart', onDrag, true);
    return () => {
      document.removeEventListener('mousedown', onDoc, true);
      document.removeEventListener('keydown', onKey);
      document.removeEventListener('dragstart', onDrag, true);
    };
  }, [onClose]);

  // Re-pin if the window resizes while open.
  useEffect(() => {
    const onResize = () => {
      const wantLeft = anchorRect.right + GAP;
      const flipped = wantLeft + BALLOON_WIDTH > window.innerWidth - 8;
      const left = flipped ? anchorRect.left - GAP - BALLOON_WIDTH : wantLeft;
      setPos({ left, top: anchorRect.top + anchorRect.height / 2, flipped });
    };
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, [anchorRect]);

  return createPortal(
    <div
      ref={ref}
      className={`surface-help-balloon ${pos.flipped ? 'surface-help-balloon--left' : ''}`}
      style={{
        position: 'fixed',
        left: pos.left,
        top: pos.top,
        width: BALLOON_WIDTH,
        transform: 'translateY(-50%)',
        zIndex: 1100,
      }}
      role="tooltip"
    >
      <button
        type="button"
        className="surface-help-balloon__close"
        aria-label="Dismiss"
        onClick={onClose}
      >
        <i className="fas fa-times" />
      </button>
      {title && (
        <div className="surface-help-balloon__title">
          <i className="fas fa-info-circle me-2" />
          {title}
        </div>
      )}
      <div
        className="surface-help-balloon__body"
        // Hardcoded help content from the element registry — safe.
        dangerouslySetInnerHTML={{ __html: bodyHtml }}
      />
      <span className="surface-help-balloon__tail" />
    </div>,
    document.body
  );
};

export default HelpBalloon;
