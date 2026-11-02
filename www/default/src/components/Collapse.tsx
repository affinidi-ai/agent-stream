import React, { useRef, useEffect, useState } from 'react';

interface CollapseProps {
  isOpen: boolean;
  children: React.ReactNode;
  className?: string;
  id?: string;
  ariaLabelledBy?: string;
}

const Collapse: React.FC<CollapseProps> = ({
  isOpen,
  children,
  className = '',
  id,
  ariaLabelledBy,
}) => {
  const contentRef = useRef<HTMLDivElement>(null);
  const innerRef = useRef<HTMLDivElement>(null);
  const [height, setHeight] = useState<string>('0px');
  const [shouldTransition, setShouldTransition] = useState(false);

  useEffect(() => {
    if (!innerRef.current) return;

    const updateHeight = () => {
      if (isOpen) {
        const contentHeight = innerRef.current!.scrollHeight;
        setHeight(`${contentHeight}px`);
        setShouldTransition(true);
      } else {
        setHeight('0px');
        setShouldTransition(true);
      }
    };

    // Small delay to ensure DOM is ready
    const timer = setTimeout(updateHeight, 10);
    return () => clearTimeout(timer);
  }, [isOpen]);

  const outerStyle: React.CSSProperties = {
    height: height,
    overflow: 'hidden',
    transition: shouldTransition ? 'height 0.35s ease' : 'none',
  };

  return (
    // eslint-disable-next-line react/forbid-dom-props
    <div
      ref={contentRef}
      id={id}
      className={`collapse ${isOpen ? 'show' : ''} ${className}`}
      style={outerStyle}
      aria-labelledby={ariaLabelledBy}
    >
      <div ref={innerRef}>{children}</div>
    </div>
  );
};

export default Collapse;
