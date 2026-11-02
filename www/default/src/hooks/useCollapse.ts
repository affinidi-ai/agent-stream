import { useEffect, useRef, useState } from 'react';

export const useCollapse = (isOpen: boolean) => {
  const contentRef = useRef<HTMLDivElement>(null);
  const [height, setHeight] = useState<number | undefined>(isOpen ? undefined : 0);
  const [isTransitioning, setIsTransitioning] = useState(false);

  useEffect(() => {
    if (!contentRef.current) return;

    const updateHeight = () => {
      if (isOpen) {
        setIsTransitioning(true);
        setHeight(contentRef.current?.scrollHeight);

        const timer = setTimeout(() => {
          setHeight(undefined);
          setIsTransitioning(false);
        }, 350);

        return () => clearTimeout(timer);
      } else {
        setHeight(contentRef.current?.scrollHeight);

        requestAnimationFrame(() => {
          setIsTransitioning(true);
          setHeight(0);

          const timer = setTimeout(() => {
            setIsTransitioning(false);
          }, 350);
        });
      }
    };

    updateHeight();
  }, [isOpen]);

  const style: React.CSSProperties = {
    height: height,
    overflow: 'hidden',
    transition: isTransitioning ? 'height 0.35s ease' : 'none',
  };

  return { contentRef, style, isOpen };
};
