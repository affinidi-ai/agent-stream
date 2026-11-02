import React, { useState, useCallback } from 'react';

interface CopyButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  text: string;
  size?: 'sm' | 'xs';
}

export const CopyButton: React.FC<CopyButtonProps> = ({
  text,
  title = 'Copy',
  className = '',
  size = 'sm',
  ...rest
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(
    (e: React.MouseEvent) => {
      e.stopPropagation();
      navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    },
    [text]
  );

  return (
    <button
      type="button"
      className={`btn btn-link btn-${size} p-0 ms-2 align-baseline border-0 ${className}`}
      onClick={handleCopy}
      title={title}
      style={{ lineHeight: 1 }}
    >
      <i
        className={`fas ${copied ? 'fa-check text-success' : 'fa-copy text-muted'}`}
        style={{ fontSize: '0.8em' }}
      ></i>
    </button>
  );
};
