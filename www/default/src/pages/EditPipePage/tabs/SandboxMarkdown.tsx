import React from 'react';

/**
 * Minimal, dependency-free, XSS-safe Markdown renderer for the sandbox chat.
 *
 * LLM answers are Markdown; rendering them as plain text loses headings, bold,
 * lists, code, and links. This renders a pragmatic Markdown subset into **React
 * elements** (never `dangerouslySetInnerHTML`), so all text is auto-escaped by
 * React and links are scheme-validated — a model can't inject markup or a
 * `javascript:` URL. It degrades gracefully on partial Markdown (mid-stream),
 * leaving an unclosed token as literal text until its delimiter arrives.
 *
 * Supported: headings (`#`..`######`), bold (`**`/`__`), italic (`*`/`_`),
 * inline code (`` ` ``), fenced code blocks (```` ``` ````), unordered/ordered
 * lists, blockquotes, horizontal rules, `[text](url)` links, and bare
 * http(s)/www URLs. Anything else renders as text.
 */

type Node = React.ReactNode;

// Only these schemes may become a real anchor; everything else renders as text.
const SAFE_SCHEME = /^(https?:|mailto:)/i;

function safeHref(url: string): string | null {
  const trimmed = url.trim();
  if (SAFE_SCHEME.test(trimmed)) return trimmed;
  if (/^www\./i.test(trimmed)) return `https://${trimmed}`;
  return null;
}

function link(text: Node, url: string, key: number): Node {
  const href = safeHref(url);
  if (!href) return <React.Fragment key={key}>{text}</React.Fragment>;
  return (
    <a key={key} href={href} target="_blank" rel="noopener noreferrer nofollow">
      {text}
    </a>
  );
}

interface InlineRule {
  re: RegExp;
  build: (m: RegExpExecArray, key: number) => Node;
}

// Ordered by precedence: earlier rules win ties at the same position. Code is
// first (its content is literal — no nested formatting), then bold before
// italic (so `**` isn't eaten by the single-`*` rule), then links, then bare
// URLs.
const INLINE_RULES: InlineRule[] = [
  {
    re: /`([^`\n]+)`/,
    build: (m, k) => (
      <code key={k} className="sandbox-md-code">
        {m[1]}
      </code>
    ),
  },
  {
    re: /\*\*([\s\S]+?)\*\*/,
    build: (m, k) => <strong key={k}>{parseInline(m[1])}</strong>,
  },
  {
    re: /__([\s\S]+?)__/,
    build: (m, k) => <strong key={k}>{parseInline(m[1])}</strong>,
  },
  {
    re: /\[([^\]\n]+)\]\(([^)\s]+)\)/,
    build: (m, k) => link(parseInline(m[1]), m[2], k),
  },
  {
    re: /\*([^\s*][\s\S]*?)\*/,
    build: (m, k) => <em key={k}>{parseInline(m[1])}</em>,
  },
  {
    re: /_([^\s_][\s\S]*?)_/,
    build: (m, k) => <em key={k}>{parseInline(m[1])}</em>,
  },
  {
    re: /(https?:\/\/[^\s<]+[^\s<.,;:!?)])/,
    build: (m, k) => link(m[1], m[1], k),
  },
  {
    re: /(www\.[^\s<]+[^\s<.,;:!?)])/,
    build: (m, k) => link(m[1], m[1], k),
  },
];

/** Parse inline Markdown in a single text run into React nodes. */
function parseInline(text: string): Node[] {
  const out: Node[] = [];
  let rest = text;
  let key = 0;
  while (rest.length > 0) {
    let best: { rule: InlineRule; m: RegExpExecArray } | null = null;
    for (const rule of INLINE_RULES) {
      const m = rule.re.exec(rest);
      if (m && (best === null || m.index < best.m.index)) {
        best = { rule, m };
        if (m.index === 0) break; // nothing can start earlier
      }
    }
    if (!best) {
      out.push(rest);
      break;
    }
    if (best.m.index > 0) out.push(rest.slice(0, best.m.index));
    out.push(best.rule.build(best.m, key++));
    rest = rest.slice(best.m.index + best.m[0].length);
  }
  return out;
}

const HEADING = /^(#{1,6})\s+(.*)$/;
const FENCE = /^\s*```/;
const HR = /^\s*([-*_])\1{2,}\s*$/;
const QUOTE = /^\s*>\s?/;
const UL = /^\s*[-*+]\s+/;
const OL = /^\s*\d+\.\s+/;

function isBlockStart(line: string): boolean {
  return (
    HEADING.test(line) ||
    FENCE.test(line) ||
    HR.test(line) ||
    QUOTE.test(line) ||
    UL.test(line) ||
    OL.test(line)
  );
}

/** Parse block-level Markdown into React nodes. */
export function renderMarkdown(md: string): Node {
  const lines = md.replace(/\r\n?/g, '\n').split('\n');
  const blocks: Node[] = [];
  let i = 0;
  let key = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Fenced code block
    if (FENCE.test(line)) {
      i += 1;
      const buf: string[] = [];
      while (i < lines.length && !FENCE.test(lines[i])) {
        buf.push(lines[i]);
        i += 1;
      }
      i += 1; // consume closing fence (or EOF)
      blocks.push(
        <pre key={key++} className="sandbox-md-pre">
          <code>{buf.join('\n')}</code>
        </pre>
      );
      continue;
    }

    // Heading
    const h = HEADING.exec(line);
    if (h) {
      const level = h[1].length;
      const Tag = `h${level}` as keyof JSX.IntrinsicElements;
      blocks.push(
        <Tag key={key++} className={`sandbox-md-h sandbox-md-h${level}`}>
          {parseInline(h[2].trim())}
        </Tag>
      );
      i += 1;
      continue;
    }

    // Horizontal rule
    if (HR.test(line)) {
      blocks.push(<hr key={key++} className="sandbox-md-hr" />);
      i += 1;
      continue;
    }

    // Blockquote (recurse on the stripped content)
    if (QUOTE.test(line)) {
      const buf: string[] = [];
      while (i < lines.length && QUOTE.test(lines[i])) {
        buf.push(lines[i].replace(QUOTE, ''));
        i += 1;
      }
      blocks.push(
        <blockquote key={key++} className="sandbox-md-quote">
          {renderMarkdown(buf.join('\n'))}
        </blockquote>
      );
      continue;
    }

    // Unordered list
    if (UL.test(line)) {
      const items: Node[] = [];
      while (i < lines.length && UL.test(lines[i])) {
        items.push(<li key={items.length}>{parseInline(lines[i].replace(UL, ''))}</li>);
        i += 1;
      }
      blocks.push(
        <ul key={key++} className="sandbox-md-list">
          {items}
        </ul>
      );
      continue;
    }

    // Ordered list
    if (OL.test(line)) {
      const items: Node[] = [];
      while (i < lines.length && OL.test(lines[i])) {
        items.push(<li key={items.length}>{parseInline(lines[i].replace(OL, ''))}</li>);
        i += 1;
      }
      blocks.push(
        <ol key={key++} className="sandbox-md-list">
          {items}
        </ol>
      );
      continue;
    }

    // Blank line
    if (line.trim() === '') {
      i += 1;
      continue;
    }

    // Paragraph — gather consecutive non-blank, non-block lines. A single
    // newline inside a paragraph is a soft break (matches chat expectations).
    const buf: string[] = [];
    while (i < lines.length && lines[i].trim() !== '' && !isBlockStart(lines[i])) {
      buf.push(lines[i]);
      i += 1;
    }
    const para: Node[] = [];
    buf.forEach((l, idx) => {
      if (idx > 0) para.push(<br key={`br${idx}`} />);
      para.push(...parseInline(l));
    });
    blocks.push(
      <p key={key++} className="sandbox-md-p">
        {para}
      </p>
    );
  }

  return blocks;
}

/** Render a Markdown string as themed React content for a sandbox chat bubble. */
const SandboxMarkdown: React.FC<{ text: string }> = ({ text }) => (
  <div className="sandbox-md">{renderMarkdown(text)}</div>
);

export default SandboxMarkdown;
