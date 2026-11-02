import { render, screen } from '@testing-library/react';
import SandboxMarkdown from '../SandboxMarkdown';

describe('SandboxMarkdown', () => {
  it('renders headings as heading elements', () => {
    render(<SandboxMarkdown text={'# Title\n\nBody text'} />);
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('Title');
    expect(screen.getByText('Body text')).toBeInTheDocument();
  });

  it('renders bold and italic with the right tags', () => {
    render(<SandboxMarkdown text={'This is **bold** and *italic*.'} />);
    expect(screen.getByText('bold').tagName).toBe('STRONG');
    expect(screen.getByText('italic').tagName).toBe('EM');
  });

  it('renders a markdown link as a safe anchor opening in a new tab', () => {
    render(<SandboxMarkdown text={'See [the docs](https://example.com/page).'} />);
    const link = screen.getByRole('link', { name: 'the docs' });
    expect(link).toHaveAttribute('href', 'https://example.com/page');
    expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('rel', expect.stringContaining('noopener'));
  });

  it('autolinks a bare http URL', () => {
    render(<SandboxMarkdown text={'Visit https://affinidi.com now'} />);
    expect(screen.getByRole('link', { name: 'https://affinidi.com' })).toHaveAttribute(
      'href',
      'https://affinidi.com'
    );
  });

  it('does NOT create an anchor for an unsafe scheme (renders as text)', () => {
    render(<SandboxMarkdown text={'[click](javascript:alert(1))'} />);
    expect(screen.queryByRole('link')).toBeNull();
    expect(screen.getByText(/click/)).toBeInTheDocument();
  });

  it('renders inline and fenced code', () => {
    render(<SandboxMarkdown text={'Use `npm test`.\n\n```\nconst x = 1;\n```'} />);
    const inline = screen.getByText('npm test');
    expect(inline.tagName).toBe('CODE');
    expect(inline).toHaveClass('sandbox-md-code');
    expect(screen.getByText('const x = 1;').tagName).toBe('CODE');
  });

  it('renders unordered and ordered lists', () => {
    render(<SandboxMarkdown text={'- one\n- two\n\n1. first\n2. second'} />);
    expect(screen.getAllByRole('list')).toHaveLength(2);
    expect(screen.getAllByRole('listitem')).toHaveLength(4);
  });

  it('does not treat bold markers as italic', () => {
    render(<SandboxMarkdown text={'**strong only**'} />);
    expect(screen.getByText('strong only').tagName).toBe('STRONG');
  });
});
