import { normalizeDomain } from '../DomainListEditor';

describe('normalizeDomain', () => {
  it('reduces a pasted URL to its bare host', () => {
    expect(normalizeDomain('https://docs.example.com/page?x=1#h')).toBe('docs.example.com');
    expect(normalizeDomain('http://host:8080/path')).toBe('host');
  });

  it('lowercases and trims', () => {
    expect(normalizeDomain('  Example.COM  ')).toBe('example.com');
  });

  it('passes a bare domain through', () => {
    expect(normalizeDomain('example.com')).toBe('example.com');
  });

  it('returns empty for blank input', () => {
    expect(normalizeDomain('')).toBe('');
    expect(normalizeDomain('   ')).toBe('');
  });
});
