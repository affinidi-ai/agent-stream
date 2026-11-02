import { escapeHtml } from './escapeHtml';

describe('escapeHtml', () => {
  it('escapes every character that can open markup or end an attribute', () => {
    expect(escapeHtml(`<img src=x onerror="a('b')"> & more`)).toBe(
      '&lt;img src=x onerror=&quot;a(&#39;b&#39;)&quot;&gt; &amp; more'
    );
  });

  it('leaves plain text as it is', () => {
    expect(escapeHtml('Surface Chat 1')).toBe('Surface Chat 1');
  });
});
