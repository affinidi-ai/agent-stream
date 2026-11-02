import { mergeStreamedContent } from '../streamMerge';

describe('mergeStreamedContent', () => {
  it('appends incremental deltas (OpenAI/Anthropic shape)', () => {
    let acc = '';
    acc = mergeStreamedContent(acc, 'Hello');
    acc = mergeStreamedContent(acc, ' world');
    acc = mergeStreamedContent(acc, '!');
    expect(acc).toBe('Hello world!');
  });

  it('adopts cumulative snapshots without duplicating (Copilot/Entra shape)', () => {
    let acc = '';
    acc = mergeStreamedContent(acc, 'Hello');
    acc = mergeStreamedContent(acc, 'Hello world');
    acc = mergeStreamedContent(acc, 'Hello world, how');
    acc = mergeStreamedContent(acc, 'Hello world, how are you?');
    expect(acc).toBe('Hello world, how are you?');
  });

  it('ignores a stale/duplicate shorter snapshot', () => {
    let acc = mergeStreamedContent('', 'Hello world');
    acc = mergeStreamedContent(acc, 'Hello'); // re-sent prefix
    expect(acc).toBe('Hello world');
    acc = mergeStreamedContent(acc, 'Hello world'); // exact resend
    expect(acc).toBe('Hello world');
  });

  it('treats an empty incoming chunk as a no-op', () => {
    expect(mergeStreamedContent('abc', '')).toBe('abc');
  });

  it('takes the first chunk verbatim from an empty accumulator', () => {
    expect(mergeStreamedContent('', 'first')).toBe('first');
  });

  it('handles a cumulative stream that starts non-empty then grows', () => {
    let acc = mergeStreamedContent('', 'The');
    acc = mergeStreamedContent(acc, 'The quick');
    acc = mergeStreamedContent(acc, 'The quick brown fox');
    expect(acc).toBe('The quick brown fox');
  });
});
