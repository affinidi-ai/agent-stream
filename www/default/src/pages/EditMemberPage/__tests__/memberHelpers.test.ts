import { fromDateTimeLocal, toDateTimeLocal } from '../memberHelpers';

describe('budget period anchor input', () => {
  it('round-trips an instant through the local date/time input', () => {
    const iso = '2026-09-27T09:14:00.000Z';
    expect(fromDateTimeLocal(toDateTimeLocal(iso))).toBe(iso);
  });

  it('treats an empty input as no anchor', () => {
    expect(fromDateTimeLocal('')).toBeNull();
    expect(fromDateTimeLocal('   ')).toBeNull();
  });

  it('rejects an unparseable input rather than sending garbage', () => {
    expect(fromDateTimeLocal('not-a-date')).toBeNull();
  });

  it('renders a missing or invalid anchor as an empty input', () => {
    expect(toDateTimeLocal(null)).toBe('');
    expect(toDateTimeLocal(undefined)).toBe('');
    expect(toDateTimeLocal('garbage')).toBe('');
  });
});
