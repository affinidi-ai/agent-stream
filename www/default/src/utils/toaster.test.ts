import { removeToast, showToast } from './toaster';

const PAYLOAD =
  '<img src=x onerror=alert(1)><svg onload=alert(1)></svg><a href="javascript:alert(1)">x</a><script>alert(1)</script>';

const INJECTED = 'img, svg, script, [onerror], [onload], a:not(#app-toast-action)';

const toast = () => document.getElementById('app-toast');

describe('showToast', () => {
  afterEach(() => {
    removeToast();
    jest.useRealTimers();
  });

  it('shows the message as text, never as markup', () => {
    showToast('error', PAYLOAD);

    expect(toast()).toHaveTextContent(PAYLOAD);
    expect(toast()?.querySelector(INJECTED)).toBeNull();
  });

  it('shows the action label as text, and runs the action then closes the toast', () => {
    const onClick = jest.fn();
    showToast('error', 'Save blocked', { action: { label: PAYLOAD, onClick } });

    const link = document.getElementById('app-toast-action');
    expect(link).toHaveTextContent(PAYLOAD);
    expect(link).toHaveAttribute('href', '#');
    expect(toast()?.querySelector(INJECTED)).toBeNull();

    link?.click();
    expect(onClick).toHaveBeenCalledTimes(1);
    expect(toast()).toBeNull();
  });

  it('closes from its close button without an inline handler', () => {
    showToast('info', 'Saved');

    const close = toast()?.querySelector('button');
    expect(close).toHaveAttribute('title', 'Close notification');
    expect(close).not.toHaveAttribute('onclick');

    close?.click();
    expect(toast()).toBeNull();
  });

  it('labels the toast and styles it for its type', () => {
    for (const [type, label, alertClass] of [
      ['success', 'Success!', 'alert-success'],
      ['error', 'Error!', 'alert-danger'],
      ['warning', 'Heads up', 'alert-warning'],
      ['info', 'Info', 'alert-info'],
      ['loading', 'Loading...', 'alert-info'],
    ] as const) {
      showToast(type, 'message');
      expect(toast()?.querySelector('strong')).toHaveTextContent(label);
      expect(toast()?.querySelector('.alert')).toHaveClass(alertClass);
    }
  });

  it('replaces the previous toast and removes itself after its duration', () => {
    jest.useFakeTimers();
    showToast('success', 'first');
    showToast('success', 'second', { autoRemove: true, duration: 1000 });

    expect(document.querySelectorAll('#app-toast')).toHaveLength(1);
    expect(toast()).toHaveTextContent('second');

    jest.advanceTimersByTime(1000);
    expect(toast()).toBeNull();
  });

  it('is not closed early by the timer of the toast it replaced', () => {
    jest.useFakeTimers();
    showToast('success', 'Saved', { autoRemove: true, duration: 2000 });
    jest.advanceTimersByTime(1500);
    showToast('error', 'Save failed', { autoRemove: true, duration: 5000 });

    jest.advanceTimersByTime(500);
    expect(toast()).toHaveTextContent('Save failed');

    jest.advanceTimersByTime(4500);
    expect(toast()).toBeNull();
  });
});
