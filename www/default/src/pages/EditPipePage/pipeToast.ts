import { showToast, type ToastAction } from '../../utils/toaster';

/** Pipe-editor toast with type-specific durations and an optional inline action. */
export function showPipeToast(
  type: 'success' | 'error' | 'loading',
  text: string,
  action?: ToastAction
) {
  const duration = type === 'error' ? 8000 : type === 'success' ? 2000 : 10000;
  showToast(type, text, { autoRemove: type !== 'loading', duration, action });
}
