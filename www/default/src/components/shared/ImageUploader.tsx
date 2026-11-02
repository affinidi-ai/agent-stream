import React, { memo, useCallback, useRef, useState } from 'react';
import { apiClient } from '../../api';

const MAX_IMAGE_SIZE = 5 * 1024 * 1024;
const DEFAULT_ACCEPT = 'image/png,image/jpeg,image/gif,image/webp';

const resolveImageSrc = (value?: string): string => {
  if (!value) return '';
  if (/^(https?:|data:|\/)/.test(value)) return value;
  return `/${value}`;
};

interface UseImageUploadOptions {
  /** Current stored value: a relative storage path (e.g. `uploads/x.png`), an absolute path, or URL. */
  value?: string;
  /** Upload endpoint, e.g. `/api/v1/uploads/image`. */
  endpoint: string;
  /** Multipart field name. Defaults to `file`. */
  fieldName?: string;
  /** Extracts the stored path from the upload response JSON. Defaults to `data.path`. */
  extractPath?: (data: unknown) => string | undefined;
  /** Called with the new stored path after a successful upload. */
  onUploaded: (path: string) => void;
  /** Called when the value is cleared. */
  onClear?: () => void;
  accept?: string;
  testId?: string;
}

interface UseImageUpload {
  /** The image source to display (local preview during upload, otherwise the stored value). */
  shownSrc: string;
  uploading: boolean;
  error: string;
  /** Opens the native file picker. */
  triggerUpload: () => void;
  /** Clears the local preview and invokes `onClear`. */
  clear: () => void;
  /** Hidden file input element. Render it once anywhere in the tree. */
  fileInput: React.ReactElement;
}

/**
 * Headless image-upload logic shared by `ImageUploader` and by pages that want
 * to lay out the preview and controls separately. Owns the hidden file input,
 * upload request, local preview, and error state.
 */
export const useImageUpload = ({
  value,
  endpoint,
  fieldName = 'file',
  extractPath,
  onUploaded,
  onClear,
  accept = DEFAULT_ACCEPT,
  testId,
}: UseImageUploadOptions): UseImageUpload => {
  const inputRef = useRef<HTMLInputElement>(null);
  const [preview, setPreview] = useState<string>('');
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string>('');

  const shownSrc = preview || resolveImageSrc(value);

  const handleChange = useCallback(
    async (event: React.ChangeEvent<HTMLInputElement>) => {
      const file = event.target.files?.[0];
      event.target.value = '';
      if (!file) return;

      if (!file.type.startsWith('image/')) {
        setError('Please select an image file');
        return;
      }
      if (file.size > MAX_IMAGE_SIZE) {
        setError('Image size must be less than 5MB');
        return;
      }

      const reader = new FileReader();
      reader.onloadend = () => setPreview(reader.result as string);
      reader.readAsDataURL(file);

      setUploading(true);
      setError('');
      try {
        const formData = new FormData();
        formData.append(fieldName, file);
        const response = await apiClient.fetch(endpoint, { method: 'POST', body: formData });
        if (!response.ok) {
          const message = await response.text();
          throw new Error(message || 'Failed to upload image');
        }
        const data = await response.json();
        const path = extractPath ? extractPath(data) : (data as { path?: string }).path;
        if (!path) {
          throw new Error('Upload succeeded but no path was returned');
        }
        onUploaded(path);
      } catch (err) {
        setPreview('');
        setError(err instanceof Error ? err.message : 'Failed to upload image');
      } finally {
        setUploading(false);
      }
    },
    [endpoint, extractPath, fieldName, onUploaded]
  );

  const triggerUpload = useCallback(() => inputRef.current?.click(), []);

  const clear = useCallback(() => {
    setPreview('');
    setError('');
    onClear?.();
  }, [onClear]);

  const fileInput = (
    <input
      ref={inputRef}
      type="file"
      accept={accept}
      onChange={handleChange}
      disabled={uploading}
      style={{ display: 'none' }}
      data-testid={testId ? `${testId}-input` : undefined}
    />
  );

  return { shownSrc, uploading, error, triggerUpload, clear, fileInput };
};

interface ImagePreviewProps {
  src: string;
  shape?: 'circle' | 'square';
  /** Preview edge length in pixels. Defaults to 96. */
  size?: number;
  testId?: string;
}

/** Square/circular image preview with a placeholder when no source is set. */
export const ImagePreview: React.FC<ImagePreviewProps> = ({
  src,
  shape = 'square',
  size = 96,
  testId,
}) => {
  const previewStyle: React.CSSProperties = {
    width: `${size}px`,
    height: `${size}px`,
    borderRadius: shape === 'circle' ? '50%' : '0.5rem',
    objectFit: 'contain',
    border: '1px solid var(--bs-border-color, #dee2e6)',
    background: 'var(--bs-tertiary-bg, #f8f9fa)',
  };

  if (src) {
    return (
      <img
        src={src}
        alt="Upload preview"
        style={previewStyle}
        data-testid={testId ? `${testId}-preview` : undefined}
      />
    );
  }

  const placeholderStyle: React.CSSProperties = {
    ...previewStyle,
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    objectFit: undefined,
    color: 'var(--bs-secondary-color, #6c757d)',
    fontSize: `${Math.round(size / 3)}px`,
  };

  return (
    <div style={placeholderStyle} data-testid={testId ? `${testId}-placeholder` : undefined}>
      <i className="fas fa-image"></i>
    </div>
  );
};

interface ImageUploaderProps extends UseImageUploadOptions {
  shape?: 'circle' | 'square';
  /** Preview edge length in pixels. Defaults to 96. */
  previewSize?: number;
  /** Controls placement relative to the preview. Defaults to `horizontal` (controls to the right). */
  layout?: 'horizontal' | 'vertical';
  uploadLabel?: string;
  helpText?: string;
}

const ImageUploader: React.FC<ImageUploaderProps> = ({
  shape = 'square',
  previewSize = 96,
  layout = 'horizontal',
  uploadLabel = 'Upload image',
  helpText = 'Max size: 5MB. Formats: JPG, PNG, GIF, WebP',
  onClear,
  testId,
  ...uploadOptions
}) => {
  const { shownSrc, uploading, error, triggerUpload, clear, fileInput } = useImageUpload({
    ...uploadOptions,
    onClear,
    testId,
  });

  return (
    <div
      className={
        layout === 'vertical'
          ? 'd-inline-flex flex-column align-items-start gap-3'
          : 'd-flex align-items-start gap-3'
      }
      data-testid={testId}
    >
      <ImagePreview src={shownSrc} shape={shape} size={previewSize} testId={testId} />

      <div>
        {fileInput}
        <div className="d-flex gap-2">
          <button
            type="button"
            className="btn btn-sm btn-primary"
            onClick={triggerUpload}
            disabled={uploading}
            data-testid={testId ? `${testId}-button` : undefined}
          >
            <i className="fas fa-upload me-1"></i>
            {uploading ? 'Uploading…' : uploadLabel}
          </button>
          {onClear && shownSrc && !uploading && (
            <button
              type="button"
              className="btn btn-sm btn-outline-secondary"
              onClick={clear}
              data-testid={testId ? `${testId}-clear` : undefined}
            >
              <i className="fas fa-times me-1"></i>
              Remove
            </button>
          )}
        </div>
        {error ? (
          <p
            className="text-danger small mt-2 mb-0"
            data-testid={testId ? `${testId}-error` : undefined}
          >
            {error}
          </p>
        ) : (
          <p className="text-muted small mt-2 mb-0">{helpText}</p>
        )}
      </div>
    </div>
  );
};

export default memo(ImageUploader);
