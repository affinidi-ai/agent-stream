import React from 'react';

interface AccessTokenEditHeaderProps {
  title: string;
  subtitle: string;
  onBack: () => void;
  backDisabled?: boolean;
  onSave?: () => void;
  saving?: boolean;
  saveDisabled?: boolean;
}

/** Back button + title/subtitle + optional Save action, matching the Secret editor. */
const AccessTokenEditHeader: React.FC<AccessTokenEditHeaderProps> = ({
  title,
  subtitle,
  onBack,
  backDisabled,
  onSave,
  saving,
  saveDisabled,
}) => (
  <>
    <div className="mb-3">
      <button
        className="btn btn-sm btn-secondary"
        onClick={onBack}
        disabled={backDisabled}
        type="button"
        data-testid="access-token-back-button"
      >
        <i className="fas fa-arrow-left" aria-hidden="true" />
      </button>
    </div>
    <div className="d-sm-flex align-items-center justify-content-between mb-4">
      <div>
        <h1 className="h3 mb-0 text-gray-800">
          <i className="fas fa-key me-2" aria-hidden="true" />
          {title}
        </h1>
        <p className="text-muted mt-2">{subtitle}</p>
      </div>
      {onSave && (
        <div>
          <button
            className="btn btn-sm btn-primary me-2"
            onClick={onSave}
            disabled={saveDisabled}
            type="button"
            data-testid="access-token-save-button"
          >
            {saving ? (
              <>
                <span
                  className="spinner-border spinner-border-sm me-1"
                  role="status"
                  aria-hidden="true"
                ></span>
                Saving...
              </>
            ) : (
              <>
                <i className="fas fa-save me-1" aria-hidden="true" />
                Save
              </>
            )}
          </button>
        </div>
      )}
    </div>
  </>
);

export default AccessTokenEditHeader;
