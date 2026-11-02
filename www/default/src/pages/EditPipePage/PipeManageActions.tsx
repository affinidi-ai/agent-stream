import React from 'react';
import { DeleteButton } from '../../components/shared/DeleteButton';

interface PipeManageActionsProps {
  saving: boolean;
  isModified: boolean;
  isNew: boolean;
  onSave: () => void;
  onDelete: () => void | Promise<void>;
  onClose: () => void;
  /** Human label for the surface type, used in button tooltips. */
  entityLabel?: string;
}

/** Save / Delete / Close buttons rendered in the pipe shell's Manage section. */
export const PipeManageActions: React.FC<PipeManageActionsProps> = ({
  saving,
  isModified,
  isNew,
  onSave,
  onDelete,
  onClose,
  entityLabel = 'LLM surface',
}) => (
  <div className="d-flex gap-2">
    <button
      type="button"
      className="btn btn-secondary btn-sm"
      onClick={onClose}
      disabled={saving}
      title={`Back to ${entityLabel}s`}
    >
      <i className="fas fa-arrow-left" />
    </button>
    {isNew ? (
      <button
        type="button"
        className="btn btn-success btn-sm"
        onClick={onSave}
        disabled={saving}
        title={saving ? 'Creating…' : `Create ${entityLabel}`}
      >
        {saving ? <i className="fas fa-spinner fa-spin" /> : <i className="fas fa-check" />}
      </button>
    ) : (
      <button
        type="button"
        className="btn btn-primary btn-sm"
        onClick={onSave}
        disabled={saving || !isModified}
        title={saving ? 'Saving…' : 'Save changes'}
      >
        {saving ? <i className="fas fa-spinner fa-spin" /> : <i className="fas fa-save" />}
      </button>
    )}
    {!isNew && (
      <DeleteButton
        onDelete={onDelete}
        disabled={saving}
        size="sm"
        title={`Delete this ${entityLabel}`}
      />
    )}
  </div>
);

export default PipeManageActions;
