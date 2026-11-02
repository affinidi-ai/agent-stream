import React from 'react';
import { type PipePromptGuardPattern } from './pipePanelData';
import type { LLMProviderInfo } from '../../../shared/LLMProviderSelector';
import type { Secret } from '../../../shared/SecretSelector';
import { type LlmPiiConfig } from './llmPii';
import { type PromptGuard } from './regexGuard';
import RegexGuardBody from './RegexGuardBody';
import AiDetectorBody from './AiDetectorBody';

export type DetectorType = '' | 'regex' | 'ai';

interface PromptGuardCardProps {
  displayIndex: number;
  phase: 'request' | 'response';
  /** Whether the AI Matching detector type is offered (request side only). */
  allowAi: boolean;
  type: DetectorType;
  onChangeType: (t: 'regex' | 'ai') => void;
  onRemove: () => void;
  patterns: PipePromptGuardPattern[];
  llmProviders: LLMProviderInfo[];
  secrets: Secret[];
  guard?: PromptGuard;
  onGuardChange?: (g: PromptGuard) => void;
  detector?: LlmPiiConfig;
  onDetectorChange?: (patch: Partial<LlmPiiConfig>) => void;
  onTested?: () => void;
}

/**
 * One "Prompt Guard": a card that first asks *how* to detect (Regular Expression
 * or AI Matching), then progressively reveals the detect fields and the shared
 * "When detected" control. A guard with no type chosen is incomplete.
 */
const PromptGuardCard: React.FC<PromptGuardCardProps> = ({
  displayIndex,
  phase,
  allowAi,
  type,
  onChangeType,
  onRemove,
  patterns,
  llmProviders,
  secrets,
  guard,
  onGuardChange,
  detector,
  onDetectorChange,
  onTested,
}) => {
  const idPrefix = `pg-${phase}-${displayIndex}`;
  return (
    <div className="card shadow-sm mb-3">
      <div className="card-header bg-light d-flex justify-content-between align-items-center py-2">
        <span className="font-weight-bold text-dark" style={{ fontSize: '14px' }}>
          <i
            className={`fas ${phase === 'request' ? 'fa-arrow-right' : 'fa-arrow-left'} me-1 text-primary`}
          ></i>
          Prompt Guard #{displayIndex}
        </span>
        <button
          type="button"
          className="btn btn-sm btn-outline-danger"
          data-testid="prompt-guard-remove"
          onClick={onRemove}
          title="Remove this Prompt Guard"
        >
          <i className="fas fa-trash-alt me-1"></i>Remove
        </button>
      </div>
      <div className="card-body">
        <div className="mb-3">
          <label className="font-weight-bold" style={{ fontSize: '13px' }}>
            Type of detection
          </label>
          <select
            className={`form-control form-control-sm dropdown-styling${type === '' ? ' is-invalid' : ''}`}
            style={{ maxWidth: '320px' }}
            data-testid="prompt-guard-type"
            value={type}
            onChange={e => onChangeType(e.target.value as 'regex' | 'ai')}
          >
            <option value="" disabled>
              Select…
            </option>
            <option value="regex">Regular Expression</option>
            {allowAi && <option value="ai">AI Matching</option>}
          </select>
          {type === '' && (
            <div className="invalid-feedback d-block" style={{ fontSize: '12px' }}>
              Choose how this Prompt Guard detects content, then configure it below.
            </div>
          )}
        </div>

        {type === 'regex' && guard && onGuardChange && (
          <RegexGuardBody
            guard={guard}
            phase={phase}
            patterns={patterns}
            idPrefix={idPrefix}
            onChange={onGuardChange}
          />
        )}

        {type === 'ai' && detector && onDetectorChange && (
          <AiDetectorBody
            detector={detector}
            llmProviders={llmProviders}
            secrets={secrets}
            idPrefix={idPrefix}
            onChange={onDetectorChange}
            onTested={onTested ?? (() => {})}
          />
        )}
      </div>
    </div>
  );
};

export default PromptGuardCard;
