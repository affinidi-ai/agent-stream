import React, { useCallback, useEffect, useRef, useState } from 'react';
import type { ConfigPanelProps } from '../types';
import { apiClient } from '../../../../api';
import { usePipePanelData } from './pipePanelData';
import type { LLMProviderInfo } from '../../../shared/LLMProviderSelector';
import type { Secret } from '../../../shared/SecretSelector';
import PromptGuardCard from './PromptGuardCard';
import { DEFAULT_LLM_PII, toLlmPiiList, type LlmPiiConfig } from './llmPii';
import { readGuards, type PromptGuard } from './regexGuard';

export type { LlmPiiConfig, RejectionConfig } from './llmPii';
export type { PromptGuard, RegexRule, RegexRules } from './regexGuard';

type Side = 'request' | 'response';

const newRegexGuard = (side: Side): PromptGuard => ({
  regex: { action: side === 'response' ? 'mask' : 'reject', mask_mode: 'redact', rules: [] },
  rejection: null,
});

/**
 * Full-area editor for the pipe-prompt-guard node. Each direction holds one or
 * more "Prompt Guards"; a guard first picks how it detects (Regular Expression
 * or AI Matching), then progressively reveals the detect fields and the shared
 * "When detected" action. Regex guards live in the node's `request`/`response`
 * arrays; AI detectors live in `llm_pii` (request only). Built-in pattern
 * definitions come from {@link usePipePanelData}.
 */
const PipePromptGuardFullscreenPanel: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  updateFields,
  closeFullscreenEditor,
}) => {
  const { promptGuardPatterns, llmProviders, secrets } = usePipePanelData();
  const providers = llmProviders as unknown as LLMProviderInfo[];
  const secretList = secrets as unknown as Secret[];
  const request = readGuards(config?.request);
  const response = readGuards(config?.response);
  const llmPiiList = toLlmPiiList(config?.llm_pii);
  const direction = config?.direction;
  const showRequest = direction !== 'response';
  const showResponse = direction !== 'request';

  const updateRegexGuard = (side: Side, index: number, guard: PromptGuard) => {
    const arr = side === 'request' ? request : response;
    const next = [...arr];
    next[index] = guard;
    updateField(side, next);
  };
  const removeRegexGuard = (side: Side, index: number) => {
    const arr = side === 'request' ? request : response;
    updateField(
      side,
      arr.filter((_, i) => i !== index)
    );
  };

  const writeLlmPiiList = (next: LlmPiiConfig[]) => updateField('llm_pii', next);
  const updateLlmPiiDetector = (index: number, patch: Partial<LlmPiiConfig>) =>
    writeLlmPiiList(llmPiiList.map((d, i) => (i === index ? { ...d, ...patch } : d)));
  const removeLlmPiiDetector = (index: number) =>
    writeLlmPiiList(llmPiiList.filter((_, i) => i !== index));

  // Undecided new guards live locally until the user picks a detection type.
  const [drafts, setDrafts] = useState<{ id: string; side: Side }[]>([]);
  const addDraft = (side: Side) =>
    setDrafts(d => [...d, { id: Math.random().toString(36).slice(2), side }]);
  const removeDraft = (id: string) => setDrafts(d => d.filter(x => x.id !== id));
  const commitDraft = (id: string, side: Side, type: 'regex' | 'ai') => {
    if (type === 'ai') writeLlmPiiList([...llmPiiList, { ...DEFAULT_LLM_PII }]);
    else {
      const arr = side === 'request' ? request : response;
      updateField(side, [...arr, newRegexGuard(side)]);
    }
    removeDraft(id);
  };

  // Switching a committed card's type moves it between arrays, keeping the
  // handling choice (reject / redact / NER ID) where possible.
  const changeType = (side: Side, from: 'regex' | 'ai', index: number, to: 'regex' | 'ai') => {
    if (from === to) return;
    if (from === 'regex' && to === 'ai') {
      if (side !== 'request') return;
      const g = request[index];
      const detector: LlmPiiConfig = {
        ...DEFAULT_LLM_PII,
        action: g.regex.action,
        mask_mode: g.regex.mask_mode ?? 'redact',
        rejection: g.rejection ?? null,
      };
      updateFields({
        request: request.filter((_, i) => i !== index),
        llm_pii: [...llmPiiList, detector],
      });
    } else if (from === 'ai' && to === 'regex') {
      const d = llmPiiList[index];
      const arr = side === 'request' ? request : response;
      const guard: PromptGuard = {
        regex: {
          action: d.action === 'reject' ? 'reject' : 'mask',
          mask_mode: d.mask_mode ?? 'redact',
          rules: [],
        },
        rejection: d.rejection ?? null,
      };
      updateFields({
        [side]: [...arr, guard],
        llm_pii: llmPiiList.filter((_, i) => i !== index),
      });
    }
  };

  // Process-wide detector health (successful/failed calls, error rate).
  const [llmPiiHealth, setLlmPiiHealth] = useState<{
    successful_calls: number;
    failed_calls: number;
    total_calls: number;
    error_rate: number;
  } | null>(null);
  const loadLlmPiiHealth = useCallback(async () => {
    try {
      const { data } = await apiClient.get<{
        successful_calls: number;
        failed_calls: number;
        total_calls: number;
        error_rate: number;
      }>('/prompt-guard/detector-stats');
      setLlmPiiHealth(data);
    } catch {
      setLlmPiiHealth(null);
    }
  }, []);
  const hasAi = llmPiiList.length > 0;
  useEffect(() => {
    if (hasAi) loadLlmPiiHealth();
  }, [hasAi, loadLlmPiiHealth]);

  // When an enabled guard opens with nothing configured on a visible side, seed
  // one undecided draft so the operator lands directly on "pick a detection type"
  // instead of an empty section.
  const seededRef = useRef(false);
  useEffect(() => {
    if (seededRef.current) return;
    if (config?.enabled !== true) return;
    seededRef.current = true;
    const seeds: { id: string; side: Side }[] = [];
    if (showRequest && request.length === 0 && llmPiiList.length === 0) {
      seeds.push({ id: Math.random().toString(36).slice(2), side: 'request' });
    }
    if (showResponse && response.length === 0) {
      seeds.push({ id: Math.random().toString(36).slice(2), side: 'response' });
    }
    if (seeds.length > 0) setDrafts(seeds);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const renderSide = (side: Side) => {
    const allowAi = side === 'request';
    const regexGuards = side === 'request' ? request : response;
    const aiDetectors = side === 'request' ? llmPiiList : [];
    const sideDrafts = drafts.filter(d => d.side === side);
    const total = regexGuards.length + aiDetectors.length + sideDrafts.length;
    const aiBase = regexGuards.length;
    const draftBase = regexGuards.length + aiDetectors.length;
    return (
      <div className="card shadow-sm mb-4" key={side}>
        <div className="card-header bg-light">
          <div className="d-flex justify-content-between align-items-center">
            <h6 className="m-0 font-weight-bold text-primary">
              <i
                className={`fas ${side === 'request' ? 'fa-arrow-right' : 'fa-arrow-left'} me-1`}
              ></i>{' '}
              Prompt Guard
              <small className="text-muted ms-2">
                {side === 'request'
                  ? 'Screen requests before they reach the model'
                  : 'Screen responses before they reach the caller'}
              </small>
            </h6>
            <button
              type="button"
              className="btn btn-sm btn-outline-primary"
              data-testid="prompt-guard-add"
              onClick={() => addDraft(side)}
            >
              <i className="fas fa-plus me-1"></i>Add Prompt Guard
            </button>
          </div>
        </div>
        <div className="card-body">
          {total === 0 && (
            <p className="text-muted text-center mb-0" style={{ fontSize: '13px' }}>
              No Prompt Guard yet. Click "Add Prompt Guard" and choose Regular Expression
              {allowAi ? ' or AI Matching' : ''} to create one.
            </p>
          )}
          {regexGuards.map((guard, i) => (
            <PromptGuardCard
              key={`regex-${i}`}
              displayIndex={i + 1}
              phase={side}
              allowAi={allowAi}
              type="regex"
              onChangeType={t => changeType(side, 'regex', i, t)}
              onRemove={() => removeRegexGuard(side, i)}
              patterns={promptGuardPatterns}
              llmProviders={providers}
              secrets={secretList}
              guard={guard}
              onGuardChange={g => updateRegexGuard(side, i, g)}
            />
          ))}
          {aiDetectors.map((detector, i) => (
            <PromptGuardCard
              key={`ai-${i}`}
              displayIndex={aiBase + i + 1}
              phase={side}
              allowAi={allowAi}
              type="ai"
              onChangeType={t => changeType(side, 'ai', i, t)}
              onRemove={() => removeLlmPiiDetector(i)}
              patterns={promptGuardPatterns}
              llmProviders={providers}
              secrets={secretList}
              detector={detector}
              onDetectorChange={patch => updateLlmPiiDetector(i, patch)}
              onTested={loadLlmPiiHealth}
            />
          ))}
          {sideDrafts.map((d, i) => (
            <PromptGuardCard
              key={`draft-${d.id}`}
              displayIndex={draftBase + i + 1}
              phase={side}
              allowAi={allowAi}
              type=""
              onChangeType={t => commitDraft(d.id, side, t)}
              onRemove={() => removeDraft(d.id)}
              patterns={promptGuardPatterns}
              llmProviders={providers}
              secrets={secretList}
            />
          ))}
          {allowAi && aiDetectors.length > 0 && llmPiiHealth && (
            <small
              className="form-text d-block"
              data-testid="prompt-guard-llm-pii-health"
              style={{ fontSize: '12px' }}
            >
              {llmPiiHealth.total_calls === 0 ? (
                <span className="text-muted">
                  <i className="fas fa-heartbeat me-1"></i>
                  Detector health: no calls recorded yet (since appliance start).
                </span>
              ) : (
                <span className={llmPiiHealth.failed_calls > 0 ? 'text-warning' : 'text-muted'}>
                  <i className="fas fa-heartbeat me-1"></i>
                  Detector health (since start): {llmPiiHealth.successful_calls} ok ·{' '}
                  {llmPiiHealth.failed_calls} failed · {(llmPiiHealth.error_rate * 100).toFixed(1)}%
                  error rate.
                </span>
              )}
            </small>
          )}
        </div>
      </div>
    );
  };

  return (
    <div className="pipe-prompt-guard-editor">
      {closeFullscreenEditor && (
        <div className="d-flex justify-content-end mb-3">
          <button
            type="button"
            className="btn btn-sm btn-outline-secondary"
            onClick={closeFullscreenEditor}
          >
            <i className="fas fa-times me-1"></i>
            Close tab
          </button>
        </div>
      )}
      {showRequest && renderSide('request')}
      {showResponse && renderSide('response')}
    </div>
  );
};

export default PipePromptGuardFullscreenPanel;
