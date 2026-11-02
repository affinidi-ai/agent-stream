import React, { useState } from 'react';
import { Badge } from '../../components/shared/Badge';
import { AppButton } from '../../components/shared/AppButton';
import { formatCost, outcomeTone, shortDigest } from './governanceHelpers';
import { formatDateTime } from '../../utils/stringUtils';
import type { StoredRecord, SurfaceSummary } from './types';

interface Props {
  stored: StoredRecord | null;
  surface?: SurfaceSummary | null;
}

/** Read-only detail of one signed governance record: identity, the stage
 * transcript, the captured prompt/completion, metrics, and the raw signed VC. */
const GovernanceRecordDetail: React.FC<Props> = ({ stored, surface }) => {
  const [showVc, setShowVc] = useState(false);

  if (!stored) {
    return (
      <div className="text-center text-muted py-5" data-testid="governance-detail-empty">
        <i className="fas fa-file-shield fa-2x mb-3 d-block" aria-hidden="true"></i>
        Select a record to inspect its prompt, processing stages, and completion.
      </div>
    );
  }

  const { record } = stored;
  const name = record.surface_name ?? surface?.surface_name ?? record.surface_id;
  const description = surface?.surface_description;
  return (
    <div data-testid={`governance-detail-${record.record_id}`}>
      <div className="d-flex justify-content-between align-items-start flex-wrap gap-2 mb-3">
        <div>
          <div className="fw-bold text-gray-800">{name}</div>
          <div className="small text-muted">{formatDateTime(record.timestamp, true)}</div>
          <div className="small text-muted font-monospace">{record.record_id}</div>
        </div>
        <div className="text-end small text-muted">
          {record.metrics.provider && (
            <div>
              <i className="fas fa-server me-1" aria-hidden="true"></i>
              {record.metrics.provider} · {record.metrics.model}
            </div>
          )}
          <div>
            {record.metrics.total_tokens.toLocaleString()} tokens ·{' '}
            {formatCost(record.metrics.cost)} · {record.metrics.latency_ms} ms
          </div>
        </div>
      </div>

      <Section title="Surface">
        <KeyVal label="Name" value={name} />
        {description && <KeyVal label="Description" value={description} />}
        <KeyVal label="Surface ID" value={record.surface_id} mono />
        <KeyVal label="Recorded" value={formatDateTime(record.timestamp, true)} />
      </Section>

      <Section title="Identity & chain">
        <KeyVal label="Trace" value={record.trace_id ?? '—'} mono />
        <KeyVal label="Caller (hashed)" value={shortDigest(record.caller_identity_hash)} mono />
        <KeyVal label="Content hash" value={shortDigest(record.content_hash)} mono />
        <KeyVal label="Previous hash" value={shortDigest(record.prev_record_hash)} mono />
      </Section>

      <Section title="Processing stages">
        <div className="d-flex flex-column gap-2">
          {record.stages.map((stage, i) => {
            const key = `${stage.stage}-${i}`;
            const hasBodies =
              stage.input !== undefined ||
              stage.output !== undefined ||
              !!stage.input_digest ||
              !!stage.output_digest;
            return (
              <div key={key} className="border rounded px-2 py-1">
                <div className="d-flex align-items-center justify-content-between">
                  <div className="d-flex align-items-center gap-2">
                    <Badge value={stage.outcome} tone={outcomeTone(stage.outcome)} size="sm" />
                    <span className="small fw-semibold">{stage.stage}</span>
                    {stage.reason && <span className="small text-muted">— {stage.reason}</span>}
                  </div>
                  {stage.llm_call && (
                    <span className="small text-muted font-monospace">
                      {stage.llm_call.provider}/{stage.llm_call.model} ·{' '}
                      {stage.llm_call.input_tokens}/{stage.llm_call.output_tokens} tok
                    </span>
                  )}
                </div>
                {hasBodies && (
                  <div className="mt-2 d-flex flex-column gap-1">
                    <StageBody
                      label="Input"
                      body={stage.input}
                      digest={stage.input_digest}
                      testid={`governance-stage-input-${key}`}
                    />
                    <StageBody
                      label="Output"
                      body={stage.output}
                      digest={stage.output_digest}
                      testid={`governance-stage-output-${key}`}
                    />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </Section>

      {record.prompt !== undefined && (
        <Section title="Prompt">
          <pre className="governance-body" data-testid="governance-prompt">
            {record.prompt || '(empty)'}
          </pre>
        </Section>
      )}
      {record.completion !== undefined && (
        <Section title="Completion">
          <pre className="governance-body" data-testid="governance-completion">
            {record.completion || '(empty)'}
          </pre>
        </Section>
      )}

      <Section title="Signed credential">
        <AppButton
          variant="outline-secondary"
          size="sm"
          onClick={() => setShowVc(v => !v)}
          data-testid="governance-toggle-vc"
          iconStart={
            <i className={`fas fa-chevron-${showVc ? 'down' : 'right'} me-1`} aria-hidden="true" />
          }
        >
          {showVc ? 'Hide' : 'Show'} signed VC
        </AppButton>
        {showVc && (
          <pre className="governance-body mt-2" data-testid="governance-vc">
            {JSON.stringify(stored.signed_vc, null, 2)}
          </pre>
        )}
      </Section>
    </div>
  );
};

const Section: React.FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => (
  <div className="mb-3">
    <div className="text-xs text-uppercase text-muted fw-bold mb-2">{title}</div>
    {children}
  </div>
);

const KeyVal: React.FC<{ label: string; value: string; mono?: boolean }> = ({
  label,
  value,
  mono,
}) => (
  <div className="d-flex justify-content-between small py-1 border-bottom">
    <span className="text-muted">{label}</span>
    <span className={mono ? 'font-monospace text-truncate ms-2' : 'ms-2'} title={value}>
      {value}
    </span>
  </div>
);

/** Collapsible per-stage input/output body. Shows the full body when it was
 * captured, or just the digest when body capture was off (digests-only mode). */
const StageBody: React.FC<{
  label: string;
  body?: string;
  digest?: string;
  testid: string;
}> = ({ label, body, digest, testid }) => {
  const [open, setOpen] = useState(false);
  if (body === undefined) {
    if (!digest) return null;
    return (
      <div className="text-xs text-muted font-monospace" data-testid={`${testid}-digest`}>
        {label}: {shortDigest(digest)}
      </div>
    );
  }
  return (
    <div>
      <button
        type="button"
        className="btn btn-link btn-sm p-0 text-decoration-none small"
        onClick={() => setOpen(o => !o)}
        data-testid={`${testid}-toggle`}
      >
        <i className={`fas fa-chevron-${open ? 'down' : 'right'} me-1`} aria-hidden="true" />
        {label} ({body.length.toLocaleString()} chars)
      </button>
      {open && (
        <pre className="governance-body mt-1" data-testid={testid}>
          {body || '(empty)'}
        </pre>
      )}
    </div>
  );
};

export default GovernanceRecordDetail;
