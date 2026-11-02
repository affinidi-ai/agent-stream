import React from 'react';
import { BadgeField, BadgeList, Field, SectionHeading } from './readonly';
import type { LlmProviderForm } from './types';

interface ProviderDetailsSectionProps {
  form: LlmProviderForm;
  testId: string;
}

const ProviderDetailsSection: React.FC<ProviderDetailsSectionProps> = ({ form, testId }) => {
  return (
    <div data-testid={`${testId}-section`}>
      <SectionHeading icon="fa-sliders-h">General</SectionHeading>
      <div className="row">
        <div className="col-md-6">
          <Field label="Provider name" value={form.name} testId={`${testId}-name`} />
        </div>
        <div className="col-md-6">
          <BadgeField label="Status">
            <span
              className={`badge bg-${form.enabled ? 'success' : 'secondary'}`}
              data-testid={`${testId}-enabled`}
            >
              {form.enabled ? 'Enabled' : 'Disabled'}
            </span>
          </BadgeField>
        </div>
      </div>

      <Field label="Description" value={form.description} testId={`${testId}-description`} />

      <div className="row">
        <div className="col-md-4">
          <Field
            label="API key label"
            value={form.api_key_label}
            testId={`${testId}-api-key-label`}
          />
        </div>
        <div className="col-md-4">
          <BadgeField label="API key">
            <span
              className={`badge bg-${
                form.api_key_validation === 'mandatory'
                  ? 'info'
                  : form.api_key_validation === 'optional'
                    ? 'warning'
                    : 'secondary'
              }`}
              data-testid={`${testId}-api-key-validation`}
            >
              {form.api_key_validation === 'mandatory'
                ? 'Mandatory'
                : form.api_key_validation === 'optional'
                  ? 'Optional'
                  : 'None'}
            </span>
          </BadgeField>
        </div>
        <div className="col-md-4">
          <BadgeField label="Icon">
            {form.icon ? (
              <span
                className="badge bg-secondary fw-normal font-monospace"
                data-testid={`${testId}-icon`}
              >
                <i className={`fas ${form.icon} me-1`}></i>
                {form.icon}
              </span>
            ) : (
              <span className="text-muted small fst-italic" data-testid={`${testId}-icon`}>
                None
              </span>
            )}
          </BadgeField>
        </div>
      </div>

      <Field
        label="Tag filter"
        value={form.filter_tag}
        mono
        hint="Case-insensitive regex. When secret tag filtering is enabled, only secrets with a tag matching this pattern are offered."
        testId={`${testId}-filter-tag`}
      />

      <hr className="my-4" />

      <SectionHeading icon="fa-lock">Platform configuration</SectionHeading>
      <div className="row">
        <div className="col-md-6">
          <Field
            label="Unique identifier"
            value={form.enum_value}
            mono
            hint="Used internally and not shown to the user."
            testId={`${testId}-enum-value`}
          />
        </div>
        <div className="col-md-6">
          <Field
            label="API schema"
            value={form.api_schema}
            hint="Defines the expected request and response formats for this provider."
            testId={`${testId}-api-schema`}
          />
        </div>
        <div className="col-md-6">
          <Field
            label="Base URL"
            value={form.default_base_url}
            mono
            testId={`${testId}-base-url`}
          />
        </div>
        <div className="col-md-6">
          <Field
            label="API version prefix"
            value={form.api_version_prefix}
            mono
            testId={`${testId}-version-prefix`}
          />
        </div>
      </div>

      <BadgeField label="Provider capabilities">
        <BadgeList
          values={form.provider_capabilities}
          emptyLabel="No capabilities declared."
          testId={`${testId}-capabilities`}
        />
      </BadgeField>
    </div>
  );
};

export default ProviderDetailsSection;
