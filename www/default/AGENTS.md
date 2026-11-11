# Frontend Agent Instructions

These instructions apply to work under `www/default/`, the dashboard shipped with Agent
Stream. Paths below are relative to `www/default/`.

## Scope

Use this file when building or editing the React dashboard frontend.

Applies to:

1. `src/pages/**`
2. `src/components/**`
3. `src/context/**`
4. `src/utils/**` when changes are frontend-specific
5. frontend config files in `www/default/`

## Design patterns

For a fast, snippet-first cheat sheet of the reusable UI patterns (tabs, badges,
buttons, empty states, list/table, page shell) and a new-page recipe, see
[`www/default/DESIGN_PATTERNS.md`](./DESIGN_PATTERNS.md).

## Frontend Working Rules

1. Preserve existing dashboard visual language before introducing new UI patterns.
2. Prefer shared dashboard building blocks before creating page-local alternatives.
3. Keep page entry files orchestration-focused; move page-owned logic into sections, hooks, helpers, and local types when needed.
4. If logic is only used by one page folder, keep it inside that page folder unless it becomes genuinely shared.
5. Prefer configuration-driven rendering over duplicated sibling JSX sections.
6. Avoid introducing `any` in new frontend code.
7. Do not add new design systems, component libraries, or styling approaches unless explicitly requested.
8. Every new interactive element ships with a `data-testid`. Page
   roots use `page-<area>`; CTAs use `<area>-<verb>-button`; list items use
   `<area>-card-<id>` / `<area>-row-<id>`. New wizards use `wizard-<name>` plus
   `wizard-step-<name>` and `wizard-next` / `wizard-back` / `wizard-submit`; the existing
   wizards do not set these IDs yet. Tests under `ui-tests/specs/` are the consumer.
9. The Access Token editor has a single collapsed **Advanced resource scoping** card:
   edit the canonical `TENANT:${header}:<kind>:<id-pattern>` and required headers
   directly, require exactly one tenant-header placeholder occurrence, show
   appliance/tenant/invalid inference, and preview the exact canonical target the
   backend matches with a live tester that reports full-value header outcomes. Existing
   values must never be silently rewritten. Broad selectors remain subject to
   trusted-edge enforcement. Agent Stream keeps its own resource-kind vocabulary.
   Bound-user copy distinguishes the PAT subject from its audit creator: the dashboard
   creates a root PAT for the current administrator, while the API may bind it to an
   approved `subject_user_id` and `created_by` keeps the issuer.
10. New Access Tokens use a create-only expiry control: default to **Never expires**;
    disabling it reveals a required local date/time input with future and 3650-day
    bounds, submitted as exact UTC `expires_at`. The native date/time chrome follows the
    active light/dark color scheme. In dark theme, the disabled Never field uses the
    shared muted-slate fill, border, and text at full opacity. Expiry is immutable after
    creation. `/access-tokens/new` presets the create form from query parameters
    (`accessTokenPrefill`) without submitting; its **Copy creation link** button (create
    mode only, `accessTokenPermalinkQuery`) copies that link only while the form is
    valid. Scopes the operator cannot grant show as red pills that block save, and the
    created card keeps the new secret masked behind a **Copy** button.
11. Integration starting content comes from `utils/integrationSamples.ts`, never
    from hard-coded samples in the forms.
    `buildIntegrationSamples` builds, for the selected category, the
    Stream/Webhook JSON payload (**Event Payload Template** / **Payload
    Template**), the Email subject and body, and the Slack message text from the
    backend runtime-variable catalogue (`GET /integrations/runtime-variables`:
    the general variables plus the category's own), so a sample only uses
    variables that category can substitute. Every sample leads with
    `appliance_id: ${APPLIANCE_ID}` (a general variable the backend fills on
    every delivery and never takes from event or caller values: the **Appliance
    ID** set in Settings › System Settings (`appliance_id`,
    `settings-appliance-id-input`), and
    left unfilled while none is set; it is never the appliance DID.
    `GET /integrations/runtime-variables` returns the set value as its
    `example`, and saving settings clears the cached catalogue). The Appliance
    ID is independent of any Kafka topic name;
    `audit` keeps its curated
    full-record JSON payload, and Email/Slack leave out `AUDIT_RECORD` and
    `AUDIT_VP_JWT`. The Add wizard and Edit page apply it through
    `hooks/useIntegrationSamples.ts`: when the category changes, each type's
    content that is empty or still the previous category's sample (compared
    ignoring key order, since stored payloads have sorted keys) is replaced with
    the new sample, and edited content is kept. The Edit page starts only after
    the integration has loaded, so stored content is never replaced on open.
12. The **Governance Audit** integration category (`audit`) is offered in the
    Add and Edit category selects only to users with `audit.view`
    (`selectableCategories` in `utils/auditIntegrations.ts`), for every
    integration type: Email and Slack are allowed and send one message per
    record. Choosing it shows the **Governance Audit** card
    (`components/integrations/AuditIntegrationCard.tsx`,
    `integration-audit-card`) at the top of the right column; for Stream and
    Webhook (`AUDIT_PAYLOAD_TYPES`, the types with a JSON payload) its **Use
    audit record template** action
    (`integration-audit-template-button`) replaces the payload with the audit
    template (routing fields plus `record: ${AUDIT_RECORD}`). The Add wizard
    honours `?category=` and `?type=` once permissions have loaded and never
    overrides a category the user already picked; a requested category the user
    can't choose shows the `integration-category-unavailable` warning instead of
    silently falling back.
13. Integration credentials are never shown again after save, so the forms in
    `components/integration-forms/` never prefill them. A field that must be a
    secret reference (Email SMTP password, Stream SASL password) is a
    `CredentialSecretField` (the shared `SecretSelector` plus a **Create secret**
    link that opens `/secrets/new` in a new tab, so the half-filled form is kept;
    `useSecretOptions` reloads the secrets when the window regains focus; it
    reads them only with `secrets.view`, waiting for permissions to load, and the
    link shows only with `secrets.edit`) bound
    to `<key>_secret_id`. The SMTP password is required on create; the SASL
    password is optional; both are optional on edit. Kinesis has no credential
    fields: it uses the appliance's AWS credential chain (environment, profile or
    IAM role). Integration URLs (Slack `webhook_url`, Webhook `url`, Stream
    `redis_url`) are accepted only as secret references: each is a
    `UrlCredentialField`, a `CredentialSecretField` bound to `<key>_secret_id`
    with no typed input, required on create and on edit. In edit mode it shows
    the host the server pinned for the saved secret
    (`configuration.pinned_destination[<key>]`, `<testId>-pinned-destination`,
    "Sends to hooks.slack.com:443") and, once a different secret is picked, that
    the new destination is checked on save. An edited integration that loaded
    with neither a reference nor a pinned host for that URL shows
    `<testId>-legacy-hint` ("This integration may still use a URL typed in
    earlier…") until a secret is picked. The "keep saved" hints and relaxed
    `required` for the SMTP password, SASL password and signing secret apply only
    when the field was not loaded as a secret reference: the server keeps an
    inline credential a save leaves out, but not a `<key>_secret_id`, so a
    cleared reference never claims to keep anything. The Edit page is the single
    source of truth: it records the references the integration loaded with
    (`loadedSecretReferences`) and the pinned hosts (`pinnedDestinations`) once
    and passes them to the forms as `loadedReferences` and `pinnedDestinations`,
    so a form remounted by a category change still knows what was saved; the Add
    wizard passes nothing. Its save checks refuse a blank URL secret, a cleared
    SMTP password, SASL password or signing secret that was loaded as a
    reference, and a typed signing secret shorter than 32 characters (the form
    marks it invalid and its help text states the minimum; the generated UUID
    is 36). Cmd/Ctrl+S submits through `requestSubmit()` so browser constraint
    validation runs first. The Webhook signing secret stays inline: it is
    generated only on create; on edit it starts blank and is kept unless
    replaced. Webhook **Secret Headers** rows (`SecretHeaderRows`)
    round-trip `headers_secret_id`; in the headers JSON a saved credential header
    (any name containing auth, cookie, cred, key, pass, secret, session or
    token, in any case) is kept when left out
    and `"Name": null` removes it. Credential pickers take the form's `disabled`
    (`SecretSelector` `locked`, which keeps the selection shown) while saving.
    Integration secret pickers pass `autoSelectSole={false}` so a blank picker
    keeps its meaning. Saves and tests build the configuration with
    `credentialPayload` (`utils/integrationCredentials.ts`), which never sends a
    credential together with its reference, leaves a blank signing secret out,
    and drops the server-recorded `pinned_destination`.
    The integration list and connection-point **Test** buttons send
    `integration_id` with the configuration as loaded. Integration pickers read
    `GET /integrations` only with `integrations.view`
    (`hooks/useIntegrationsAccess.ts`); without it they show
    `IntegrationsAdminOnlyNotice` ("Integrations are managed by
    administrators."; each call site passes its own `data-testid`) and leave
    saved selections untouched: the Surface and IDE Surface **Integrations** tab
    and the connection-point wizard and editor (`integrations-admin-only-notice`),
    usage alerts (`usage-alert-<i>-admin-only`), governance export targets
    (`surface-governance-integrations-admin-only`), and drift alerts
    (`drift-alert-integrations-admin-only`). The connection-point editor shows
    **Test Integrations** (`connection-point-test-integrations-button`) only with
    `integrations.view` and `integrations.edit`. The connection secret appears
    only on the creation wizard's last step (`CompleteStep`), from the create
    response; Connection Point reads never return it, so the editor has no
    secret field.
14. Text from the server or a user (messages, names, log lines) reaches the DOM as
    text: through React, or `textContent` outside it. `utils/toaster.ts` builds its
    toast with DOM APIs for this reason. Where a view must build an HTML string
    (`dangerouslySetInnerHTML`, the log viewers), every interpolated value that is
    not a constant goes through `escapeHtml` (`utils/escapeHtml.ts`).
15. The wording that says what deleting a user does (the delete button title, the success
    toast, the "Deleted:" line and the label of a kept user's provider account, and the
    notice on the Edit User page) comes from `utils/userDelete.ts`, never inline, so every
    place that deletes a user says the same thing. The Edit User page shows the provider
    account and the deleted notice for a disabled user bound to one, with test ids
    `edit-user-kept-account` and `edit-user-deleted-notice`.

## Surface builder

The canvas is the source of truth for every element below. Each block is written on save
by a `*FromCanvas` helper and the node is synthesised on load by
`reconcilePipeCanvasGuards`, both in `src/pages/EditPipePage/pipeMappingHelpers.ts`. Every
block can also be edited through the Config JSON view.

To add an LLM Surface element: write its `NodeDefinition` in
`src/components/builder/elements/pipe/definitions.ts` and add it to
`pipeAnchorDefinitions`, which `src/components/builder/elements/index.ts` registers; give
it a `ConfigPanel` (plus a `FullscreenPanel` when it needs a full-page editor); then map it
in `pipeMappingHelpers.ts` with a `*FromCanvas` helper for save and a branch in
`reconcilePipeCanvasGuards` for load. IDE Surface elements follow the same shape with
`ideAnchorDefinitions` in `elements/ide/definitions.ts`, mapped by `nodesFromIde` and the
`readIde*` readers in `elements/ide/ideNodesFromConfig.ts`.

### Caller Context

**Caller Context** (`pipe-caller-auth` and `ide-caller-auth`) is the source-authentication
element shared by LLM and IDE Surfaces. Both use the panels in
`src/components/builder/elements/caller-auth/` (`CallerAuthPanel`, `CallerAuthFullscreen`)
and the wire mapping in `caller-auth/sourceAuthMapping.ts`; `callerAuthIncompleteReason`
decides when the node is incomplete (no method, or a missing JWT strategy, audience, API
key secret, or mTLS certificate). The LLM Surface saves it via `sourceAuthFromCanvas`; the
IDE Surface reads it with `readIdeSourceAuth`.

### Judge and Juror confidence

The Judge (`JudgeTab.tsx`) and each Juror (`JurorEditor.tsx`) have an optional
**Target Confidence** slider. It only asks the model for a confidence score; the
confidence never overrides the decision, and a rejection always stands. Copy must not
suggest that low-confidence rejections become approvals.

### LLM-bound elements: Inputs and Tools

Inputs (**Audio File**, **Audio Stream**, **Image File**, **Document File**) and Tools
(**Web Search**, **Web Fetch**) are LLM-bound palette elements: their definitions carry
`llmTool: true`, so a dragged element binds only to the LLM node's top landing area (the
`pointInLlmLanding` zone, shown as the `surface-tool-landing` strip and an LLM highlight
during drag), becomes a child of the LLM (`parentId: 'pipe-upstream'`), and lays out in one
evenly spaced row above it, Inputs then Tools, centred on the LLM
(`llmToolSlotPosition(ordinal, count)`, `LLM_TOOL_ROW_Y`). This mirrors the Decider
candidate row below the LLM.

- Each element is free-draggable: Auto Layout or a drop seeds it at its slot, then it keeps
  its own `fx`/`fy`. A move persists via `onNodeMove` and survives reload because
  `reconcilePipeCanvasGuards` only synthesises an element that is not already on the
  canvas.
- The LLM-to-tool connector is an orthogonal bus (`llm-tool-bus`): a trunk up from the
  LLM, a horizontal bus, and one vertical drop per element that ends just below its label
  (`TOOL_LABEL_CLEARANCE`). The trunk rises about three-quarters of a witness length
  (`WITNESS_RISE * 0.75`) so the bus clears the Jury-to-LLM redrive arc; `LLM_TOOL_ROW_Y`
  is 200 to leave room. Its links are flagged `llmToolEdge` and skipped by the
  straight-line renderer. It mirrors the IDE `ide-member-bus`.
- Auto Layout (`computePipeAutoLayout`, `PIPE_TOOL_ROW_Y = LLM_TOOL_ROW_Y`) reserves that
  row and places Expert Witnesses below the spine.
- The gated drop lives in `SurfaceCanvas` (dragover/drop); `useSurfaceBuilder.handleDrop`
  creates the node.

Input definitions are `pipeAudioInputDefinition`, `pipeAudioStreamDefinition`,
`pipeImageInputDefinition`, and `pipeDocumentInputDefinition` in
`src/components/builder/elements/pipe/definitions.ts`, with panels in
`InputModalityPanels.tsx`. Each panel's accepted-format checklist is backend-driven: the
backend publishes its supported modalities on `GET /pipes/config` as `input_modalities`,
threaded through `usePipeConfigData` into `PipePanelData.inputModalities`. They save via
`audioInputFromCanvas`, `realtimeFromCanvas`, `imageInputFromCanvas`, and
`documentInputFromCanvas`. Document ingestion is configured on the **Document File**
element.

**Audio Stream** is realtime voice, distinct from the file-based **Audio File**. Its
sidebar has an enable switch and a Configure button; the full-page editor
(`AudioStreamFullscreenPanel.tsx`) holds the max-session-seconds and optional voice
controls, **Voice safety** (enforcement mode and refusal), filler clips whose pickers come
from the published `audio_streams` catalogue, and **Minimum gap after filler**
(`realtime.audio_streams.filler_guard_band_ms`). It shows a config-time capability warning
when the selected model is not realtime-capable, mirroring the backend gate. An enabled
standard Judge on a realtime voice Surface is marked invalid (marching ants and a
save-blocking **Show me** toast).

**Web Search** and **Web Fetch** use the `pipe-web-search` / `pipe-web-fetch` definitions,
with panels that have an engine dropdown and a `SecretSelector`. They save via
`serverToolsFromCanvas`.

### Router

The **Router** (`pipe-router`, `pipeRouterDefinition`) is an edge-bound Inputs-palette
element that snaps onto the inbound edge, first after the Access Point, mirroring the
backend order. It has a sidebar summary (`RouterPanel`) and a full-page rule editor
(`RouterFullscreenPanel`, reusing `RoutingRulesControls`, with the **Attachment type** match
kind and a greyed **Text → base** option). `routing_rules` stays a base form field, shared
with variant-catalogue sync; the node carries only the enable flag and saves via
`routerEnabledFromCanvas`. Per-Variant modality and realtime settings round-trip through
the Variant canvas snapshot and `buildPipeVariantOverrides`
(`src/components/builder/pipe-variants/pipeVariantMapping.ts`).

### Drift Harness

The **Drift Harness** (`pipe-drift-harness`, `src/components/builder/elements/drift-harness/`)
is an LLM-bound element in the same row as Inputs and Tools. The node carries only an
enable flag; the full `drift` block stays a base form field and is the single source of
truth for enable (a freshly dropped node persists). It saves via `buildDriftFromCanvas`.
The sidebar shows an enable switch and a Configure button; the full-page editor
(`DriftHarnessFullscreenPanel`) covers enable, sampling rate, the **Warn** and **Drift**
thresholds (explained in the UI as relative-change-from-baseline levels: Warn is amber,
Drift is red), **Block saves on regression**, **Replay evaluation** (an embeddings model
picked from catalogue dropdowns by `EmbeddingsTargetEditor` with a `filter_tag`-filtered
secret, never a typed URL; an auto-run schedule; a max-sessions cap; a per-run cost
ceiling), and **Drift alerts** (`DriftAlertControls`: the `llm_drift`-category
integrations to notify and the re-alert cadence). The page header shows a **Drift** badge
while monitoring is enabled.

### Governance recording

The Surface properties panel has a **Governance recording** feature row that opens the
Surface Configuration full-page editor: enable, which interactions are recorded, which keep
bodies, streaming capture, local retention, and export targets (OpenTelemetry and/or
selected integrations). The page header shows a **Governance** indicator while recording
is enabled. `GovernanceRecordingControls` in `SurfacePanel.tsx` renders both choices as
three-way selects (`surface-governance-record-outcomes`: every interaction, blocked only,
blocked and failed; `surface-governance-capture-bodies`: every recorded interaction,
blocked only, never) and saves exactly the values the backend writes (`true`, `"blocked"`,
`false`; `all`, `blocked`, `blocked_and_failed`).

## LLM configuration tab

`src/pages/EditPipePage/tabs/LLMConfigTab.tsx` holds:

- The **Upstream Headers** card. `upstream_headers` round-trips via `mapPipeToFormData` /
  `buildUpstreamHeaders` in `pipeMappingHelpers.ts`, which drops a half-filled row rather
  than failing the save. Target `headers` ride inside the target objects, which the editor
  carries through a save unchanged. Each Variant carries its own list: `upstream_headers`
  is a `PIPE_VARIANT_FIELDS` snapshot field, so the card edits the active Variant's list, a
  new Variant starts as a copy of the one it was created from, and the list round-trips
  through `buildPipeVariantOverrides` / `snapshotFromWireVariant`
  (`src/components/builder/pipe-variants/`), which mirror the backend's resolve semantics.
- The **Context Window Management** card. `context_management` round-trips via
  `buildContextManagement` / `mapContextManagement` on `PipeFormData`.

`upstream_pricing` round-trips through the form unedited. The Models page (`/llm-providers`)
and its sidebar entry need `llm_catalog.edit`.

## Monitoring pages

- **Governance Records** (`src/pages/GovernanceRecordsPage/`, route `/governance`, sidebar
  under Monitoring, gated by `governance.view`): pick a recorded Surface by name, scan its
  signed records (cards show Surface name, description, id, and interaction time), inspect
  a record's identity, chain, stages, prompt, completion, and credential, and verify the
  Surface's hash chain.
- **LLM Drift** (`src/pages/LLMDriftPage/`, route `/drift`, sidebar under Monitoring, gated
  by `drift.view`): one chart per dimension from `GET /v1/drift/series`, each with its
  baseline as a dashed reference line and a status badge, an overall status badge, a
  **Set baseline** action, and an **Indicative surface data** panel with captured sessions,
  a run-evaluation button, and the run history. Drift graphs appear only on this page; the
  main dashboard reads `/telemetry/series` and `/dashboard/ops-series`, never the drift
  store.

## Validation

After frontend edits, prefer these checks when relevant:

1. `npm run lint`
2. `npm run lint:fix`
3. `npm run format`
4. `npm run typecheck`
5. `npm test -- --watchAll=false` (or `make npm-test`)

When only page architecture is touched, prioritize lint and format first.

## Source Of Truth

Consult these files before inventing new patterns:

1. `src/dashboard.css`
2. `src/pages/AuthenticatedApp.tsx`
3. `src/components/shared/SearchInput.tsx`
4. `src/context/AppContext.tsx`
5. `src/context/PermissionsContext.tsx`

If these instructions and live code disagree, follow the live code and update this file afterward.
