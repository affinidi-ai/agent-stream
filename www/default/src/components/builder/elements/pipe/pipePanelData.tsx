import { createContext, useContext } from 'react';

/**
 * External, asynchronously-loaded data that pipe ConfigPanels need but that
 * does not live in a node's own config (LLM provider catalogue, available
 * secrets). The host page (EditPipePage) loads these and supplies them via
 * {@link PipePanelDataProvider}; panels read them with {@link usePipePanelData}.
 *
 * This is deliberately a context, not a SurfaceBuilder/NodeConfigPanel prop:
 * the generic builder stays pipe-agnostic and never learns about providers or
 * secrets. Only the pipe-scoped panels consume this.
 */

export interface PipeLlmEndpoint {
  name: string;
  path: string;
}

export interface PipeLlmModel {
  name: string;
  value: string;
  enabled?: boolean;
  cost_per_1k_input?: number;
  cost_per_1k_output?: number;
}

export interface PipeLlmProvider {
  enum_value: string;
  name: string;
  /** Wire schema the provider speaks (`openai` | `anthropic` | `gemini` | `copilot` | …). */
  api_schema?: string;
  /**
   * Declarative capability flag: when true, a surface fronting this provider
   * MUST forward the caller's validated bearer token (identity pass-through),
   * so the editor auto-enables forwarding and requires a JWT-bearer Caller
   * Context. Property-driven — a new delegated-only provider opts in by setting
   * this in the catalog, no code change. Copilot-schema providers are treated
   * as requiring it even without the flag (back-compat).
   */
  requires_forward_caller_token?: boolean;
  api_key_label?: string;
  /** Three-state key policy (`mandatory` | `optional` | `none`). */
  api_key_validation?: string;
  api_key_required?: boolean;
  filter_tag?: string;
  endpoints: PipeLlmEndpoint[];
  models: PipeLlmModel[];
}

/**
 * Whether a surface fronting this provider requires identity pass-through
 * (forwarding the caller's validated bearer token). Reads provider *properties*
 * rather than hardcoding a provider id: the declarative
 * `requires_forward_caller_token` catalog flag is authoritative, with the
 * `copilot` wire schema as a back-compat fallback so a custom Copilot-schema
 * provider that predates the flag is still detected. Kept aligned with the
 * backend guard in `llm_handler.rs`.
 */
export function providerRequiresForwardCallerToken(
  provider: { api_schema?: string; requires_forward_caller_token?: boolean } | undefined | null
): boolean {
  if (!provider) return false;
  return provider.requires_forward_caller_token === true || provider.api_schema === 'copilot';
}

export interface PipeSecretRef {
  id: string;
  name: string;
  tags?: string[];
}

export interface PipePathPrefix {
  id: string;
  name: string;
  prefix: string;
}

export interface PipeRoutingConfig {
  availableListenAddresses: string[];
  pathPrefixes: PipePathPrefix[];
}

export interface PipePromptGuardPattern {
  key: string;
  label: string;
  icon: string;
  description: string;
  regex: string;
}

/**
 * Backend-published support for inbound binary modalities, so the Inputs
 * elements render their type/format pickers from what the gateway actually
 * accepts (see `crate::pipes::modality::supported_input_modalities`) rather than
 * a hardcoded list. Falls back to {@link DEFAULT_INPUT_MODALITIES} until the
 * `/pipes/config` fetch resolves.
 */
export interface InputModalitySupport {
  audio: { formats: string[] };
  image: { formats: string[] };
  document: { extractable: string[]; forward_only: string[] };
}

export const DEFAULT_INPUT_MODALITIES: InputModalitySupport = {
  audio: { formats: ['wav', 'mp3'] },
  image: { formats: ['png', 'jpeg', 'gif', 'webp'] },
  document: { extractable: ['text', 'markdown', 'csv', 'json', 'docx'], forward_only: ['pdf'] },
};

/**
 * Backend-published catalog of pre-recorded audio-stream clips (see
 * `crate::pipes::audio_streams::published_catalog`), so the realtime streaming
 * config can offer real clip ids for its filler / refusal / on-fail buckets.
 * Empty until the `/pipes/config` fetch resolves.
 */
export interface AudioStreamClipInfo {
  id: string;
  label?: string;
  text?: string;
  tags?: string[];
  duration_ms?: number;
}

export interface AudioStreamsCatalog {
  clips: AudioStreamClipInfo[];
}

export const EMPTY_AUDIO_STREAMS: AudioStreamsCatalog = { clips: [] };

export interface PipePanelData {
  llmProviders: PipeLlmProvider[];
  secrets: PipeSecretRef[];
  routing: PipeRoutingConfig;
  promptGuardPatterns: PipePromptGuardPattern[];
  inputModalities: InputModalitySupport;
  audioStreams: AudioStreamsCatalog;
}

const EMPTY: PipePanelData = {
  llmProviders: [],
  secrets: [],
  routing: { availableListenAddresses: [], pathPrefixes: [] },
  promptGuardPatterns: [],
  inputModalities: DEFAULT_INPUT_MODALITIES,
  audioStreams: EMPTY_AUDIO_STREAMS,
};

const PipePanelDataContext = createContext<PipePanelData>(EMPTY);

export const PipePanelDataProvider = PipePanelDataContext.Provider;

export function usePipePanelData(): PipePanelData {
  return useContext(PipePanelDataContext);
}
