import { createContext, useContext } from 'react';

/**
 * External, asynchronously-loaded data that IDE ConfigPanels need but that
 * does not live in a node's own config: the catalogue of real LLM Surfaces
 * (and their variants) an IDE surface can aggregate, and the routing options
 * for the front door. The host page (EditIdePage) loads these and supplies
 * them via {@link IdePanelDataProvider}; panels read them with
 * {@link useIdePanelData}.
 *
 * Deliberately a context, not a SurfaceBuilder/NodeConfigPanel prop, so the
 * generic builder stays IDE-agnostic and never learns about member surfaces.
 */

export interface IdeMemberVariant {
  alias: string;
  name: string;
}

export interface IdeMemberPipe {
  id: string;
  name: string;
  route?: string;
  provider?: string;
  model?: string;
  variants: IdeMemberVariant[];
}

export interface IdePathPrefix {
  id: string;
  name: string;
  prefix: string;
}

/**
 * A JWT verification strategy the Client sign-in panel can auto-fill from. Only
 * the fields the panel reads are modelled; `expected_issuer` yields the Entra
 * tenant (e.g. `https://login.microsoftonline.com/<tenant>/v2.0`).
 */
export interface IdeJwtStrategy {
  id: string;
  name: string;
  expected_issuer?: string;
}

/**
 * An LLM provider's public sandbox sign-in identifiers, surfaced so the Client
 * sign-in and Upstream-slot editors can offer a one-click "Populate from
 * provider" prefill (removing the need to retype the same tenant/client/scopes
 * already configured on the provider's `sandbox_auth` in `llm.json`). Only the
 * public OAuth identifiers are modelled — never secrets.
 */
export interface IdeProviderAuth {
  enum_value: string;
  name: string;
  sandbox_auth?: {
    provider?: string;
    tenant_id?: string;
    client_id?: string;
    scopes?: string[];
  } | null;
}

/**
 * A referenceable OAuth Identifier profile (from the Credentials store) offered
 * as the "Profile" sign-in source in the Client sign-in / Upstream editors. Only
 * the fields the pickers need are modelled; `provider` is the shape tag.
 */
export interface IdeOAuthIdentifier {
  id: string;
  name: string;
  provider: string;
}

/**
 * An IDE-scoped OPA policy definition (`policy_type: ide`) offered by both the
 * front-door OPA panel and every per-member Model Policy chip. Loaded once by
 * the host page so opening several policy pickers in one session does not fire
 * a fresh `/policy-definitions` request each time — the previous per-panel
 * fetch flashed a "no policies defined" warning on every mount.
 */
export interface IdePolicyOption {
  id: string;
  name: string;
  description: string;
}

export interface IdeRoutingConfig {
  availableListenAddresses: string[];
  pathPrefixes: IdePathPrefix[];
}

export interface IdePanelData {
  /** Real LLM Surfaces (and their variants) that this IDE surface can expose. */
  memberPipes: IdeMemberPipe[];
  routing: IdeRoutingConfig;
  /** JWT verification strategies offered as tenant auto-fill in Client sign-in. */
  strategies: IdeJwtStrategy[];
  /** LLM providers whose `sandbox_auth` can prefill sign-in identifiers. */
  providers: IdeProviderAuth[];
  /** OAuth Identifier profiles referenceable as a sign-in source. */
  oauthIdentifiers: IdeOAuthIdentifier[];
  /** IDE-scoped OPA policies for the front door and per-member Model Policy. */
  policies: IdePolicyOption[];
}

const EMPTY: IdePanelData = {
  memberPipes: [],
  routing: { availableListenAddresses: [], pathPrefixes: [] },
  strategies: [],
  providers: [],
  oauthIdentifiers: [],
  policies: [],
};

const IdePanelDataContext = createContext<IdePanelData>(EMPTY);

export const IdePanelDataProvider = IdePanelDataContext.Provider;

export function useIdePanelData(): IdePanelData {
  return useContext(IdePanelDataContext);
}
