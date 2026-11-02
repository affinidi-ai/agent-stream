use once_cell::sync::Lazy;
use regex::{Captures, Regex};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use tracing::warn;

const DEFAULT_VARIABLE_PATTERN: &str = r"\$\{([A-Za-z0-9_]+)(?::([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)";
const DEFAULT_CUSTOM_VARIABLE_PREFIX: &str = "_";

fn default_variable_regex() -> Regex {
    match Regex::new(DEFAULT_VARIABLE_PATTERN) {
        Ok(regex) => regex,
        Err(e) => panic!("default integration variable regex must compile: {e}"),
    }
}

/// Global storage for variable patterns from config
static VARIABLE_PATTERN: Lazy<RwLock<String>> = Lazy::new(|| RwLock::new(DEFAULT_VARIABLE_PATTERN.to_string()));

static CUSTOM_VARIABLE_PREFIX: Lazy<RwLock<String>> =
    Lazy::new(|| RwLock::new(DEFAULT_CUSTOM_VARIABLE_PREFIX.to_string()));

/// Cached compiled regex for variable substitution
static VAR_REGEX: Lazy<RwLock<Regex>> = Lazy::new(|| RwLock::new(default_variable_regex()));

/// Variable filled only from the Appliance ID set in System Settings.
pub const APPLIANCE_ID_VARIABLE: &str = "APPLIANCE_ID";

/// The Appliance ID set in System Settings, if any.
fn configured_appliance_id() -> Option<String> {
    crate::storage::settings_store::global_appliance_id_override()
}

/// The value that fills `name` in a template. `${APPLIANCE_ID}` comes only
/// from the appliance's settings, never from event or caller values, so no
/// trigger can make an event look like it came from another appliance; while
/// no Appliance ID is set it stays unfilled.
pub fn variable_value(
    name: &str,
    values: &HashMap<String, String>,
) -> Option<String> {
    variable_value_with(name, values, configured_appliance_id)
}

fn variable_value_with(
    name: &str,
    values: &HashMap<String, String>,
    appliance_id: impl FnOnce() -> Option<String>,
) -> Option<String> {
    if name == APPLIANCE_ID_VARIABLE {
        appliance_id()
    } else {
        values.get(name).cloned()
    }
}

/// Update the variable patterns from config (called during startup)
pub fn set_variable_patterns(
    variable_pattern: String,
    custom_prefix: String,
) -> Result<(), String> {
    let new_regex = Regex::new(&variable_pattern).map_err(|e| format!("invalid integration variable pattern: {e}"))?;

    *VARIABLE_PATTERN
        .write()
        .map_err(|_| "integration variable pattern lock poisoned".to_string())? = variable_pattern;
    *CUSTOM_VARIABLE_PREFIX
        .write()
        .map_err(|_| "integration custom variable prefix lock poisoned".to_string())? = custom_prefix;
    *VAR_REGEX
        .write()
        .map_err(|_| "integration variable regex lock poisoned".to_string())? = new_regex;

    Ok(())
}

fn current_custom_prefix() -> String {
    CUSTOM_VARIABLE_PREFIX
        .read()
        .map(|prefix| prefix.clone())
        .unwrap_or_else(|_| {
            warn!("Integration custom variable prefix lock poisoned; using default prefix");
            DEFAULT_CUSTOM_VARIABLE_PREFIX.to_string()
        })
}

fn current_variable_regex() -> Regex {
    VAR_REGEX
        .read()
        .map(|regex| regex.clone())
        .unwrap_or_else(|_| {
            warn!("Integration variable regex lock poisoned; using default pattern");
            default_variable_regex()
        })
}

fn variable_name_from_capture<'a>(cap: &Captures<'a>) -> Option<&'a str> {
    cap.get(1)
        .or_else(|| cap.get(3))
        .or_else(|| cap.get(2))
        .map(|m| m.as_str().trim())
        .filter(|name| !name.is_empty())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeVariable {
    pub name: String,
    pub label: String,
    pub description: String,
    pub example: String,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeVariableCategory {
    pub category: String,
    pub label: String,
    pub description: String,
    pub variables: Vec<RuntimeVariable>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeVariablesResponse {
    pub categories: Vec<RuntimeVariableCategory>,
}

/// Get all runtime variable definitions
pub fn get_runtime_variables() -> RuntimeVariablesResponse {
    RuntimeVariablesResponse {
        categories: vec![
            get_general_variables(),
            get_connection_point_variables(),
            get_user_variables(),
            get_gateway_variables(),
            get_identity_variables(),
            get_mediator_variables(),
            get_trust_registry_variables(),
            get_secrets_variables(),
            get_pipe_variables(),
            get_llm_governance_variables(),
            get_llm_drift_variables(),
            get_audit_variables(),
        ],
    }
}

/// Variables whose value is JSON text. When one fills an entire JSON string
/// value of a template (`"record": "${AUDIT_RECORD}"`), the JSON is embedded as
/// structured data instead of an escaped string.
const JSON_VALUED_VARIABLES: &[&str] = &["AUDIT_RECORD"];

fn get_general_variables() -> RuntimeVariableCategory {
    RuntimeVariableCategory {
        category: "general".to_string(),
        label: "General".to_string(),
        description: "Variables available to all integrations regardless of context".to_string(),
        variables: vec![
            RuntimeVariable {
                name: APPLIANCE_ID_VARIABLE.to_string(),
                label: "Appliance ID".to_string(),
                description: "Appliance ID set in System Settings (e.g. this appliance's id in Agent Watch), filled on every delivery; left unfilled while none is set".to_string(),
                example: configured_appliance_id().unwrap_or_else(|| "${APPLIANCE_ID}".to_string()),
                category: "general".to_string(),
            },
            RuntimeVariable {
                name: "OLD_STATE".to_string(),
                label: "Old State".to_string(),
                description: "JSON representation of the entity's state before the event. Empty for CREATE events. Contains complete entity object (Gateway, User, etc.) for UPDATE and DELETE events.".to_string(),
                example: r#"${OLD_STATE}"#.to_string(),
                category: "general".to_string(),
            },
            RuntimeVariable {
                name: "NEW_STATE".to_string(),
                label: "New State".to_string(),
                description: "JSON representation of the entity's state after the event. Empty for DELETE events. Contains complete entity object (Gateway, User, etc.) for CREATE and UPDATE events.".to_string(),
                example: r#"${NEW_STATE}"#.to_string(),
                category: "general".to_string(),
            },
            RuntimeVariable {
                name: "EVENT_TYPE".to_string(),
                label: "Event Type".to_string(),
                description: "The type of event that triggered the integration (e.g., 'gateway.created', 'user.updated', etc.)".to_string(),
                example: "${EVENT_TYPE}".to_string(),
                category: "general".to_string(),
            },
            RuntimeVariable {
                name: "TIMESTAMP".to_string(),
                label: "Timestamp".to_string(),
                description: "ISO 8601 timestamp when the event occurred".to_string(),
                example: "$TIMESTAMP".to_string(),
                category: "general".to_string(),
            },
            RuntimeVariable {
                name: "SERVER_NAME".to_string(),
                label: "Server Name".to_string(),
                description: "Name of the Agent Stream server".to_string(),
                example: "$SERVER_NAME".to_string(),
                category: "general".to_string(),
            },
            RuntimeVariable {
                name: "SERVER_DOMAIN".to_string(),
                label: "Server Domain".to_string(),
                description: "Domain name of the server".to_string(),
                example: "$SERVER_DOMAIN".to_string(),
                category: "general".to_string(),
            },
            RuntimeVariable {
                name: "MESSAGE_ID".to_string(),
                label: "Message ID".to_string(),
                description: "Unique identifier for the message/event".to_string(),
                example: "$MESSAGE_ID".to_string(),
                category: "general".to_string(),
            },
        ],
    }
}

fn get_connection_point_variables() -> RuntimeVariableCategory {
    RuntimeVariableCategory {
        category: "connection_point".to_string(),
        label: "Connection Point".to_string(),
        description: "Variables available when notifications are triggered from connection point events".to_string(),
        variables: vec![
            RuntimeVariable {
                name: "CP_ID".to_string(),
                label: "Connection Point ID".to_string(),
                description: "Unique identifier of the connection point".to_string(),
                example: "$CP_ID".to_string(),
                category: "connection_point".to_string(),
            },
            RuntimeVariable {
                name: "CP_NAME".to_string(),
                label: "Connection Point Name".to_string(),
                description: "Display name of the connection point".to_string(),
                example: "$CP_NAME".to_string(),
                category: "connection_point".to_string(),
            },
            RuntimeVariable {
                name: "CP_DESCRIPTION".to_string(),
                label: "Connection Point Description".to_string(),
                description: "Description of the connection point".to_string(),
                example: "$CP_DESCRIPTION".to_string(),
                category: "connection_point".to_string(),
            },
            RuntimeVariable {
                name: "GATEWAY".to_string(),
                label: "Gateway Name".to_string(),
                description: "Name of the associated gateway".to_string(),
                example: "$GATEWAY".to_string(),
                category: "connection_point".to_string(),
            },
            RuntimeVariable {
                name: "GATEWAY_ID".to_string(),
                label: "Gateway ID".to_string(),
                description: "Unique identifier of the gateway".to_string(),
                example: "$GATEWAY_ID".to_string(),
                category: "connection_point".to_string(),
            },
        ],
    }
}

fn get_user_variables() -> RuntimeVariableCategory {
    RuntimeVariableCategory {
        category: "user".to_string(),
        label: "User Management".to_string(),
        description: "Variables available when notifications are triggered from user management events".to_string(),
        variables: vec![
            RuntimeVariable {
                name: "USER_ID".to_string(),
                label: "User ID".to_string(),
                description: "Unique identifier of the user".to_string(),
                example: "$USER_ID".to_string(),
                category: "user".to_string(),
            },
            RuntimeVariable {
                name: "USERNAME".to_string(),
                label: "Username".to_string(),
                description: "Username of the user".to_string(),
                example: "$USERNAME".to_string(),
                category: "user".to_string(),
            },
            RuntimeVariable {
                name: "USER_EMAIL".to_string(),
                label: "User Email".to_string(),
                description: "Email address of the user".to_string(),
                example: "$USER_EMAIL".to_string(),
                category: "user".to_string(),
            },
            RuntimeVariable {
                name: "USER_ROLE".to_string(),
                label: "User Role".to_string(),
                description: "Role assigned to the user (administrator, poweruser, user)".to_string(),
                example: "$USER_ROLE".to_string(),
                category: "user".to_string(),
            },
            RuntimeVariable {
                name: "USER_STATUS".to_string(),
                label: "User Status".to_string(),
                description: "Current status of the user (new, approved, disabled)".to_string(),
                example: "$USER_STATUS".to_string(),
                category: "user".to_string(),
            },
            RuntimeVariable {
                name: "EVENT_TYPE".to_string(),
                label: "Event Type".to_string(),
                description: "Type of user event (user.created, user.approved, user.updated, user.deleted, user.login)"
                    .to_string(),
                example: "$EVENT_TYPE".to_string(),
                category: "user".to_string(),
            },
        ],
    }
}

fn get_gateway_variables() -> RuntimeVariableCategory {
    RuntimeVariableCategory {
        category: "gateway".to_string(),
        label: "Gateway".to_string(),
        description: "Variables available when notifications are triggered from gateway events".to_string(),
        variables: vec![
            RuntimeVariable {
                name: "GATEWAY_ID".to_string(),
                label: "Gateway ID".to_string(),
                description: "Unique identifier of the gateway".to_string(),
                example: "$GATEWAY_ID".to_string(),
                category: "gateway".to_string(),
            },
            RuntimeVariable {
                name: "GATEWAY_NAME".to_string(),
                label: "Gateway Name".to_string(),
                description: "Display name of the gateway".to_string(),
                example: "$GATEWAY_NAME".to_string(),
                category: "gateway".to_string(),
            },
            RuntimeVariable {
                name: "GATEWAY_DESCRIPTION".to_string(),
                label: "Gateway Description".to_string(),
                description: "Description of the gateway".to_string(),
                example: "$GATEWAY_DESCRIPTION".to_string(),
                category: "gateway".to_string(),
            },
            RuntimeVariable {
                name: "GATEWAY_DID".to_string(),
                label: "Gateway DID".to_string(),
                description: "Decentralized Identifier of the gateway".to_string(),
                example: "$GATEWAY_DID".to_string(),
                category: "gateway".to_string(),
            },
            RuntimeVariable {
                name: "GATEWAY_TYPE".to_string(),
                label: "Gateway Type".to_string(),
                description: "Type of gateway (SelfGateway or Remote)".to_string(),
                example: "$GATEWAY_TYPE".to_string(),
                category: "gateway".to_string(),
            },
            RuntimeVariable {
                name: "GATEWAY_STATUS".to_string(),
                label: "Gateway Status".to_string(),
                description: "Current status of the gateway (Active, Disabled, etc.)".to_string(),
                example: "$GATEWAY_STATUS".to_string(),
                category: "gateway".to_string(),
            },
            RuntimeVariable {
                name: "GATEWAY_OLD_STATUS".to_string(),
                label: "Gateway Old Status".to_string(),
                description: "Previous status of the gateway (available in status_changed events)".to_string(),
                example: "$GATEWAY_OLD_STATUS".to_string(),
                category: "gateway".to_string(),
            },
            RuntimeVariable {
                name: "EVENT_TYPE".to_string(),
                label: "Event Type".to_string(),
                description:
                    "Type of gateway event (gateway.created, gateway.updated, gateway.deleted, gateway.status_changed)"
                        .to_string(),
                example: "$EVENT_TYPE".to_string(),
                category: "gateway".to_string(),
            },
        ],
    }
}

fn get_identity_variables() -> RuntimeVariableCategory {
    RuntimeVariableCategory {
        category: "identity".to_string(),
        label: "Identity".to_string(),
        description: "Variables available when notifications are triggered from DID identity events".to_string(),
        variables: vec![
            RuntimeVariable {
                name: "IDENTITY_DID".to_string(),
                label: "Identity DID".to_string(),
                description: "Decentralized Identifier of the identity".to_string(),
                example: "$IDENTITY_DID".to_string(),
                category: "identity".to_string(),
            },
            RuntimeVariable {
                name: "IDENTITY_TYPE".to_string(),
                label: "Identity Type".to_string(),
                description: "Type of DID (did:web, did:key, etc.)".to_string(),
                example: "$IDENTITY_TYPE".to_string(),
                category: "identity".to_string(),
            },
            RuntimeVariable {
                name: "IDENTITY_CONTROLLER".to_string(),
                label: "Identity Controller".to_string(),
                description: "DID of the identity controller".to_string(),
                example: "$IDENTITY_CONTROLLER".to_string(),
                category: "identity".to_string(),
            },
            RuntimeVariable {
                name: "CHANNEL_ID".to_string(),
                label: "Channel ID".to_string(),
                description: "Channel where identity appeared (for identity.appeared events)".to_string(),
                example: "$CHANNEL_ID".to_string(),
                category: "identity".to_string(),
            },
            RuntimeVariable {
                name: "EVENT_TYPE".to_string(),
                label: "Event Type".to_string(),
                description: "Type of identity event (identity.created, identity.updated, identity.deleted, identity.appeared, identity.accessed)".to_string(),
                example: "$EVENT_TYPE".to_string(),
                category: "identity".to_string(),
            },
        ],
    }
}

fn get_mediator_variables() -> RuntimeVariableCategory {
    RuntimeVariableCategory {
        category: "mediator".to_string(),
        label: "Mediator".to_string(),
        description: "Variables available when notifications are triggered from Mediator events".to_string(),
        variables: vec![
            RuntimeVariable {
                name: "MEDIATOR_ID".to_string(),
                label: "Mediator ID".to_string(),
                description: "Unique identifier of the mediator".to_string(),
                example: "$MEDIATOR_ID".to_string(),
                category: "mediator".to_string(),
            },
            RuntimeVariable {
                name: "MEDIATOR_NAME".to_string(),
                label: "Mediator Name".to_string(),
                description: "Name of the mediator".to_string(),
                example: "$MEDIATOR_NAME".to_string(),
                category: "mediator".to_string(),
            },
            RuntimeVariable {
                name: "MEDIATOR_DESCRIPTION".to_string(),
                label: "Mediator Description".to_string(),
                description: "Description of the mediator".to_string(),
                example: "$MEDIATOR_DESCRIPTION".to_string(),
                category: "mediator".to_string(),
            },
            RuntimeVariable {
                name: "MEDIATOR_ENDPOINT".to_string(),
                label: "Mediator Endpoint".to_string(),
                description: "Endpoint URL of the mediator".to_string(),
                example: "$MEDIATOR_ENDPOINT".to_string(),
                category: "mediator".to_string(),
            },
            RuntimeVariable {
                name: "MEDIATOR_DID".to_string(),
                label: "Mediator DID".to_string(),
                description: "Decentralized Identifier of the mediator".to_string(),
                example: "$MEDIATOR_DID".to_string(),
                category: "mediator".to_string(),
            },
            RuntimeVariable {
                name: "MEDIATOR_STATUS".to_string(),
                label: "Mediator Status".to_string(),
                description: "Current status of the mediator (Active, Disabled)".to_string(),
                example: "$MEDIATOR_STATUS".to_string(),
                category: "mediator".to_string(),
            },
            RuntimeVariable {
                name: "EVENT_TYPE".to_string(),
                label: "Event Type".to_string(),
                description: "Type of mediator event (mediator.created, mediator.updated, mediator.deleted, mediator.status_changed)".to_string(),
                example: "$EVENT_TYPE".to_string(),
                category: "mediator".to_string(),
            },
        ],
    }
}

fn get_trust_registry_variables() -> RuntimeVariableCategory {
    RuntimeVariableCategory {
        category: "trust_registry".to_string(),
        label: "Trust Registry".to_string(),
        description: "Variables available when notifications are triggered from Trust Registry events".to_string(),
        variables: vec![
            RuntimeVariable {
                name: "TRUST_REGISTRY_ID".to_string(),
                label: "Trust Registry ID".to_string(),
                description: "Unique identifier of the trust registry".to_string(),
                example: "$TRUST_REGISTRY_ID".to_string(),
                category: "trust_registry".to_string(),
            },
            RuntimeVariable {
                name: "TRUST_REGISTRY_NAME".to_string(),
                label: "Trust Registry Name".to_string(),
                description: "Name of the trust registry".to_string(),
                example: "$TRUST_REGISTRY_NAME".to_string(),
                category: "trust_registry".to_string(),
            },
            RuntimeVariable {
                name: "TRUST_REGISTRY_DESCRIPTION".to_string(),
                label: "Trust Registry Description".to_string(),
                description: "Description of the trust registry".to_string(),
                example: "$TRUST_REGISTRY_DESCRIPTION".to_string(),
                category: "trust_registry".to_string(),
            },
            RuntimeVariable {
                name: "TRUST_REGISTRY_DID".to_string(),
                label: "Trust Registry DID".to_string(),
                description: "Decentralized Identifier of the trust registry".to_string(),
                example: "$TRUST_REGISTRY_DID".to_string(),
                category: "trust_registry".to_string(),
            },
            RuntimeVariable {
                name: "TRUST_REGISTRY_STATUS".to_string(),
                label: "Trust Registry Status".to_string(),
                description: "Current status of the trust registry (Active, Disabled)".to_string(),
                example: "$TRUST_REGISTRY_STATUS".to_string(),
                category: "trust_registry".to_string(),
            },
            RuntimeVariable {
                name: "EVENT_TYPE".to_string(),
                label: "Event Type".to_string(),
                description: "Type of trust registry event (trust_registry.created, trust_registry.updated, trust_registry.deleted, trust_registry.status_changed)".to_string(),
                example: "$EVENT_TYPE".to_string(),
                category: "trust_registry".to_string(),
            },
        ],
    }
}

fn get_secrets_variables() -> RuntimeVariableCategory {
    RuntimeVariableCategory {
        category: "secrets".to_string(),
        label: "Secrets".to_string(),
        description: "Variables available when notifications are triggered from Secrets vault events".to_string(),
        variables: vec![
            RuntimeVariable {
                name: "SECRET_ID".to_string(),
                label: "Secret ID".to_string(),
                description: "Unique identifier of the secret".to_string(),
                example: "$SECRET_ID".to_string(),
                category: "secrets".to_string(),
            },
            RuntimeVariable {
                name: "SECRET_NAME".to_string(),
                label: "Secret Name".to_string(),
                description: "Name of the secret".to_string(),
                example: "$SECRET_NAME".to_string(),
                category: "secrets".to_string(),
            },
            RuntimeVariable {
                name: "SECRET_DESCRIPTION".to_string(),
                label: "Secret Description".to_string(),
                description: "Description of the secret".to_string(),
                example: "$SECRET_DESCRIPTION".to_string(),
                category: "secrets".to_string(),
            },
            RuntimeVariable {
                name: "SECRET_TAGS".to_string(),
                label: "Secret Tags".to_string(),
                description: "Comma-separated tags associated with the secret".to_string(),
                example: "$SECRET_TAGS".to_string(),
                category: "secrets".to_string(),
            },
            RuntimeVariable {
                name: "EVENT_TYPE".to_string(),
                label: "Event Type".to_string(),
                description: "Type of secret event (secret.created, secret.updated, secret.deleted)".to_string(),
                example: "$EVENT_TYPE".to_string(),
                category: "secrets".to_string(),
            },
        ],
    }
}

fn get_pipe_variables() -> RuntimeVariableCategory {
    RuntimeVariableCategory {
        category: "pipe".to_string(),
        label: "LLM Surface".to_string(),
        description: "Variables available when notifications are triggered from LLM Surface events".to_string(),
        variables: vec![
            RuntimeVariable {
                name: "SURFACE_ID".to_string(),
                label: "Pipe ID".to_string(),
                description: "Unique identifier of the pipe".to_string(),
                example: "$SURFACE_ID".to_string(),
                category: "pipe".to_string(),
            },
            RuntimeVariable {
                name: "SURFACE_NAME".to_string(),
                label: "Pipe Name".to_string(),
                description: "Display name of the pipe".to_string(),
                example: "$SURFACE_NAME".to_string(),
                category: "pipe".to_string(),
            },
            RuntimeVariable {
                name: "SURFACE_TYPE".to_string(),
                label: "Pipe Type".to_string(),
                description: "Type of pipe (llm)".to_string(),
                example: "$SURFACE_TYPE".to_string(),
                category: "pipe".to_string(),
            },
            RuntimeVariable {
                name: "SURFACE_PROVIDER".to_string(),
                label: "LLM Provider".to_string(),
                description: "LLM provider (openai, anthropic, azure_openai, bedrock, etc.)".to_string(),
                example: "$SURFACE_PROVIDER".to_string(),
                category: "pipe".to_string(),
            },
            RuntimeVariable {
                name: "SURFACE_MODEL".to_string(),
                label: "Model".to_string(),
                description: "LLM model being used".to_string(),
                example: "$SURFACE_MODEL".to_string(),
                category: "pipe".to_string(),
            },
            RuntimeVariable {
                name: "SURFACE_ENDPOINT".to_string(),
                label: "Endpoint URL".to_string(),
                description: "API endpoint URL".to_string(),
                example: "$SURFACE_ENDPOINT".to_string(),
                category: "pipe".to_string(),
            },
            RuntimeVariable {
                name: "PIPE_LISTEN_ADDRESS".to_string(),
                label: "Listen Address".to_string(),
                description: "Address where the pipe listens".to_string(),
                example: "$PIPE_LISTEN_ADDRESS".to_string(),
                category: "pipe".to_string(),
            },
            RuntimeVariable {
                name: "SURFACE_ROUTE".to_string(),
                label: "Route Path".to_string(),
                description: "Route path for the pipe".to_string(),
                example: "$SURFACE_ROUTE".to_string(),
                category: "pipe".to_string(),
            },
            RuntimeVariable {
                name: "PIPE_STATUS".to_string(),
                label: "Pipe Status".to_string(),
                description: "Current status of the pipe (enabled/disabled)".to_string(),
                example: "$PIPE_STATUS".to_string(),
                category: "pipe".to_string(),
            },
            RuntimeVariable {
                name: "TENANT_ID".to_string(),
                label: "Tenant ID".to_string(),
                description: "Tenant that owns the surface; absent for an appliance-global surface".to_string(),
                example: "$TENANT_ID".to_string(),
                category: "pipe".to_string(),
            },
            RuntimeVariable {
                name: "GOVERNANCE_ENABLED".to_string(),
                label: "Governance Enabled".to_string(),
                description: "Whether signed governance recording is enabled on the surface (true or false); sent with the surface lifecycle events".to_string(),
                example: "$GOVERNANCE_ENABLED".to_string(),
                category: "pipe".to_string(),
            },
            RuntimeVariable {
                name: "SURFACE_ENABLED".to_string(),
                label: "Pipe Enabled".to_string(),
                description: "Whether the pipe is enabled (true/false)".to_string(),
                example: "$SURFACE_ENABLED".to_string(),
                category: "pipe".to_string(),
            },
            RuntimeVariable {
                name: "EVENT_TYPE".to_string(),
                label: "Event Type".to_string(),
                description:
                    "Type of pipe event (pipe.created, pipe.updated, pipe.deleted, pipe.error, drift.detected, …)"
                        .to_string(),
                example: "$EVENT_TYPE".to_string(),
                category: "pipe".to_string(),
            },
            RuntimeVariable {
                name: "DRIFT_STATUS".to_string(),
                label: "Drift Status".to_string(),
                description: "Overall drift status of the surface when the event fired (drift for drift.detected; stable, warn or unknown for drift.resolved)".to_string(),
                example: "$DRIFT_STATUS".to_string(),
                category: "pipe".to_string(),
            },
            RuntimeVariable {
                name: "DRIFT_DIMENSION".to_string(),
                label: "Drift Dimension".to_string(),
                description: "The dimension that drifted furthest (e.g. Latency, Refusal rate)".to_string(),
                example: "$DRIFT_DIMENSION".to_string(),
                category: "pipe".to_string(),
            },
            RuntimeVariable {
                name: "DRIFT_BASELINE".to_string(),
                label: "Drift Baseline".to_string(),
                description: "The baseline mean for the drifted dimension".to_string(),
                example: "$DRIFT_BASELINE".to_string(),
                category: "pipe".to_string(),
            },
            RuntimeVariable {
                name: "DRIFT_CURRENT".to_string(),
                label: "Drift Current".to_string(),
                description: "The current-window mean for the drifted dimension".to_string(),
                example: "$DRIFT_CURRENT".to_string(),
                category: "pipe".to_string(),
            },
            RuntimeVariable {
                name: "DRIFT_DELTA".to_string(),
                label: "Drift Delta".to_string(),
                description: "Current minus baseline for the drifted dimension".to_string(),
                example: "$DRIFT_DELTA".to_string(),
                category: "pipe".to_string(),
            },
        ],
    }
}

fn get_llm_governance_variables() -> RuntimeVariableCategory {
    let cat = "llm_governance";
    let var = |name: &str, label: &str, description: &str, example: &str| RuntimeVariable {
        name: name.to_string(),
        label: label.to_string(),
        description: description.to_string(),
        example: example.to_string(),
        category: cat.to_string(),
    };
    RuntimeVariableCategory {
        category: cat.to_string(),
        label: "LLM Governance".to_string(),
        description: "Variables available when a signed governance record is exported from an LLM surface".to_string(),
        variables: vec![
            var("RECORD_ID", "Record ID", "Unique identifier of the signed governance record", "$RECORD_ID"),
            var("SURFACE_ID", "Surface ID", "Identifier of the LLM surface the record was captured on", "$SURFACE_ID"),
            var(
                "SURFACE_NAME",
                "Surface Name",
                "Display name of the LLM surface the record was captured on",
                "$SURFACE_NAME",
            ),
            var("CONTENT_HASH", "Content Hash", "SHA-256 content hash of the record (sha256:… hex)", "$CONTENT_HASH"),
            var(
                "PREV_RECORD_HASH",
                "Previous Record Hash",
                "Content hash of the previous record in the per-surface chain",
                "$PREV_RECORD_HASH",
            ),
            var(
                "CREDENTIAL",
                "Signed Credential",
                "The full signed W3C Verifiable Credential (JSON) for the record",
                "${CREDENTIAL}",
            ),
            var(
                "RECORD",
                "Record",
                "The full governance record (JSON), including stages, prompt/completion digests, and metrics",
                "${RECORD}",
            ),
            var("EVENT_TYPE", "Event Type", "The governance export event type (governance.record)", "$EVENT_TYPE"),
        ],
    }
}

fn get_llm_drift_variables() -> RuntimeVariableCategory {
    let cat = "llm_drift";
    let var = |name: &str, label: &str, description: &str, example: &str| RuntimeVariable {
        name: name.to_string(),
        label: label.to_string(),
        description: description.to_string(),
        example: example.to_string(),
        category: cat.to_string(),
    };
    RuntimeVariableCategory {
        category: cat.to_string(),
        label: "LLM Drift".to_string(),
        description: "Variables available when an LLM surface drifts past its baseline (drift.detected) or leaves drift (drift.resolved)"
            .to_string(),
        variables: vec![
            var("SURFACE_ID", "Surface ID", "Identifier of the LLM surface that drifted", "$SURFACE_ID"),
            var("SURFACE_NAME", "Surface Name", "Display name of the LLM surface that drifted", "$SURFACE_NAME"),
            var(
                "DRIFT_STATUS",
                "Drift Status",
                "Overall drift status of the surface when the event fired (drift for drift.detected; stable, warn or unknown for drift.resolved)",
                "$DRIFT_STATUS",
            ),
            var(
                "DRIFT_DIMENSION",
                "Drift Dimension",
                "The dimension that drifted furthest (e.g. Latency, Refusal rate)",
                "$DRIFT_DIMENSION",
            ),
            var("DRIFT_BASELINE", "Drift Baseline", "The baseline mean for the drifted dimension", "$DRIFT_BASELINE"),
            var(
                "DRIFT_CURRENT",
                "Drift Current",
                "The current-window mean for the drifted dimension",
                "$DRIFT_CURRENT",
            ),
            var("DRIFT_DELTA", "Drift Delta", "Current minus baseline for the drifted dimension", "$DRIFT_DELTA"),
            var("EVENT_TYPE", "Event Type", "The drift event type (drift.detected or drift.resolved)", "$EVENT_TYPE"),
        ],
    }
}

fn get_audit_variables() -> RuntimeVariableCategory {
    let cat = "audit";
    let var = |name: &str, label: &str, description: &str| RuntimeVariable {
        name: name.to_string(),
        label: label.to_string(),
        description: description.to_string(),
        example: format!("${{{}}}", name),
        category: cat.to_string(),
    };
    RuntimeVariableCategory {
        category: cat.to_string(),
        label: "Governance Audit".to_string(),
        description: "Variables available when a governance audit record is written to the VP Audit Log".to_string(),
        variables: vec![
            var(
                "AUDIT_RECORD",
                "Audit Record",
                "The complete audit record as JSON, in the same shape as a VP Audit Log entry. Used as an entire JSON string value (\"record\": \"${AUDIT_RECORD}\") it is embedded as a JSON object; inside other text it is inserted as JSON text.",
            ),
            var(
                "AUDIT_CATEGORY",
                "Audit Category",
                "Category of the audit record (policy_decision, audit_configuration_changed, vp_injected, token_injected, consent_granted, …). EVENT_TYPE carries the same value as audit.<category>.",
            ),
            var(
                "AUDIT_TRACE_ID",
                "Trace ID",
                "Request trace ID that correlates every record written for the same request",
            ),
            var("AUDIT_SURFACE_ID", "Surface ID", "ID of the Surface the record belongs to"),
            var("AUDIT_SURFACE_NAME", "Surface Name", "Name of the Surface the record belongs to, when recorded"),
            var("AUDIT_PROTOCOL", "Protocol", "Protocol of the surface (a2a, mcp, …), when recorded"),
            var("AUDIT_AGENT_DID", "Agent DID", "DID of the agent the record was written for, when recorded"),
            var(
                "AUDIT_VIA_FABRIC",
                "Via Fabric",
                "true when the request traversed the gateway-to-gateway fabric, otherwise false",
            ),
            var(
                "AUDIT_PRINCIPAL",
                "Principal",
                "The authenticated caller of a policy_decision record: the JWT subject, API key name or mTLS principal. Empty without an authenticated caller.",
            ),
            var(
                "AUDIT_PRINCIPAL_EMAIL",
                "Principal Email",
                "Always empty: Agent Stream records no caller email. Offered so one template serves Agent Stream and Agent Gateway.",
            ),
            var(
                "AUDIT_PRINCIPAL_NAME",
                "Principal Name",
                "Always empty: Agent Stream records no caller display name. Offered so one template serves Agent Stream and Agent Gateway.",
            ),
            var(
                "AUDIT_AUTH_METHOD",
                "Auth Method",
                "How the caller of a policy_decision record authenticated (jwt_bearer, api_key, mtls); empty without an authenticated caller",
            ),
            var(
                "AUDIT_DECISION",
                "Policy Decision",
                "Policy decision (allow, deny, error or missing_engine) for policy_decision records; empty for other categories",
            ),
            var(
                "AUDIT_DENY_REASON",
                "Deny Reason",
                "Reason reported for a policy_decision record that did not allow; empty otherwise",
            ),
            var(
                "AUDIT_POLICY_NAME",
                "Policy Name",
                "Name of the policy that made the decision (its policy definition name, else its Rego query) for policy_decision records; empty otherwise",
            ),
            var(
                "AUDIT_POLICY_VERSION",
                "Policy Version",
                "Version of the enforced policy revision for policy_decision records, when the policy is versioned",
            ),
            var(
                "AUDIT_POLICY_CONTENT_HASH",
                "Policy Content Hash",
                "sha256:<hex> hash of the exact Rego enforced for policy_decision records, when known",
            ),
            var("AUDIT_VP_JWT", "Signed VP", "Signed Verifiable Presentation (JWT) attached to the record"),
            var(
                "AUDIT_VP_FINGERPRINT",
                "VP Fingerprint",
                "sha256:<hex> fingerprint of the signed VP attached to the record",
            ),
            var("EVENT_TYPE", "Event Type", "The audit event type, audit.<category>"),
        ],
    }
}

/// Get list of variable names for a specific category (for validation)
pub fn get_variable_names_for_category(category: &str) -> Vec<String> {
    let all_vars = get_runtime_variables();

    // For 'general' category, only return general variables
    // For other categories, return general + category-specific variables
    let mut variable_names = Vec::new();

    // Add general variables
    if let Some(general_category) = all_vars
        .categories
        .iter()
        .find(|c| c.category == "general")
    {
        variable_names.extend(
            general_category
                .variables
                .iter()
                .map(|v| v.name.clone()),
        );
    }

    // Add category-specific variables (unless category is 'general')
    if category != "general"
        && let Some(specific_category) = all_vars
            .categories
            .iter()
            .find(|c| c.category == category)
    {
        variable_names.extend(
            specific_category
                .variables
                .iter()
                .map(|v| v.name.clone()),
        );
    }

    variable_names
}

/// Validate that all runtime variables in a template are valid for the given category
/// Returns a list of invalid variable names (runtime vars that don't exist for this category)
/// Custom variables (starting with _) are always considered valid
pub fn validate_template_variables(
    template: &str,
    category: &str,
) -> Vec<String> {
    let allowed_variables = get_variable_names_for_category(category);

    let custom_prefix = current_custom_prefix();
    let re = current_variable_regex();

    let mut invalid_vars = Vec::new();

    for cap in re.captures_iter(template) {
        let Some(var_name) = variable_name_from_capture(&cap) else {
            continue;
        };

        // Custom variables (start with custom prefix) are always valid
        if var_name.starts_with(&custom_prefix) {
            continue;
        }

        // Check if runtime variable is in allowed list
        if !allowed_variables
            .iter()
            .any(|v| v == var_name)
            && !invalid_vars
                .iter()
                .any(|v| v == var_name)
        {
            invalid_vars.push(var_name.to_string());
        }
    }

    invalid_vars
}

/// Substitute runtime variables in a template string
///
/// This function replaces ${VARIABLE_NAME} placeholders with actual values
/// from the provided HashMap. Also supports ${VARIABLE:Label} format where :Label is ignored.
///
/// Variables are categorized as:
/// - Runtime variables: Validated against category allowed list
/// - Custom variables: Start with underscore (${_MY_VAR}) - always allowed, not validated
///
/// If category is None, all variables from the HashMap will be substituted regardless of category.
pub fn substitute_variables(
    template: &str,
    category: Option<&str>,
    values: &HashMap<String, String>,
) -> String {
    let mut result = template.to_string();

    // Get variable names for the category if specified
    let allowed_variables: Option<Vec<String>> = category.map(get_variable_names_for_category);

    let custom_prefix = current_custom_prefix();
    let re = current_variable_regex();

    // Collect all matches first to avoid issues with multiple replacements
    let mut replacements = Vec::new();
    for cap in re.captures_iter(template) {
        let Some(var_name) = variable_name_from_capture(&cap) else {
            continue;
        };
        let placeholder = &cap[0];

        // Custom variables (start with custom prefix) are always allowed
        let is_custom = var_name.starts_with(&custom_prefix);

        // Check if this variable is allowed for the category
        let is_allowed = is_custom
            || allowed_variables
                .as_ref()
                .map(|vars| {
                    vars.iter()
                        .any(|v| v == var_name)
                })
                .unwrap_or(true); // If no category specified, allow all

        if !is_allowed {
            continue;
        }
        if let Some(value) = variable_value(var_name, values) {
            replacements.push((placeholder.to_string(), value));
        }
    }

    // Apply all replacements
    for (placeholder, value) in replacements {
        result = result.replace(&placeholder, &value);
    }

    result
}

/// The structured value for a template string that consists of exactly one
/// JSON-valued variable placeholder allowed in `category`, or `None` when the
/// string should be substituted as text.
fn embedded_json_value(
    template: &str,
    category: Option<&str>,
    values: &HashMap<String, String>,
) -> Option<serde_json::Value> {
    let re = current_variable_regex();
    let cap = re.captures(template)?;
    if cap.get(0)?.as_str() != template {
        return None;
    }
    let var_name = variable_name_from_capture(&cap)?;
    if !JSON_VALUED_VARIABLES.contains(&var_name) {
        return None;
    }
    if let Some(category) = category
        && !get_variable_names_for_category(category)
            .iter()
            .any(|name| name == var_name)
    {
        return None;
    }
    serde_json::from_str(values.get(var_name)?).ok()
}

/// Substitute variables in a JSON value structure (recursive, JSON-safe)
/// This preserves the JSON structure and properly handles special characters
pub fn substitute_variables_in_json(
    value: &serde_json::Value,
    category: Option<&str>,
    variables: &HashMap<String, String>,
) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => embedded_json_value(s, category, variables)
            .unwrap_or_else(|| serde_json::Value::String(substitute_variables(s, category, variables))),
        serde_json::Value::Array(arr) => {
            // Recursively process array elements
            serde_json::Value::Array(
                arr.iter()
                    .map(|item| substitute_variables_in_json(item, category, variables))
                    .collect(),
            )
        }
        serde_json::Value::Object(obj) => {
            // Recursively process object values
            serde_json::Value::Object(
                obj.iter()
                    .map(|(k, v)| (k.clone(), substitute_variables_in_json(v, category, variables)))
                    .collect(),
            )
        }
        // Numbers, booleans, and null are returned as-is
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_runtime_variables() {
        let vars = get_runtime_variables();
        assert!(!vars.categories.is_empty());

        // Check that connection_point category exists
        let cp_category = vars
            .categories
            .iter()
            .find(|c| c.category == "connection_point");
        assert!(cp_category.is_some_and(|category| !category.variables.is_empty()));
    }

    #[test]
    fn test_get_variable_names_for_category() {
        let names = get_variable_names_for_category("user");
        assert!(names.contains(&"USER_ID".to_string()));
        assert!(names.contains(&"USERNAME".to_string()));
        assert!(names.contains(&"USER_EMAIL".to_string()));
    }

    #[test]
    fn test_substitute_variables() {
        let mut values = HashMap::new();
        values.insert("USER_ID".to_string(), "user_123".to_string());
        values.insert("USERNAME".to_string(), "john.doe".to_string());
        values.insert("USER_EMAIL".to_string(), "john@example.com".to_string());

        let template = "User ${USER_ID} (${USERNAME}) has email ${USER_EMAIL}";
        let result = substitute_variables(template, Some("user"), &values);

        assert_eq!(result, "User user_123 (john.doe) has email john@example.com");
    }

    #[test]
    fn appliance_id_is_a_general_variable_for_every_category() {
        assert!(get_variable_names_for_category("general").contains(&APPLIANCE_ID_VARIABLE.to_string()));
        assert!(get_variable_names_for_category("audit").contains(&APPLIANCE_ID_VARIABLE.to_string()));
        assert!(validate_template_variables("${APPLIANCE_ID}", "llm_governance").is_empty());
    }

    #[test]
    fn appliance_id_comes_only_from_the_configured_id() {
        let mut values = HashMap::new();
        values.insert(APPLIANCE_ID_VARIABLE.to_string(), "forged-appliance".to_string());
        values.insert("EVENT_TYPE".to_string(), "user.created".to_string());

        assert_eq!(
            variable_value_with(APPLIANCE_ID_VARIABLE, &values, || Some("aw-appliance-42".to_string())),
            Some("aw-appliance-42".to_string())
        );
        assert_eq!(variable_value_with(APPLIANCE_ID_VARIABLE, &values, || None), None);
        assert_eq!(
            variable_value_with("EVENT_TYPE", &values, || Some("aw-appliance-42".to_string())),
            Some("user.created".to_string())
        );
    }

    #[test]
    fn unset_appliance_id_stays_unfilled_even_when_a_value_is_supplied() {
        let mut values = HashMap::new();
        values.insert(APPLIANCE_ID_VARIABLE.to_string(), "forged-appliance".to_string());
        values.insert("EVENT_TYPE".to_string(), "user.created".to_string());

        let text = substitute_variables("${APPLIANCE_ID} sent ${EVENT_TYPE}", Some("user"), &values);
        assert_eq!(text, "${APPLIANCE_ID} sent user.created");

        let json =
            substitute_variables_in_json(&serde_json::json!({ "appliance_id": "${APPLIANCE_ID}" }), None, &values);
        assert_eq!(json, serde_json::json!({ "appliance_id": "${APPLIANCE_ID}" }));
    }

    #[test]
    fn test_substitute_variables_with_labels() {
        let mut values = HashMap::new();
        values.insert("USER_ID".to_string(), "user_456".to_string());

        let template = "User ID: ${USER_ID:User Identifier}";
        let result = substitute_variables(template, Some("user"), &values);

        assert_eq!(result, "User ID: user_456");
    }

    #[test]
    fn test_substitute_variables_dollar_format() {
        let mut values = HashMap::new();
        values.insert("USERNAME".to_string(), "jane".to_string());

        let template = "Welcome $USERNAME!";
        let result = substitute_variables(template, Some("user"), &values);

        assert_eq!(result, "Welcome jane!");
    }

    #[test]
    fn test_substitute_variables_in_json() {
        let mut values = HashMap::new();
        values.insert("USER_ID".to_string(), "user_123".to_string());
        values.insert("USERNAME".to_string(), "John \"The Boss\" Doe".to_string());
        values.insert("_MESSAGE".to_string(), "Hello\nWorld".to_string());

        let json_template = serde_json::json!({
            "user_id": "${USER_ID}",
            "username": "${USERNAME}",
            "message": "${_MESSAGE}",
            "nested": {
                "value": "${USER_ID}"
            },
            "array": ["${USERNAME}", "static"]
        });

        let result = substitute_variables_in_json(&json_template, Some("user"), &values);

        assert_eq!(result["user_id"], "user_123");
        assert_eq!(result["username"], "John \"The Boss\" Doe");
        assert_eq!(result["message"], "Hello\nWorld");
        assert_eq!(result["nested"]["value"], "user_123");
        assert_eq!(result["array"][0], "John \"The Boss\" Doe");
        assert_eq!(result["array"][1], "static");
    }

    #[test]
    fn test_substitute_variables_in_dollar_format() {
        let mut values = HashMap::new();
        values.insert("USERNAME".to_string(), "jane".to_string());

        let template = "Welcome $USERNAME!";
        let result = substitute_variables(template, Some("user"), &values);

        assert_eq!(result, "Welcome jane!");
    }

    #[test]
    fn test_substitute_variables_missing_value() {
        let mut values = HashMap::new();
        values.insert("USER_ID".to_string(), "user_123".to_string());

        let template = "User ${USER_ID} (${USERNAME})";
        let result = substitute_variables(template, Some("user"), &values);

        // Variables without values should remain unchanged
        assert_eq!(result, "User user_123 (${USERNAME})");
    }

    #[test]
    fn test_substitute_variables_no_category_restriction() {
        let mut values = HashMap::new();
        values.insert("CUSTOM_VAR".to_string(), "custom_value".to_string());

        let template = "Value: ${CUSTOM_VAR}";
        let result = substitute_variables(template, None, &values);

        assert_eq!(result, "Value: custom_value");
    }

    fn audit_values() -> HashMap<String, String> {
        HashMap::from([
            ("EVENT_TYPE".to_string(), "audit.policy_decision".to_string()),
            ("AUDIT_TRACE_ID".to_string(), "trace-1".to_string()),
            (
                "AUDIT_RECORD".to_string(),
                r#"{"event":{"policy_decision":{"decision":"deny"}},"trace_id":"trace-1"}"#.to_string(),
            ),
            ("OLD_STATE".to_string(), r#"{"id":"p-1"}"#.to_string()),
        ])
    }

    #[test]
    fn audit_category_variables_are_valid_for_audit_templates() {
        let template = r#"{"type": "${EVENT_TYPE}", "trace": "${AUDIT_TRACE_ID}", "record": "${AUDIT_RECORD}"}"#;
        assert!(validate_template_variables(template, "audit").is_empty());
        assert_eq!(validate_template_variables(template, "pipe"), vec!["AUDIT_TRACE_ID", "AUDIT_RECORD"]);
        assert_eq!(validate_template_variables("${SURFACE_ID}", "audit"), vec!["SURFACE_ID"]);
    }

    #[test]
    fn json_valued_variable_is_embedded_as_structured_json() {
        let template = serde_json::json!({
            "event_type": "${EVENT_TYPE}",
            "record": "${AUDIT_RECORD}",
            "labelled": "${AUDIT_RECORD:Audit record}",
            "nested": ["${AUDIT_RECORD}"],
        });
        let result = substitute_variables_in_json(&template, Some("audit"), &audit_values());

        let record = serde_json::json!({"event": {"policy_decision": {"decision": "deny"}}, "trace_id": "trace-1"});
        assert_eq!(result["event_type"], "audit.policy_decision");
        assert_eq!(result["record"], record);
        assert_eq!(result["labelled"], record);
        assert_eq!(result["nested"][0], record);
    }

    #[test]
    fn json_valued_variable_inside_text_or_outside_its_category_stays_text() {
        let raw = r#"{"event":{"policy_decision":{"decision":"deny"}},"trace_id":"trace-1"}"#;
        let template = serde_json::json!({"summary": "Record: ${AUDIT_RECORD}", "old": "${OLD_STATE}"});
        let result = substitute_variables_in_json(&template, Some("audit"), &audit_values());
        assert_eq!(result["summary"], format!("Record: {raw}"));
        assert_eq!(result["old"], r#"{"id":"p-1"}"#, "OLD_STATE keeps its string form");

        let template = serde_json::json!({"record": "${AUDIT_RECORD}"});
        let result = substitute_variables_in_json(&template, Some("pipe"), &audit_values());
        assert_eq!(result["record"], "${AUDIT_RECORD}");

        let mut values = audit_values();
        values.insert("AUDIT_RECORD".to_string(), "not json".to_string());
        let result = substitute_variables_in_json(&template, Some("audit"), &values);
        assert_eq!(result["record"], "not json");
    }
}
