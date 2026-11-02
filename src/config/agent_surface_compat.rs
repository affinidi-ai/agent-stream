//! Identity-injection helpers shared between `AgentSurface` and the legacy
//! `ManagedIdentityConfig` shape still consumed by the proxy pipeline.

use crate::config::agent_surface::IdentityInjectionConfig;
/// Map the surface's `target.identity_injection` to the legacy
/// `ManagedIdentityConfig` the proxy pipeline still consumes. All four
/// extraction strategies the UI exposes (`from_payload`, `from_api_key`,
/// `from_mtls`, `static`) are persisted faithfully so user configuration
/// is not silently dropped on round-trip; runtime support for the
/// non-payload variants is wired in incrementally.
pub(crate) fn identity_injection_to_managed_identity(
    ii: &IdentityInjectionConfig
) -> Option<crate::source_auth::ManagedIdentityConfig> {
    use crate::source_auth::ManagedIdentityConfig;
    use crate::source_auth::models::PayloadExtractionConfig;

    let kind = ii.identity_type.as_deref()?;
    match kind {
        "from_payload" => {
            let meta_field = ii
                .meta_field
                .clone()
                .filter(|s| !s.is_empty())?;
            let extension_rules = ii
                .json_schema
                .as_ref()
                .map(|schema| crate::config::ExtensionRules {
                    json_schema: Some(schema.clone()),
                    rules: vec![],
                });
            Some(ManagedIdentityConfig::PayloadExtraction(PayloadExtractionConfig {
                meta_field,
                fields: ii.fields.clone(),
                json_schema: ii.json_schema.clone(),
                extension_rules,
                strip_raw_meta: ii.strip_raw_meta,
            }))
        }
        "from_api_key" => {
            let api_key_id = ii
                .api_key_id
                .clone()
                .filter(|s| !s.is_empty())?;
            Some(ManagedIdentityConfig::FromApiKey { api_key_id })
        }
        "from_mtls" => {
            let certificate_id = ii
                .certificate_id
                .clone()
                .filter(|s| !s.is_empty())?;
            Some(ManagedIdentityConfig::FromMtls { certificate_id })
        }
        "static" => {
            let did = ii
                .static_did
                .clone()
                .filter(|s| !s.is_empty())?;
            Some(ManagedIdentityConfig::Static { did })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    // ── identity_injection_to_managed_identity ───────────────────────────────

    #[test]
    fn test_identity_injection_json_schema_forwarded_to_extension_rules() {
        use crate::config::agent_surface::IdentityInjectionConfig;
        use crate::source_auth::ManagedIdentityConfig;

        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "agentIdentity": {
                    "type": "object",
                    "properties": {
                        "llmInfo": {
                            "type": "object",
                            "properties": {
                                "provider": { "type": "string", "x-identity": true }
                            }
                        }
                    }
                }
            }
        });

        let ii = IdentityInjectionConfig {
            inject_vp: true,
            identity_type: Some("from_payload".to_string()),
            meta_field: Some("agentIdentity".to_string()),
            json_schema: Some(schema.clone()),
            ..Default::default()
        };

        let result = super::identity_injection_to_managed_identity(&ii);
        let Some(ManagedIdentityConfig::PayloadExtraction(cfg)) = result else {
            panic!("expected PayloadExtraction");
        };
        assert_eq!(cfg.meta_field, "agentIdentity");
        let ext_rules = cfg
            .extension_rules
            .expect("extension_rules must be Some when json_schema is set");
        assert_eq!(ext_rules.json_schema.as_ref(), Some(&schema));
        assert!(ext_rules.rules.is_empty());
    }

    #[test]
    fn test_identity_injection_no_json_schema_gives_no_extension_rules() {
        use crate::config::agent_surface::IdentityInjectionConfig;
        use crate::source_auth::ManagedIdentityConfig;

        let ii = IdentityInjectionConfig {
            inject_vp: false,
            identity_type: Some("from_payload".to_string()),
            meta_field: Some("agentIdentity".to_string()),
            json_schema: None,
            ..Default::default()
        };

        let result = super::identity_injection_to_managed_identity(&ii);
        let Some(ManagedIdentityConfig::PayloadExtraction(cfg)) = result else {
            panic!("expected PayloadExtraction");
        };
        assert!(cfg.extension_rules.is_none());
    }
}
