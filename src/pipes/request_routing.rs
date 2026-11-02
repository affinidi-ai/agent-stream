//! Per-request routing preferences (OpenRouter-style `models: [...]` and
//! `provider: { order, only, ignore, allow_fallbacks, sort, max_price }`),
//! **bounded to the surface's configured candidate pool**.
//!
//! Agent Stream surfaces carry their own provider keys, so a caller cannot add
//! arbitrary providers the way OpenRouter does. Instead these preferences
//! **filter and reorder the pool the surface already offers** — its primary
//! provider plus any failover / load-balancing targets. The caller can narrow
//! or reorder, never widen beyond what the operator configured, so the pool is
//! itself the governance boundary. See `docs/INFERENCE_CONTROLS.md`.

use serde_json::Value;

use crate::pipes::judge_jury::LLMTarget;

/// A per-request ceiling on catalog price (USD per 1k tokens).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MaxPrice {
    pub prompt: Option<f64>,
    pub completion: Option<f64>,
}

/// Parsed per-request routing preferences.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RoutingPreferences {
    /// Preferred models, in priority order (filters + orders the pool by model).
    pub models: Vec<String>,
    /// Preferred provider order (provider_type, case-insensitive).
    pub order: Vec<String>,
    /// Allow-list of provider types; when set, only these are eligible.
    pub only: Vec<String>,
    /// Deny-list of provider types.
    pub ignore: Vec<String>,
    /// Whether to try candidates beyond the first. Defaults to true.
    pub allow_fallbacks: bool,
    /// Ordering strategy: `price` (catalog), `latency`, or `throughput`.
    pub sort: Option<String>,
    /// Drop candidates whose catalog price exceeds this ceiling.
    pub max_price: Option<MaxPrice>,
}

/// One candidate in the surface's routing pool. `target: None` is the surface's
/// own primary provider (run via the primary path); `Some` is a failover /
/// load-balancing target (run via `clone_with_failover_target`).
#[derive(Debug, Clone)]
pub struct RoutingCandidate {
    pub provider_type: String,
    pub model: String,
    pub target: Option<LLMTarget>,
}

/// Parse per-request routing preferences from the request body, or `None` when
/// neither `models` nor `provider` is present.
pub fn parse(body: &Value) -> Option<RoutingPreferences> {
    let models: Vec<String> = body
        .get("models")
        .and_then(|m| m.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    let provider = body
        .get("provider")
        .and_then(|p| p.as_object());

    if models.is_empty() && provider.is_none() {
        return None;
    }

    let str_list = |key: &str| -> Vec<String> {
        provider
            .and_then(|p| p.get(key))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };

    let allow_fallbacks = provider
        .and_then(|p| p.get("allow_fallbacks"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let sort = provider
        .and_then(|p| p.get("sort"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let max_price = provider
        .and_then(|p| p.get("max_price"))
        .map(|mp| MaxPrice {
            prompt: mp
                .get("prompt")
                .and_then(|v| v.as_f64()),
            completion: mp
                .get("completion")
                .and_then(|v| v.as_f64()),
        })
        .filter(|mp| mp.prompt.is_some() || mp.completion.is_some());

    Some(RoutingPreferences {
        models,
        order: str_list("order"),
        only: str_list("only"),
        ignore: str_list("ignore"),
        allow_fallbacks,
        sort,
        max_price,
    })
}

/// Remove the routing-preference fields from the body so they never reach an
/// upstream provider.
pub fn strip_routing_fields(body: &mut Value) {
    if let Some(obj) = body.as_object_mut() {
        obj.remove("models");
        obj.remove("provider");
    }
}

/// True when a requested model matches a candidate's model. Accepts an exact
/// (case-insensitive) match or an OpenRouter-style `vendor/model` slug whose
/// trailing segment matches.
fn model_matches(
    requested: &str,
    candidate_model: &str,
) -> bool {
    let requested_leaf = requested
        .rsplit('/')
        .next()
        .unwrap_or(requested);
    requested.eq_ignore_ascii_case(candidate_model) || requested_leaf.eq_ignore_ascii_case(candidate_model)
}

/// Index of the first `order`/`models` entry that matches a candidate, used as a
/// stable sort key. Non-matching candidates sort last (keeping pool order).
fn preference_rank(
    keys: &[String],
    value: &str,
    is_model: bool,
) -> usize {
    keys.iter()
        .position(|k| {
            if is_model {
                model_matches(k, value)
            } else {
                k.eq_ignore_ascii_case(value)
            }
        })
        .unwrap_or(usize::MAX)
}

/// Filter and order the pool by the caller's `only` / `ignore` / `models`
/// filters and `order` / `models` ordering. Pure; catalog-driven `sort` and
/// `max_price` are applied separately by the executor. `allow_fallbacks` is not
/// applied here (it truncates after sorting).
pub fn filter_and_order(
    prefs: &RoutingPreferences,
    pool: Vec<RoutingCandidate>,
) -> Vec<RoutingCandidate> {
    let mut candidates = pool;

    if !prefs.only.is_empty() {
        candidates.retain(|c| {
            prefs
                .only
                .iter()
                .any(|p| p.eq_ignore_ascii_case(&c.provider_type))
        });
    }
    if !prefs.ignore.is_empty() {
        candidates.retain(|c| {
            !prefs
                .ignore
                .iter()
                .any(|p| p.eq_ignore_ascii_case(&c.provider_type))
        });
    }
    if !prefs.models.is_empty() {
        candidates.retain(|c| {
            prefs
                .models
                .iter()
                .any(|m| model_matches(m, &c.model))
        });
    }

    // Order by explicit provider `order`, else by `models` order; stable so
    // equal-rank candidates keep their configured pool position.
    if !prefs.order.is_empty() {
        candidates.sort_by_key(|c| preference_rank(&prefs.order, &c.provider_type, false));
    } else if !prefs.models.is_empty() {
        candidates.sort_by_key(|c| preference_rank(&prefs.models, &c.model, true));
    }

    candidates
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cand(
        provider: &str,
        model: &str,
        primary: bool,
    ) -> RoutingCandidate {
        RoutingCandidate {
            provider_type: provider.to_string(),
            model: model.to_string(),
            target: if primary {
                None
            } else {
                Some(LLMTarget {
                    provider_type: provider.to_string(),
                    model: model.to_string(),
                    endpoint_url: String::new(),
                    api_key_secret: None,
                    parameters: None,
                    timeout_secs: 30,
                    capabilities: None,
                    api_schema: provider.to_string(),
                    headers: Vec::new(),
                    pricing: None,
                })
            },
        }
    }

    fn pool() -> Vec<RoutingCandidate> {
        vec![
            cand("openai", "gpt-4o", true),
            cand("anthropic", "claude-haiku-4-5", false),
            cand("gemini", "gemini-2.0-flash", false),
        ]
    }

    #[test]
    fn parse_none_without_fields() {
        assert!(parse(&json!({ "messages": [] })).is_none());
    }

    #[test]
    fn parse_models_and_provider() {
        let prefs = parse(&json!({
            "models": ["anthropic/claude-haiku-4-5", "gpt-4o"],
            "provider": { "only": ["anthropic", "openai"], "allow_fallbacks": false, "sort": "price" }
        }))
        .unwrap();
        assert_eq!(prefs.models, vec!["anthropic/claude-haiku-4-5", "gpt-4o"]);
        assert_eq!(prefs.only, vec!["anthropic", "openai"]);
        assert!(!prefs.allow_fallbacks);
        assert_eq!(prefs.sort.as_deref(), Some("price"));
    }

    #[test]
    fn parse_defaults_allow_fallbacks_true() {
        let prefs = parse(&json!({ "provider": { "order": ["openai"] } })).unwrap();
        assert!(prefs.allow_fallbacks);
    }

    #[test]
    fn parse_max_price() {
        let prefs = parse(&json!({ "provider": { "max_price": { "prompt": 5, "completion": 15 } } })).unwrap();
        let mp = prefs.max_price.unwrap();
        assert_eq!(mp.prompt, Some(5.0));
        assert_eq!(mp.completion, Some(15.0));
    }

    #[test]
    fn strip_removes_fields() {
        let mut body = json!({ "model": "x", "models": ["a"], "provider": { "only": ["openai"] } });
        strip_routing_fields(&mut body);
        assert!(body.get("models").is_none());
        assert!(body.get("provider").is_none());
        assert_eq!(body["model"], json!("x"));
    }

    #[test]
    fn only_keeps_allowed_providers() {
        let prefs = RoutingPreferences {
            only: vec!["anthropic".into()],
            allow_fallbacks: true,
            ..Default::default()
        };
        let out = filter_and_order(&prefs, pool());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].provider_type, "anthropic");
    }

    #[test]
    fn ignore_drops_providers() {
        let prefs = RoutingPreferences {
            ignore: vec!["openai".into()],
            allow_fallbacks: true,
            ..Default::default()
        };
        let out = filter_and_order(&prefs, pool());
        assert_eq!(out.len(), 2);
        assert!(
            out.iter()
                .all(|c| c.provider_type != "openai")
        );
    }

    #[test]
    fn order_reorders_by_provider() {
        let prefs = RoutingPreferences {
            order: vec!["gemini".into(), "openai".into()],
            allow_fallbacks: true,
            ..Default::default()
        };
        let out = filter_and_order(&prefs, pool());
        // gemini first, openai second, anthropic (unranked) last.
        assert_eq!(out[0].provider_type, "gemini");
        assert_eq!(out[1].provider_type, "openai");
        assert_eq!(out[2].provider_type, "anthropic");
    }

    #[test]
    fn models_filters_and_orders_with_slug() {
        let prefs = RoutingPreferences {
            models: vec!["anthropic/claude-haiku-4-5".into(), "gpt-4o".into()],
            allow_fallbacks: true,
            ..Default::default()
        };
        let out = filter_and_order(&prefs, pool());
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].model, "claude-haiku-4-5");
        assert_eq!(out[1].model, "gpt-4o");
    }

    #[test]
    fn filters_can_empty_the_pool() {
        let prefs = RoutingPreferences {
            only: vec!["cohere".into()],
            allow_fallbacks: true,
            ..Default::default()
        };
        assert!(filter_and_order(&prefs, pool()).is_empty());
    }
}
