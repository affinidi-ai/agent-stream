//! Governed server-side tools: `web_search` and `web_fetch`.
//!
//! Unlike a plain tool schema (which the caller's app must execute), these tools
//! are executed **by the appliance itself** inside the request: the model emits a tool
//! call, the gateway runs the search/fetch under governance (OPA, per-surface
//! domain allow/deny, SSRF guard, metering, governance recording), injects the
//! result, and re-invokes the model. This module holds the config, the tool
//! schema, the call detection, the domain guard, the pluggable search engines
//! (request builders + response parsers), and result/citation formatting. The
//! HTTP execution and the bounded agentic loop live in the executor.
//!
//! See `docs/INFERENCE_CONTROLS.md`.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const WEB_SEARCH_TOOL: &str = "web_search";
pub const WEB_FETCH_TOOL: &str = "web_fetch";

fn default_max_iterations() -> u32 {
    3
}
fn default_max_results() -> u32 {
    5
}
fn default_max_content_bytes() -> usize {
    60_000
}
fn default_search_engine() -> String {
    "tavily".to_string()
}

/// Domain-policy baseline for a governed web tool. The exception list
/// (`domain_exceptions`) is read against this baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DomainPolicy {
    /// Allow every domain **except** those listed (a block-list). Default.
    #[default]
    AllowAll,
    /// Block every domain **except** those listed (an allow-list).
    BlockAll,
}

/// Per-surface server-tools configuration (off by default).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ServerToolsConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Maximum model⇄tool round-trips before the loop stops (bounds cost/latency).
    #[serde(default = "default_max_iterations")]
    pub max_iterations: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web_search: Option<WebSearchConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web_fetch: Option<WebFetchConfig>,
}

/// `web_search` tool config: which engine + key, result cap, domain policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebSearchConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Search engine id: `tavily`, `brave`, or `google`.
    #[serde(default = "default_search_engine")]
    pub engine: String,
    /// Secret id holding the engine API key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_secret: Option<String>,
    #[serde(default = "default_max_results")]
    pub max_results: u32,
    /// Google Programmable Search Engine id (`cx`), required for the `google` engine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub google_cse_id: Option<String>,
    /// Domain-policy baseline: allow-all-except (block-list) or
    /// block-all-except (allow-list).
    #[serde(default)]
    pub domain_policy: DomainPolicy,
    /// Exception domains read against `domain_policy` (suffix-matched, so
    /// `example.com` covers `docs.example.com`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_exceptions: Vec<String>,
}

impl Default for WebSearchConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            engine: default_search_engine(),
            engine_secret: None,
            max_results: default_max_results(),
            google_cse_id: None,
            domain_policy: DomainPolicy::default(),
            domain_exceptions: Vec::new(),
        }
    }
}

/// `web_fetch` tool config: content cap + domain policy. Needs no external key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebFetchConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_max_content_bytes")]
    pub max_content_bytes: usize,
    /// Domain-policy baseline: allow-all-except (block-list) or
    /// block-all-except (allow-list).
    #[serde(default)]
    pub domain_policy: DomainPolicy,
    /// Exception domains read against `domain_policy` (suffix-matched).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_exceptions: Vec<String>,
}

impl Default for WebFetchConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_content_bytes: default_max_content_bytes(),
            domain_policy: DomainPolicy::default(),
            domain_exceptions: Vec::new(),
        }
    }
}

impl ServerToolsConfig {
    /// Whether any server tool is active (the surface toggle plus at least one
    /// enabled tool).
    pub fn is_active(&self) -> bool {
        self.enabled && (self.web_search_active() || self.web_fetch_active())
    }
    pub fn web_search_active(&self) -> bool {
        self.web_search
            .as_ref()
            .is_some_and(|s| s.enabled)
    }
    pub fn web_fetch_active(&self) -> bool {
        self.web_fetch
            .as_ref()
            .is_some_and(|f| f.enabled)
    }

    /// The active server-tool names, for policy exposure and logging.
    pub fn active_tool_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        if self.web_search_active() {
            names.push(WEB_SEARCH_TOOL.to_string());
        }
        if self.web_fetch_active() {
            names.push(WEB_FETCH_TOOL.to_string());
        }
        names
    }
}

/// The OpenAI tool schema for `web_search`.
pub fn web_search_tool_def() -> Value {
    json!({
        "type": "function",
        "function": {
            "name": WEB_SEARCH_TOOL,
            "description": "Search the web for current information. Returns a list of results (title, url, snippet). Use this when the answer may depend on recent or external facts.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "The search query." }
                },
                "required": ["query"]
            }
        }
    })
}

/// The OpenAI tool schema for `web_fetch`.
pub fn web_fetch_tool_def() -> Value {
    json!({
        "type": "function",
        "function": {
            "name": WEB_FETCH_TOOL,
            "description": "Fetch and read the readable text content of a web page by URL.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "The absolute http(s) URL to fetch." }
                },
                "required": ["url"]
            }
        }
    })
}

/// Append the enabled server-tool schemas to the request body's `tools` array
/// (creating it if absent), without duplicating an already-present definition.
pub fn inject_tool_defs(
    body: &mut Value,
    cfg: &ServerToolsConfig,
) {
    if !cfg.is_active() {
        return;
    }
    let Some(obj) = body.as_object_mut() else {
        return;
    };
    let tools = obj
        .entry("tools".to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    let Some(arr) = tools.as_array_mut() else {
        return;
    };
    let has = |arr: &[Value], name: &str| {
        arr.iter().any(|t| {
            t.get("function")
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str())
                == Some(name)
        })
    };
    if cfg.web_search_active() && !has(arr, WEB_SEARCH_TOOL) {
        arr.push(web_search_tool_def());
    }
    if cfg.web_fetch_active() && !has(arr, WEB_FETCH_TOOL) {
        arr.push(web_fetch_tool_def());
    }
}

/// One server-tool invocation extracted from a model response.
#[derive(Debug, Clone, PartialEq)]
pub struct ServerToolInvocation {
    pub tool_call_id: String,
    pub name: String,
    pub arguments: Value,
}

/// Extract `web_search` / `web_fetch` tool calls from an OpenAI-canonical
/// assistant message. Non-server tool calls are ignored (left for the caller).
pub fn extract_server_tool_calls(message: &Value) -> Vec<ServerToolInvocation> {
    let Some(tool_calls) = message
        .get("tool_calls")
        .and_then(|t| t.as_array())
    else {
        return Vec::new();
    };
    tool_calls
        .iter()
        .filter_map(|tc| {
            let function = tc.get("function")?;
            let name = function
                .get("name")
                .and_then(|n| n.as_str())?;
            if name != WEB_SEARCH_TOOL && name != WEB_FETCH_TOOL {
                return None;
            }
            let id = tc
                .get("id")
                .and_then(|i| i.as_str())
                .unwrap_or("")
                .to_string();
            let arguments = function
                .get("arguments")
                .and_then(|a| a.as_str())
                .and_then(|s| serde_json::from_str::<Value>(s).ok())
                .unwrap_or_else(|| json!({}));
            Some(ServerToolInvocation {
                tool_call_id: id,
                name: name.to_string(),
                arguments,
            })
        })
        .collect()
}

/// Whether a host is permitted by the domain policy. Under `AllowAll` a host is
/// permitted unless it matches an exception (a block-list); under `BlockAll` a
/// host is permitted only if it matches an exception (an allow-list). Matching
/// is suffix-based so `example.com` covers `docs.example.com`.
pub fn domain_allowed(
    host: &str,
    policy: DomainPolicy,
    exceptions: &[String],
) -> bool {
    let host = host
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let matched = exceptions.iter().any(|p| {
        let p = p
            .trim()
            .trim_start_matches("*.")
            .trim_end_matches('.')
            .to_ascii_lowercase();
        !p.is_empty() && (host == p || host.ends_with(&format!(".{p}")))
    });
    match policy {
        DomainPolicy::AllowAll => !matched,
        DomainPolicy::BlockAll => matched,
    }
}

/// One normalized web-search result.
#[derive(Debug, Clone, PartialEq)]
pub struct SearchResult {
    pub title: String,
    pub url: String,
    pub snippet: String,
}

/// The HTTP request for a search engine query: (method, url, headers, optional body).
#[derive(Debug, Clone, PartialEq)]
pub struct EngineRequest {
    pub method: EngineMethod,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EngineMethod {
    Get,
    Post,
}

/// Build the HTTP request for a search engine query, or `Err` when the engine
/// is unknown or misconfigured. Pure — the executor performs the HTTP call and
/// hands the JSON back to [`parse_engine_response`].
pub fn build_engine_request(
    cfg: &WebSearchConfig,
    api_key: &str,
    query: &str,
) -> Result<EngineRequest, String> {
    match cfg.engine.as_str() {
        "tavily" => Ok(EngineRequest {
            method: EngineMethod::Post,
            url: "https://api.tavily.com/search".to_string(),
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: Some(json!({
                "api_key": api_key,
                "query": query,
                "max_results": cfg.max_results,
            })),
        }),
        "brave" => Ok(EngineRequest {
            method: EngineMethod::Get,
            url: format!(
                "https://api.search.brave.com/res/v1/web/search?q={}&count={}",
                urlencoding::encode(query),
                cfg.max_results
            ),
            headers: vec![
                ("accept".to_string(), "application/json".to_string()),
                ("x-subscription-token".to_string(), api_key.to_string()),
            ],
            body: None,
        }),
        "google" => {
            let cse = cfg
                .google_cse_id
                .as_deref()
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| "google engine requires a Programmable Search Engine id (google_cse_id)".to_string())?;
            Ok(EngineRequest {
                method: EngineMethod::Get,
                url: format!(
                    "https://www.googleapis.com/customsearch/v1?key={}&cx={}&q={}&num={}",
                    urlencoding::encode(api_key),
                    urlencoding::encode(cse),
                    urlencoding::encode(query),
                    cfg.max_results.min(10)
                ),
                headers: vec![("accept".to_string(), "application/json".to_string())],
                body: None,
            })
        }
        other => Err(format!("unknown web search engine '{other}'")),
    }
}

/// Parse a search engine's JSON response into normalized [`SearchResult`]s.
pub fn parse_engine_response(
    engine: &str,
    response: &Value,
    max_results: u32,
) -> Vec<SearchResult> {
    let take = max_results.max(1) as usize;
    let mut out = Vec::new();
    match engine {
        "tavily" => {
            if let Some(results) = response
                .get("results")
                .and_then(|r| r.as_array())
            {
                for r in results.iter().take(take) {
                    out.push(SearchResult {
                        title: str_field(r, "title"),
                        url: str_field(r, "url"),
                        snippet: str_field(r, "content"),
                    });
                }
            }
        }
        "brave" => {
            if let Some(results) = response
                .pointer("/web/results")
                .and_then(|r| r.as_array())
            {
                for r in results.iter().take(take) {
                    out.push(SearchResult {
                        title: str_field(r, "title"),
                        url: str_field(r, "url"),
                        snippet: str_field(r, "description"),
                    });
                }
            }
        }
        "google" => {
            if let Some(items) = response
                .get("items")
                .and_then(|r| r.as_array())
            {
                for r in items.iter().take(take) {
                    out.push(SearchResult {
                        title: str_field(r, "title"),
                        url: str_field(r, "link"),
                        snippet: str_field(r, "snippet"),
                    });
                }
            }
        }
        _ => {}
    }
    out
}

fn str_field(
    value: &Value,
    key: &str,
) -> String {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// Format search results into a `tool` result message for the model.
pub fn search_results_message(
    tool_call_id: &str,
    query: &str,
    results: &[SearchResult],
) -> Value {
    let content = if results.is_empty() {
        format!("No results for query: {query}")
    } else {
        let mut s = format!("Search results for \"{query}\":\n");
        for (i, r) in results.iter().enumerate() {
            s.push_str(&format!("\n[{}] {}\n{}\n{}\n", i + 1, r.title, r.url, r.snippet));
        }
        s
    };
    json!({ "role": "tool", "tool_call_id": tool_call_id, "content": content })
}

/// Format fetched page content into a `tool` result message for the model.
pub fn fetch_result_message(
    tool_call_id: &str,
    url: &str,
    content: &str,
) -> Value {
    json!({
        "role": "tool",
        "tool_call_id": tool_call_id,
        "content": format!("Content of {url}:\n\n{content}")
    })
}

/// A `tool` result message reporting that a tool call was denied by policy.
pub fn denied_message(
    tool_call_id: &str,
    reason: &str,
) -> Value {
    json!({ "role": "tool", "tool_call_id": tool_call_id, "content": format!("Tool call denied: {reason}") })
}

/// URL citations (OpenRouter-style `annotations`) built from search results, to
/// attach to the final assistant message.
pub fn citations_from_results(results: &[SearchResult]) -> Vec<Value> {
    results
        .iter()
        .map(|r| {
            json!({
                "type": "url_citation",
                "url_citation": { "url": r.url, "title": r.title }
            })
        })
        .collect()
}

/// Reduce fetched HTML/text to a plain-text excerpt bounded by `max_bytes`.
/// A very small tag stripper — enough to hand the model readable text without a
/// full HTML parser dependency.
pub fn extract_text(
    raw: &str,
    max_bytes: usize,
) -> String {
    let mut out = String::with_capacity(raw.len().min(max_bytes));
    let mut in_tag = false;
    let mut in_script = false;
    // ASCII lowercasing keeps every byte offset, so a char boundary of `raw`
    // is also one of `lower`.
    let lower = raw.to_ascii_lowercase();
    let mut i = 0;
    while let Some(c) = raw[i..].chars().next() {
        if !in_tag && lower[i..].starts_with("<script") {
            in_script = true;
        }
        if in_script && lower[i..].starts_with("</script>") {
            in_script = false;
            i += "</script>".len();
            continue;
        }
        if c == '<' {
            in_tag = true;
        } else if c == '>' {
            in_tag = false;
        } else if !in_tag && !in_script {
            out.push(c);
        }
        i += c.len_utf8();
    }
    // Collapse runs of whitespace.
    let mut collapsed = out
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    collapsed.truncate(collapsed.floor_char_boundary(max_bytes));
    collapsed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_active_requires_toggle_and_a_tool() {
        let mut cfg = ServerToolsConfig {
            enabled: true,
            ..Default::default()
        };
        assert!(!cfg.is_active());
        cfg.web_fetch = Some(WebFetchConfig {
            enabled: true,
            ..Default::default()
        });
        assert!(cfg.is_active());
        cfg.enabled = false;
        assert!(!cfg.is_active());
    }

    #[test]
    fn inject_tool_defs_adds_enabled_tools() {
        let cfg = ServerToolsConfig {
            enabled: true,
            max_iterations: 3,
            web_search: Some(WebSearchConfig {
                enabled: true,
                ..Default::default()
            }),
            web_fetch: Some(WebFetchConfig {
                enabled: true,
                ..Default::default()
            }),
        };
        let mut body = json!({ "messages": [] });
        inject_tool_defs(&mut body, &cfg);
        let tools = body["tools"]
            .as_array()
            .unwrap();
        assert_eq!(tools.len(), 2);
        let names: Vec<&str> = tools
            .iter()
            .filter_map(|t| t["function"]["name"].as_str())
            .collect();
        assert!(names.contains(&"web_search"));
        assert!(names.contains(&"web_fetch"));
    }

    #[test]
    fn inject_tool_defs_no_duplicates_and_preserves_caller_tools() {
        let cfg = ServerToolsConfig {
            enabled: true,
            max_iterations: 3,
            web_search: Some(WebSearchConfig {
                enabled: true,
                ..Default::default()
            }),
            web_fetch: None,
        };
        let mut body = json!({ "tools": [
            { "type": "function", "function": { "name": "my_tool" } },
            { "type": "function", "function": { "name": "web_search" } }
        ]});
        inject_tool_defs(&mut body, &cfg);
        let tools = body["tools"]
            .as_array()
            .unwrap();
        assert_eq!(tools.len(), 2, "no duplicate web_search, caller tool preserved");
    }

    #[test]
    fn inject_noop_when_inactive() {
        let cfg = ServerToolsConfig::default();
        let mut body = json!({ "messages": [] });
        inject_tool_defs(&mut body, &cfg);
        assert!(body.get("tools").is_none());
    }

    #[test]
    fn extract_server_tool_calls_filters_to_web_tools() {
        let message = json!({ "tool_calls": [
            { "id": "a", "function": { "name": "web_search", "arguments": "{\"query\":\"rust\"}" } },
            { "id": "b", "function": { "name": "my_tool", "arguments": "{}" } },
            { "id": "c", "function": { "name": "web_fetch", "arguments": "{\"url\":\"https://x.com\"}" } }
        ]});
        let calls = extract_server_tool_calls(&message);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].name, "web_search");
        assert_eq!(calls[0].arguments["query"], json!("rust"));
        assert_eq!(calls[1].name, "web_fetch");
        assert_eq!(calls[1].arguments["url"], json!("https://x.com"));
    }

    #[test]
    fn extract_none_when_no_tool_calls() {
        assert!(extract_server_tool_calls(&json!({ "content": "hi" })).is_empty());
    }

    #[test]
    fn domain_allowed_allow_all_blocks_exceptions() {
        let ex = vec!["evil.com".to_string()];
        assert!(!domain_allowed("evil.com", DomainPolicy::AllowAll, &ex));
        assert!(!domain_allowed("sub.evil.com", DomainPolicy::AllowAll, &ex));
        assert!(domain_allowed("good.com", DomainPolicy::AllowAll, &ex));
    }

    #[test]
    fn domain_allowed_block_all_allows_only_exceptions() {
        let ex = vec!["example.com".to_string()];
        assert!(domain_allowed("example.com", DomainPolicy::BlockAll, &ex));
        assert!(domain_allowed("docs.example.com", DomainPolicy::BlockAll, &ex));
        assert!(!domain_allowed("other.com", DomainPolicy::BlockAll, &ex));
    }

    #[test]
    fn domain_allowed_allow_all_empty_allows_everything() {
        assert!(domain_allowed("anything.com", DomainPolicy::AllowAll, &[]));
    }

    #[test]
    fn domain_allowed_block_all_empty_blocks_everything() {
        assert!(!domain_allowed("anything.com", DomainPolicy::BlockAll, &[]));
    }

    #[test]
    fn tavily_request_and_parse() {
        let cfg = WebSearchConfig {
            engine: "tavily".into(),
            max_results: 3,
            ..Default::default()
        };
        let req = build_engine_request(&cfg, "KEY", "rust lang").unwrap();
        assert_eq!(req.method, EngineMethod::Post);
        assert_eq!(req.url, "https://api.tavily.com/search");
        assert_eq!(req.body.as_ref().unwrap()["api_key"], json!("KEY"));

        let resp = json!({ "results": [
            { "title": "Rust", "url": "https://rust-lang.org", "content": "A language" },
            { "title": "Docs", "url": "https://doc.rust-lang.org", "content": "Docs" }
        ]});
        let results = parse_engine_response("tavily", &resp, 3);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].title, "Rust");
        assert_eq!(results[0].url, "https://rust-lang.org");
    }

    #[test]
    fn brave_request_uses_header_and_parses() {
        let cfg = WebSearchConfig {
            engine: "brave".into(),
            max_results: 2,
            ..Default::default()
        };
        let req = build_engine_request(&cfg, "TOK", "cats").unwrap();
        assert_eq!(req.method, EngineMethod::Get);
        assert!(
            req.url
                .starts_with("https://api.search.brave.com/")
        );
        assert!(
            req.headers
                .iter()
                .any(|(k, v)| k == "x-subscription-token" && v == "TOK")
        );

        let resp =
            json!({ "web": { "results": [ { "title": "Cats", "url": "https://cats.com", "description": "Meow" } ] } });
        let results = parse_engine_response("brave", &resp, 2);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].snippet, "Meow");
    }

    #[test]
    fn google_requires_cse_id() {
        let cfg = WebSearchConfig {
            engine: "google".into(),
            ..Default::default()
        };
        assert!(build_engine_request(&cfg, "KEY", "q").is_err());
        let cfg = WebSearchConfig {
            engine: "google".into(),
            google_cse_id: Some("cx1".into()),
            ..Default::default()
        };
        let req = build_engine_request(&cfg, "KEY", "q").unwrap();
        assert!(req.url.contains("cx=cx1"));

        let resp = json!({ "items": [ { "title": "T", "link": "https://g.com", "snippet": "S" } ] });
        let results = parse_engine_response("google", &resp, 5);
        assert_eq!(results[0].url, "https://g.com");
    }

    #[test]
    fn unknown_engine_errors() {
        let cfg = WebSearchConfig {
            engine: "bing".into(),
            ..Default::default()
        };
        assert!(build_engine_request(&cfg, "K", "q").is_err());
    }

    #[test]
    fn search_results_message_shape() {
        let results = vec![SearchResult {
            title: "T".into(),
            url: "https://u.com".into(),
            snippet: "S".into(),
        }];
        let msg = search_results_message("call_1", "q", &results);
        assert_eq!(msg["role"], json!("tool"));
        assert_eq!(msg["tool_call_id"], json!("call_1"));
        assert!(
            msg["content"]
                .as_str()
                .unwrap()
                .contains("https://u.com")
        );
    }

    #[test]
    fn citations_shape() {
        let results = vec![SearchResult {
            title: "T".into(),
            url: "https://u.com".into(),
            snippet: "S".into(),
        }];
        let cites = citations_from_results(&results);
        assert_eq!(cites[0]["type"], json!("url_citation"));
        assert_eq!(cites[0]["url_citation"]["url"], json!("https://u.com"));
    }

    #[test]
    fn extract_text_strips_tags_and_scripts() {
        let html = "<html><head><script>var x = 1 < 2;</script></head><body><p>Hello   world</p></body></html>";
        let text = extract_text(html, 1000);
        assert_eq!(text, "Hello world");
        assert!(!text.contains("var x"));
    }

    #[test]
    fn extract_text_truncates() {
        let text = extract_text("aaaa bbbb cccc", 6);
        assert_eq!(text, "aaaa b");
    }

    #[test]
    fn extract_text_keeps_multibyte_text_intact() {
        let html = "<p>Café für 東京 🚀</p><script>alert('ü')</script><b>naïve</b>";
        assert_eq!(extract_text(html, 1000), "Café für 東京 🚀naïve");
    }

    #[test]
    fn extract_text_detects_script_after_multibyte_text() {
        let html = "é<SCRIPT>secret()</Script>ok";
        assert_eq!(extract_text(html, 1000), "éok");
    }

    #[test]
    fn extract_text_truncates_on_a_char_boundary() {
        let text = extract_text("aé🚀", 4);
        assert_eq!(text, "aé");
        assert!(text.len() <= 4);
    }

    #[test]
    fn extract_text_truncates_to_zero_bytes() {
        assert_eq!(extract_text("🚀", 0), "");
        assert_eq!(extract_text("abc", 0), "");
    }
}
