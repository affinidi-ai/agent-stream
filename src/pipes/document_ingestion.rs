//! Inbound document ingestion.
//!
//! Recognize document content parts a caller attaches inline to a chat message
//! (`{ "type": "file", "file": { "filename", "file_data" } }` in the
//! OpenAI-canonical body) and — when the gateway can parse the type locally —
//! extract the text and inject it into the prompt as a plain `text` part. This
//! lets any model (not just document-native ones) read the document, and routes
//! the extracted text through the same PII masking, guardrails, and
//! context-window guard as ordinary prompt text. The stage is a structural
//! operation on the OpenAI-canonical body, so it is dialect- and
//! provider-agnostic (an Anthropic `document` block / a Responses `input_file`
//! part is normalized to the canonical file part upstream).
//!
//! Engines: plain text / markdown / csv / json (decoded directly) and DOCX (a
//! ZIP of XML, parsed with the `zip` + `quick-xml` crates). PDF is a planned
//! follow-up.
//!
//! Parsing untrusted documents is an attack surface, so the stage is governed:
//! a per-surface allow-list of types, a decoded-size cap, an extracted-length
//! cap, and — for the ZIP-backed DOCX path — entry-count, declared-size, and
//! compression-ratio guards against ZIP bombs. The detected document types are
//! exposed to Rego as `input.resource.document_types`. Off by default.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use serde_json::Value;

fn default_allowed_types() -> Vec<String> {
    ["text", "markdown", "csv", "json", "docx"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}
fn default_max_file_bytes() -> usize {
    5 * 1024 * 1024
}
fn default_max_extracted_chars() -> usize {
    100_000
}

/// How the stage treats a recognized, allowed document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DocumentIngestionMode {
    /// Extract types the gateway can parse locally; forward the rest untouched.
    /// The sensible default — forward-compatible as new engines (PDF) land.
    #[default]
    Auto,
    /// Extract every allowed type; error if the type cannot be parsed locally.
    Extract,
    /// Never extract; leave file parts as-is (forward to a document-native
    /// upstream). Still enforces the allow-list and size cap.
    Passthrough,
}

/// Per-surface document-ingestion configuration (off by default).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DocumentIngestionConfig {
    /// Master switch. When off, document parts pass through untouched.
    #[serde(default)]
    pub enabled: bool,
    /// Allow-list of document types the surface accepts (`text`, `markdown`,
    /// `csv`, `json`, `docx`, `pdf`). An inline document of any other type is
    /// rejected (fail-closed).
    #[serde(default = "default_allowed_types")]
    pub allowed_types: Vec<String>,
    /// Maximum decoded size of a single inline document, in bytes.
    #[serde(default = "default_max_file_bytes")]
    pub max_file_bytes: usize,
    /// Maximum number of extracted characters injected per document; longer
    /// text is truncated with a marker.
    #[serde(default = "default_max_extracted_chars")]
    pub max_extracted_chars: usize,
    /// Extraction strategy.
    #[serde(default)]
    pub mode: DocumentIngestionMode,
}

impl Default for DocumentIngestionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_types: default_allowed_types(),
            max_file_bytes: default_max_file_bytes(),
            max_extracted_chars: default_max_extracted_chars(),
            mode: DocumentIngestionMode::default(),
        }
    }
}

impl DocumentIngestionConfig {
    fn allows(
        &self,
        t: DocType,
    ) -> bool {
        self.allowed_types
            .iter()
            .any(|a| a.eq_ignore_ascii_case(t.as_str()))
    }
}

/// The recognized document types (P1 engines + the not-yet-parsed `pdf`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DocType {
    Text,
    Markdown,
    Csv,
    Json,
    Docx,
    Pdf,
    Unknown,
}

impl DocType {
    fn as_str(self) -> &'static str {
        match self {
            DocType::Text => "text",
            DocType::Markdown => "markdown",
            DocType::Csv => "csv",
            DocType::Json => "json",
            DocType::Docx => "docx",
            DocType::Pdf => "pdf",
            DocType::Unknown => "unknown",
        }
    }
    /// Whether the gateway can extract text from this type locally (P1).
    fn parseable(self) -> bool {
        matches!(self, DocType::Text | DocType::Markdown | DocType::Csv | DocType::Json | DocType::Docx)
    }
}

fn type_from_filename(name: &str) -> DocType {
    let ext = name
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "txt" | "text" | "log" => DocType::Text,
        "md" | "markdown" | "mdown" => DocType::Markdown,
        "csv" | "tsv" => DocType::Csv,
        "json" => DocType::Json,
        "docx" => DocType::Docx,
        "pdf" => DocType::Pdf,
        _ => DocType::Unknown,
    }
}

fn type_from_mime(mime: &str) -> DocType {
    match mime
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "text/plain" => DocType::Text,
        "text/markdown" | "text/x-markdown" => DocType::Markdown,
        "text/csv" | "application/csv" | "text/tab-separated-values" => DocType::Csv,
        "application/json" | "text/json" => DocType::Json,
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => DocType::Docx,
        "application/pdf" => DocType::Pdf,
        _ => DocType::Unknown,
    }
}

/// Detect the document type from the filename first, then the declared MIME.
fn detect_type(
    filename: Option<&str>,
    mime: Option<&str>,
) -> DocType {
    if let Some(name) = filename {
        let t = type_from_filename(name);
        if t != DocType::Unknown {
            return t;
        }
    }
    mime.map(type_from_mime)
        .unwrap_or(DocType::Unknown)
}

/// Read the `data:` URL MIME prefix without decoding the payload — cheap enough
/// to run during policy-input assembly.
fn mime_from_data_url(file_data: &str) -> Option<&str> {
    let meta = file_data
        .strip_prefix("data:")?
        .split_once(',')?
        .0;
    meta.split(';')
        .next()
        .filter(|m| !m.is_empty())
}

/// Decode an inline `file_data` value (a `data:` URL or bare base64) into its
/// declared MIME and raw bytes.
fn decode_inline(file_data: &str) -> Option<(Option<String>, Vec<u8>)> {
    if let Some(rest) = file_data.strip_prefix("data:") {
        let (meta, payload) = rest.split_once(',')?;
        let mime = meta
            .split(';')
            .next()
            .filter(|m| !m.is_empty())
            .map(|m| m.to_ascii_lowercase());
        let bytes = if meta.contains(";base64") {
            BASE64
                .decode(payload.trim().as_bytes())
                .ok()?
        } else {
            payload.as_bytes().to_vec()
        };
        Some((mime, bytes))
    } else {
        BASE64
            .decode(file_data.trim().as_bytes())
            .ok()
            .map(|b| (None, b))
    }
}

/// The `file` object of a `{ type: "file" }` content part, if present.
fn file_object(part: &Value) -> Option<&Value> {
    if part
        .get("type")
        .and_then(|t| t.as_str())
        != Some("file")
    {
        return None;
    }
    part.get("file")
}

/// The detected type of a `{ type: "file" }` part, without decoding the payload.
/// `None` for a non-file part or a reference-only part (`file_id` / `file_url`)
/// the gateway cannot inspect.
fn part_doc_type(part: &Value) -> Option<DocType> {
    let file = file_object(part)?;
    let file_data = file
        .get("file_data")
        .and_then(|d| d.as_str())?;
    let filename = file
        .get("filename")
        .and_then(|n| n.as_str());
    Some(detect_type(filename, mime_from_data_url(file_data)))
}

/// The distinct document types present in the request, for the policy input
/// (`input.resource.document_types`). Cheap: filename + `data:` MIME only.
pub fn document_types_present(body: &Value) -> Option<Vec<String>> {
    let messages = body
        .get("messages")
        .and_then(|m| m.as_array())?;
    let mut types: Vec<String> = Vec::new();
    for message in messages {
        if let Some(parts) = message
            .get("content")
            .and_then(|c| c.as_array())
        {
            for part in parts {
                if let Some(t) = part_doc_type(part) {
                    let s = t.as_str().to_string();
                    if !types.contains(&s) {
                        types.push(s);
                    }
                }
            }
        }
    }
    if types.is_empty() {
        None
    } else {
        types.sort();
        Some(types)
    }
}

/// The outcome of the ingestion stage, for the response header and governance.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DocumentIngestionOutcome {
    pub extracted: usize,
    pub passed_through: usize,
    pub chars_injected: usize,
    pub types: Vec<String>,
}

impl DocumentIngestionOutcome {
    pub fn applied(&self) -> bool {
        self.extracted > 0 || self.passed_through > 0
    }
    /// `x-agent-stream-documents` header value.
    pub fn header_value(&self) -> String {
        format!(
            "extracted={}; passthrough={}; chars={}; types={}",
            self.extracted,
            self.passed_through,
            self.chars_injected,
            self.types.join(",")
        )
    }
    /// Human-readable governance-stage detail.
    pub fn governance_detail(&self) -> String {
        format!(
            "{} extracted · {} passed through · {} char(s) · types: {}",
            self.extracted,
            self.passed_through,
            self.chars_injected,
            self.types.join(",")
        )
    }
}

/// Extract readable text from a document of type `t`.
fn extract_text(
    t: DocType,
    bytes: &[u8],
    max_bytes: usize,
) -> Result<String, String> {
    match t {
        DocType::Text | DocType::Markdown | DocType::Csv | DocType::Json => {
            Ok(String::from_utf8_lossy(bytes).into_owned())
        }
        DocType::Docx => extract_docx(bytes, max_bytes),
        DocType::Pdf | DocType::Unknown => Err(format!("cannot extract '{}' documents yet", t.as_str())),
    }
}

/// Zip-bomb guards for the DOCX (ZIP) path.
const DOCX_MAX_ENTRIES: usize = 512;
const DOCX_MAX_RATIO: u64 = 200;

/// Extract paragraph text from a DOCX by reading `word/document.xml` and
/// collecting `<w:t>` runs. Bounded against ZIP bombs.
fn extract_docx(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<String, String> {
    use std::io::Read;
    let mut archive =
        zip::ZipArchive::new(std::io::Cursor::new(bytes)).map_err(|e| format!("not a valid docx (zip) file: {e}"))?;
    if archive.len() > DOCX_MAX_ENTRIES {
        return Err("docx has too many entries".to_string());
    }
    let entry = archive
        .by_name("word/document.xml")
        .map_err(|_| "docx is missing word/document.xml".to_string())?;
    // Declared-size + ratio guards before reading a single byte.
    let cap = (max_bytes as u64)
        .saturating_mul(8)
        .min(64 * 1024 * 1024);
    if entry.size() > cap {
        return Err("docx body exceeds the size limit".to_string());
    }
    let compressed = entry.compressed_size().max(1);
    if entry.size() / compressed > DOCX_MAX_RATIO {
        return Err("docx compression ratio exceeds the limit".to_string());
    }
    let mut raw: Vec<u8> = Vec::new();
    entry
        .take(cap)
        .read_to_end(&mut raw)
        .map_err(|e| format!("failed to read docx body: {e}"))?;
    Ok(docx_xml_to_text(&String::from_utf8_lossy(&raw)))
}

/// Turn WordprocessingML into plain text: emit `<w:t>` text, a newline per
/// paragraph (`</w:p>`), and tabs/breaks for `<w:tab>` / `<w:br>` / `<w:cr>`.
fn docx_xml_to_text(xml: &str) -> String {
    use quick_xml::escape::unescape;
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;
    let mut reader = Reader::from_str(xml);
    let mut out = String::new();
    let mut in_text = false;
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) if e.local_name().as_ref() == b"t" => {
                in_text = true;
            }
            Ok(Event::End(e)) => match e.local_name().as_ref() {
                b"t" => in_text = false,
                b"p" => out.push('\n'),
                _ => {}
            },
            Ok(Event::Empty(e)) => match e.local_name().as_ref() {
                b"br" | b"cr" | b"p" => out.push('\n'),
                b"tab" => out.push('\t'),
                _ => {}
            },
            Ok(Event::Text(e)) if in_text => {
                let raw = String::from_utf8_lossy(e.as_ref());
                match unescape(&raw) {
                    Ok(text) => out.push_str(&text),
                    Err(_) => out.push_str(&raw),
                }
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    normalize_whitespace(&out)
}

/// Trim, and collapse runs of 3+ newlines down to a blank-line separator.
fn normalize_whitespace(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut newlines = 0usize;
    for ch in s.chars() {
        if ch == '\n' {
            newlines += 1;
            if newlines <= 2 {
                result.push('\n');
            }
        } else {
            newlines = 0;
            result.push(ch);
        }
    }
    result.trim().to_string()
}

/// Truncate `text` to at most `max_chars` characters, appending a marker when
/// it was cut. Returns the text and the character count injected.
fn bound_text(
    text: &str,
    max_chars: usize,
) -> (String, usize) {
    let count = text.chars().count();
    if count <= max_chars {
        (text.to_string(), count)
    } else {
        let mut bounded: String = text
            .chars()
            .take(max_chars)
            .collect();
        bounded.push_str("\n\n[document truncated]");
        (bounded, max_chars)
    }
}

/// Replace an extracted document with a `text` content part carrying a header
/// and the extracted body.
fn text_part(
    filename: Option<&str>,
    body: &str,
) -> Value {
    let header = match filename {
        Some(name) if !name.is_empty() => format!("[Attached document: {name}]\n\n"),
        _ => "[Attached document]\n\n".to_string(),
    };
    serde_json::json!({ "type": "text", "text": format!("{header}{body}") })
}

/// Apply document ingestion to a request body: recognize inline document parts,
/// enforce the per-surface allow-list + size cap, and — per the configured
/// `mode` — extract parseable documents to text in place. Returns the outcome
/// when any document was handled; `Ok(None)` when disabled or none are present;
/// `Err` when a document violates the surface's constraints (surfaced as a 400).
pub fn apply(
    config: Option<&DocumentIngestionConfig>,
    body: &mut Value,
) -> Result<Option<DocumentIngestionOutcome>, String> {
    let cfg = match config {
        Some(c) if c.enabled => c,
        _ => return Ok(None),
    };
    let Some(messages) = body
        .get_mut("messages")
        .and_then(|m| m.as_array_mut())
    else {
        return Ok(None);
    };

    let mut outcome = DocumentIngestionOutcome::default();
    for message in messages.iter_mut() {
        let Some(parts) = message
            .get_mut("content")
            .and_then(|c| c.as_array_mut())
        else {
            continue;
        };
        let mut rewritten: Vec<Value> = Vec::with_capacity(parts.len());
        for part in parts.drain(..) {
            if let Some(p) = process_part(cfg, part, &mut outcome)? {
                rewritten.push(p);
            }
        }
        *parts = rewritten;
    }

    outcome.types.sort();
    outcome.types.dedup();
    if outcome.applied() {
        Ok(Some(outcome))
    } else {
        Ok(None)
    }
}

/// Handle a single content part, returning the (possibly rewritten) part to
/// keep. A non-file part is returned unchanged; an extracted document becomes a
/// `text` part.
fn process_part(
    cfg: &DocumentIngestionConfig,
    part: Value,
    outcome: &mut DocumentIngestionOutcome,
) -> Result<Option<Value>, String> {
    let Some(file) = file_object(&part) else {
        return Ok(Some(part));
    };
    let filename = file
        .get("filename")
        .and_then(|n| n.as_str())
        .map(str::to_string);
    let file_data = file
        .get("file_data")
        .and_then(|d| d.as_str());

    // Reference-only parts (provider `file_id` / `file_url`) are forwarded.
    let Some(file_data) = file_data else {
        outcome.passed_through += 1;
        return Ok(Some(part));
    };

    let mime = mime_from_data_url(file_data);
    let doc_type = detect_type(filename.as_deref(), mime);
    if !cfg.allows(doc_type) {
        return Err(format!("document type '{}' is not permitted on this surface", doc_type.as_str()));
    }

    let (_decoded_mime, bytes) =
        decode_inline(file_data).ok_or_else(|| "document data could not be decoded".to_string())?;
    if bytes.len() > cfg.max_file_bytes {
        return Err(format!("document exceeds the {} byte size limit", cfg.max_file_bytes));
    }

    let type_label = doc_type.as_str().to_string();
    let extract = match cfg.mode {
        DocumentIngestionMode::Passthrough => false,
        DocumentIngestionMode::Extract => true,
        DocumentIngestionMode::Auto => doc_type.parseable(),
    };
    if !extract {
        outcome.passed_through += 1;
        if !outcome
            .types
            .contains(&type_label)
        {
            outcome.types.push(type_label);
        }
        return Ok(Some(part));
    }

    let text = extract_text(doc_type, &bytes, cfg.max_file_bytes)?;
    let (bounded, injected) = bound_text(&text, cfg.max_extracted_chars);
    outcome.extracted += 1;
    outcome.chars_injected += injected;
    if !outcome
        .types
        .contains(&type_label)
    {
        outcome.types.push(type_label);
    }
    Ok(Some(text_part(filename.as_deref(), &bounded)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;

    fn cfg() -> DocumentIngestionConfig {
        DocumentIngestionConfig {
            enabled: true,
            ..Default::default()
        }
    }

    fn text_data_url(
        mime: &str,
        body: &str,
    ) -> String {
        format!("data:{mime};base64,{}", BASE64.encode(body.as_bytes()))
    }

    /// Minimal single-entry DOCX (`word/document.xml`) with the given runs.
    fn make_docx(paragraphs: &[&str]) -> Vec<u8> {
        make_docx_with(paragraphs, zip::CompressionMethod::Deflated)
    }

    fn make_docx_with(
        paragraphs: &[&str],
        method: zip::CompressionMethod,
    ) -> Vec<u8> {
        let mut body = String::from(r#"<?xml version="1.0"?><w:document xmlns:w="x"><w:body>"#);
        for p in paragraphs {
            body.push_str(&format!("<w:p><w:r><w:t>{p}</w:t></w:r></w:p>"));
        }
        body.push_str("</w:body></w:document>");
        let mut buf = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts: zip::write::SimpleFileOptions = zip::write::FileOptions::default().compression_method(method);
            zip.start_file("word/document.xml", opts)
                .unwrap();
            zip.write_all(body.as_bytes())
                .unwrap();
            zip.finish().unwrap();
        }
        buf
    }

    #[test]
    fn detect_prefers_extension_then_mime() {
        assert_eq!(detect_type(Some("a.md"), Some("text/plain")), DocType::Markdown);
        assert_eq!(detect_type(Some("blob"), Some("application/json")), DocType::Json);
        assert_eq!(detect_type(None, Some("application/pdf")), DocType::Pdf);
        assert_eq!(detect_type(Some("x.bin"), None), DocType::Unknown);
    }

    #[test]
    fn disabled_is_noop() {
        let mut body = json!({
            "messages": [{ "role": "user", "content": [
                { "type": "file", "file": { "filename": "a.txt", "file_data": text_data_url("text/plain", "hello") } }
            ] }]
        });
        let before = body.clone();
        assert_eq!(apply(None, &mut body).unwrap(), None);
        assert_eq!(body, before);
    }

    #[test]
    fn extracts_plain_text_into_a_text_part() {
        let mut body = json!({
            "messages": [{ "role": "user", "content": [
                { "type": "text", "text": "summarise:" },
                { "type": "file", "file": { "filename": "note.txt", "file_data": text_data_url("text/plain", "the body") } }
            ] }]
        });
        let outcome = apply(Some(&cfg()), &mut body)
            .unwrap()
            .unwrap();
        assert_eq!(outcome.extracted, 1);
        let parts = body["messages"][0]["content"]
            .as_array()
            .unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[1]["type"], "text");
        let injected = parts[1]["text"]
            .as_str()
            .unwrap();
        assert!(injected.contains("note.txt"));
        assert!(injected.contains("the body"));
    }

    #[test]
    fn extracts_docx_paragraphs() {
        let docx = make_docx(&["First para", "Second para"]);
        let data_url = format!(
            "data:application/vnd.openxmlformats-officedocument.wordprocessingml.document;base64,{}",
            BASE64.encode(&docx)
        );
        let mut body = json!({
            "messages": [{ "role": "user", "content": [
                { "type": "file", "file": { "filename": "doc.docx", "file_data": data_url } }
            ] }]
        });
        let outcome = apply(Some(&cfg()), &mut body)
            .unwrap()
            .unwrap();
        assert_eq!(outcome.extracted, 1);
        let injected = body["messages"][0]["content"][0]["text"]
            .as_str()
            .unwrap();
        assert!(injected.contains("First para"));
        assert!(injected.contains("Second para"));
    }

    #[test]
    fn extracts_stored_method_docx() {
        // The conformance harness builds STORE-method (uncompressed) zips; make
        // sure the reader handles them, not just Deflated ones.
        let docx = make_docx_with(&["Stored body"], zip::CompressionMethod::Stored);
        let data_url = format!(
            "data:application/vnd.openxmlformats-officedocument.wordprocessingml.document;base64,{}",
            BASE64.encode(&docx)
        );
        let mut body = json!({
            "messages": [{ "role": "user", "content": [
                { "type": "file", "file": { "filename": "doc.docx", "file_data": data_url } }
            ] }]
        });
        let outcome = apply(Some(&cfg()), &mut body)
            .unwrap()
            .unwrap();
        assert_eq!(outcome.extracted, 1);
        assert!(
            body["messages"][0]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("Stored body")
        );
    }

    #[test]
    fn rejects_disallowed_type() {
        let mut body = json!({
            "messages": [{ "role": "user", "content": [
                { "type": "file", "file": { "filename": "a.pdf", "file_data": "data:application/pdf;base64,QUJD" } }
            ] }]
        });
        // Default allow-list excludes pdf.
        let err = apply(Some(&cfg()), &mut body).unwrap_err();
        assert!(err.contains("pdf"));
    }

    #[test]
    fn rejects_oversize_document() {
        let big = "x".repeat(200);
        let mut body = json!({
            "messages": [{ "role": "user", "content": [
                { "type": "file", "file": { "filename": "a.txt", "file_data": text_data_url("text/plain", &big) } }
            ] }]
        });
        let mut c = cfg();
        c.max_file_bytes = 50;
        let err = apply(Some(&c), &mut body).unwrap_err();
        assert!(err.contains("size limit"));
    }

    #[test]
    fn auto_mode_forwards_unparseable_but_allowed_type() {
        let mut c = cfg();
        c.allowed_types
            .push("pdf".to_string());
        let mut body = json!({
            "messages": [{ "role": "user", "content": [
                { "type": "file", "file": { "filename": "a.pdf", "file_data": "data:application/pdf;base64,QUJD" } }
            ] }]
        });
        let outcome = apply(Some(&c), &mut body)
            .unwrap()
            .unwrap();
        assert_eq!(outcome.passed_through, 1);
        assert_eq!(outcome.extracted, 0);
        // The file part is left intact for the upstream.
        assert_eq!(body["messages"][0]["content"][0]["type"], "file");
    }

    #[test]
    fn extract_mode_errors_on_unparseable_type() {
        let mut c = cfg();
        c.mode = DocumentIngestionMode::Extract;
        c.allowed_types
            .push("pdf".to_string());
        let mut body = json!({
            "messages": [{ "role": "user", "content": [
                { "type": "file", "file": { "filename": "a.pdf", "file_data": "data:application/pdf;base64,QUJD" } }
            ] }]
        });
        let err = apply(Some(&c), &mut body).unwrap_err();
        assert!(err.contains("cannot extract"));
    }

    #[test]
    fn reference_only_part_is_passed_through() {
        let mut body = json!({
            "messages": [{ "role": "user", "content": [
                { "type": "file", "file": { "file_id": "file-123" } }
            ] }]
        });
        let outcome = apply(Some(&cfg()), &mut body)
            .unwrap()
            .unwrap();
        assert_eq!(outcome.passed_through, 1);
        assert_eq!(body["messages"][0]["content"][0]["file"]["file_id"], "file-123");
    }

    #[test]
    fn document_types_present_lists_sorted_unique() {
        let body = json!({
            "messages": [{ "role": "user", "content": [
                { "type": "file", "file": { "filename": "a.txt", "file_data": "data:text/plain;base64,QQ==" } },
                { "type": "file", "file": { "filename": "b.pdf", "file_data": "data:application/pdf;base64,QQ==" } },
                { "type": "text", "text": "hi" }
            ] }]
        });
        assert_eq!(document_types_present(&body), Some(vec!["pdf".to_string(), "text".to_string()]));
        assert_eq!(document_types_present(&json!({ "messages": [] })), None);
    }

    #[test]
    fn passthrough_mode_keeps_file_but_records_outcome() {
        let mut c = cfg();
        c.mode = DocumentIngestionMode::Passthrough;
        let mut body = json!({
            "messages": [{ "role": "user", "content": [
                { "type": "file", "file": { "filename": "a.txt", "file_data": text_data_url("text/plain", "hi") } }
            ] }]
        });
        let outcome = apply(Some(&c), &mut body)
            .unwrap()
            .unwrap();
        assert_eq!(outcome.passed_through, 1);
        assert_eq!(body["messages"][0]["content"][0]["type"], "file");
    }
}
