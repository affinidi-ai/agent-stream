//! Supported input-modality descriptors, shared by the per-surface modality
//! gates (audio / image / document) and published to the dashboard so the
//! builder's type pickers are **backend-driven** — new parsers/formats light up
//! in the UI automatically instead of drifting against a hardcoded list.

use serde_json::{Value, json};

/// Audio container formats the gateway can carry to an audio-capable model.
pub const AUDIO_FORMATS: &[&str] = &["wav", "mp3"];

/// Image formats the gateway accepts for a vision-capable model.
pub const IMAGE_FORMATS: &[&str] = &["png", "jpeg", "gif", "webp"];

/// Document types the gateway can extract to text locally.
pub const DOCUMENT_EXTRACTABLE_TYPES: &[&str] = &["text", "markdown", "csv", "json", "docx"];

/// Document types accepted but forwarded to a document-native model (not yet
/// extracted locally).
pub const DOCUMENT_FORWARD_ONLY_TYPES: &[&str] = &["pdf"];

fn as_values(items: &[&str]) -> Vec<Value> {
    items
        .iter()
        .map(|s| Value::String((*s).to_string()))
        .collect()
}

/// The supported input modalities and their types/formats, published on the
/// pipes-config document so the surface builder renders its Audio / Image /
/// Document type pickers from what the backend actually supports.
pub fn supported_input_modalities() -> Value {
    json!({
        "audio": { "formats": as_values(AUDIO_FORMATS) },
        "image": { "formats": as_values(IMAGE_FORMATS) },
        "document": {
            "extractable": as_values(DOCUMENT_EXTRACTABLE_TYPES),
            "forward_only": as_values(DOCUMENT_FORWARD_ONLY_TYPES),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_modalities_list_expected_types() {
        let m = supported_input_modalities();
        assert_eq!(m["audio"]["formats"], json!(["wav", "mp3"]));
        assert_eq!(m["image"]["formats"], json!(["png", "jpeg", "gif", "webp"]));
        assert_eq!(m["document"]["extractable"], json!(["text", "markdown", "csv", "json", "docx"]));
        assert_eq!(m["document"]["forward_only"], json!(["pdf"]));
    }
}
