//! Recognizer result type

/// A PII match found by a recognizer
#[derive(Debug, Clone, PartialEq)]
pub struct RecognizerResult {
    /// The type of entity detected (e.g., "SSN", "EMAIL", "CREDIT_CARD")
    pub entity_type: String,
    /// The matched text
    pub matched: String,
    /// Start byte offset in the original text
    pub start: usize,
    /// End byte offset in the original text
    pub end: usize,
    /// Confidence score (0.0 - 1.0)
    pub score: f32,
}
