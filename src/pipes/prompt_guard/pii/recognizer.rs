//! Recognizer trait for PII detection

use super::RecognizerResult;

/// Trait for PII pattern recognizers
pub trait Recognizer {
    /// Scan text and return all PII matches found
    fn recognize(
        &self,
        text: &str,
    ) -> Vec<RecognizerResult>;
    /// Human-readable name for this recognizer
    fn name(&self) -> &str;
}

/// Blanket implementation so `Box<dyn Recognizer + ...>` also implements `Recognizer`
impl<T: Recognizer + ?Sized> Recognizer for Box<T> {
    fn recognize(
        &self,
        text: &str,
    ) -> Vec<RecognizerResult> {
        (**self).recognize(text)
    }

    fn name(&self) -> &str {
        (**self).name()
    }
}
