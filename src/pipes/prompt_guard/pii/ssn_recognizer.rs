//! US Social Security Number recognizer

use super::{PatternRecognizer, Recognizer, RecognizerResult};

pub struct SsnRecognizer {
    inner: PatternRecognizer,
}

impl SsnRecognizer {
    pub fn new() -> Self {
        let mut recognizer = PatternRecognizer::new("SSN");
        // Standard SSN format: 123-45-6789
        recognizer.add_pattern("ssn_dashes", r"\b([0-9]{3})-([0-9]{2})-([0-9]{4})\b", 0.85);
        // SSN with spaces: 123 45 6789
        recognizer.add_pattern("ssn_spaces", r"\b([0-9]{3}) ([0-9]{2}) ([0-9]{4})\b", 0.85);
        // SSN with dots: 123.45.6789
        recognizer.add_pattern("ssn_dots", r"\b([0-9]{3})\.([0-9]{2})\.([0-9]{4})\b", 0.85);
        // SSN without separators (weaker match since 9-digit numbers are common)
        recognizer.add_pattern("ssn_no_sep", r"\b[0-9]{9}\b", 0.3);
        Self { inner: recognizer }
    }
}

impl Recognizer for SsnRecognizer {
    fn recognize(
        &self,
        text: &str,
    ) -> Vec<RecognizerResult> {
        self.inner.recognize(text)
    }

    fn name(&self) -> &str {
        "SSN"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssn_with_dashes() {
        let recognizer = SsnRecognizer::new();
        let results = recognizer.recognize("My SSN is 123-45-6789");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].matched, "123-45-6789");
    }

    #[test]
    fn test_ssn_with_spaces() {
        let recognizer = SsnRecognizer::new();
        let results = recognizer.recognize("SSN: 123 45 6789 on file");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].matched, "123 45 6789");
    }

    #[test]
    fn test_no_ssn() {
        let recognizer = SsnRecognizer::new();
        let results = recognizer.recognize("Hello world, no PII here");
        assert!(results.is_empty());
    }
}
