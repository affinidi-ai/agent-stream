//! Phone number recognizer

use super::{PatternRecognizer, Recognizer, RecognizerResult};

pub struct PhoneRecognizer {
    inner: PatternRecognizer,
}

impl PhoneRecognizer {
    pub fn new() -> Self {
        let mut recognizer = PatternRecognizer::new("PHONE_NUMBER");
        // International format: +1-234-567-8901 or +44 20 7123 4567
        recognizer.add_pattern("international", r"\+\d{1,3}[- ]?\(?\d{1,4}\)?[- ]?\d{1,4}[- ]?\d{1,9}", 0.7);
        // US/CA format: (123) 456-7890
        recognizer.add_pattern("us_parens", r"\(\d{3}\)\s?\d{3}[- ]?\d{4}", 0.75);
        // US format: 123-456-7890
        recognizer.add_pattern("us_dashes", r"\b\d{3}-\d{3}-\d{4}\b", 0.7);
        // US format: 123.456.7890
        recognizer.add_pattern("us_dots", r"\b\d{3}\.\d{3}\.\d{4}\b", 0.7);
        // US format with spaces: 123 456 7890
        recognizer.add_pattern("us_spaces", r"\b\d{3} \d{3} \d{4}\b", 0.5);
        Self { inner: recognizer }
    }
}

impl Recognizer for PhoneRecognizer {
    fn recognize(
        &self,
        text: &str,
    ) -> Vec<RecognizerResult> {
        self.inner.recognize(text)
    }

    fn name(&self) -> &str {
        "PHONE_NUMBER"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_us_phone_dashes() {
        let recognizer = PhoneRecognizer::new();
        let results = recognizer.recognize("Call 555-123-4567");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].matched, "555-123-4567");
    }

    #[test]
    fn test_us_phone_parens() {
        let recognizer = PhoneRecognizer::new();
        let results = recognizer.recognize("Phone: (555) 123-4567");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_international_phone() {
        let recognizer = PhoneRecognizer::new();
        let results = recognizer.recognize("Call +44 20 7123 4567");
        assert!(!results.is_empty());
    }

    #[test]
    fn test_no_phone() {
        let recognizer = PhoneRecognizer::new();
        let results = recognizer.recognize("No phone numbers here");
        assert!(results.is_empty());
    }
}
