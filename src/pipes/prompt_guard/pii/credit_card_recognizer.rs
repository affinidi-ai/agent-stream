//! Credit card number recognizer

use super::{PatternRecognizer, Recognizer, RecognizerResult};

pub struct CreditCardRecognizer {
    inner: PatternRecognizer,
}

impl CreditCardRecognizer {
    pub fn new() -> Self {
        let mut recognizer = PatternRecognizer::new("CREDIT_CARD");
        // Visa: starts with 4
        recognizer.add_pattern("visa", r"\b4\d{3}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", 0.6);
        // Mastercard: starts with 51-55
        recognizer.add_pattern("mastercard", r"\b5[1-5]\d{2}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", 0.6);
        // Amex: starts with 34 or 37
        recognizer.add_pattern("amex", r"\b3[47]\d{2}[- ]?\d{6}[- ]?\d{5}\b", 0.6);
        // Discover: starts with 6011 or 65
        recognizer.add_pattern("discover", r"\b6(?:011|5\d{2})[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", 0.6);
        Self { inner: recognizer }
    }
}

impl Recognizer for CreditCardRecognizer {
    fn recognize(
        &self,
        text: &str,
    ) -> Vec<RecognizerResult> {
        self.inner.recognize(text)
    }

    fn name(&self) -> &str {
        "CREDIT_CARD"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_visa() {
        let recognizer = CreditCardRecognizer::new();
        let results = recognizer.recognize("Card: 4111-1111-1111-1111");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entity_type, "CREDIT_CARD");
    }

    #[test]
    fn test_visa_no_dashes() {
        let recognizer = CreditCardRecognizer::new();
        let results = recognizer.recognize("Card: 4111111111111111");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_mastercard() {
        let recognizer = CreditCardRecognizer::new();
        let results = recognizer.recognize("MC: 5500 0000 0000 0004");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_no_credit_card() {
        let recognizer = CreditCardRecognizer::new();
        let results = recognizer.recognize("Just a normal number 12345");
        assert!(results.is_empty());
    }
}
