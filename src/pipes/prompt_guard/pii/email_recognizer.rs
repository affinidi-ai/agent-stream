//! Email address recognizer

use super::{PatternRecognizer, Recognizer, RecognizerResult};

pub struct EmailRecognizer {
    inner: PatternRecognizer,
}

impl EmailRecognizer {
    pub fn new() -> Self {
        let mut recognizer = PatternRecognizer::new("EMAIL");
        recognizer.add_pattern("standard_email", r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", 0.85);
        Self { inner: recognizer }
    }
}

impl Recognizer for EmailRecognizer {
    fn recognize(
        &self,
        text: &str,
    ) -> Vec<RecognizerResult> {
        self.inner.recognize(text)
    }

    fn name(&self) -> &str {
        "EMAIL"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_email() {
        let recognizer = EmailRecognizer::new();
        let results = recognizer.recognize("Contact me at user@example.com please");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].matched, "user@example.com");
    }

    #[test]
    fn test_email_with_plus() {
        let recognizer = EmailRecognizer::new();
        let results = recognizer.recognize("Email: user+tag@domain.co.uk");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].matched, "user+tag@domain.co.uk");
    }

    #[test]
    fn test_multiple_emails() {
        let recognizer = EmailRecognizer::new();
        let results = recognizer.recognize("Send to a@b.com and c@d.org");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_no_email() {
        let recognizer = EmailRecognizer::new();
        let results = recognizer.recognize("No email addresses here");
        assert!(results.is_empty());
    }
}
