//! Generic pattern-based recognizer

use super::{Recognizer, RecognizerResult};
use regex::Regex;

/// A named regex pattern with a confidence score
#[derive(Debug, Clone)]
pub struct Pattern {
    pub name: String,
    pub regex: Regex,
    pub score: f32,
}

/// A recognizer that uses regex patterns to detect PII
pub struct PatternRecognizer {
    patterns: Vec<Pattern>,
    entity_type: String,
}

impl PatternRecognizer {
    /// Create a new pattern recognizer for the given entity type
    pub fn new(entity_type: &str) -> Self {
        Self {
            patterns: Vec::new(),
            entity_type: entity_type.to_string(),
        }
    }

    /// Add a pattern to this recognizer
    pub fn add_pattern(
        &mut self,
        name: &str,
        regex_str: &str,
        score: f32,
    ) {
        if let Ok(regex) = Regex::new(regex_str) {
            self.patterns.push(Pattern {
                name: name.to_string(),
                regex,
                score,
            });
        } else {
            tracing::warn!("Invalid PII regex pattern '{}': {}", name, regex_str);
        }
    }
}

impl Recognizer for PatternRecognizer {
    fn recognize(
        &self,
        text: &str,
    ) -> Vec<RecognizerResult> {
        let mut results = Vec::new();
        for pattern in &self.patterns {
            for m in pattern.regex.find_iter(text) {
                results.push(RecognizerResult {
                    entity_type: self.entity_type.clone(),
                    matched: m.as_str().to_string(),
                    start: m.start(),
                    end: m.end(),
                    score: pattern.score,
                });
            }
        }
        results
    }

    fn name(&self) -> &str {
        &self.entity_type
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_recognizer() {
        let mut recognizer = PatternRecognizer::new("TEST");
        recognizer.add_pattern("test_pattern", r"\b\d{3}-\d{4}\b", 0.5);

        let results = recognizer.recognize("Call 555-1234 now");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].matched, "555-1234");
        assert_eq!(results[0].entity_type, "TEST");
    }
}
