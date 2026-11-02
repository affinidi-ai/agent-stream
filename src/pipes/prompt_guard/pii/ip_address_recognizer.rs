//! IP address recognizer

use super::{PatternRecognizer, Recognizer, RecognizerResult};

pub struct IpAddressRecognizer {
    inner: PatternRecognizer,
}

impl IpAddressRecognizer {
    pub fn new() -> Self {
        let mut recognizer = PatternRecognizer::new("IP_ADDRESS");
        // IPv4: 192.168.1.1
        recognizer.add_pattern(
            "ipv4",
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
            0.6,
        );
        // IPv6 (simplified, common formats)
        recognizer.add_pattern("ipv6", r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b", 0.7);
        Self { inner: recognizer }
    }
}

impl Recognizer for IpAddressRecognizer {
    fn recognize(
        &self,
        text: &str,
    ) -> Vec<RecognizerResult> {
        self.inner.recognize(text)
    }

    fn name(&self) -> &str {
        "IP_ADDRESS"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4() {
        let recognizer = IpAddressRecognizer::new();
        let results = recognizer.recognize("Server at 192.168.1.100");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].matched, "192.168.1.100");
    }

    #[test]
    fn test_ipv4_boundary() {
        let recognizer = IpAddressRecognizer::new();
        let results = recognizer.recognize("IP: 10.0.0.1 is internal");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].matched, "10.0.0.1");
    }

    #[test]
    fn test_no_ip() {
        let recognizer = IpAddressRecognizer::new();
        let results = recognizer.recognize("No IPs in this text");
        assert!(results.is_empty());
    }
}
