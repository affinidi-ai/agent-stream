//! PII (Personally Identifiable Information) recognizer framework
//!
//! Provides built-in pattern recognizers for common PII types like
//! SSN, credit cards, email addresses, phone numbers, and more.

mod pattern_recognizer;
mod recognizer;
mod recognizer_result;

// Built-in recognizers
mod credit_card_recognizer;
mod email_recognizer;
mod ip_address_recognizer;
mod phone_recognizer;
mod ssn_recognizer;

pub use pattern_recognizer::PatternRecognizer;
pub use recognizer::Recognizer;
pub use recognizer_result::RecognizerResult;

use std::sync::LazyLock;

/// Built-in email recognizer
pub static EMAIL: LazyLock<Box<dyn Recognizer + Sync + Send + 'static>> =
    LazyLock::new(|| Box::new(email_recognizer::EmailRecognizer::new()));

/// Built-in phone number recognizer
pub static PHONE: LazyLock<Box<dyn Recognizer + Sync + Send + 'static>> =
    LazyLock::new(|| Box::new(phone_recognizer::PhoneRecognizer::new()));

/// Built-in credit card recognizer
pub static CREDIT_CARD: LazyLock<Box<dyn Recognizer + Sync + Send + 'static>> =
    LazyLock::new(|| Box::new(credit_card_recognizer::CreditCardRecognizer::new()));

/// Built-in US SSN recognizer
pub static SSN: LazyLock<Box<dyn Recognizer + Sync + Send + 'static>> =
    LazyLock::new(|| Box::new(ssn_recognizer::SsnRecognizer::new()));

/// Built-in IP address recognizer
pub static IP_ADDRESS: LazyLock<Box<dyn Recognizer + Sync + Send + 'static>> =
    LazyLock::new(|| Box::new(ip_address_recognizer::IpAddressRecognizer::new()));

/// Run a recognizer against text and return all matches
pub fn recognize(
    recognizer: &(dyn Recognizer + Sync + Send),
    text: &str,
) -> Vec<RecognizerResult> {
    recognizer.recognize(text)
}
