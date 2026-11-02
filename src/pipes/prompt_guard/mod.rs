//! Prompt Guard — Content filtering for LLM pipe requests and responses
//!
//! Inspects and filters LLM requests/responses to prevent prompt injection attacks
//! and block sensitive data (PII) from being sent to AI models or returned to clients.
//!
//! # Features
//!
//! - **Regex-based filtering**: Custom regex patterns and built-in PII detectors
//! - **Request guards**: Filter content before it reaches the LLM provider
//! - **Response guards**: Filter LLM responses before they reach the client
//! - **Two actions**: `reject` (block the request) or `mask` (rewrite matched content)
//! - **Two mask modes**: `redact` (static `<EMAIL>` token) or `pseudonymize`
//!   (stable NER IDs like `[EMAIL_NER_001]` that preserve entity relationships)
//! - **Built-in PII patterns**: SSN, credit card, email, phone number, IP address
//!
//! # Configuration
//!
//! ```json
//! {
//!   "prompt_guard": {
//!     "request": [
//!       {
//!         "regex": {
//!           "action": "reject",
//!           "rules": [
//!             { "builtin": "ssn" },
//!             { "builtin": "credit_card" },
//!             { "pattern": "password[=:]\\s*\\S+" }
//!           ]
//!         },
//!         "rejection": {
//!           "status_code": 400,
//!           "body": "Request rejected: contains sensitive information"
//!         }
//!       }
//!     ],
//!     "response": [
//!       {
//!         "regex": {
//!           "action": "mask",
//!           "rules": [
//!             { "builtin": "email" },
//!             { "builtin": "phone_number" }
//!           ]
//!         }
//!       }
//!     ]
//!   }
//! }
//! ```

#[allow(dead_code)]
pub mod pii;

mod config;
mod definitions;
mod external;
mod filter;
mod pii_cache;
mod stream_rehydrate;

pub mod detector_stats;
pub mod llm_pii;

pub use config::*;
pub use definitions::*;
pub use external::*;
pub use filter::*;
pub use stream_rehydrate::StreamRehydrator;
