//! Judge & Jury — LLM-based content validation pipeline
//!
//! Provides pre-processing (Judge) and post-processing (Jury) LLM-based validation
//! for LLM pipe requests and responses, complementing the regex-based Prompt Guard.
//!
//! # Pipeline Flow
//!
//! ```text
//! Request → Prompt Guard (regex) → Judge (LLM) → Processing LLM
//!     → Prompt Guard (regex) → Jury (LLM) → Response
//! ```
//!
//! # Judge
//!
//! After Prompt Guard passes, the Judge sends the entire payload to a separate LLM
//! with a user-defined system prompt to validate whether the request should proceed.
//!
//! # Jury
//!
//! After the processing LLM responds and Prompt Guard passes, one or more Jury members
//! (each with their own LLM and system prompt) validate the response.
//! Supports parallel, serial, and majority voting execution modes.

mod config;
mod executor;

pub use config::*;
pub use executor::*;
