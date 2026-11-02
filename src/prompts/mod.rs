//! Versioned, reusable prompt templates rendered at the gateway.
//!
//! A [`Prompt`] is a named, versioned collection of chat messages with
//! `{{variable}}` placeholders. Clients can reference a prompt (by id +
//! optional version) in a request and supply variable values; the gateway
//! renders the selected version into an OpenAI `messages` array before the
//! request enters the normal pipeline. This decouples prompt changes from
//! application deploys and enables versioning / A/B testing.

pub mod expand;
pub mod store;
pub mod types;

pub use expand::{inject_messages, take_prompt_reference};
pub use store::{FileSystemPromptStore, global_prompt_store, set_global_prompt_store};
pub use types::is_valid_prompt_id;
