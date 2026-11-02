//! Pipe Templates — portable, reusable snapshots of pipe configurations.
//!
//! A template carries a whole-pipe snapshot the frontend applies to seed
//! the pipe canvas. Builtin templates ship out of the box; users can
//! also create, import and export their own.

pub mod filesystem;
pub mod handlers;
pub mod types;

pub use filesystem::FileSystemPipeTemplateStore;
#[allow(unused_imports)]
pub use types::{CreatePipeTemplate, PipeTemplate};
