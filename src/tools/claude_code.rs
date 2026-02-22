//! Re-exports the Claude Code tool from the orra library.
//!
//! Configuration is handled in this crate's config module; registration
//! wires it up via `orra::tools::claude_code::register_tools`.

pub use orra::tools::claude_code::{ClaudeCodeConfig, ClaudeCodeTool, ClaudeCodeResumeTool};
