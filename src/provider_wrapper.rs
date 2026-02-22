//! Re-exports the dynamic provider from the agentic library.
//!
//! The implementation has been moved to `orra::providers::dynamic`.
//! This module re-exports the types for backward compatibility within
//! this crate.

pub use orra::providers::dynamic::{DynamicProvider, PlaceholderProvider};
