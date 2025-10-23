//! Scanner execution and orchestration
//!
//! Handles running multiple scanners in parallel, aggregating their results, and
//! generating unified reports. The scanning engine manages execution flow while the
//! registry provides dynamic scanner discovery and instantiation. New scanners can
//! be added without modifying the execution infrastructure, supporting an extensible
//! architecture.

pub mod engine;
pub mod registry;

pub use engine::{ScanReport, ScanningEngine};
pub use registry::ScannerRegistry;
