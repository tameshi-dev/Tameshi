//! Command implementations for the Tameshi CLI
//!
//! Three specialized commands cover different analysis workflows: `scan` provides
//! fast deterministic vulnerability detection for CI/CD pipelines, `transform`
//! generates and inspects intermediate representations for debugging and research,
//! and `analyze` runs comprehensive multi-modal detection combining both pattern
//! matching and LLM-powered semantic analysis.

pub mod scan;
pub mod transform;
pub mod analyze;
