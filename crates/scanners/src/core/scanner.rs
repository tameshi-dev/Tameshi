//! Scanner trait and architecture for pluggable vulnerability detection.
//!
//! ## Design Philosophy: Composition over Inheritance
//!
//! Rather than a monolithic analyzer, Tameshi uses independent scanners that implement
//! a common trait. This architecture enables:
//!
//! 1. **Parallel Execution**: Scanners have no shared mutable state, making them trivially
//!    parallelizable. A 10-scanner analysis can run 10x faster on a 10-core machine.
//!
//! 2. **Incremental Development**: New vulnerability patterns can be added as new scanners
//!    without touching existing code. No risk of regression in working detectors.
//!
//! 3. **Selective Analysis**: Users can disable expensive scanners for faster feedback loops,
//!    or enable only specific categories (e.g., "only check reentrancy").
//!
//! ## Why `RepresentationSet`?
//!
//! Different scanners work better with different intermediate representations:
//!
//! - **Source AST**: Best for style/pattern checks (unchecked return values, naming)
//! - **IR/CFG**: Best for data flow analysis (reentrancy, state tracking)
//! - **Call Graph**: Best for cross-contract interactions
//!
//! Rather than forcing all scanners to use one representation, we let each scanner
//! declare what it needs. The framework ensures these representations are available.
//!
//! ## The `HybridScanner` Extension
//!
//! Some sophisticated patterns benefit from multiple viewpoints. For example, detecting
//! a reentrancy in a library that's used by multiple contracts requires:
//! - IR analysis for the data flow pattern
//! - Call graph for cross-contract tracking
//! - Source context for meaningful error messages
//!
//! `HybridScanner` provides this multi-representation analysis capability.

use crate::core::{AnalysisContext, Confidence, Finding, Severity};
use crate::representations::RepresentationSet;
use anyhow::Result;

pub trait Scanner: Send + Sync {
    fn id(&self) -> &'static str;

    fn name(&self) -> &'static str;

    fn description(&self) -> &'static str {
        "No description provided"
    }

    fn severity(&self) -> Severity;

    fn confidence(&self) -> Confidence;

    fn scan(&self, context: &AnalysisContext) -> Result<Vec<Finding>>;

    fn required_representations(&self) -> RepresentationSet {
        RepresentationSet::default()
    }

    fn enabled_by_default(&self) -> bool {
        true
    }

    fn estimated_gas_cost(&self) -> u32 {
        100 // Default medium cost
    }
}

pub trait HybridScanner: Scanner {
    fn analyze_hybrid(&self, context: &AnalysisContext) -> Result<Vec<Finding>>;

    fn scan(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        self.analyze_hybrid(context)
    }
}

#[macro_export]
macro_rules! impl_scanner {
    (
        $scanner:ty,
        id: $id:expr,
        name: $name:expr,
        severity: $severity:expr,
        confidence: $confidence:expr
        $(, description: $description:expr)?
    ) => {
        impl Scanner for $scanner {
            fn id(&self) -> &'static str {
                $id
            }

            fn name(&self) -> &'static str {
                $name
            }

            fn severity(&self) -> Severity {
                $severity
            }

            fn confidence(&self) -> Confidence {
                $confidence
            }

            $(
                fn description(&self) -> &'static str {
                    $description
                }
            )?

            fn scan(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
                self.scan_impl(context)
            }
        }
    };
}
