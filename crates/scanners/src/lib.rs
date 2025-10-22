//! Tameshi Scanners - Vulnerability Detection Framework
//!
//! This crate provides a flexible, trait-based system for detecting vulnerabilities
//! in smart contracts through multiple program representations.

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_assignments)]

pub mod analysis;
pub mod core;
pub mod representations;
pub mod runner;

pub mod reentrancy;
pub mod unchecked_return;
pub mod state_modifications;
pub mod dangerous_functions;
pub mod integer_overflow;
pub mod access_control;
pub mod time_vulnerabilities;
pub mod dos_vulnerabilities;
pub mod price_manipulation;
pub mod cross_function_reentrancy;

pub mod source;

pub mod provenance;

#[cfg(feature = "llm")]
pub mod llm;

#[cfg(feature = "llm")]
pub mod llm_scanners;

pub use core::{AnalysisContext, ContractInfo, Confidence, Scanner, Finding, Severity};

pub use representations::{Representation, RepresentationBundle};

pub use runner::{ScanningEngine, ScanReport, ScannerRegistry};

pub use reentrancy::IRReentrancyScanner;
pub use access_control::IRAccessControlScanner;
pub use unchecked_return::IRUncheckedReturnScanner;
pub use state_modifications::IRStateModificationScanner;
pub use dangerous_functions::IRDangerousFunctionsScanner;
pub use integer_overflow::IRIntegerOverflowScanner;
pub use time_vulnerabilities::IRTimeVulnerabilityScanner;
pub use dos_vulnerabilities::IRDoSVulnerabilityScanner;
pub use price_manipulation::IRPriceManipulationScanner;
pub use cross_function_reentrancy::IRCrossFunctionReentrancyScanner;

pub use source::{
    SourceLoopReentrancyScanner,
    SourceClassicReentrancyScanner,
    SourceIntegerOverflowScanner,
    SourceAccessControlScanner,
    SourceUncheckedReturnScanner,
    SourceDangerousFunctionsScanner,
    SourceTimeVulnerabilitiesScanner,
    SourceDoSVulnerabilitiesScanner,
    SourceMissingAccessControlScanner,
    SourceGasLimitDoSScanner,
    SourceDelegatecallScanner,
    SourceUncheckedOverflowScanner,
    SimpleTimestampScanner,
    get_functions_with_modifiers,
};

pub use source::dos_ast::ASTDoSVulnerabilitiesScanner;

pub use provenance::get_instruction_location;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_registration() {
        let registry = ScannerRegistry::default();
        assert_eq!(registry.list_ids().len(), 0);
    }
}

#[cfg(test)]
mod test_imports;
