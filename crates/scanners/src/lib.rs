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

pub mod access_control;
pub mod cross_function_reentrancy;
pub mod dangerous_functions;
pub mod dos_vulnerabilities;
pub mod integer_overflow;
pub mod price_manipulation;
pub mod reentrancy;
pub mod state_modifications;
pub mod time_vulnerabilities;
pub mod unchecked_return;

pub mod source;

pub mod provenance;

#[cfg(feature = "llm")]
pub mod llm;

#[cfg(feature = "llm")]
pub mod llm_scanners;

pub use core::{AnalysisContext, Confidence, ContractInfo, Finding, Scanner, Severity};

pub use representations::{Representation, RepresentationBundle};

pub use runner::{ScanReport, ScannerRegistry, ScanningEngine};

pub use access_control::IRAccessControlScanner;
pub use cross_function_reentrancy::IRCrossFunctionReentrancyScanner;
pub use dangerous_functions::IRDangerousFunctionsScanner;
pub use dos_vulnerabilities::IRDoSVulnerabilityScanner;
pub use integer_overflow::IRIntegerOverflowScanner;
pub use price_manipulation::IRPriceManipulationScanner;
pub use reentrancy::IRReentrancyScanner;
pub use state_modifications::IRStateModificationScanner;
pub use time_vulnerabilities::IRTimeVulnerabilityScanner;
pub use unchecked_return::IRUncheckedReturnScanner;

pub use source::{
    get_functions_with_modifiers, SimpleTimestampScanner, SourceAccessControlScanner,
    SourceClassicReentrancyScanner, SourceDangerousFunctionsScanner, SourceDelegatecallScanner,
    SourceDoSVulnerabilitiesScanner, SourceGasLimitDoSScanner, SourceIntegerOverflowScanner,
    SourceLoopReentrancyScanner, SourceMissingAccessControlScanner,
    SourceTimeVulnerabilitiesScanner, SourceUncheckedOverflowScanner, SourceUncheckedReturnScanner,
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
