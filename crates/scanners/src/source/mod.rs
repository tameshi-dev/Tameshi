//! Source-level vulnerability scanners
//!
//! Scanners analyzing Solidity source code directly through tree-sitter AST traversal.
//! These complement IR-based scanners by detecting patterns visible in source but
//! potentially lost in compilation: specific coding idioms, dangerous function usage,
//! and timestamp dependencies. Particularly effective for Solidity-specific features
//! and providing accurate source code locations in vulnerability reports.

pub mod loop_reentrancy;
pub mod classic_reentrancy;
pub mod integer_overflow;
pub mod access_control;
pub mod unchecked_return;
pub mod dangerous_functions;
pub mod time_vulnerabilities;
pub mod dos_vulnerabilities;
pub mod dos_ast;
pub mod missing_access_control;
pub mod gas_limit_dos;
pub mod delegatecall;
pub mod unchecked_overflow;
pub mod timestamp_simple;

pub use loop_reentrancy::SourceLoopReentrancyScanner;
pub use classic_reentrancy::SourceClassicReentrancyScanner;
pub use integer_overflow::SourceIntegerOverflowScanner;
pub use access_control::{SourceAccessControlScanner, get_functions_with_modifiers};
pub use unchecked_return::SourceUncheckedReturnScanner;
pub use dangerous_functions::SourceDangerousFunctionsScanner;
pub use time_vulnerabilities::SourceTimeVulnerabilitiesScanner;
pub use dos_vulnerabilities::SourceDoSVulnerabilitiesScanner;
pub use missing_access_control::SourceMissingAccessControlScanner;
pub use gas_limit_dos::SourceGasLimitDoSScanner;
pub use delegatecall::SourceDelegatecallScanner;
pub use unchecked_overflow::SourceUncheckedOverflowScanner;
pub use timestamp_simple::SimpleTimestampScanner;
