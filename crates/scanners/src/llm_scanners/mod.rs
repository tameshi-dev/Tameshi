//! LLM-powered vulnerability scanners
//!
//! Uses a single comprehensive AI-powered scanner that detects all major vulnerability
//! types in one LLM call. This approach is significantly more cost-effective and faster
//! than running multiple specialized scanners, while maintaining high detection accuracy
//! through carefully crafted prompts that guide the model to analyze contracts for
//! reentrancy, access control, integer issues, unchecked calls, DoS vectors, weak
//! randomness, front-running, timestamp dependence, tx.origin misuse, and delegatecall
//! vulnerabilities.

pub mod llm_comprehensive_scanner;
pub mod suite;

pub use llm_comprehensive_scanner::LLMComprehensiveScanner;

pub use suite::{
    LLMScannerSuite,
    LLMScannerSuiteBuilder,
    create_llm_scanner_suite,
};
