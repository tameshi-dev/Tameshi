//! Analysis utilities for smart contract vulnerability detection
//!
//! Foundational analysis capabilities shared by both deterministic and LLM-based
//! scanners. Pattern recognition identifies known safe coding practices, call graphs
//! enable interprocedural analysis, confidence scoring reduces false positives, and
//! specialized loop and path analyzers help detect complex vulnerability patterns by
//! understanding code structure and developer intent.

pub mod safe_patterns;
pub mod secure_patterns;
pub mod version_parser;
pub mod call_graph;
pub mod confidence;
pub mod interprocedural;
pub mod name_resolution;
pub mod hooks;
pub mod loop_analyzer;
pub mod path_explorer;

pub use safe_patterns::{SafePattern, SafePatternAnalysis, SafePatternRecognizer};
pub use secure_patterns::SecurePatternRecognizer as OpenZeppelinPatternRecognizer;
pub use version_parser::{SolidityVersion, parse_solidity_version};
pub use call_graph::{CallGraph, CallGraphBuilder, FunctionCall};
pub use confidence::{ConfidenceScorer, ConfidenceFactor};
pub use interprocedural::{
    InterproceduralAnalyzer, FunctionSummary, CrossFunctionPattern,
};
pub use name_resolution::canonical_match;
pub use hooks::{
    HookAnalyzer, CallbackType, CallbackTrigger,
    is_erc777_hook, is_nft_hook, is_callback_hook,
};
pub use loop_analyzer::{
    LoopAnalyzer, Loop, LoopReentrancyPattern,
};
pub use path_explorer::{
    PathExplorer, CFGPath, ConditionalReentrancyPattern,
};
