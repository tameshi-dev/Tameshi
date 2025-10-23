//! Analysis utilities for smart contract vulnerability detection
//!
//! Foundational analysis capabilities shared by both deterministic and LLM-based
//! scanners. Pattern recognition identifies known safe coding practices, call graphs
//! enable interprocedural analysis, confidence scoring reduces false positives, and
//! specialized loop and path analyzers help detect complex vulnerability patterns by
//! understanding code structure and developer intent.

pub mod call_graph;
pub mod confidence;
pub mod hooks;
pub mod interprocedural;
pub mod loop_analyzer;
pub mod name_resolution;
pub mod path_explorer;
pub mod safe_patterns;
pub mod secure_patterns;
pub mod version_parser;

pub use call_graph::{CallGraph, CallGraphBuilder, FunctionCall};
pub use confidence::{ConfidenceFactor, ConfidenceScorer};
pub use hooks::{
    is_callback_hook, is_erc777_hook, is_nft_hook, CallbackTrigger, CallbackType, HookAnalyzer,
};
pub use interprocedural::{CrossFunctionPattern, FunctionSummary, InterproceduralAnalyzer};
pub use loop_analyzer::{Loop, LoopAnalyzer, LoopReentrancyPattern};
pub use name_resolution::canonical_match;
pub use path_explorer::{CFGPath, ConditionalReentrancyPattern, PathExplorer};
pub use safe_patterns::{SafePattern, SafePatternAnalysis, SafePatternRecognizer};
pub use secure_patterns::SecurePatternRecognizer as OpenZeppelinPatternRecognizer;
pub use version_parser::{parse_solidity_version, SolidityVersion};
