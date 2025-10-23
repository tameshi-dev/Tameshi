//! LLM integration infrastructure for AI-powered vulnerability detection
//!
//! Foundation for using large language models to analyze smart contracts. Extractors
//! format different code representations (raw Solidity, IR, or hybrid views) into
//! prompts that LLMs can reason about effectively. The provider abstraction switches
//! between different LLM backends, while the schema system ensures structured,
//! parseable responses. This enables semantic understanding of vulnerability patterns
//! that are difficult to express as deterministic rules.

pub mod config;
pub mod factory;
pub mod hybrid_extractor;
pub mod ir_extractor;
pub mod ir_formatter;
pub mod ir_scanner_base;
pub mod llm_provider;
pub mod position_marked_ir_extractor;
pub mod prompts;
pub mod provider;
pub mod raw_solidity_extractor;
pub mod representation;
pub mod scanner;
pub mod schemas;
pub mod source_extractor;
pub mod thalir_extractor;

pub mod mock_provider;

pub use config::LLMConfig;
pub use factory::{LLMScannerBuilder, LLMScannerFactory};
pub use hybrid_extractor::HybridExtractor;
pub use ir_extractor::IRExtractor;
pub use ir_formatter::{IRFormatter, VulnerabilityFocus};
pub use position_marked_ir_extractor::PositionMarkedIRExtractor;
pub use prompts::{PromptBuilder, PromptTemplate};
pub use provider::{LLMError, LLMProvider, OpenAIProvider};
pub use representation::{
    Focus, RepresentationConfig, RepresentationExtractor, RepresentationFormat,
    RepresentationSnippet, SnippetStrategy, VulnerabilityPattern,
};
pub use scanner::{LLMScanner, LLMScannerConfig};
pub use schemas::{ScannerResponse, VulnerabilityFinding};
pub use source_extractor::SoliditySourceExtractor;
