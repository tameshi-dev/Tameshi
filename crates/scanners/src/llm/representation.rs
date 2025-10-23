use crate::core::context::AnalysisContext;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

pub trait RepresentationExtractor: Debug + Send + Sync {
    fn extract(&self, context: &AnalysisContext) -> Result<RepresentationSnippet>;

    fn extract_focused(
        &self,
        context: &AnalysisContext,
        focus: &Focus,
    ) -> Result<RepresentationSnippet>;

    fn representation_type(&self) -> &str;

    fn estimate_tokens(&self, content: &str) -> usize {
        content.len() / 4
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepresentationSnippet {
    pub content: String,
    pub metadata: SnippetMetadata,
    pub token_count: usize,
}

impl RepresentationSnippet {
    pub fn new(content: String, metadata: SnippetMetadata) -> Self {
        let token_count = content.len() / 4; // Simple estimation
        Self {
            content,
            metadata,
            token_count,
        }
    }

    pub fn placeholder() -> Self {
        Self {
            content: "Contract code representation".to_string(),
            metadata: SnippetMetadata::placeholder(),
            token_count: 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnippetMetadata {
    pub representation_type: String,
    pub extraction_strategy: String,
    pub source_location: Option<SourceLocation>,
    pub included_functions: Vec<String>,
    pub included_contracts: Vec<String>,
    pub was_truncated: bool,
}

impl SnippetMetadata {
    pub fn placeholder() -> Self {
        Self {
            representation_type: "placeholder".to_string(),
            extraction_strategy: "none".to_string(),
            source_location: None,
            included_functions: vec![],
            included_contracts: vec![],
            was_truncated: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceLocation {
    pub file: String,
    pub start_line: usize,
    pub end_line: usize,
}

#[derive(Debug, Clone)]
pub enum Focus {
    Function(String),
    Contract(String),
    Pattern(VulnerabilityPattern),
    Region(SourceLocation),
    Multiple(Vec<Focus>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VulnerabilityPattern {
    ExternalCalls,
    AccessControl,
    Initialization,
    MoneyFlow,
    Arithmetic,
    LowLevelCalls,
    Events,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepresentationConfig {
    pub format: RepresentationFormat,
    pub max_tokens: usize,
    pub include_context: bool,
    pub snippet_strategy: SnippetStrategy,
    pub include_comments: bool,
    pub include_private: bool,
}

impl Default for RepresentationConfig {
    fn default() -> Self {
        Self {
            format: RepresentationFormat::Auto,
            max_tokens: 4000,
            include_context: true,
            snippet_strategy: SnippetStrategy::VulnerabilityFocused,
            include_comments: false,
            include_private: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RepresentationFormat {
    Semantic,
    IR,
    Combined,
    Auto,
    Placeholder,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SnippetStrategy {
    FullContract,
    FunctionLevel,
    VulnerabilityFocused,
    TokenOptimized,
    PublicInterface,
}

pub struct RepresentationConfigBuilder {
    config: RepresentationConfig,
}

impl Default for RepresentationConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RepresentationConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: RepresentationConfig::default(),
        }
    }

    pub fn format(mut self, format: RepresentationFormat) -> Self {
        self.config.format = format;
        self
    }

    pub fn max_tokens(mut self, max_tokens: usize) -> Self {
        self.config.max_tokens = max_tokens;
        self
    }

    pub fn snippet_strategy(mut self, strategy: SnippetStrategy) -> Self {
        self.config.snippet_strategy = strategy;
        self
    }

    pub fn include_context(mut self, include: bool) -> Self {
        self.config.include_context = include;
        self
    }

    pub fn include_comments(mut self, include: bool) -> Self {
        self.config.include_comments = include;
        self
    }

    pub fn include_private(mut self, include: bool) -> Self {
        self.config.include_private = include;
        self
    }

    pub fn build(self) -> RepresentationConfig {
        self.config
    }
}

pub struct TokenEstimator;

impl TokenEstimator {
    pub fn estimate(text: &str) -> usize {
        text.len() / 4
    }

    pub fn fits_budget(text: &str, max_tokens: usize) -> bool {
        Self::estimate(text) <= max_tokens
    }

    pub fn truncate_to_fit(text: &str, max_tokens: usize) -> String {
        let estimated_chars = max_tokens * 4;
        if text.len() <= estimated_chars {
            text.to_string()
        } else {
            let truncated = &text[..estimated_chars];
            format!("{}\n... (truncated)", truncated)
        }
    }
}
