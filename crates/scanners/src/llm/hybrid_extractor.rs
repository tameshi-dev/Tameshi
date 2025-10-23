use super::representation::{
    RepresentationConfig, RepresentationExtractor, RepresentationSnippet, SnippetMetadata,
    TokenEstimator,
};
use anyhow::Result;
use std::fmt::Write;

#[derive(Debug)]
pub struct HybridExtractor {
    config: RepresentationConfig,
}

impl HybridExtractor {
    pub fn new(config: RepresentationConfig) -> Self {
        Self { config }
    }

    pub fn extract_hybrid(&self, source: &str, ir: &str) -> Result<RepresentationSnippet> {
        let mut output = String::new();
        let mut token_count = 0;

        writeln!(output, "# Hybrid Analysis: Source Code + Cranelift IR")?;
        writeln!(output, "## Source Code Context")?;
        writeln!(output, "```solidity")?;
        writeln!(output, "{}", source)?;
        writeln!(output, "```")?;
        writeln!(output)?;
        writeln!(output, "## Corresponding Cranelift IR")?;
        writeln!(output, "```")?;
        writeln!(output, "{}", ir)?;
        writeln!(output, "```")?;

        token_count = TokenEstimator::estimate(&output);

        Ok(RepresentationSnippet {
            content: output,
            token_count,
            metadata: SnippetMetadata {
                representation_type: "hybrid_source_ir".to_string(),
                extraction_strategy: "dual_layer".to_string(),
                was_truncated: false,
                included_functions: vec![],
                included_contracts: vec![],
                source_location: None,
            },
        })
    }
}

impl RepresentationExtractor for HybridExtractor {
    fn extract(
        &self,
        _context: &crate::core::context::AnalysisContext,
    ) -> Result<RepresentationSnippet> {
        Ok(RepresentationSnippet {
            content: "Hybrid extractor requires specific source and IR inputs".to_string(),
            token_count: 10,
            metadata: SnippetMetadata {
                representation_type: "hybrid".to_string(),
                extraction_strategy: "placeholder".to_string(),
                was_truncated: false,
                included_functions: vec![],
                included_contracts: vec![],
                source_location: None,
            },
        })
    }

    fn extract_focused(
        &self,
        _context: &crate::core::context::AnalysisContext,
        _focus: &super::representation::Focus,
    ) -> Result<RepresentationSnippet> {
        self.extract(_context)
    }

    fn representation_type(&self) -> &str {
        "hybrid_source_ir"
    }
}
