//! LLM Scanner Suite Builder
//!
//! Provides a high-level API for creating and managing the comprehensive LLM scanner.
//! This module is designed for programmatic use by LSP servers, IDEs, and other tools.

use crate::core::Scanner;
use crate::llm::provider::LLMProvider;
use crate::llm_scanners::LLMComprehensiveScanner;
use anyhow::Result;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LLMScannerSuite {
    SingleComprehensive,
}

impl LLMScannerSuite {
    pub fn name(&self) -> &'static str {
        match self {
            Self::SingleComprehensive => "Single Comprehensive",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::SingleComprehensive => {
                "Single comprehensive scanner detecting all vulnerability types in one call"
            }
        }
    }

    pub fn scanner_count(&self) -> usize {
        match self {
            Self::SingleComprehensive => 1,
        }
    }
}

pub struct LLMScannerSuiteBuilder {
    suite: LLMScannerSuite,
    provider: Option<Arc<dyn LLMProvider>>,
    dump_prompt: bool,
    dump_response: bool,
}

impl LLMScannerSuiteBuilder {
    pub fn new(suite: LLMScannerSuite) -> Self {
        Self {
            suite,
            provider: None,
            dump_prompt: false,
            dump_response: false,
        }
    }

    pub fn with_provider(mut self, provider: Arc<dyn LLMProvider>) -> Self {
        self.provider = Some(provider);
        self
    }

    pub fn with_dump_prompt(mut self, dump_prompt: bool) -> Self {
        self.dump_prompt = dump_prompt;
        self
    }

    pub fn with_dump_response(mut self, dump_response: bool) -> Self {
        self.dump_response = dump_response;
        self
    }

    pub fn build(self) -> Result<Vec<Arc<dyn Scanner>>> {
        let provider = self
            .provider
            .ok_or_else(|| anyhow::anyhow!("LLM provider must be set before building suite"))?;

        let mut scanners: Vec<Arc<dyn Scanner>> = Vec::new();

        match self.suite {
            LLMScannerSuite::SingleComprehensive => {
                let scanner = LLMComprehensiveScanner::new(provider.clone())
                    .with_dump_prompt(self.dump_prompt)
                    .with_dump_response(self.dump_response);
                scanners.push(Arc::new(scanner));
            }
        }

        Ok(scanners)
    }
}

pub fn create_llm_scanner_suite(
    suite: LLMScannerSuite,
    provider: Arc<dyn LLMProvider>,
) -> Result<Vec<Arc<dyn Scanner>>> {
    LLMScannerSuiteBuilder::new(suite)
        .with_provider(provider)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::provider::{LLMResponse, TokenUsage};
    use async_trait::async_trait;

    struct MockProvider;

    #[async_trait]
    impl LLMProvider for MockProvider {
        async fn analyze(
            &self,
            _request: crate::llm::provider::LLMRequest,
        ) -> std::result::Result<LLMResponse, crate::llm::provider::LLMError> {
            Ok(LLMResponse {
                content: r#"{"vulnerabilities": []}"#.to_string(),
                model: "mock-model".to_string(),
                usage: TokenUsage {
                    prompt_tokens: 100,
                    completion_tokens: 50,
                    total_tokens: 150,
                },
            })
        }

        fn max_tokens(&self) -> usize {
            4096
        }

        fn model_name(&self) -> &str {
            "mock-model"
        }
    }

    #[test]
    fn test_suite_properties() {
        assert_eq!(
            LLMScannerSuite::SingleComprehensive.name(),
            "Single Comprehensive"
        );
        assert_eq!(
            LLMScannerSuite::SingleComprehensive.description(),
            "Single comprehensive scanner detecting all vulnerability types in one call"
        );
        assert_eq!(LLMScannerSuite::SingleComprehensive.scanner_count(), 1);
    }

    #[test]
    fn test_builder_without_provider_fails() {
        let result = LLMScannerSuiteBuilder::new(LLMScannerSuite::SingleComprehensive).build();
        assert!(result.is_err(), "Builder should fail without provider");
        match result {
            Err(e) => assert!(e.to_string().contains("provider must be set")),
            Ok(_) => panic!("Should have failed"),
        }
    }

    #[test]
    fn test_builder_with_provider_succeeds() {
        let provider = Arc::new(MockProvider);
        let result = LLMScannerSuiteBuilder::new(LLMScannerSuite::SingleComprehensive)
            .with_provider(provider)
            .build();

        assert!(result.is_ok());
        let scanners = result.unwrap();
        assert_eq!(
            scanners.len(),
            1,
            "SingleComprehensive suite should have 1 scanner"
        );
    }

    #[test]
    fn test_builder_comprehensive_suite() {
        let provider = Arc::new(MockProvider);
        let scanners = LLMScannerSuiteBuilder::new(LLMScannerSuite::SingleComprehensive)
            .with_provider(provider)
            .build()
            .expect("Failed to build SingleComprehensive suite");

        assert_eq!(scanners.len(), 1);
        assert_eq!(scanners[0].id(), "llm_comprehensive");
        assert_eq!(scanners[0].name(), "LLM Comprehensive Security Scanner");
    }

    #[test]
    fn test_builder_with_debug_flags() {
        let provider = Arc::new(MockProvider);
        let result = LLMScannerSuiteBuilder::new(LLMScannerSuite::SingleComprehensive)
            .with_provider(provider)
            .with_dump_prompt(true)
            .with_dump_response(true)
            .build();

        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[test]
    fn test_convenience_function() {
        let provider = Arc::new(MockProvider);
        let scanners = create_llm_scanner_suite(LLMScannerSuite::SingleComprehensive, provider)
            .expect("Convenience function should succeed");

        assert_eq!(scanners.len(), 1);
    }

    #[test]
    fn test_scanners_implement_scanner_trait() {
        let provider = Arc::new(MockProvider);
        let scanners = create_llm_scanner_suite(LLMScannerSuite::SingleComprehensive, provider)
            .expect("Failed to create scanners");

        for scanner in scanners {
            assert!(!scanner.id().is_empty());
            assert!(!scanner.name().is_empty());
            assert!(!scanner.description().is_empty());
            assert!(scanner.enabled_by_default());
        }
    }

    #[test]
    fn test_scanner_registry_integration() {
        use crate::runner::ScannerRegistry;

        let provider = Arc::new(MockProvider);
        let scanners = create_llm_scanner_suite(LLMScannerSuite::SingleComprehensive, provider)
            .expect("Failed to create scanners");

        let mut registry = ScannerRegistry::new();

        for scanner in scanners {
            registry.register_llm_scanner(scanner);
        }

        assert_eq!(registry.list_ids().len(), 1);
        assert!(registry.get("llm_comprehensive").is_some());
    }
}
