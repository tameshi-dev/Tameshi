use crate::llm::{
    hybrid_extractor::HybridExtractor,
    provider::{LLMProvider, OpenAIProvider},
    representation::RepresentationConfig,
    scanner::{LLMScanner, LLMScannerConfig},
    source_extractor::SoliditySourceExtractor,
    thalir_extractor::ThalIRExtractor,
};
use anyhow::Result;
use std::sync::Arc;

pub struct LLMScannerFactory {
    provider: Arc<dyn LLMProvider>,
}

impl LLMScannerFactory {
    pub fn new_openai(model: Option<String>) -> Result<Self> {
        let provider = OpenAIProvider::new(model)?;
        Ok(Self {
            provider: Arc::new(provider),
        })
    }

    pub fn with_provider(provider: Arc<dyn LLMProvider>) -> Self {
        Self { provider }
    }

    pub fn create_general_scanner(&self) -> LLMScanner {
        let config = LLMScannerConfig {
            template_name: "general_vulnerability".to_string(),
            scanner_name: "llm_general".to_string(),
            description: "LLM-based general vulnerability scanner".to_string(),
            temperature: 0.2,
            max_tokens: 4000,
            confidence_threshold: 0.5,
            include_low_severity: false,
            representation_config: RepresentationConfig::default(),
            dump_prompt: false,
        };

        LLMScanner::new(self.provider.clone(), config)
    }

    pub fn create_reentrancy_scanner(&self) -> LLMScanner {
        let config = LLMScannerConfig {
            template_name: "reentrancy".to_string(),
            scanner_name: "llm_reentrancy".to_string(),
            description: "LLM-based reentrancy vulnerability scanner".to_string(),
            temperature: 0.15, // Lower temperature for more focused detection
            max_tokens: 3000,
            confidence_threshold: 0.6, // Higher threshold for specific scanner
            include_low_severity: false,
            representation_config: RepresentationConfig::default(),
            dump_prompt: false,
        };

        LLMScanner::new(self.provider.clone(), config)
    }

    pub fn create_access_control_scanner(&self) -> LLMScanner {
        let config = LLMScannerConfig {
            template_name: "access_control".to_string(),
            scanner_name: "llm_access_control".to_string(),
            description: "LLM-based access control vulnerability scanner".to_string(),
            temperature: 0.15,
            max_tokens: 3000,
            confidence_threshold: 0.6,
            include_low_severity: false,
            representation_config: RepresentationConfig::default(),
            dump_prompt: false,
        };

        LLMScanner::new(self.provider.clone(), config)
    }

    pub fn create_overflow_scanner(&self) -> LLMScanner {
        let config = LLMScannerConfig {
            template_name: "overflow".to_string(),
            scanner_name: "llm_overflow".to_string(),
            description: "LLM-based integer overflow/underflow scanner".to_string(),
            temperature: 0.1, // Very low temperature for arithmetic analysis
            max_tokens: 2500,
            confidence_threshold: 0.7, // High threshold for arithmetic issues
            include_low_severity: false,
            representation_config: RepresentationConfig::default(),
            dump_prompt: false,
        };

        LLMScanner::new(self.provider.clone(), config)
    }

    pub fn create_logic_error_scanner(&self) -> LLMScanner {
        let config = LLMScannerConfig {
            template_name: "logic_error".to_string(),
            scanner_name: "llm_logic".to_string(),
            description: "LLM-based business logic error scanner".to_string(),
            temperature: 0.25, // Slightly higher for creative logic analysis
            max_tokens: 4000,
            confidence_threshold: 0.5,
            include_low_severity: true, // Include low severity for logic issues
            representation_config: RepresentationConfig::default(),
            dump_prompt: false,
        };

        LLMScanner::new(self.provider.clone(), config)
    }

    pub fn create_custom_scanner(&self, config: LLMScannerConfig) -> LLMScanner {
        LLMScanner::new(self.provider.clone(), config)
    }

    pub fn create_unchecked_returns_scanner(&self) -> LLMScanner {
        let config = LLMScannerConfig {
            template_name: "unchecked_returns".to_string(),
            scanner_name: "llm_unchecked_returns".to_string(),
            description: "LLM-based unchecked return values scanner".to_string(),
            temperature: 0.1, // Low temperature for precise detection
            max_tokens: 3000,
            confidence_threshold: 0.65,
            include_low_severity: false,
            representation_config: RepresentationConfig::default(),
            dump_prompt: false,
        };

        LLMScanner::new(self.provider.clone(), config)
    }

    pub fn create_dos_patterns_scanner(&self) -> LLMScanner {
        let config = LLMScannerConfig {
            template_name: "dos_patterns".to_string(),
            scanner_name: "llm_dos".to_string(),
            description: "LLM-based denial-of-service patterns scanner".to_string(),
            temperature: 0.15,
            max_tokens: 3500,
            confidence_threshold: 0.6,
            include_low_severity: false,
            representation_config: RepresentationConfig::default(),
            dump_prompt: false,
        };

        LLMScanner::new(self.provider.clone(), config)
    }

    pub fn create_timestamp_dependence_scanner(&self) -> LLMScanner {
        let config = LLMScannerConfig {
            template_name: "timestamp_dependence".to_string(),
            scanner_name: "llm_timestamp".to_string(),
            description: "LLM-based timestamp dependence scanner".to_string(),
            temperature: 0.1, // Very low for deterministic analysis
            max_tokens: 2500,
            confidence_threshold: 0.7,
            include_low_severity: true, // Include low severity for timestamp issues
            representation_config: RepresentationConfig::default(),
            dump_prompt: false,
        };

        LLMScanner::new(self.provider.clone(), config)
    }

    pub fn create_front_running_scanner(&self) -> LLMScanner {
        let config = LLMScannerConfig {
            template_name: "front_running".to_string(),
            scanner_name: "llm_front_running".to_string(),
            description: "LLM-based front-running and MEV scanner".to_string(),
            temperature: 0.2,
            max_tokens: 3500,
            confidence_threshold: 0.55,
            include_low_severity: false,
            representation_config: RepresentationConfig::default(),
            dump_prompt: false,
        };

        LLMScanner::new(self.provider.clone(), config)
    }

    pub fn create_source_scanner(&self) -> LLMScanner {
        let config = LLMScannerConfig {
            template_name: "source_analysis".to_string(),
            scanner_name: "llm_source".to_string(),
            description: "LLM-based scanner operating on raw Solidity source code".to_string(),
            temperature: 0.2,
            max_tokens: 4000,
            confidence_threshold: 0.5,
            include_low_severity: true,
            representation_config: RepresentationConfig::default(),
            dump_prompt: false,
        };

        let source_extractor = Box::new(SoliditySourceExtractor::new());
        LLMScanner::new(self.provider.clone(), config).with_extractor(source_extractor)
    }

    pub fn create_source_reentrancy_scanner(&self) -> LLMScanner {
        let config = LLMScannerConfig {
            template_name: "source_reentrancy".to_string(),
            scanner_name: "llm_source_reentrancy".to_string(),
            description: "Source-based reentrancy scanner".to_string(),
            temperature: 0.1,
            max_tokens: 3500,
            confidence_threshold: 0.65,
            include_low_severity: false,
            representation_config: RepresentationConfig::default(),
            dump_prompt: false,
        };

        let source_extractor = Box::new(SoliditySourceExtractor::new());
        LLMScanner::new(self.provider.clone(), config).with_extractor(source_extractor)
    }

    pub fn create_source_access_control_scanner(&self) -> LLMScanner {
        let config = LLMScannerConfig {
            template_name: "source_access_control".to_string(),
            scanner_name: "llm_source_access".to_string(),
            description: "Source-based access control scanner".to_string(),
            temperature: 0.15,
            max_tokens: 3500,
            confidence_threshold: 0.6,
            include_low_severity: false,
            representation_config: RepresentationConfig::default(),
            dump_prompt: false,
        };

        let source_extractor = Box::new(SoliditySourceExtractor::new());
        LLMScanner::new(self.provider.clone(), config).with_extractor(source_extractor)
    }

    pub fn create_source_unchecked_returns_scanner(&self) -> LLMScanner {
        let config = LLMScannerConfig {
            template_name: "source_unchecked_returns".to_string(),
            scanner_name: "llm_source_unchecked".to_string(),
            description: "Source-based unchecked returns scanner".to_string(),
            temperature: 0.1,
            max_tokens: 3000,
            confidence_threshold: 0.65,
            include_low_severity: false,
            representation_config: RepresentationConfig::default(),
            dump_prompt: false,
        };

        let source_extractor = Box::new(SoliditySourceExtractor::new());
        LLMScanner::new(self.provider.clone(), config).with_extractor(source_extractor)
    }

    pub fn create_source_dos_scanner(&self) -> LLMScanner {
        let config = LLMScannerConfig {
            template_name: "source_dos".to_string(),
            scanner_name: "llm_source_dos".to_string(),
            description: "Source-based DoS patterns scanner".to_string(),
            temperature: 0.15,
            max_tokens: 3500,
            confidence_threshold: 0.6,
            include_low_severity: false,
            representation_config: RepresentationConfig::default(),
            dump_prompt: false,
        };

        let source_extractor = Box::new(SoliditySourceExtractor::new());
        LLMScanner::new(self.provider.clone(), config).with_extractor(source_extractor)
    }

    pub fn create_source_timestamp_scanner(&self) -> LLMScanner {
        let config = LLMScannerConfig {
            template_name: "source_timestamp".to_string(),
            scanner_name: "llm_source_timestamp".to_string(),
            description: "Source-based timestamp dependence scanner".to_string(),
            temperature: 0.1,
            max_tokens: 2500,
            confidence_threshold: 0.7,
            include_low_severity: true,
            representation_config: RepresentationConfig::default(),
            dump_prompt: false,
        };

        let source_extractor = Box::new(SoliditySourceExtractor::new());
        LLMScanner::new(self.provider.clone(), config).with_extractor(source_extractor)
    }

    pub fn create_source_front_running_scanner(&self) -> LLMScanner {
        let config = LLMScannerConfig {
            template_name: "source_front_running".to_string(),
            scanner_name: "llm_source_frontrun".to_string(),
            description: "Source-based front-running scanner".to_string(),
            temperature: 0.2,
            max_tokens: 3500,
            confidence_threshold: 0.55,
            include_low_severity: false,
            representation_config: RepresentationConfig::default(),
            dump_prompt: false,
        };

        let source_extractor = Box::new(SoliditySourceExtractor::new());
        LLMScanner::new(self.provider.clone(), config).with_extractor(source_extractor)
    }

    pub fn create_source_overflow_scanner(&self) -> LLMScanner {
        let config = LLMScannerConfig {
            template_name: "source_overflow".to_string(),
            scanner_name: "llm_source_overflow".to_string(),
            description: "Source-based overflow/underflow scanner".to_string(),
            temperature: 0.1,
            max_tokens: 2500,
            confidence_threshold: 0.7,
            include_low_severity: false,
            representation_config: RepresentationConfig::default(),
            dump_prompt: false,
        };

        let source_extractor = Box::new(SoliditySourceExtractor::new());
        LLMScanner::new(self.provider.clone(), config).with_extractor(source_extractor)
    }

    pub fn create_thalir_scanner(&self) -> LLMScanner {
        let config = LLMScannerConfig {
            template_name: "thalir-simple".to_string(),
            scanner_name: "llm_thalir_general".to_string(),
            description: "ThalIR-based general vulnerability scanner".to_string(),
            temperature: 0.2,
            max_tokens: 3000,
            confidence_threshold: 0.5,
            include_low_severity: false,
            representation_config: RepresentationConfig::default(),
            dump_prompt: false,
        };

        let thalir_extractor = Box::new(ThalIRExtractor::new(config.representation_config.clone()));
        LLMScanner::new(self.provider.clone(), config).with_extractor(thalir_extractor)
    }

    pub fn create_thalir_reentrancy_scanner(&self) -> LLMScanner {
        let config = LLMScannerConfig {
            template_name: "thalir-reentrancy".to_string(),
            scanner_name: "llm_thalir_reentrancy".to_string(),
            description: "ThalIR-based reentrancy vulnerability scanner".to_string(),
            temperature: 0.15,
            max_tokens: 2500,
            confidence_threshold: 0.6,
            include_low_severity: false,
            representation_config: RepresentationConfig::default(),
            dump_prompt: false,
        };

        let thalir_extractor = Box::new(ThalIRExtractor::new(config.representation_config.clone()));
        LLMScanner::new(self.provider.clone(), config).with_extractor(thalir_extractor)
    }

    pub fn create_hybrid_reentrancy_scanner(&self) -> LLMScanner {
        let config = LLMScannerConfig {
            template_name: "hybrid-reentrancy".to_string(),
            scanner_name: "llm_hybrid_reentrancy".to_string(),
            description: "Hybrid source + IR reentrancy vulnerability scanner".to_string(),
            temperature: 0.1,
            max_tokens: 4000,          // Higher token limit for dual representations
            confidence_threshold: 0.7, // Higher threshold for hybrid validation
            include_low_severity: false,
            representation_config: RepresentationConfig::default(),
            dump_prompt: false,
        };

        let hybrid_extractor = Box::new(HybridExtractor::new(config.representation_config.clone()));
        LLMScanner::new(self.provider.clone(), config).with_extractor(hybrid_extractor)
    }

    pub fn create_hybrid_access_control_scanner(&self) -> LLMScanner {
        let config = LLMScannerConfig {
            template_name: "hybrid-access-control".to_string(),
            scanner_name: "llm_hybrid_access_control".to_string(),
            description: "Hybrid source + IR access control vulnerability scanner".to_string(),
            temperature: 0.1,
            max_tokens: 4000,
            confidence_threshold: 0.7,
            include_low_severity: false,
            representation_config: RepresentationConfig::default(),
            dump_prompt: false,
        };

        let hybrid_extractor = Box::new(HybridExtractor::new(config.representation_config.clone()));
        LLMScanner::new(self.provider.clone(), config).with_extractor(hybrid_extractor)
    }

    pub fn create_all_scanners(&self) -> Vec<LLMScanner> {
        vec![
            self.create_general_scanner(),
            self.create_reentrancy_scanner(),
            self.create_access_control_scanner(),
            self.create_overflow_scanner(),
            self.create_logic_error_scanner(),
            self.create_unchecked_returns_scanner(),
            self.create_dos_patterns_scanner(),
            self.create_timestamp_dependence_scanner(),
            self.create_front_running_scanner(),
            self.create_source_scanner(),
        ]
    }
}

pub struct LLMScannerBuilder {
    config: LLMScannerConfig,
}

impl LLMScannerBuilder {
    pub fn new(scanner_name: impl Into<String>) -> Self {
        Self {
            config: LLMScannerConfig {
                template_name: "general_vulnerability".to_string(),
                scanner_name: scanner_name.into(),
                description: "Custom LLM scanner".to_string(),
                temperature: 0.2,
                max_tokens: 4000,
                confidence_threshold: 0.5,
                include_low_severity: false,
                representation_config: RepresentationConfig::default(),
                dump_prompt: false,
            },
        }
    }

    pub fn template(mut self, template_name: impl Into<String>) -> Self {
        self.config.template_name = template_name.into();
        self
    }

    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.config.description = description.into();
        self
    }

    pub fn temperature(mut self, temperature: f32) -> Self {
        self.config.temperature = temperature.clamp(0.0, 1.0);
        self
    }

    pub fn max_tokens(mut self, max_tokens: u32) -> Self {
        self.config.max_tokens = max_tokens;
        self
    }

    pub fn confidence_threshold(mut self, threshold: f32) -> Self {
        self.config.confidence_threshold = threshold.clamp(0.0, 1.0);
        self
    }

    pub fn include_low_severity(mut self, include: bool) -> Self {
        self.config.include_low_severity = include;
        self
    }

    pub fn representation_config(mut self, config: RepresentationConfig) -> Self {
        self.config.representation_config = config;
        self
    }

    pub fn build(self) -> LLMScannerConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_builder() {
        let config = LLMScannerBuilder::new("test_scanner")
            .template("reentrancy")
            .description("Test reentrancy scanner")
            .temperature(0.15)
            .max_tokens(3000)
            .confidence_threshold(0.7)
            .include_low_severity(false)
            .build();

        assert_eq!(config.scanner_name, "test_scanner");
        assert_eq!(config.template_name, "reentrancy");
        assert_eq!(config.temperature, 0.15);
        assert_eq!(config.max_tokens, 3000);
        assert_eq!(config.confidence_threshold, 0.7);
        assert!(!config.include_low_severity);
    }
}
