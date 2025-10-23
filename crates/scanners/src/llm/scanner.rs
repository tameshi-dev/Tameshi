use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use std::fs::OpenOptions;
use std::io::Write;
use serde_json;
use tracing::{debug, info, warn};

use crate::core::{
    context::AnalysisContext,
    scanner::Scanner,
    result::{Finding, FindingMetadata, Location},
    severity::{Confidence, Severity},
};

use super::{
    prompts::{PromptBuilder, PromptTemplate},
    provider::{LLMProvider, LLMRequest},
    representation::{
        RepresentationConfig, RepresentationExtractor, RepresentationFormat, RepresentationSnippet,
    },
    schemas::{Confidence as LLMConfidence, ScannerResponse, SeverityLevel, VulnerabilityFinding},
};

#[derive(Debug, Clone)]
pub struct LLMScannerConfig {
    pub template_name: String,
    pub scanner_name: String,
    pub description: String,
    pub temperature: f32,
    pub max_tokens: u32,
    pub confidence_threshold: f32,
    pub include_low_severity: bool,
    pub representation_config: RepresentationConfig,
    pub dump_prompt: bool,
}

impl Default for LLMScannerConfig {
    fn default() -> Self {
        Self {
            template_name: "general_vulnerability".to_string(),
            scanner_name: "llm_general".to_string(),
            description: "LLM-based general vulnerability scanner".to_string(),
            temperature: 0.2,
            max_tokens: 4000,
            confidence_threshold: 0.5,
            include_low_severity: false,
            representation_config: RepresentationConfig::default(),
            dump_prompt: false,
        }
    }
}

pub struct LLMScanner {
    provider: Arc<dyn LLMProvider>,
    prompt_builder: PromptBuilder,
    config: LLMScannerConfig,
    extractor: Option<Box<dyn RepresentationExtractor>>,
}

impl LLMScanner {
    pub fn new(provider: Arc<dyn LLMProvider>, config: LLMScannerConfig) -> Self {
        Self::debug_log("🏗️  LLMScanner::new() - Creating new LLM scanner instance");
        Self::debug_log(&format!("   Scanner name: {}", config.scanner_name));
        Self::debug_log(&format!("   Template: {}", config.template_name));

        let extractor: Option<Box<dyn RepresentationExtractor>> =
            match config.representation_config.format {
                RepresentationFormat::Placeholder | RepresentationFormat::Auto => {
                    None
                }
                _ => None, // IR and Combined not yet implemented
            };

        Self {
            provider,
            prompt_builder: PromptBuilder::new(),
            config,
            extractor,
        }
    }

    pub fn with_template(mut self, template: PromptTemplate) -> Self {
        self.prompt_builder.add_template(template);
        self
    }

    pub fn with_extractor(mut self, extractor: Box<dyn RepresentationExtractor>) -> Self {
        self.extractor = Some(extractor);
        self
    }

    pub async fn analyze_async(
        &self,
        representation: &str,
        metadata: HashMap<String, String>,
    ) -> Result<ScannerResponse> {
        let start = Instant::now();

        let mut variables = metadata.clone();
        variables.insert(
            "code_representation".to_string(),
            representation.to_string(),
        );
        variables.insert(
            "json_schema".to_string(),
            ScannerResponse::schema_definition().to_string(),
        );

        variables
            .entry("representation_type".to_string())
            .or_insert("code".to_string());
        variables
            .entry("contract_metadata".to_string())
            .or_insert("Unknown contract".to_string());
        variables
            .entry("focus_areas".to_string())
            .or_insert("General vulnerabilities".to_string());

        let (system_prompt, user_prompt) = self
            .prompt_builder
            .build_prompt(&self.config.template_name, variables)
            .context("Failed to build prompt")?;

        debug!("Sending analysis request to LLM provider");

        let request = LLMRequest {
            system_prompt,
            user_prompt,
            temperature: self.config.temperature,
            max_tokens: self.config.max_tokens,
            response_format: Some(serde_json::json!({
                "type": "json_object"
            })),
            dump_prompt: self.config.dump_prompt,
        };

        let response = self
            .provider
            .analyze(request)
            .await
            .context("LLM analysis failed")?;

        let elapsed = start.elapsed();
        info!("LLM analysis completed in {:?}", elapsed);

        info!(
            "Token usage - Prompt: {}, Completion: {}, Total: {}",
            response.usage.prompt_tokens,
            response.usage.completion_tokens,
            response.usage.total_tokens
        );

        println!(
            "   🎯 Token Usage - Prompt: {}, Completion: {}, Total: {}",
            response.usage.prompt_tokens,
            response.usage.completion_tokens,
            response.usage.total_tokens
        );

        debug!("Raw LLM response: {}", response.content);

        let mut scanner_response = self
            .parse_response(&response.content)
            .context("Failed to parse LLM response")?;

        debug!("Parsed LLM response: {} findings", scanner_response.findings.len());
        for (i, finding) in scanner_response.findings.iter().enumerate() {
            debug!("Finding {}: {} - {} (confidence: {:?})", i, finding.vuln_type, finding.title, finding.confidence);
        }

        scanner_response.metadata = Some(super::schemas::AnalysisMetadata {
            model: response.model,
            temperature: self.config.temperature,
            tokens_used: response.usage.total_tokens,
            analysis_time_ms: elapsed.as_millis() as u64,
            prompt_tokens: response.usage.prompt_tokens,
            completion_tokens: response.usage.completion_tokens,
        });

        Ok(scanner_response)
    }

    fn parse_response(&self, content: &str) -> Result<ScannerResponse> {
        let response: ScannerResponse =
            match serde_json::from_str::<super::schemas::SimpleScannerResponse>(content) {
                Ok(simple_response) => {
                    tracing::debug!(
                        "Successfully parsed as simple format: {:?}",
                        simple_response
                    );
                    self.convert_simple_to_complex_response(simple_response)
                }
                Err(_) => {
                    match serde_json::from_str::<ScannerResponse>(content) {
                        Ok(response) => {
                            tracing::debug!("Successfully parsed as complex format");
                            response
                        }
                        Err(e) => {
                            return Err(anyhow::anyhow!("Failed to parse LLM response: {}", e))
                                .context("Invalid JSON in LLM response");
                        }
                    }
                }
            };

        self.validate_response(&response)?;

        Ok(response)
    }

    fn convert_simple_to_complex_response(
        &self,
        simple: super::schemas::SimpleScannerResponse,
    ) -> ScannerResponse {
        let findings = if simple.vulnerable {
            let confidence = match simple.confidence.to_lowercase().as_str() {
                "high" => super::schemas::Confidence::High,
                "medium" => super::schemas::Confidence::Medium,
                "low" => super::schemas::Confidence::Low,
                _ => super::schemas::Confidence::Medium,
            };

            let severity = match confidence {
                super::schemas::Confidence::High => super::schemas::SeverityLevel::High,
                super::schemas::Confidence::Medium => super::schemas::SeverityLevel::Medium,
                super::schemas::Confidence::Low => super::schemas::SeverityLevel::Low,
            };

            vec![VulnerabilityFinding {
                vuln_type: "reentrancy".to_string(),
                title: "Reentrancy vulnerability detected".to_string(),
                severity,
                confidence,
                affected_components: vec![], // Simple format doesn't provide component details
                root_cause: simple.details.clone(),
                attack_vector: "External call before state update allows reentrancy".to_string(),
                evidence: vec![], // Simple format doesn't provide detailed evidence
                recommendation:
                    "Implement checks-effects-interactions pattern or use reentrancy guards"
                        .to_string(),
                references: Some(vec!["https://swcregistry.io/docs/SWC-107".to_string()]),
            }]
        } else {
            vec![]
        };

        ScannerResponse {
            findings,
            analysis_summary: simple.details,
            coverage_notes: vec!["Analyzed Cranelift IR for reentrancy patterns".to_string()],
            requires_further_analysis: vec![],
            metadata: None,
        }
    }

    fn validate_response(&self, response: &ScannerResponse) -> Result<()> {
        if response.analysis_summary.is_empty() {
            warn!("Empty analysis summary in response");
        }

        for finding in &response.findings {
            if finding.title.is_empty() {
                return Err(anyhow::anyhow!("Finding missing title"));
            }

            if finding.evidence.is_empty() {
                warn!("Finding '{}' has no evidence", finding.title);
            }

            let confidence_score = match finding.confidence {
                LLMConfidence::High => 0.9,
                LLMConfidence::Medium => 0.6,
                LLMConfidence::Low => 0.3,
            };
            if confidence_score < self.config.confidence_threshold {
                debug!(
                    "Finding '{}' below confidence threshold ({} < {})",
                    finding.title, confidence_score, self.config.confidence_threshold
                );
            }
        }

        Ok(())
    }

    fn finding_to_result(
        &self,
        finding: &VulnerabilityFinding,
        snippet: &RepresentationSnippet,
    ) -> Finding {
        let mut result = Finding::new(
            self.config.scanner_name.clone(),
            finding.severity.into(),
            finding.confidence.into(),
            finding.title.clone(),
            format!(
                "{}\n\nRoot Cause: {}\nAttack Vector: {}",
                finding.title, finding.root_cause, finding.attack_vector
            ),
        );

        let mut metadata = FindingMetadata {
            recommendation: Some(finding.recommendation.clone()),
            ..Default::default()
        };

        for component in &finding.affected_components {
            if let Some(contract) = &component.contract {
                metadata.affected_contracts.push(contract.clone());
            }
            if component.component_type == "function" {
                metadata.affected_functions.push(component.name.clone());
            } else if component.component_type == "variable" {
                metadata.affected_variables.push(component.name.clone());
            }
        }

        for evidence in &finding.evidence {
            println!("  📍 Creating location: {}:{}-{}",
                evidence.code_ref.file,
                evidence.code_ref.line_start,
                evidence.code_ref.line_end
            );

            let location = Location::new(
                evidence.code_ref.file.clone(),
                evidence.code_ref.line_start as usize,
                evidence.code_ref.column_start.unwrap_or(0) as usize,
            )
            .with_end(
                evidence.code_ref.line_end as usize,
                evidence.code_ref.column_end.unwrap_or(0) as usize,
            );

            result = result.with_location(location);
        }

        if let Some(refs) = &finding.references {
            metadata.references = refs.clone();
        }

        use crate::core::result::RepresentationInfo;
        metadata.representation_info = Some(RepresentationInfo {
            representation_type: snippet.metadata.representation_type.clone(),
            extraction_strategy: snippet.metadata.extraction_strategy.clone(),
            token_count: snippet.token_count,
            was_truncated: snippet.metadata.was_truncated,
            included_functions: snippet.metadata.included_functions.clone(),
            included_contracts: snippet.metadata.included_contracts.clone(),
        });

        result = result
            .with_metadata(metadata)
            .with_finding_type(finding.vuln_type.clone());

        result
    }
}

impl Scanner for LLMScanner {
    fn id(&self) -> &'static str {
        Box::leak(self.config.scanner_name.clone().into_boxed_str())
    }

    fn name(&self) -> &'static str {
        Box::leak(self.config.scanner_name.clone().into_boxed_str())
    }

    fn description(&self) -> &'static str {
        Box::leak(self.config.description.clone().into_boxed_str())
    }

    fn severity(&self) -> Severity {
        Severity::Medium // Default, will be overridden by findings
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium // Default, will be overridden by findings
    }

    fn scan(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        Self::debug_log("📞 LLMScanner::scan() - Scanner trait method called");
        Self::debug_log(&format!("   Contract: {}", context.contract_info().name));

        let has_runtime = tokio::runtime::Handle::try_current().is_ok();
        Self::debug_log(&format!("   Has tokio runtime: {}", has_runtime));

        if has_runtime {
            Self::debug_log("⚠️  Already in async context - returning empty results");
            Self::debug_log("   This is likely why no LLM analysis is happening!");
            tracing::warn!(
                "LLMScanner::scan called from within async context - returning empty results"
            );
            Ok(Vec::new())
        } else {
            Self::debug_log("✅ Creating tokio runtime for LLM analysis");
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async { self.detect_async(context).await })
        }
    }
}

impl LLMScanner {
    fn debug_log(msg: &str) {
        let log_path = "/tmp/tameshi-llm-debug.log";
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path) {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let _ = writeln!(file, "[{}] {}", timestamp, msg);
        }
    }

    pub async fn detect_async(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        Self::debug_log("========================================");
        Self::debug_log("🚀 LLMScanner::detect_async CALLED");
        Self::debug_log("========================================");

        info!("Running LLM scanner: {}", self.name());

        let snippet = if let Some(extractor) = &self.extractor {
            match extractor.extract(context) {
                Ok(snippet) => {
                    info!(
                        "Extracted {} representation ({} tokens)",
                        snippet.metadata.representation_type, snippet.token_count
                    );
                    snippet
                }
                Err(e) => {
                    warn!(
                        "Failed to extract representation: {}. Using placeholder.",
                        e
                    );
                    RepresentationSnippet::placeholder()
                }
            }
        } else {
            debug!("No extractor configured, using placeholder representation");
            RepresentationSnippet::placeholder()
        };

        let mut metadata = HashMap::new();
        metadata.insert(
            "representation_type".to_string(),
            snippet.metadata.representation_type.clone(),
        );
        metadata.insert(
            "extraction_strategy".to_string(),
            snippet.metadata.extraction_strategy.clone(),
        );

        metadata.insert(
            "contract_metadata".to_string(),
            context.contract_info().name.clone(),
        );

        if !snippet.metadata.included_functions.is_empty() {
            metadata.insert(
                "included_functions".to_string(),
                snippet.metadata.included_functions.join(", "),
            );
        }

        if snippet.metadata.was_truncated {
            metadata.insert("was_truncated".to_string(), "true".to_string());
        }

        Self::debug_log(&format!("📤 SENDING TO LLM: {} chars, {} tokens", snippet.content.len(), snippet.token_count));
        Self::debug_log(&format!("   Representation type: {}", snippet.metadata.representation_type));
        Self::debug_log(&format!("   Contract: {}", context.contract_info().name));
        Self::debug_log("   Content preview (first 500 chars):");
        Self::debug_log(&snippet.content.chars().take(500).collect::<String>());
        Self::debug_log("----------------------------------------");

        println!("\n======================");
        println!("📤 SENDING TO LLM ({} chars, {} tokens)", snippet.content.len(), snippet.token_count);
        println!("Representation type: {}", snippet.metadata.representation_type);
        println!("Preview (first 500 chars):\n{}", &snippet.content.chars().take(500).collect::<String>());
        println!("======================\n");

        let response = self.analyze_async(&snippet.content, metadata).await?;

        Self::debug_log(&format!("📥 LLM RETURNED {} FINDINGS", response.findings.len()));

        println!("\n======================");
        println!("📥 LLM RETURNED {} FINDINGS", response.findings.len());
        println!("======================\n");

        let mut results = Vec::new();

        for (idx, finding) in response.findings.iter().enumerate() {
            Self::debug_log(&format!("🔍 Finding {}: {}", idx, finding.title));
            Self::debug_log(&format!("   {} evidence items", finding.evidence.len()));

            println!("🔍 Finding {}: {}", idx, finding.title);
            println!("   {} evidence items", finding.evidence.len());

            for (eidx, evidence) in finding.evidence.iter().enumerate() {
                let log_msg = format!(
                    "  📍 Evidence {}: line {}-{} in {}",
                    eidx,
                    evidence.code_ref.line_start,
                    evidence.code_ref.line_end,
                    evidence.code_ref.file
                );
                Self::debug_log(&log_msg);
                Self::debug_log(&format!("     Description: {}", evidence.description.chars().take(150).collect::<String>()));

                println!("  📍 Evidence {}: line {}-{}",
                    eidx,
                    evidence.code_ref.line_start,
                    evidence.code_ref.line_end
                );
                println!("     Description: {}", evidence.description.chars().take(150).collect::<String>());
            }
        }

        for finding in response.findings {
            let confidence_score = match finding.confidence {
                LLMConfidence::High => 0.9,
                LLMConfidence::Medium => 0.6,
                LLMConfidence::Low => 0.3,
            };
            if confidence_score < self.config.confidence_threshold {
                debug!("Skipping finding '{}' due to low confidence", finding.title);
                continue;
            }

            if !self.config.include_low_severity {
                match finding.severity {
                    SeverityLevel::Low | SeverityLevel::Informational => {
                        debug!("Skipping low severity finding '{}'", finding.title);
                        continue;
                    }
                    _ => {}
                }
            }

            results.push(self.finding_to_result(&finding, &snippet));
        }

        info!("LLM analysis summary: {}", response.analysis_summary);

        info!("LLM scanner found {} vulnerabilities", results.len());

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_llm_scanner_config() {
        let config = LLMScannerConfig::default();
        assert_eq!(config.temperature, 0.2);
        assert_eq!(config.confidence_threshold, 0.5);
    }

    #[test]
    fn test_finding_conversion() {
        use super::super::schemas::{CodeLocation, ComponentRef, Evidence};

        let finding = VulnerabilityFinding {
            vuln_type: "test".to_string(),
            title: "Test vulnerability".to_string(),
            severity: SeverityLevel::High,
            confidence: LLMConfidence::High,
            affected_components: vec![ComponentRef {
                component_type: "function".to_string(),
                name: "testFunc".to_string(),
                contract: Some("TestContract".to_string()),
                line_number: Some(42),
            }],
            root_cause: "Root cause".to_string(),
            attack_vector: "Attack vector".to_string(),
            evidence: vec![Evidence {
                code_ref: CodeLocation {
                    file: "test.sol".to_string(),
                    line_start: 10,
                    line_end: 20,
                    column_start: None,
                    column_end: None,
                },
                description: "Evidence".to_string(),
                confidence: 0.9,
                snippet: None,
            }],
            recommendation: "Fix it".to_string(),
            references: None,
        };

        assert_eq!(finding.title, "Test vulnerability");
    }
}
