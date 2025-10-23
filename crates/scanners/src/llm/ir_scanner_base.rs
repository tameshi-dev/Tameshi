use anyhow::{Context as AnyhowContext, Result};
use async_trait::async_trait;
use serde_json;
use std::collections::HashMap;
use std::sync::Arc;
use thalir_core::{analysis::Pass, block::Terminator, contract::Contract as IRContract};
use tracing::{debug, info, warn};

use crate::core::result::{Finding, FindingMetadata, Location};

use super::{
    ir_extractor::IRExtractor,
    ir_formatter::{IRFormatter, VulnerabilityFocus},
    prompts::{PromptBuilder, PromptTemplate},
    provider::{LLMProvider, LLMRequest},
    representation::RepresentationConfig,
    schemas::{ScannerResponse, SimpleScannerResponse, VulnerabilityFinding},
};

#[derive(Debug, Clone)]
pub struct LLMIRScannerConfig {
    pub scanner_name: String,
    pub description: String,
    pub vulnerability_focus: VulnerabilityFocus,
    pub temperature: f32,
    pub max_tokens: u32,
    pub confidence_threshold: f32,
    pub include_cfg: bool,
    pub include_types: bool,
    pub include_dominance: bool,
    pub simplify_ir: bool,
    pub dump_prompt: bool,
}

impl Default for LLMIRScannerConfig {
    fn default() -> Self {
        Self {
            scanner_name: "llm_ir_general".to_string(),
            description: "LLM-based IR vulnerability scanner".to_string(),
            vulnerability_focus: VulnerabilityFocus::General,
            temperature: 0.2,
            max_tokens: 4000,
            confidence_threshold: 0.5,
            include_cfg: true,
            include_types: true,
            include_dominance: false,
            simplify_ir: true,
            dump_prompt: false,
        }
    }
}

#[async_trait]
pub trait LLMIRScanner: Send + Sync {
    fn config(&self) -> &LLMIRScannerConfig;

    fn prepare_ir_context(&self, ir: &IRContract) -> Result<IRAnalysisContext>;

    fn build_analysis_prompt(&self, context: &IRAnalysisContext) -> Result<(String, String)>;

    fn interpret_llm_response(
        &self,
        response: &ScannerResponse,
        context: &IRAnalysisContext,
    ) -> Result<Vec<Finding>>;

    async fn detect_ir_async(&self, ir: &IRContract) -> Result<Vec<Finding>>;
}

pub struct IRAnalysisContext {
    pub ir_representation: String,
    pub vulnerability_context: String,
    pub function_summaries: HashMap<String, FunctionSummary>,
    pub instruction_counts: HashMap<String, usize>,
    pub has_external_calls: bool,
    pub has_state_modifications: bool,
    pub token_count: usize,
}

#[derive(Debug, Clone)]
pub struct FunctionSummary {
    pub name: String,
    pub visibility: String,
    pub has_external_calls: bool,
    pub has_state_modifications: bool,
    pub has_loops: bool,
    pub has_conditionals: bool,
    pub instruction_count: usize,
}

pub struct BaseLLMIRScanner {
    config: LLMIRScannerConfig,
    provider: Arc<dyn LLMProvider>,
    prompt_builder: PromptBuilder,
    ir_extractor: IRExtractor,
    ir_formatter: IRFormatter,
}

impl BaseLLMIRScanner {
    pub fn new(config: LLMIRScannerConfig, provider: Arc<dyn LLMProvider>) -> Self {
        let representation_config = RepresentationConfig {
            max_tokens: config.max_tokens as usize,
            include_context: false,
            snippet_strategy: super::representation::SnippetStrategy::FullContract,
            include_comments: false,
            include_private: false,
            format: super::representation::RepresentationFormat::Auto,
        };

        let ir_extractor = IRExtractor::with_options(
            representation_config,
            config.include_types,
            config.include_cfg,
            config.include_dominance,
            config.simplify_ir,
        );

        Self {
            config,
            provider,
            prompt_builder: PromptBuilder::new(),
            ir_extractor,
            ir_formatter: IRFormatter::new(),
        }
    }

    pub fn with_template(mut self, template: PromptTemplate) -> Self {
        self.prompt_builder.add_template(template);
        self
    }

    fn convert_simple_to_complex_response(simple: SimpleScannerResponse) -> ScannerResponse {
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
}

#[async_trait]
impl LLMIRScanner for BaseLLMIRScanner {
    fn config(&self) -> &LLMIRScannerConfig {
        &self.config
    }

    async fn detect_ir_async(&self, ir: &IRContract) -> Result<Vec<Finding>> {
        info!("Running LLM-IR scanner: {}", self.config.scanner_name);

        let context = self.prepare_ir_context(ir)?;

        let (system_prompt, user_prompt) = self.build_analysis_prompt(&context)?;

        debug!("Sending IR analysis request to LLM");

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

        let llm_response = self
            .provider
            .analyze(request)
            .await
            .context("LLM analysis failed")?;

        info!(
            "LLM analysis complete - Tokens: {} (prompt: {}, completion: {})",
            llm_response.usage.total_tokens,
            llm_response.usage.prompt_tokens,
            llm_response.usage.completion_tokens
        );

        let scanner_response: ScannerResponse = match serde_json::from_str::<SimpleScannerResponse>(
            &llm_response.content,
        ) {
            Ok(simple_response) => {
                println!(
                    "✅ Successfully parsed as simple format: {:?}",
                    simple_response
                );
                BaseLLMIRScanner::convert_simple_to_complex_response(simple_response)
            }
            Err(simple_err) => {
                println!("❌ Failed to parse as simple format: {}", simple_err);
                println!("🔍 LLM response content: {}", llm_response.content);
                match serde_json::from_str::<ScannerResponse>(&llm_response.content) {
                    Ok(response) => {
                        println!("✅ Successfully parsed as complex format");
                        response
                    }
                    Err(complex_err) => {
                        println!("❌ Failed to parse as complex format: {}", complex_err);
                        warn!("Failed to parse LLM response as either simple or complex format. Simple error: {}, Complex error: {}", simple_err, complex_err);
                        warn!("LLM response content: {}", llm_response.content);
                        return Err(anyhow::anyhow!(
                            "Failed to parse LLM response: {}",
                            complex_err
                        ));
                    }
                }
            }
        };

        let findings = self.interpret_llm_response(&scanner_response, &context)?;

        info!("LLM-IR scanner found {} vulnerabilities", findings.len());

        Ok(findings)
    }

    fn prepare_ir_context(&self, ir: &IRContract) -> Result<IRAnalysisContext> {
        let ir_snippet = self.ir_extractor.extract_from_ir(ir)?;

        let vuln_context = self
            .ir_formatter
            .format_for_vulnerability_detection(ir, self.config.vulnerability_focus.clone())?;

        let mut function_summaries = HashMap::new();
        let mut total_external_calls = false;
        let mut total_state_mods = false;

        for (_name, func) in &ir.functions {
            let mut summary = FunctionSummary {
                name: func.name().to_string(),
                visibility: format!("{:?}", func.visibility),
                has_external_calls: false,
                has_state_modifications: false,
                has_loops: false,
                has_conditionals: false,
                instruction_count: 0,
            };

            for block in func.body.blocks.values() {
                summary.instruction_count += block.instructions.len();

                for inst in &block.instructions {
                    match inst {
                        thalir_core::instructions::Instruction::Call { .. } => {
                            summary.has_external_calls = true;
                            total_external_calls = true;
                        }
                        thalir_core::instructions::Instruction::StorageStore { .. }
                        | thalir_core::instructions::Instruction::MappingStore { .. }
                        | thalir_core::instructions::Instruction::ArrayStore { .. } => {
                            summary.has_state_modifications = true;
                            total_state_mods = true;
                        }
                        _ => {}
                    }
                }

                if let Terminator::Branch { .. } = &block.terminator {
                    summary.has_conditionals = true;
                }
            }

            function_summaries.insert(func.name().to_string(), summary);
        }

        let mut instruction_counts = HashMap::new();
        for (_name, func) in &ir.functions {
            for block in func.body.blocks.values() {
                for inst in &block.instructions {
                    let inst_type = format!("{:?}", inst)
                        .split_whitespace()
                        .next()
                        .unwrap_or("Unknown")
                        .to_string();
                    *instruction_counts.entry(inst_type).or_insert(0) += 1;
                }
            }
        }

        Ok(IRAnalysisContext {
            ir_representation: ir_snippet.content,
            vulnerability_context: vuln_context,
            function_summaries,
            instruction_counts,
            has_external_calls: total_external_calls,
            has_state_modifications: total_state_mods,
            token_count: ir_snippet.token_count,
        })
    }

    fn build_analysis_prompt(&self, context: &IRAnalysisContext) -> Result<(String, String)> {
        let system_prompt = format!(
            r#"You are an expert smart contract security auditor analyzing Cranelift IR (Intermediate Representation) in SSA form.

Focus Area: {:?}

The IR uses the following instruction types:
- Call: External function calls
- Binary/Unary: Arithmetic operations
- ConditionalBranch: Control flow
- Assert: Requirement checks

You MUST respond with valid JSON matching this exact structure:
{{
    "findings": [
        {{
            "vuln_type": "string (e.g., reentrancy, access-control)",
            "severity": "high|medium|low",
            "confidence": "high|medium|low", 
            "title": "string",
            "description": "string",
            "root_cause": "string",
            "attack_vector": "string",
            "recommendation": "string",
            "affected_components": [
                {{
                    "component_type": "function|contract|variable",
                    "name": "string",
                    "contract": "string (optional)"
                }}
            ],
            "evidence": [
                {{
                    "description": "string",
                    "code_ref": {{
                        "file": "string",
                        "line_start": 0,
                        "line_end": 0,
                        "column_start": 0,
                        "column_end": 0,
                        "snippet": "string"
                    }}
                }}
            ]
        }}
    ],
    "analysis_summary": "string",
    "coverage_notes": ["string"],
    "requires_further_analysis": ["string"]
}}"#,
            self.config.vulnerability_focus
        );

        let user_prompt = format!(
            r#"Analyze this Cranelift IR for vulnerabilities:

{}

Vulnerability Context:
{}

Summary:
- Functions analyzed: {}
- Has external calls: {}
- Has state modifications: {}

Provide a detailed vulnerability analysis. Remember to return valid JSON with a "findings" array containing any vulnerabilities found. If no vulnerabilities are found, return an empty findings array."#,
            context.ir_representation,
            context.vulnerability_context,
            context.function_summaries.len(),
            context.has_external_calls,
            context.has_state_modifications
        );

        Ok((system_prompt, user_prompt))
    }

    fn interpret_llm_response(
        &self,
        response: &ScannerResponse,
        _context: &IRAnalysisContext,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for vuln in &response.findings {
            let confidence_score = match vuln.confidence {
                super::schemas::Confidence::High => 0.9,
                super::schemas::Confidence::Medium => 0.6,
                super::schemas::Confidence::Low => 0.3,
            };

            if confidence_score < self.config.confidence_threshold {
                debug!("Skipping finding '{}' due to low confidence", vuln.title);
                continue;
            }

            let mut finding = Finding::new(
                self.config.scanner_name.clone(),
                vuln.severity.into(),
                vuln.confidence.into(),
                vuln.title.clone(),
                format!(
                    "{}\n\nRoot Cause: {}\nAttack Vector: {}",
                    vuln.title, vuln.root_cause, vuln.attack_vector
                ),
            );

            let mut metadata = FindingMetadata {
                recommendation: Some(vuln.recommendation.clone()),
                ..Default::default()
            };

            for component in &vuln.affected_components {
                if let Some(contract) = &component.contract {
                    metadata.affected_contracts.push(contract.clone());
                }
                if component.component_type == "function" {
                    metadata.affected_functions.push(component.name.clone());
                }
            }

            for evidence in &vuln.evidence {
                let location = Location::new(
                    evidence.code_ref.file.clone(),
                    evidence.code_ref.line_start as usize,
                    evidence.code_ref.column_start.unwrap_or(0) as usize,
                );
                finding = finding.with_location(location);
            }

            finding = finding
                .with_metadata(metadata)
                .with_finding_type(vuln.vuln_type.clone());

            findings.push(finding);
        }

        Ok(findings)
    }
}

pub fn create_llm_ir_scanner(
    name: &str,
    focus: VulnerabilityFocus,
    provider: Arc<dyn LLMProvider>,
) -> Box<dyn LLMIRScanner> {
    let config = LLMIRScannerConfig {
        scanner_name: format!("llm_ir_{}", name),
        description: format!("LLM-based IR scanner for {}", name),
        vulnerability_focus: focus,
        ..Default::default()
    };

    Box::new(BaseLLMIRScanner::new(config, provider))
}
