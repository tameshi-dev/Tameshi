use crate::llm::{
    provider::{LLMError, LLMProvider, LLMRequest, LLMResponse, TokenUsage},
    schemas::{
        CodeLocation, ComponentRef, Confidence as LLMConfidence, Evidence, ScannerResponse,
        SeverityLevel, VulnerabilityFinding,
    },
};
use async_trait::async_trait;
use std::collections::HashMap;

pub struct MockLLMProvider {
    responses: HashMap<String, ScannerResponse>,
    default_response: ScannerResponse,
    call_count: std::sync::atomic::AtomicUsize,
    should_fail: bool,
}

impl Default for MockLLMProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl MockLLMProvider {
    pub fn new() -> Self {
        Self {
            responses: Self::default_responses(),
            default_response: Self::empty_response(),
            call_count: std::sync::atomic::AtomicUsize::new(0),
            should_fail: false,
        }
    }

    pub fn failing() -> Self {
        let mut provider = Self::new();
        provider.should_fail = true;
        provider
    }

    pub fn with_response(mut self, pattern: &str, response: ScannerResponse) -> Self {
        self.responses.insert(pattern.to_string(), response);
        self
    }

    pub fn call_count(&self) -> usize {
        self.call_count.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn reset_count(&self) {
        self.call_count
            .store(0, std::sync::atomic::Ordering::SeqCst);
    }

    fn default_responses() -> HashMap<String, ScannerResponse> {
        let mut responses = HashMap::new();

        responses.insert(
            "reentrancy".to_string(),
            ScannerResponse {
                findings: vec![VulnerabilityFinding {
                    vuln_type: "reentrancy".to_string(),
                    title: "Reentrancy vulnerability in withdraw function".to_string(),
                    severity: SeverityLevel::High,
                    confidence: LLMConfidence::High,
                    affected_components: vec![ComponentRef {
                        component_type: "function".to_string(),
                        name: "withdraw".to_string(),
                        contract: Some("MockContract".to_string()),
                        line_number: Some(42),
                    }],
                    root_cause: "External call before state update".to_string(),
                    attack_vector: "Attacker can re-enter and drain funds".to_string(),
                    evidence: vec![Evidence {
                        code_ref: CodeLocation {
                            file: "contract.sol".to_string(),
                            line_start: 42,
                            line_end: 45,
                            column_start: Some(8),
                            column_end: Some(30),
                        },
                        description: "Call to external address before balance update".to_string(),
                        confidence: 0.95,
                        snippet: Some("msg.sender.call{value: amount}(\"\")".to_string()),
                    }],
                    recommendation: "Use checks-effects-interactions pattern".to_string(),
                    references: Some(vec!["https://swcregistry.io/docs/SWC-107".to_string()]),
                }],
                analysis_summary: "Found 1 high severity reentrancy vulnerability".to_string(),
                coverage_notes: vec!["Analyzed all external calls".to_string()],
                requires_further_analysis: vec![],
                metadata: None,
            },
        );

        responses.insert(
            "access".to_string(),
            ScannerResponse {
                findings: vec![VulnerabilityFinding {
                    vuln_type: "access_control".to_string(),
                    title: "Missing access control on critical function".to_string(),
                    severity: SeverityLevel::Critical,
                    confidence: LLMConfidence::High,
                    affected_components: vec![ComponentRef {
                        component_type: "function".to_string(),
                        name: "emergencyWithdraw".to_string(),
                        contract: Some("MockContract".to_string()),
                        line_number: Some(100),
                    }],
                    root_cause: "No modifier or require statement checking caller permissions"
                        .to_string(),
                    attack_vector: "Any user can call this function and drain contract".to_string(),
                    evidence: vec![Evidence {
                        code_ref: CodeLocation {
                            file: "contract.sol".to_string(),
                            line_start: 100,
                            line_end: 105,
                            column_start: None,
                            column_end: None,
                        },
                        description: "Function lacks access control".to_string(),
                        confidence: 0.99,
                        snippet: None,
                    }],
                    recommendation: "Add onlyOwner modifier or equivalent access control"
                        .to_string(),
                    references: Some(vec!["https://swcregistry.io/docs/SWC-105".to_string()]),
                }],
                analysis_summary: "Found 1 critical access control vulnerability".to_string(),
                coverage_notes: vec!["Analyzed all public functions".to_string()],
                requires_further_analysis: vec![],
                metadata: None,
            },
        );

        responses.insert(
            "overflow".to_string(),
            ScannerResponse {
                findings: vec![VulnerabilityFinding {
                    vuln_type: "integer_overflow".to_string(),
                    title: "Potential integer overflow in arithmetic operation".to_string(),
                    severity: SeverityLevel::Medium,
                    confidence: LLMConfidence::Medium,
                    affected_components: vec![ComponentRef {
                        component_type: "function".to_string(),
                        name: "unsafeAdd".to_string(),
                        contract: Some("MockContract".to_string()),
                        line_number: Some(200),
                    }],
                    root_cause: "Unchecked arithmetic operation".to_string(),
                    attack_vector: "Large values could cause overflow".to_string(),
                    evidence: vec![],
                    recommendation: "Use SafeMath or Solidity 0.8+ with built-in overflow checks"
                        .to_string(),
                    references: None,
                }],
                analysis_summary: "Found 1 medium severity overflow vulnerability".to_string(),
                coverage_notes: vec!["Analyzed arithmetic operations".to_string()],
                requires_further_analysis: vec!["Complex math operations".to_string()],
                metadata: None,
            },
        );

        responses
    }

    fn empty_response() -> ScannerResponse {
        ScannerResponse {
            findings: vec![],
            analysis_summary: "No vulnerabilities detected".to_string(),
            coverage_notes: vec!["Analysis complete".to_string()],
            requires_further_analysis: vec![],
            metadata: None,
        }
    }

    fn generate_response(&self, request: &LLMRequest) -> ScannerResponse {
        let combined_prompt = format!("{} {}", request.system_prompt, request.user_prompt);

        for (pattern, response) in &self.responses {
            if combined_prompt.to_lowercase().contains(pattern) {
                return response.clone();
            }
        }

        if combined_prompt.contains("withdraw") && combined_prompt.contains("call{value:") {
            if let Some(reentrancy) = self.responses.get("reentrancy") {
                return reentrancy.clone();
            }
        }

        if combined_prompt.contains("emergencyWithdraw") && !combined_prompt.contains("onlyOwner") {
            if let Some(access) = self.responses.get("access") {
                return access.clone();
            }
        }

        self.default_response.clone()
    }
}

#[async_trait]
impl LLMProvider for MockLLMProvider {
    async fn analyze(&self, request: LLMRequest) -> Result<LLMResponse, LLMError> {
        self.call_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        if self.should_fail {
            return Err(LLMError::ApiError(
                "Mock provider configured to fail".to_string(),
            ));
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        let scanner_response = self.generate_response(&request);
        let content = serde_json::to_string(&scanner_response)
            .map_err(|e| LLMError::InvalidResponse(e.to_string()))?;

        Ok(LLMResponse {
            content,
            model: "mock-model".to_string(),
            usage: TokenUsage {
                prompt_tokens: 100,
                completion_tokens: 200,
                total_tokens: 300,
            },
        })
    }

    fn model_name(&self) -> &str {
        "mock-model"
    }

    fn max_tokens(&self) -> usize {
        10000 // Arbitrary large number for mock
    }

    fn estimate_tokens(&self, text: &str) -> usize {
        text.len() / 4 // Simple estimation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_provider_reentrancy() {
        let provider = MockLLMProvider::new();

        let request = LLMRequest {
            system_prompt: "Detect vulnerabilities".to_string(),
            user_prompt: "Check for reentrancy in this code".to_string(),
            temperature: 0.2,
            max_tokens: 1000,
            response_format: None,
            dump_prompt: false,
        };

        let response = provider.analyze(request).await.unwrap();
        let scanner_response: ScannerResponse = serde_json::from_str(&response.content).unwrap();

        assert!(!scanner_response.findings.is_empty());
        assert_eq!(scanner_response.findings[0].vuln_type, "reentrancy");
    }

    #[tokio::test]
    async fn test_mock_provider_call_counting() {
        let provider = MockLLMProvider::new();
        assert_eq!(provider.call_count(), 0);

        let request = LLMRequest {
            system_prompt: "Test".to_string(),
            user_prompt: "Test".to_string(),
            temperature: 0.2,
            max_tokens: 100,
            response_format: None,
            dump_prompt: false,
        };

        provider.analyze(request.clone()).await.unwrap();
        assert_eq!(provider.call_count(), 1);

        provider.analyze(request).await.unwrap();
        assert_eq!(provider.call_count(), 2);

        provider.reset_count();
        assert_eq!(provider.call_count(), 0);
    }

    #[tokio::test]
    async fn test_mock_provider_failure() {
        let provider = MockLLMProvider::failing();

        let request = LLMRequest {
            system_prompt: "Test".to_string(),
            user_prompt: "Test".to_string(),
            temperature: 0.2,
            max_tokens: 100,
            response_format: None,
            dump_prompt: false,
        };

        let result = provider.analyze(request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_mock_provider_custom_response() {
        let custom_response = ScannerResponse {
            findings: vec![VulnerabilityFinding {
                vuln_type: "custom".to_string(),
                title: "Custom vulnerability".to_string(),
                severity: SeverityLevel::Low,
                confidence: LLMConfidence::Low,
                affected_components: vec![],
                root_cause: "Test".to_string(),
                attack_vector: "Test".to_string(),
                evidence: vec![],
                recommendation: "Test".to_string(),
                references: None,
            }],
            analysis_summary: "Custom test".to_string(),
            coverage_notes: vec![],
            requires_further_analysis: vec![],
            metadata: None,
        };

        let provider = MockLLMProvider::new().with_response("custom_pattern", custom_response);

        let request = LLMRequest {
            system_prompt: "Test".to_string(),
            user_prompt: "Check for custom_pattern".to_string(),
            temperature: 0.2,
            max_tokens: 100,
            response_format: None,
            dump_prompt: false,
        };

        let response = provider.analyze(request).await.unwrap();
        let scanner_response: ScannerResponse = serde_json::from_str(&response.content).unwrap();

        assert_eq!(scanner_response.findings[0].vuln_type, "custom");
    }
}
