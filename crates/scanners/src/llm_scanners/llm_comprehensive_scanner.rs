use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{
    core::{
        context::AnalysisContext,
        result::Finding,
        scanner::Scanner,
        severity::{Confidence, Severity},
    },
    llm::provider::{LLMProvider, LLMRequest},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ComprehensiveResponse {
    vulnerabilities: Vec<Vulnerability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Vulnerability {
    category: String,
    #[serde(rename = "type")]
    vuln_type: String,
    severity: String,
    confidence: String,
    function_name: String,
    description: String,
    line_numbers: Vec<u32>,
    code_snippet: String,
    reasoning: String,
    recommendation: String,
}

pub struct LLMComprehensiveScanner {
    provider: Arc<dyn LLMProvider>,
    temperature: f32,
    max_tokens: u32,
    dump_prompt: bool,
    dump_response: bool,
}

impl LLMComprehensiveScanner {
    fn debug_log(msg: &str) {
        use std::fs::OpenOptions;
        use std::io::Write;
        let log_path = "/tmp/tameshi-llm-debug.log";
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path) {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let _ = writeln!(file, "[{}] {}", timestamp, msg);
        }
    }

    pub fn new(provider: Arc<dyn LLMProvider>) -> Self {
        Self::debug_log("🏗️  LLMComprehensiveScanner::new() called");
        Self {
            provider,
            temperature: 0.1, // Low temperature for deterministic analysis
            max_tokens: 16_000,
            dump_prompt: false,
            dump_response: false,
        }
    }

    pub fn with_dump_prompt(mut self, dump_prompt: bool) -> Self {
        self.dump_prompt = dump_prompt;
        self
    }

    pub fn with_dump_response(mut self, dump_response: bool) -> Self {
        self.dump_response = dump_response;
        self
    }

    pub async fn analyze_source(
        &self,
        source_code: &str,
        contract_name: &str,
    ) -> Result<Vec<Finding>> {
        Self::debug_log("\n🔬 analyze_source() called (COMPREHENSIVE)");
        Self::debug_log(&format!("   Contract: {}", contract_name));
        Self::debug_log(&format!(
            "   Source code length: {} bytes",
            source_code.len()
        ));
        Self::debug_log(&format!(
            "   Source code lines: {}",
            source_code.lines().count()
        ));
        Self::debug_log("   First 500 chars of source:");
        Self::debug_log(&source_code.chars().take(500).collect::<String>());

        tracing::info!(
            "Analyzing contract '{}' with comprehensive LLM scanner (source code: {} bytes)",
            contract_name,
            source_code.len()
        );

        let (system_prompt, user_prompt) = self.build_prompt(source_code)?;

        let request = LLMRequest {
            system_prompt,
            user_prompt,
            temperature: self.temperature,
            max_tokens: self.max_tokens,
            response_format: None,
            dump_prompt: self.dump_prompt,
        };

        let llm_response = self
            .provider
            .analyze(request)
            .await
            .map_err(|e| anyhow::anyhow!("LLM analysis failed: {}", e))?;

        if self.dump_response {
            println!(
                "\n📤 {} LLM RESPONSE DUMP {}",
                "=".repeat(25),
                "=".repeat(25)
            );
            println!("🤖 Model: {}", llm_response.model);
            println!("📊 Token Usage:");
            println!("   Prompt tokens: {}", llm_response.usage.prompt_tokens);
            println!(
                "   Completion tokens: {}",
                llm_response.usage.completion_tokens
            );
            println!("   Total tokens: {}", llm_response.usage.total_tokens);
            println!("\n📝 {} RAW RESPONSE {}", "=".repeat(22), "=".repeat(22));
            println!("{}", llm_response.content);
            println!("{}", "=".repeat(70));
            println!();
        }

        Self::debug_log("📥 Parsing LLM response...");
        let response: ComprehensiveResponse = serde_json::from_str(&llm_response.content)
            .map_err(|e| anyhow::anyhow!("Failed to parse LLM response: {}", e))?;

        Self::debug_log(&format!(
            "   Found {} vulnerabilities in response",
            response.vulnerabilities.len()
        ));
        for (idx, vuln) in response.vulnerabilities.iter().enumerate() {
            Self::debug_log(&format!(
                "   Vuln {}: {} ({}) in function '{}'",
                idx, vuln.vuln_type, vuln.category, vuln.function_name
            ));
            Self::debug_log(&format!(
                "      Line numbers from LLM: {:?}",
                vuln.line_numbers
            ));
            Self::debug_log(&format!(
                "      Description: {}",
                vuln.description.chars().take(100).collect::<String>()
            ));
        }

        self.convert_to_findings(&response, contract_name)
    }

    fn build_prompt(&self, source_code: &str) -> Result<(String, String)> {
        let numbered_source: String = source_code
            .lines()
            .enumerate()
            .map(|(idx, line)| format!("{:4}: {}", idx + 1, line))
            .collect::<Vec<_>>()
            .join("\n");

        let system_prompt = r#"You are an expert smart contract security auditor with deep expertise in Solidity vulnerability detection.

You will analyze smart contracts for ALL major vulnerability categories in a SINGLE comprehensive analysis.

VULNERABILITY CATEGORIES TO DETECT:

1. REENTRANCY
   - External calls before state updates
   - Cross-function reentrancy
   Pattern: call → state change (VULNERABLE) vs state change → call (SAFE)

2. ACCESS CONTROL
   - Missing access modifiers (public functions that should be restricted)
   - Broken ownership checks
   - Missing onlyOwner or similar modifiers
   - Functions that change critical state without authentication

3. INTEGER OVERFLOW/UNDERFLOW
   - Arithmetic operations without SafeMath (Solidity < 0.8.0)
   - Unchecked blocks that disable overflow checks (Solidity >= 0.8.0)
   - Dangerous type conversions

4. UNCHECKED EXTERNAL CALLS
   - Low-level calls (.call, .delegatecall, .staticcall) without checking return value
   - Ignoring return values from external contract calls
   - Pattern: call without require(success) or if(success) check

5. DENIAL OF SERVICE (DoS)
   - Unbounded loops (for loop over dynamic array)
   - Gas limit issues in loops
   - Block gas limit vulnerabilities
   - Failing external calls that block execution

6. WEAK RANDOMNESS
   - Using block.timestamp for randomness
   - Using block.difficulty, blockhash, or block.number for randomness
   - Predictable random number generation

7. FRONT-RUNNING
   - Transaction ordering dependence
   - Commit-reveal schemes without proper protection
   - Price manipulation vulnerabilities
   - Unprotected state changes based on external data

8. TIMESTAMP DEPENDENCE
   - Using block.timestamp for critical logic
   - Time-based conditions that can be manipulated
   - Relying on now or block.timestamp for randomness or access control

9. TX.ORIGIN AUTHENTICATION
   - Using tx.origin for authorization instead of msg.sender
   - Phishing vulnerability via tx.origin

10. DELEGATECALL ISSUES
    - Delegatecall to user-controlled addresses
    - Storage collision in delegatecall contexts
    - Unprotected delegatecall allowing arbitrary code execution

ANALYSIS METHODOLOGY:
- For each function, identify all potential vulnerabilities across ALL categories
- Track execution flow, state changes, external calls, and access controls
- Consider edge cases and attack vectors
- Only report ACTUAL vulnerabilities with high confidence
- **CRITICAL: COMPLETELY IGNORE commented-out code (// or /* */). Commented code is inactive and cannot be vulnerable.**

SEVERITY LEVELS:
- Critical: Direct loss of funds, complete contract compromise
- High: Significant security risk, likely exploitable
- Medium: Potential security issue, exploitable under conditions
- Low: Minor issue, unlikely to be exploited but poor practice

CONFIDENCE LEVELS:
- High: Clear vulnerability, definite security issue
- Medium: Likely vulnerable but needs verification
- Low: Possible issue, requires deeper analysis"#.to_string();

        let user_prompt = format!(
            r#"Analyze this Solidity smart contract for ALL vulnerability types.
Each line is prefixed with its line number for precise reporting.

```solidity
{}
```

ANALYSIS PROCEDURE:
2. For EACH function, check for ALL vulnerability categories listed above
3. Identify the EXACT lines where vulnerabilities occur
4. Provide specific evidence and reasoning

Return findings in JSON format:
{{{{
  "vulnerabilities": [
    {{{{
      "category": "reentrancy|access_control|integer_overflow|unchecked_call|dos|weak_randomness|front_running|timestamp_dependence|tx_origin|delegatecall",
      "type": "specific vulnerability name",
      "severity": "Critical|High|Medium|Low",
      "confidence": "High|Medium|Low",
      "function_name": "name of vulnerable function",
      "description": "Brief description of the vulnerability",
      "line_numbers": [exact line numbers where vulnerability occurs],
      "code_snippet": "relevant code showing the vulnerability",
      "reasoning": "Step-by-step explanation of why this is vulnerable",
      "recommendation": "How to fix this vulnerability"
    }}}}
  ]
}}}}

CRITICAL REQUIREMENTS FOR LINE NUMBERS:
- line_numbers MUST contain ONLY the exact line numbers of the ACTUAL VULNERABLE CODE
- Include ONLY lines that contain the vulnerability pattern
- Do NOT include blank lines, comment lines, or function declaration lines
- Do NOT include require statements or other non-vulnerable code
- ONLY include lines with the actual vulnerability

**EXTREMELY IMPORTANT - COMMENTED CODE:**
- COMPLETELY IGNORE all commented-out code (lines starting with // or inside /* */ blocks)
- Commented code is NOT active and CANNOT be a vulnerability
- Even if a commented line contains a vulnerability pattern, DO NOT report it
- ONLY analyze and report vulnerabilities in active, uncommented code
- Example: "//return uint256(keccak256(...));" is commented and should be IGNORED

EXAMPLE:
If the code shows:
  20: // External call
  21: (bool success, ) = msg.sender.call{{value: amount}}("");
  22: require(success, "Transfer failed");
  23:
  24: // State update
  25: balances[msg.sender] -= amount;

For reentrancy, line_numbers should be: [21, 25]
- Line 21 has the external call
- Line 25 has the state update
- Do NOT include line 20 (comment), line 22 (require), line 23 (blank), or line 24 (comment)

IMPORTANT:
- Analyze for ALL vulnerability categories comprehensively
- Only report ACTUAL vulnerabilities, not potential or theoretical issues
- Be precise with line numbers using the prefixed numbers
- Provide detailed reasoning for each finding
- If no vulnerabilities found in a category, do not report it
- Focus on high-confidence findings"#,
            numbered_source
        );

        Ok((system_prompt, user_prompt))
    }

    fn convert_to_findings(
        &self,
        response: &ComprehensiveResponse,
        contract_name: &str,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for vuln in &response.vulnerabilities {
            let severity = match vuln.severity.to_lowercase().as_str() {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                "medium" => Severity::Medium,
                "low" => Severity::Low,
                _ => Severity::Medium,
            };

            let confidence = match vuln.confidence.to_lowercase().as_str() {
                "high" => Confidence::High,
                "medium" => Confidence::Medium,
                _ => Confidence::Low,
            };

            let description = format!(
                "Category: {}\nFunction: {}\n\n{}\n\nCode:\n```solidity\n{}\n```\n\nReasoning:\n{}\n\nRecommendation:\n{}",
                vuln.category,
                vuln.function_name,
                vuln.description,
                vuln.code_snippet,
                vuln.reasoning,
                vuln.recommendation
            );

            let title = format!(
                "{} - {} in {}",
                vuln.severity, vuln.vuln_type, vuln.function_name
            );

            let mut finding = Finding::new(
                "llm_comprehensive".to_string(),
                severity,
                confidence,
                title,
                description,
            );

            let mut metadata = crate::core::result::FindingMetadata::default();
            metadata.affected_contracts.push(contract_name.to_string());
            metadata.affected_functions.push(vuln.function_name.clone());
            metadata.recommendation = Some(vuln.recommendation.clone());
            finding.metadata = Some(metadata);

            Self::debug_log(&format!(
                "   ➕ Adding {} locations to finding for function '{}' ({})",
                vuln.line_numbers.len(),
                vuln.function_name,
                vuln.category
            ));
            for line_num in &vuln.line_numbers {
                Self::debug_log(&format!("      📌 Adding location at line {}", line_num));
                finding = finding.with_location_parts("", *line_num, 0);
            }

            findings.push(finding);
        }

        Ok(findings)
    }
}

#[async_trait]
impl Scanner for LLMComprehensiveScanner {
    fn id(&self) -> &'static str {
        "llm_comprehensive"
    }

    fn name(&self) -> &'static str {
        "LLM Comprehensive Security Scanner"
    }

    fn description(&self) -> &'static str {
        "LLM-powered comprehensive vulnerability detection for all major security issues in a single analysis"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn scan(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        Self::debug_log("📞 LLMComprehensiveScanner::scan() called");

        let source_code = context
            .source_code()
            .ok_or_else(|| anyhow::anyhow!("No source code available for analysis"))?;

        let contract_name = context.contract_name().unwrap_or("Unknown");

        Self::debug_log(&format!("   Contract: {}", contract_name));
        Self::debug_log(&format!("   Source length: {} bytes", source_code.len()));

        match tokio::runtime::Handle::try_current() {
            Ok(_handle) => {
                Self::debug_log("   Using existing tokio runtime");
                std::thread::scope(|s| {
                    s.spawn(|| {
                        tokio::runtime::Runtime::new()
                            .unwrap()
                            .block_on(self.analyze_source(source_code, contract_name))
                    })
                    .join()
                    .unwrap()
                })
            }
            Err(_) => {
                Self::debug_log("   Creating new tokio runtime");
                tokio::runtime::Runtime::new()
                    .unwrap()
                    .block_on(self.analyze_source(source_code, contract_name))
            }
        }
    }
}
