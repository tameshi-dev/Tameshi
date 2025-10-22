use crate::core::severity::{Confidence as CoreConfidence, Severity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub fn to_score(&self) -> f32 {
        match self {
            Confidence::High => 0.9,
            Confidence::Medium => 0.6,
            Confidence::Low => 0.3,
        }
    }
}

impl From<f32> for Confidence {
    fn from(score: f32) -> Self {
        if score >= 0.8 {
            Confidence::High
        } else if score >= 0.5 {
            Confidence::Medium
        } else {
            Confidence::Low
        }
    }
}

impl From<Confidence> for CoreConfidence {
    fn from(confidence: Confidence) -> Self {
        match confidence {
            Confidence::High => CoreConfidence::High,
            Confidence::Medium => CoreConfidence::Medium,
            Confidence::Low => CoreConfidence::Low,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentRef {
    #[serde(rename = "component_type")]
    pub component_type: String, // "function", "contract", "variable", etc.

    pub name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_number: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeLocation {
    pub file: String,
    pub line_start: u32,
    pub line_end: u32,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub column_start: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub column_end: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    #[serde(rename = "code_reference")]
    pub code_ref: CodeLocation,

    pub description: String,

    #[serde(rename = "confidence_score")]
    pub confidence: f32,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFinding {
    #[serde(rename = "vulnerability_type")]
    pub vuln_type: String, // "reentrancy", "overflow", "access_control", etc.

    pub title: String,

    pub severity: SeverityLevel,

    pub confidence: Confidence,

    #[serde(rename = "affected_components")]
    pub affected_components: Vec<ComponentRef>,

    #[serde(rename = "root_cause")]
    pub root_cause: String,

    #[serde(rename = "attack_vector")]
    pub attack_vector: String,

    pub evidence: Vec<Evidence>,

    pub recommendation: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SeverityLevel {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl From<SeverityLevel> for Severity {
    fn from(level: SeverityLevel) -> Self {
        match level {
            SeverityLevel::Critical => Severity::Critical,
            SeverityLevel::High => Severity::High,
            SeverityLevel::Medium => Severity::Medium,
            SeverityLevel::Low => Severity::Low,
            SeverityLevel::Informational => Severity::Informational,
        }
    }
}

impl From<Severity> for SeverityLevel {
    fn from(severity: Severity) -> Self {
        match severity {
            Severity::Critical => SeverityLevel::Critical,
            Severity::High => SeverityLevel::High,
            Severity::Medium => SeverityLevel::Medium,
            Severity::Low => SeverityLevel::Low,
            Severity::Informational => SeverityLevel::Informational,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerResponse {
    pub findings: Vec<VulnerabilityFinding>,

    #[serde(rename = "analysis_summary")]
    pub analysis_summary: String,

    #[serde(rename = "coverage_notes")]
    pub coverage_notes: Vec<String>,

    #[serde(rename = "requires_further_analysis")]
    pub requires_further_analysis: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<AnalysisMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleScannerResponse {
    pub vulnerable: bool,
    pub confidence: String, // "High", "Medium", "Low"
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisMetadata {
    pub model: String,
    pub temperature: f32,
    pub tokens_used: u32,
    pub analysis_time_ms: u64,
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
}

impl ScannerResponse {
    pub fn schema_definition() -> &'static str {
        r#"
{
  "findings": [
    {
      "vulnerability_type": "string (e.g., 'reentrancy', 'overflow', 'access_control')",
      "title": "string (brief description)",
      "severity": "critical|high|medium|low|info",
      "confidence": "high|medium|low",
      "affected_components": [
        {
          "component_type": "function|contract|variable|modifier",
          "name": "string",
          "contract": "string (optional)",
          "line_number": "number (optional)"
        }
      ],
      "root_cause": "string (technical explanation)",
      "attack_vector": "string (how to exploit)",
      "evidence": [
        {
          "code_reference": {
            "file": "string",
            "line_start": "number",
            "line_end": "number"
          },
          "description": "string - MUST include IR location reference if analyzing IR (e.g., 'External call at block_0, inst_2 before state update at block_0, inst_5')",
          "confidence_score": "number (0.0-1.0)"
        }
      ],
      "recommendation": "string (how to fix)"
    }
  ],
  "analysis_summary": "string (overall assessment)",
  "coverage_notes": ["string (what was analyzed)"],
  "requires_further_analysis": ["string (what needs more review)"]
}
"#
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_vulnerability_finding_serialization() {
        let finding = VulnerabilityFinding {
            vuln_type: "reentrancy".to_string(),
            title: "Reentrancy vulnerability in withdraw function".to_string(),
            severity: SeverityLevel::High,
            confidence: Confidence::High,
            affected_components: vec![ComponentRef {
                component_type: "function".to_string(),
                name: "withdraw".to_string(),
                contract: Some("Bank".to_string()),
                line_number: Some(42),
            }],
            root_cause: "State change after external call".to_string(),
            attack_vector: "Attacker can drain funds by re-entering".to_string(),
            evidence: vec![Evidence {
                code_ref: CodeLocation {
                    file: "Bank.sol".to_string(),
                    line_start: 42,
                    line_end: 45,
                    column_start: None,
                    column_end: None,
                },
                description: "External call before state update".to_string(),
                confidence: 0.95,
                snippet: Some("msg.sender.call{value: amount}(\"\")".to_string()),
            }],
            recommendation: "Use checks-effects-interactions pattern".to_string(),
            references: None,
        };

        let json = serde_json::to_string_pretty(&finding).unwrap();
        assert!(json.contains("reentrancy"));

        let deserialized: VulnerabilityFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.vuln_type, "reentrancy");
    }

    #[test]
    fn test_scanner_response_schema() {
        let response = ScannerResponse {
            findings: vec![],
            analysis_summary: "No vulnerabilities found".to_string(),
            coverage_notes: vec!["Analyzed all functions".to_string()],
            requires_further_analysis: vec![],
            metadata: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: ScannerResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.analysis_summary, response.analysis_summary);
    }
}
