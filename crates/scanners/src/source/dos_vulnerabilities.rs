//! Source-Level DoS Vulnerabilities Detector
//!
//! This scanner analyzes Solidity source code using tree-sitter queries to detect
//! DoS vulnerabilities that are lost in IR transformation.

use crate::core::result::Location;
use crate::core::{AnalysisContext, Confidence, Finding, Scanner, Severity};
use crate::representations::source::SourceRepresentation;
use anyhow::Result;

pub struct SourceDoSVulnerabilitiesScanner;

impl SourceDoSVulnerabilitiesScanner {
    pub fn new() -> Self {
        Self
    }

    fn is_constant_bounded(condition: &str) -> bool {
        let has_numeric_literal = condition.chars().any(|c| c.is_numeric());

        let has_dynamic_bound = condition.contains(".length") ||
                                condition.contains('(') ||  // Function call
                                condition.contains('['); // Array access

        has_numeric_literal && !has_dynamic_bound
    }

    fn analyze_ast(
        &self,
        source_repr: &SourceRepresentation,
        contract_name: &str,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for loop_info in &source_repr.loops {
            let is_constant_bounded = Self::is_constant_bounded(&loop_info.condition);

            if is_constant_bounded {
                continue;
            }

            if loop_info.contains_external_calls
                && (loop_info.contains_storage_writes || loop_info.iterates_over_length)
            {
                findings.push(
                    Finding::new(
                        "dos-external-call-loop-source".to_string(),
                        Severity::High,
                        Confidence::High,
                        format!("External call in unbounded loop at line {}", loop_info.location.line),
                        format!(
                            "Contract '{}' has external call in unbounded loop at line {}. \
                            If one call fails, the entire transaction reverts causing DoS. Use pull-over-push pattern.",
                            contract_name, loop_info.location.line
                        ),
                    )
                    .with_contract(contract_name)
                    .with_location(Location {
                        file: loop_info.location.file.clone(),
                        line: loop_info.location.line,
                        column: loop_info.location.column,
                        end_line: Some(loop_info.location.end_line),
                        end_column: Some(loop_info.location.end_column),
                        snippet: Some(loop_info.body.lines().take(3).collect::<Vec<_>>().join("\n")),
                        ir_position: None,
                    })
                );
            }

            if loop_info.contains_storage_writes
                && (loop_info.contains_external_calls || loop_info.iterates_over_length)
            {
                findings.push(
                    Finding::new(
                        "dos-gas-limit-loop-source".to_string(),
                        Severity::Medium,  // Downgraded from High - less severe than external calls
                        Confidence::Medium,  // Medium confidence - depends on array size
                        format!("Potential gas limit DoS - unbounded loop at line {}", loop_info.location.line),
                        format!(
                            "Contract '{}' has unbounded loop with storage operations at line {}. \
                            Large arrays can cause out-of-gas errors. Implement pagination or gas limits.",
                            contract_name, loop_info.location.line
                        ),
                    )
                    .with_contract(contract_name)
                    .with_location(Location {
                        file: loop_info.location.file.clone(),
                        line: loop_info.location.line,
                        column: loop_info.location.column,
                        end_line: Some(loop_info.location.end_line),
                        end_column: Some(loop_info.location.end_column),
                        snippet: Some(loop_info.body.lines().take(3).collect::<Vec<_>>().join("\n")),
                        ir_position: None,
                    })
                );
            }

            if loop_info.iterates_over_length
                && !loop_info.contains_external_calls
                && !loop_info.contains_storage_writes
            {
                findings.push(
                    Finding::new(
                        "dos-unbounded-loop-source".to_string(),
                        Severity::Low,  // Downgraded from Medium - informational only
                        Confidence::Low,  // Low confidence - may not be an issue in practice
                        format!("Unbounded loop at line {}", loop_info.location.line),
                        format!(
                            "Contract '{}' has loop iterating over array length at line {}. \
                            If the array can grow unbounded, this could cause gas limit issues. Review array growth patterns.",
                            contract_name, loop_info.location.line
                        ),
                    )
                    .with_contract(contract_name)
                    .with_location(Location {
                        file: loop_info.location.file.clone(),
                        line: loop_info.location.line,
                        column: loop_info.location.column,
                        end_line: Some(loop_info.location.end_line),
                        end_column: Some(loop_info.location.end_column),
                        snippet: Some(loop_info.condition.clone()),
                        ir_position: None,
                    })
                );
            }
        }

        Ok(findings)
    }
}

impl Default for SourceDoSVulnerabilitiesScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner for SourceDoSVulnerabilitiesScanner {
    fn id(&self) -> &'static str {
        "source-dos-vulnerabilities"
    }

    fn name(&self) -> &'static str {
        "Source-Level DoS Vulnerabilities Detector"
    }

    fn description(&self) -> &'static str {
        "Detects DoS vulnerabilities in Solidity source using tree-sitter queries"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn scan(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        let contract_info = context.contract_info();

        let source = match &contract_info.source_code {
            Some(src) => src,
            None => return Ok(Vec::new()),
        };

        let contract_name = &contract_info.name;
        let file_path = contract_info
            .source_path
            .as_deref()
            .unwrap_or("unknown.sol");

        let source_repr = SourceRepresentation::from_source(source, file_path, contract_name)?;

        self.analyze_ast(&source_repr, contract_name)
    }

    fn required_representations(&self) -> crate::representations::RepresentationSet {
        crate::representations::RepresentationSet::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dos_external_call_in_loop() {
        let source = r#"
        contract Test {
            function batchTransfer(address[] calldata recipients) external {
                for (uint256 i = 0; i < recipients.length; i++) {
                    recipients[i].call{value: 1 ether}("");
                }
            }
        }
        "#;

        let source_repr = SourceRepresentation::from_source(source, "test.sol", "Test").unwrap();
        let scanner = SourceDoSVulnerabilitiesScanner::new();
        let result = scanner.analyze_ast(&source_repr, "Test").unwrap();

        assert!(!result.is_empty(), "Expected at least 1 DoS finding");
        assert!(result.iter().any(|f| f.scanner_id.contains("dos")));
    }

    #[test]
    fn test_dos_unbounded_loop() {
        let source = r#"
        contract Test {
            uint256[] public data;

            function processAll() external {
                for (uint256 i = 0; i < data.length; i++) {
                    data[i] = i * 2;
                }
            }
        }
        "#;

        let source_repr = SourceRepresentation::from_source(source, "test.sol", "Test").unwrap();
        let scanner = SourceDoSVulnerabilitiesScanner::new();
        let result = scanner.analyze_ast(&source_repr, "Test").unwrap();

        assert!(
            !result.is_empty(),
            "Expected at least 1 unbounded loop finding"
        );
        assert!(result.iter().any(
            |f| f.description.contains("Unbounded loop") || f.description.contains("gas limit")
        ));
    }

    #[test]
    fn test_safe_bounded_loop() {
        let source = r#"
        contract Test {
            function safeProcess() external {
                for (uint256 i = 0; i < 10; i++) {
                }
            }
        }
        "#;

        let source_repr = SourceRepresentation::from_source(source, "test.sol", "Test").unwrap();
        let scanner = SourceDoSVulnerabilitiesScanner::new();
        let result = scanner.analyze_ast(&source_repr, "Test").unwrap();

        assert_eq!(result.len(), 0, "Bounded loop should not be flagged");
    }
}
