//! AST-Based DoS Vulnerabilities Detector
//!
//! This scanner uses tree-sitter AST representations instead of regex patterns,
//! providing more accurate and reliable vulnerability detection.

use crate::core::{Confidence, Finding, Severity, Scanner, AnalysisContext};
use crate::core::result::Location;
use crate::representations::source::{SourceRepresentation, LoopType, ExternalCallType};
use anyhow::Result;

pub struct ASTDoSVulnerabilitiesScanner;

impl ASTDoSVulnerabilitiesScanner {
    pub fn new() -> Self {
        Self
    }

    fn analyze_ast(&self, source_repr: &SourceRepresentation) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for loop_info in source_repr.loops_with_external_calls() {
            findings.push(
                Finding::new(
                    "dos-external-call-loop-ast".to_string(),
                    Severity::High,
                    Confidence::High,
                    format!("External call in {} loop at line {}",
                           match loop_info.loop_type {
                               LoopType::For => "for",
                               LoopType::While => "while",
                               LoopType::DoWhile => "do-while",
                           },
                           loop_info.location.line),
                    format!(
                        "Contract '{}' has external call in loop. \
                        If one call fails, the entire transaction reverts causing DoS. \
                        Use pull-over-push pattern.",
                        source_repr.contract_name
                    ),
                )
                .with_contract(&source_repr.contract_name)
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

        for loop_info in &source_repr.loops {
            if loop_info.contains_storage_writes {
                findings.push(
                    Finding::new(
                        "dos-gas-limit-loop-ast".to_string(),
                        Severity::High,
                        Confidence::High,
                        format!("Gas limit DoS - unbounded loop at line {}", loop_info.location.line),
                        format!(
                            "Contract '{}' has unbounded loop with storage operations. \
                            Large arrays can cause out-of-gas errors. \
                            Implement pagination or gas limits.",
                            source_repr.contract_name
                        ),
                    )
                    .with_contract(&source_repr.contract_name)
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

            if loop_info.iterates_over_length {
                findings.push(
                    Finding::new(
                        "dos-unbounded-loop-ast".to_string(),
                        Severity::Medium,
                        Confidence::High,
                        format!("Unbounded loop at line {}", loop_info.location.line),
                        format!(
                            "Contract '{}' has loop iterating over array length. \
                            Growing arrays can cause gas limit issues.",
                            source_repr.contract_name
                        ),
                    )
                    .with_contract(&source_repr.contract_name)
                    .with_location(Location {
                        file: loop_info.location.file.clone(),
                        line: loop_info.location.line,
                        column: loop_info.location.column,
                        end_line: Some(loop_info.location.end_line),
                        end_column: Some(loop_info.location.end_column),
                        snippet: Some(format!("{} loop: {}",
                                             match loop_info.loop_type {
                                                 LoopType::For => "for",
                                                 LoopType::While => "while",
                                                 LoopType::DoWhile => "do-while",
                                             },
                                             loop_info.condition)),
                        ir_position: None,
                    })
                );
            }
        }

        for call_info in source_repr.unchecked_external_calls() {
            if matches!(call_info.call_type,
                       ExternalCallType::Call |
                       ExternalCallType::DelegateCall |
                       ExternalCallType::Send) {

                let parent_has_require = call_info.target.contains("require");

                if parent_has_require {
                    findings.push(
                        Finding::new(
                            "dos-require-external-call-ast".to_string(),
                            Severity::Medium,
                            Confidence::High,
                            format!("DoS via require on external call at line {}", call_info.location.line),
                            format!(
                                "Contract '{}' uses require with external call. \
                                Failed calls will revert, causing DoS.",
                                source_repr.contract_name
                            ),
                        )
                        .with_contract(&source_repr.contract_name)
                        .with_location(Location {
                            file: call_info.location.file.clone(),
                            line: call_info.location.line,
                            column: call_info.location.column,
                            end_line: Some(call_info.location.end_line),
                            end_column: Some(call_info.location.end_column),
                            snippet: Some(call_info.target.clone()),
                            ir_position: None,
                        })
                    );
                }
            }
        }

        Ok(findings)
    }
}

impl Default for ASTDoSVulnerabilitiesScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner for ASTDoSVulnerabilitiesScanner {
    fn id(&self) -> &'static str {
        "ast-dos-vulnerabilities"
    }

    fn name(&self) -> &'static str {
        "AST-Based DoS Vulnerabilities Detector"
    }

    fn description(&self) -> &'static str {
        "Detects DoS vulnerabilities using tree-sitter AST analysis (replaces regex-based detection)"
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
        let file_path = contract_info.source_path.as_deref().unwrap_or("unknown.sol");

        let source_repr = SourceRepresentation::from_source(source, file_path, contract_name)?;

        self.analyze_ast(&source_repr)
    }

    fn required_representations(&self) -> crate::representations::RepresentationSet {
        crate::representations::RepresentationSet::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ContractInfo;

    #[test]
    fn test_detect_external_call_in_loop() {
        let source = r#"
        pragma solidity ^0.8.0;
        contract DoSPatterns {
            function batchSend(address[] calldata recipients) external {
                for (uint256 i = 0; i < recipients.length; i++) {
                    (bool success, ) = recipients[i].call{value: 1 ether}("");
                    require(success, "Transfer failed");
                }
            }
        }
        "#;

        let contract_info = ContractInfo {
            name: "DoSPatterns".to_string(),
            source_path: Some("test.sol".to_string()),
            source_code: Some(source.to_string()),
            compiler_version: None,
            optimization_enabled: false,
        };

        let bundle = crate::representations::RepresentationBundle::new();
        let mut context = AnalysisContext::new(bundle);
        context.set_contract_info(contract_info);

        let scanner = ASTDoSVulnerabilitiesScanner::new();
        let findings = scanner.scan(&context).unwrap();

        for finding in &findings {
            eprintln!("Finding: {} - {}", finding.scanner_id, finding.title);
        }
        eprintln!("Total findings: {}", findings.len());

        assert!(findings.len() >= 2, "Expected at least 2 findings, got {}", findings.len());
        assert!(findings.iter().any(|f| f.scanner_id == "dos-external-call-loop-ast"));
        assert!(findings.iter().any(|f| f.scanner_id == "dos-unbounded-loop-ast"));
    }

    #[test]
    fn test_detect_gas_limit_dos() {
        let source = r#"
        pragma solidity ^0.8.0;
        contract DoSPatterns {
            mapping(address => uint256) public balances;

            function massUpdate(uint256[] calldata values) external {
                for (uint256 i = 0; i < values.length; i++) {
                    balances[msg.sender] = values[i];
                    balances[address(this)] = values[i];
                    balances[address(0)] = values[i];
                }
            }
        }
        "#;

        let contract_info = ContractInfo {
            name: "DoSPatterns".to_string(),
            source_path: Some("test.sol".to_string()),
            source_code: Some(source.to_string()),
            compiler_version: None,
            optimization_enabled: false,
        };

        let bundle = crate::representations::RepresentationBundle::new();
        let mut context = AnalysisContext::new(bundle);
        context.set_contract_info(contract_info);

        let scanner = ASTDoSVulnerabilitiesScanner::new();
        let findings = scanner.scan(&context).unwrap();

        assert!(findings.iter().any(|f| f.scanner_id == "dos-gas-limit-loop-ast"));
    }
}
