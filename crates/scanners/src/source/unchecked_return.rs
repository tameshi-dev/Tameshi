//! Source-Level Unchecked Return Value Detector
//!
//! This scanner analyzes Solidity source code using tree-sitter queries to detect
//! unchecked return values from external calls that are lost or incorrectly transformed in IR.

use crate::core::result::Location;
use crate::core::{AnalysisContext, Confidence, Finding, Scanner, Severity};
use crate::representations::source::{ExternalCallType, SourceRepresentation};
use anyhow::Result;

pub struct SourceUncheckedReturnScanner;

impl SourceUncheckedReturnScanner {
    pub fn new() -> Self {
        Self
    }

    fn analyze_ast(
        &self,
        source_repr: &SourceRepresentation,
        contract_name: &str,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let unchecked_calls = source_repr.unchecked_external_calls();

        for call_info in unchecked_calls {
            let (scanner_id, call_type_str, description) = match &call_info.call_type {
                ExternalCallType::ERC20Transfer | ExternalCallType::ERC20TransferFrom => {
                    ("unchecked-return-source",
                     format!("ERC20 {}", match &call_info.call_type {
                         ExternalCallType::ERC20Transfer => "transfer",
                         ExternalCallType::ERC20TransferFrom => "transferFrom",
                         _ => unreachable!(),
                     }),
                     format!(
                        "Contract '{}' has unchecked return value from ERC20 {} at line {}. \
                        ERC20 functions return bool but the return value is not checked.",
                        contract_name,
                        match &call_info.call_type {
                            ExternalCallType::ERC20Transfer => "transfer",
                            ExternalCallType::ERC20TransferFrom => "transferFrom",
                            _ => unreachable!(),
                        },
                        call_info.location.line
                    ))
                },
                ExternalCallType::Call | ExternalCallType::DelegateCall | ExternalCallType::StaticCall => {
                    ("unchecked-lowlevel-call-source",
                     format!("low-level {:?}", call_info.call_type).to_lowercase(),
                     format!(
                        "Contract '{}' has unchecked return value from low-level {:?} at line {}. \
                        Low-level calls return (bool success, bytes memory data) but the return value is not checked.",
                        contract_name,
                        call_info.call_type,
                        call_info.location.line
                    ))
                },
                ExternalCallType::Send => {
                    ("unchecked-send-source",
                     "send".to_string(),
                     format!(
                        "Contract '{}' has unchecked return value from send() at line {}. \
                        send() returns bool but the return value is not checked. Use transfer() or check the return value.",
                        contract_name,
                        call_info.location.line
                    ))
                },
                ExternalCallType::Transfer => continue,
            };

            findings.push(
                Finding::new(
                    scanner_id.to_string(),
                    Severity::Medium,
                    Confidence::High,
                    format!(
                        "Unchecked {} at line {}",
                        call_type_str, call_info.location.line
                    ),
                    description,
                )
                .with_contract(contract_name)
                .with_location(Location {
                    file: call_info.location.file.clone(),
                    line: call_info.location.line,
                    column: call_info.location.column,
                    end_line: Some(call_info.location.end_line),
                    end_column: Some(call_info.location.end_column),
                    snippet: Some(
                        call_info
                            .target
                            .lines()
                            .take(3)
                            .collect::<Vec<_>>()
                            .join("\n"),
                    ),
                    ir_position: None,
                }),
            );
        }

        Ok(findings)
    }
}

impl Default for SourceUncheckedReturnScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner for SourceUncheckedReturnScanner {
    fn id(&self) -> &'static str {
        "source-unchecked-return"
    }

    fn name(&self) -> &'static str {
        "Source-Level Unchecked Return Value Detector"
    }

    fn description(&self) -> &'static str {
        "Detects unchecked return values in Solidity source (for patterns lost in IR)"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
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
    fn test_unchecked_erc20_transfer() {
        let source = r#"
        contract Test {
            function unsafeTransfer(address token, address to, uint256 amount) external {
                token.transfer(to, amount);
            }
        }
        "#;

        let source_repr = SourceRepresentation::from_source(source, "test.sol", "Test").unwrap();
        let scanner = SourceUncheckedReturnScanner::new();
        let result = scanner.analyze_ast(&source_repr, "Test").unwrap();

        assert!(
            !result.is_empty(),
            "Expected at least 1 finding for unchecked ERC20 transfer"
        );
        assert!(result.iter().any(|f| f.description.contains("ERC20")));
    }

    #[test]
    fn test_checked_transfer() {
        let source = r#"
        contract Test {
            function safeTransfer(address token, address to, uint256 amount) external {
                bool success = token.transfer(to, amount);
                require(success, "Transfer failed");
            }
        }
        "#;

        let source_repr = SourceRepresentation::from_source(source, "test.sol", "Test").unwrap();
        let scanner = SourceUncheckedReturnScanner::new();
        let result = scanner.analyze_ast(&source_repr, "Test").unwrap();

        assert_eq!(result.len(), 0, "Checked transfer should not be flagged");
    }

    #[test]
    fn test_unchecked_low_level_call() {
        let source = r#"
        contract Test {
            function unsafeCall(address target) external {
                target.call("");
            }
        }
        "#;

        let source_repr = SourceRepresentation::from_source(source, "test.sol", "Test").unwrap();
        let scanner = SourceUncheckedReturnScanner::new();
        let result = scanner.analyze_ast(&source_repr, "Test").unwrap();

        assert!(
            !result.is_empty(),
            "Expected at least 1 finding for unchecked low-level call"
        );
        assert!(result.iter().any(|f| f.description.contains("low-level")));
    }

    #[test]
    fn test_checked_call() {
        let source = r#"
        contract Test {
            function safeCall(address target) external {
                (bool success, ) = target.call("");
                require(success, "Call failed");
            }
        }
        "#;

        let source_repr = SourceRepresentation::from_source(source, "test.sol", "Test").unwrap();
        let scanner = SourceUncheckedReturnScanner::new();
        let result = scanner.analyze_ast(&source_repr, "Test").unwrap();

        assert_eq!(result.len(), 0, "Checked call should not be flagged");
    }
}
