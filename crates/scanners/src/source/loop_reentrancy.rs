//! Source-Level Loop Reentrancy Scanner
//!
//! Query-based scanner that analyzes Solidity source code using tree-sitter
//! to detect loop-based reentrancy patterns that are lost in ThalIR transformation.
//!
//! Pattern detected:
//! ```solidity
//! for (uint i = 0; i < arr.length; i++) {
//!     address.call{value: amount}("");  // External call in loop
//! }
//! balances[msg.sender] = 0;  // State update after loop
//! ```

use crate::core::result::Location;
use crate::core::{AnalysisContext, Confidence, Finding, Scanner, Severity};
use crate::representations::source::SourceRepresentation;
use anyhow::Result;

pub struct SourceLoopReentrancyScanner;

impl SourceLoopReentrancyScanner {
    pub fn new() -> Self {
        Self
    }

    fn analyze_ast(&self, source_repr: &SourceRepresentation) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for loop_info in source_repr.loops_with_external_calls() {
            if source_repr.has_assignments_after_loop(loop_info) {
                findings.push(
                    Finding::new(
                        "source-loop-reentrancy".to_string(),
                        Severity::High,
                        Confidence::High,
                        format!(
                            "Loop-based reentrancy in function '{}'",
                            loop_info.function_name
                        ),
                        format!(
                            "Function '{}' in contract '{}' contains a loop with external calls, followed by state modifications after the loop completes. \
                             An attacker can reenter during loop execution before state is finalized. \
                             Pattern: external call in loop → state modification after loop.",
                            loop_info.function_name,
                            source_repr.contract_name,
                        ),
                    )
                    .with_location(Location {
                        file: loop_info.location.file.clone(),
                        line: loop_info.location.line,
                        column: loop_info.location.column,
                        end_line: Some(loop_info.location.end_line),
                        end_column: Some(loop_info.location.end_column),
                        snippet: Some(loop_info.body.lines().take(3).collect::<Vec<_>>().join("\n")),
                        ir_position: None,
                    })
                    .with_contract(&source_repr.contract_name)
                    .with_function(&loop_info.function_name)
                    .with_confidence_score(Confidence::High, 0.9),
                );
            }
        }

        Ok(findings)
    }
}

impl Default for SourceLoopReentrancyScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner for SourceLoopReentrancyScanner {
    fn id(&self) -> &'static str {
        "source-loop-reentrancy"
    }

    fn name(&self) -> &'static str {
        "Source-Level Loop Reentrancy Scanner"
    }

    fn description(&self) -> &'static str {
        "Detects loop-based reentrancy by analyzing Solidity source code using tree-sitter queries"
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
    fn test_detect_loop_reentrancy() {
        let source = r#"
        pragma solidity ^0.8.0;
        contract VulnerableContract {
            mapping(address => uint256) public balances;

            function batchWithdraw(address[] calldata recipients, uint256[] calldata amounts) external {
                for (uint256 i = 0; i < recipients.length; i++) {
                    (bool success, ) = recipients[i].call{value: amounts[i]}("");
                    require(success, "Transfer failed");
                }
                balances[msg.sender] = 0;
            }
        }
        "#;

        let contract_info = ContractInfo {
            name: "VulnerableContract".to_string(),
            source_path: Some("test.sol".to_string()),
            source_code: Some(source.to_string()),
            compiler_version: None,
            optimization_enabled: false,
        };

        let bundle = crate::representations::RepresentationBundle::new();
        let mut context = AnalysisContext::new(bundle);
        context.set_contract_info(contract_info);

        let scanner = SourceLoopReentrancyScanner::new();
        let findings = scanner.scan(&context).unwrap();

        assert!(findings.len() >= 1, "Expected at least 1 finding");
        assert!(findings
            .iter()
            .any(|f| f.scanner_id == "source-loop-reentrancy"));
    }

    #[test]
    fn test_safe_pattern_no_finding() {
        let source = r#"
        pragma solidity ^0.8.0;
        contract SafeContract {
            mapping(address => uint256) public balances;

            function batchWithdraw(address[] calldata recipients) external {
                balances[msg.sender] = 0;

                for (uint256 i = 0; i < recipients.length; i++) {
                    (bool success, ) = recipients[i].call{value: 1 ether}("");
                    require(success, "Transfer failed");
                }
            }
        }
        "#;

        let contract_info = ContractInfo {
            name: "SafeContract".to_string(),
            source_path: Some("test.sol".to_string()),
            source_code: Some(source.to_string()),
            compiler_version: None,
            optimization_enabled: false,
        };

        let bundle = crate::representations::RepresentationBundle::new();
        let mut context = AnalysisContext::new(bundle);
        context.set_contract_info(contract_info);

        let scanner = SourceLoopReentrancyScanner::new();
        let findings = scanner.scan(&context).unwrap();

        assert_eq!(
            findings.len(),
            0,
            "Should not detect vulnerability in safe pattern"
        );
    }
}
