//! Source-Level Dangerous Functions Detector
//!
//! This scanner analyzes Solidity source code using tree-sitter queries to detect
//! dangerous function calls that are lost or incorrectly transformed in IR.

use crate::core::{Confidence, Finding, Severity, Scanner, AnalysisContext};
use crate::core::result::Location;
use anyhow::Result;
use tree_sitter::{Parser, Query, QueryCursor};
use streaming_iterator::StreamingIterator;

pub struct SourceDangerousFunctionsScanner;

impl SourceDangerousFunctionsScanner {
    pub fn new() -> Self {
        Self
    }

    fn analyze_ast(&self, source: &str, contract_name: &str, file_path: &str) -> Result<Vec<Finding>> {
        let mut parser = Parser::new();
        let language = tree_sitter_solidity::LANGUAGE.into();
        parser.set_language(&language)?;

        let tree = parser.parse(source, None)
            .ok_or_else(|| anyhow::anyhow!("Failed to parse source"))?;

        let root = tree.root_node();
        let mut findings = Vec::new();

        let call_query = Query::new(&language, "(call_expression) @call")?;
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&call_query, root, source.as_bytes());

        matches.advance();
        while let Some(match_) = matches.get() {
            for capture in match_.captures {
                let call_node = capture.node;
                let call_text = &source[call_node.byte_range()];

                if call_text.starts_with("selfdestruct") || call_text.starts_with("suicide") {
                    let start_pos = call_node.start_position();
                    findings.push(
                        Finding::new(
                            "dangerous-selfdestruct-source".to_string(),
                            Severity::High,
                            Confidence::High,
                            format!("Dangerous selfdestruct at line {}", start_pos.row + 1),
                            format!(
                                "Contract '{}' uses selfdestruct at line {}, which permanently destroys the contract. \
                                Ensure proper access control is in place.",
                                contract_name,
                                start_pos.row + 1
                            ),
                        )
                        .with_contract(contract_name)
                        .with_location(Location {
                            file: file_path.to_string(),
                            line: start_pos.row + 1,
                            column: start_pos.column,
                            end_line: Some(call_node.end_position().row + 1),
                            end_column: Some(call_node.end_position().column),
                            snippet: Some(call_text.to_string()),
                            ir_position: None,
                        })
                    );
                }

                if call_text.contains(".delegatecall") {
                    let start_pos = call_node.start_position();
                    findings.push(
                        Finding::new(
                            "dangerous-delegatecall-source".to_string(),
                            Severity::High,
                            Confidence::High,
                            format!("Dangerous delegatecall at line {}", start_pos.row + 1),
                            format!(
                                "Contract '{}' uses delegatecall at line {}, which executes code in the current contract's context. \
                                This can be exploited if the target address is user-controlled.",
                                contract_name,
                                start_pos.row + 1
                            ),
                        )
                        .with_contract(contract_name)
                        .with_location(Location {
                            file: file_path.to_string(),
                            line: start_pos.row + 1,
                            column: start_pos.column,
                            end_line: Some(call_node.end_position().row + 1),
                            end_column: Some(call_node.end_position().column),
                            snippet: Some(call_text.to_string()),
                            ir_position: None,
                        })
                    );
                }
            }
            matches.advance();
        }

        let asm_query = Query::new(&language, "(assembly_statement) @asm")?;
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&asm_query, root, source.as_bytes());

        matches.advance();
        while let Some(match_) = matches.get() {
            for capture in match_.captures {
                let asm_node = capture.node;
                let asm_text = &source[asm_node.byte_range()];

                if asm_text.contains("selfdestruct") || asm_text.contains("delegatecall") || asm_text.contains("callcode") {
                    let start_pos = asm_node.start_position();
                    findings.push(
                        Finding::new(
                            "dangerous-assembly-source".to_string(),
                            Severity::Medium,
                            Confidence::High,
                            format!("Dangerous operation in assembly at line {}", start_pos.row + 1),
                            format!(
                                "Contract '{}' uses inline assembly at line {} with potentially dangerous operations. \
                                Assembly blocks bypass Solidity's safety checks.",
                                contract_name,
                                start_pos.row + 1
                            ),
                        )
                        .with_contract(contract_name)
                        .with_location(Location {
                            file: file_path.to_string(),
                            line: start_pos.row + 1,
                            column: start_pos.column,
                            end_line: Some(asm_node.end_position().row + 1),
                            end_column: Some(asm_node.end_position().column),
                            snippet: Some(asm_text.lines().take(3).collect::<Vec<_>>().join("\n")),
                            ir_position: None,
                        })
                    );
                }
            }
            matches.advance();
        }

        Ok(findings)
    }
}

impl Default for SourceDangerousFunctionsScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner for SourceDangerousFunctionsScanner {
    fn id(&self) -> &'static str {
        "source-dangerous-functions"
    }

    fn name(&self) -> &'static str {
        "Source-Level Dangerous Functions Detector"
    }

    fn description(&self) -> &'static str {
        "Detects dangerous function calls in Solidity source (for patterns lost in IR)"
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

        self.analyze_ast(source, contract_name, file_path)
    }

    fn required_representations(&self) -> crate::representations::RepresentationSet {
        crate::representations::RepresentationSet::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_selfdestruct_detection() {
        let source = r#"
        contract Test {
            function destroy() external {
                selfdestruct(payable(owner));
            }
        }
        "#;

        let scanner = SourceDangerousFunctionsScanner::new();
        let result = scanner.analyze_ast(source, "Test", "test.sol").unwrap();

        assert_eq!(result.len(), 1);
        assert!(result[0].description.contains("selfdestruct"));
    }

    #[test]
    fn test_delegatecall_detection() {
        let source = r#"
        contract Test {
            function execute(address target) external {
                target.delegatecall("");
            }
        }
        "#;

        let scanner = SourceDangerousFunctionsScanner::new();
        let result = scanner.analyze_ast(source, "Test", "test.sol").unwrap();

        assert_eq!(result.len(), 1);
        assert!(result[0].description.contains("delegatecall"));
    }

    #[test]
    fn test_callcode_detection() {
        let source = r#"
        contract Test {
            function legacyCall(address target) external {
                assembly {
                    let success := callcode(gas(), target, 0, 0, 0, 0, 0)
                }
            }
        }
        "#;

        let scanner = SourceDangerousFunctionsScanner::new();
        let result = scanner.analyze_ast(source, "Test", "test.sol").unwrap();

        assert!(result.len() >= 1);
        assert!(result.iter().any(|f| f.description.contains("callcode") || f.description.contains("assembly")));
    }
}
