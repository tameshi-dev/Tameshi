//! Source-Level Time Vulnerabilities Detector
//!
//! This scanner analyzes Solidity source code using tree-sitter queries to detect
//! time-based vulnerabilities that are lost in IR optimization.

use crate::core::{Confidence, Finding, Severity, Scanner, AnalysisContext};
use crate::core::result::Location;
use anyhow::Result;
use tree_sitter::{Parser, Query, QueryCursor, Node};
use streaming_iterator::StreamingIterator;

pub struct SourceTimeVulnerabilitiesScanner;

impl SourceTimeVulnerabilitiesScanner {
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

        let member_query = Query::new(&language, "(member_expression) @member")?;
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&member_query, root, source.as_bytes());

        let mut block_vars = Vec::new();
        matches.advance();
        while let Some(match_) = matches.get() {
            for capture in match_.captures {
                let member_node = capture.node;
                let member_text = &source[member_node.byte_range()];

                if member_text.starts_with("block.") {
                    block_vars.push((member_node, member_text.to_string()));
                }

                if member_text == "block.difficulty" || member_text == "block.prevrandao" {
                    let start_pos = member_node.start_position();
                    findings.push(
                        Finding::new(
                            "block-difficulty-source".to_string(),
                            Severity::High,
                            Confidence::High,
                            format!("Deprecated {} at line {}", member_text, start_pos.row + 1),
                            format!(
                                "Contract '{}' uses {} at line {}, which is deprecated and unreliable. \
                                Use Chainlink VRF for randomness.",
                                contract_name,
                                member_text,
                                start_pos.row + 1
                            ),
                        )
                        .with_contract(contract_name)
                        .with_location(Location {
                            file: file_path.to_string(),
                            line: start_pos.row + 1,
                            column: start_pos.column,
                            end_line: Some(member_node.end_position().row + 1),
                            end_column: Some(member_node.end_position().column),
                            snippet: Some(member_text.to_string()),
                            ir_position: None,
                        })
                    );
                }
            }
            matches.advance();
        }

        let call_query = Query::new(&language, "(call_expression) @call")?;
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&call_query, root, source.as_bytes());

        matches.advance();
        while let Some(match_) = matches.get() {
            for capture in match_.captures {
                let call_node = capture.node;
                let call_text = &source[call_node.byte_range()];

                if (call_text.starts_with("keccak256") || call_text.starts_with("sha256") || call_text.starts_with("sha3")) &&
                   (call_text.contains("block.timestamp") || call_text.contains("now")) {

                    let func_name = self.get_function_name(&call_node, source);
                    let is_random = func_name.to_lowercase().contains("random") ||
                                   func_name.to_lowercase().contains("lottery") ||
                                   func_name.to_lowercase().contains("winner") ||
                                   func_name.to_lowercase().contains("shuffle");

                    if is_random {
                        let start_pos = call_node.start_position();
                        findings.push(
                            Finding::new(
                                "timestamp-randomness-source".to_string(),
                                Severity::High,
                                Confidence::High,
                                format!("Timestamp used for randomness at line {}", start_pos.row + 1),
                                format!(
                                    "Contract '{}' uses block.timestamp in {} for randomness at line {}. \
                                    This is predictable and can be manipulated by miners. Use Chainlink VRF instead.",
                                    contract_name,
                                    if call_text.starts_with("keccak256") { "keccak256" } else { "sha256" },
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
                                snippet: Some(call_text.lines().next().unwrap_or("").to_string()),
                                ir_position: None,
                            })
                        );
                    }
                }
            }
            matches.advance();
        }

        for (node, text) in &block_vars {
            if text == "block.number" {
                let func_name = self.get_function_name(node, source);
                let is_random = func_name.to_lowercase().contains("random") ||
                               func_name.to_lowercase().contains("lottery") ||
                               func_name.to_lowercase().contains("winner") ||
                               func_name.to_lowercase().contains("shuffle");

                if is_random {
                    let start_pos = node.start_position();
                    findings.push(
                        Finding::new(
                            "block-number-randomness-source".to_string(),
                            Severity::Medium,
                            Confidence::High,
                            format!("Block number used for randomness at line {}", start_pos.row + 1),
                            format!(
                                "Contract '{}' uses block.number for randomness at line {}. \
                                Block number is predictable and should not be used for random number generation.",
                                contract_name,
                                start_pos.row + 1
                            ),
                        )
                        .with_contract(contract_name)
                        .with_location(Location {
                            file: file_path.to_string(),
                            line: start_pos.row + 1,
                            column: start_pos.column,
                            end_line: Some(node.end_position().row + 1),
                            end_column: Some(node.end_position().column),
                            snippet: Some(text.to_string()),
                            ir_position: None,
                        })
                    );
                }
            }

            if text == "block.timestamp" {
                let func_name = self.get_function_name(node, source);

                let mut context_node = node.parent();
                let mut found_statement = None;

                while let Some(parent) = context_node {
                    let kind = parent.kind();
                    if kind.contains("statement") ||
                       kind == "assignment_expression" || kind == "return_statement" {
                        found_statement = Some(parent);
                        break;
                    }
                    context_node = parent.parent();
                }

                if let Some(stmt) = found_statement {
                    let context_text = source[stmt.byte_range()].lines().next().unwrap_or("");

                    let is_modulo = context_text.contains('%');
                    let is_comparison = context_text.contains("==") || context_text.contains("!=") ||
                                       context_text.contains('<') || context_text.contains('>');
                    let is_arithmetic = context_text.contains('+') || context_text.contains('-') ||
                                       context_text.contains('*') || context_text.contains('/') ||
                                       context_text.contains('%');

                    let is_safe_timelock = (func_name.to_lowercase().contains("withdraw") ||
                                           func_name.to_lowercase().contains("claim") ||
                                           func_name.to_lowercase().contains("unlock")) &&
                                          (context_text.contains(" > ") || context_text.contains(" >= ")) &&
                                          (context_text.contains("require") || context_text.contains("revert"));

                    let is_safe_assignment = context_text.contains("=") && !is_comparison &&
                                            !context_text.contains("if ") &&
                                            !context_text.contains("return ");

                    if (is_modulo || is_comparison || is_arithmetic) && !is_safe_timelock && !is_safe_assignment {
                        let severity = if is_modulo {
                            Severity::High  // Modulo with timestamp is very likely randomness
                        } else {
                            Severity::Medium  // Other risky timestamp usage
                        };

                        let start_pos = node.start_position();
                        let description = if is_modulo {
                            format!(
                                "Function '{}' in contract '{}' uses block.timestamp with modulo operation at line {}. \
                                This is commonly used for randomness generation, which is predictable and can be manipulated by miners within ~15 seconds. \
                                \n\nVulnerable code: {}\n\n\
                                Recommendation: Use Chainlink VRF for randomness or remove dependency on block.timestamp for critical decisions.",
                                func_name, contract_name, start_pos.row + 1, context_text.trim()
                            )
                        } else {
                            format!(
                                "Function '{}' in contract '{}' uses block.timestamp in conditional/arithmetic logic at line {}. \
                                Miners can manipulate timestamps within ~15 seconds, which may affect contract behavior. \
                                \n\nVulnerable code: {}\n\n\
                                Recommendation: Avoid using block.timestamp for critical decisions. Use block.number or external oracles for time-dependent logic.",
                                func_name, contract_name, start_pos.row + 1, context_text.trim()
                            )
                        };

                        findings.push(
                            Finding::new(
                                "timestamp".to_string(),
                                severity,
                                Confidence::High,
                                format!("Timestamp dependence in '{}'", func_name),
                                description,
                            )
                            .with_contract(contract_name)
                            .with_function(&func_name)
                            .with_location(Location {
                                file: file_path.to_string(),
                                line: start_pos.row + 1,
                                column: start_pos.column,
                                end_line: Some(node.end_position().row + 1),
                                end_column: Some(node.end_position().column),
                                snippet: Some(context_text.trim().to_string()),
                                ir_position: None,
                            })
                        );
                    }
                }
            }
        }

        Ok(findings)
    }

    fn get_function_name(&self, node: &Node, source: &str) -> String {
        let mut current = node.parent();

        while let Some(parent) = current {
            if parent.kind() == "function_definition" {
                if let Some(name_node) = parent.child_by_field_name("name") {
                    return source[name_node.byte_range()].to_string();
                }
            }
            current = parent.parent();
        }

        "unknown".to_string()
    }
}

impl Default for SourceTimeVulnerabilitiesScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner for SourceTimeVulnerabilitiesScanner {
    fn id(&self) -> &'static str {
        "source-time-vulnerabilities"
    }

    fn name(&self) -> &'static str {
        "Source-Level Time Vulnerabilities Detector"
    }

    fn description(&self) -> &'static str {
        "Detects time-based vulnerabilities in Solidity source using tree-sitter queries"
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
    fn test_timestamp_randomness_detection() {
        let source = r#"
        contract Test {
            function generateRandom() external returns (uint256) {
                return uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender)));
            }
        }
        "#;

        let scanner = SourceTimeVulnerabilitiesScanner::new();
        let result = scanner.analyze_ast(source, "Test", "test.sol").unwrap();

        assert_eq!(result.len(), 1);
        assert!(result[0].description.contains("randomness"));
    }

    #[test]
    fn test_block_difficulty_detection() {
        let source = r#"
        contract Test {
            function pickWinner() external view returns (uint256) {
                return uint256(keccak256(abi.encodePacked(block.difficulty)));
            }
        }
        "#;

        let scanner = SourceTimeVulnerabilitiesScanner::new();
        let result = scanner.analyze_ast(source, "Test", "test.sol").unwrap();

        assert_eq!(result.len(), 1);
        assert!(result[0].description.contains("difficulty"));
    }

    #[test]
    fn test_safe_timestamp_usage() {
        let source = r#"
        contract Test {
            function withdraw(uint256 deadline) external {
                require(block.timestamp >= deadline, "Deadline not reached");
            }
        }
        "#;

        let scanner = SourceTimeVulnerabilitiesScanner::new();
        let result = scanner.analyze_ast(source, "Test", "test.sol").unwrap();

        assert_eq!(result.len(), 0);
    }
}
