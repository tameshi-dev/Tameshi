//! Source-Level Integer Overflow Scanner
//!
//! Fallback scanner that analyzes Solidity source code using tree-sitter queries
//! to detect integer overflow/underflow patterns that are lost in IR transformation.
//!
//! Patterns detected:
//! 1. Multiplication in loops (lost in IR)
//! 2. Multiplication before division (optimized away in IR)
//! 3. Accumulation in loops (flattened in IR)

use crate::core::{Confidence, Finding, Severity, Scanner, AnalysisContext};
use crate::core::result::Location;
use crate::representations::source::SourceRepresentation;
use anyhow::Result;
use tree_sitter::{Query, QueryCursor};
use streaming_iterator::StreamingIterator;

pub struct SourceIntegerOverflowScanner;

impl SourceIntegerOverflowScanner {
    pub fn new() -> Self {
        Self
    }

    fn analyze_ast(&self, source_repr: &SourceRepresentation) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        findings.extend(self.check_mul_in_loops(source_repr)?);

        findings.extend(self.check_mul_div_pattern(source_repr)?);

        findings.extend(self.check_accumulation_in_loops(source_repr)?);

        Ok(findings)
    }

    fn check_mul_in_loops(&self, source_repr: &SourceRepresentation) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let language = tree_sitter_solidity::LANGUAGE.into();

        let mul_query_str = r#"
        (binary_expression) @binexpr
        "#;

        let mul_query = Query::new(&language, mul_query_str)?;

        for loop_info in &source_repr.loops {
            let mut parser = tree_sitter::Parser::new();
            parser.set_language(&language)?;

            let wrapped_code = format!("contract C {{ function f() public {} }}", loop_info.body);

            if let Some(tree) = parser.parse(&wrapped_code, None) {
                #[cfg(test)]
                eprintln!("Parsed loop body, has errors: {}", tree.root_node().has_error());

                let mut cursor = QueryCursor::new();
                let mut matches = cursor.matches(&mul_query, tree.root_node(), wrapped_code.as_bytes());

                let mut found_mul = false;
                matches.advance();
                while let Some(match_) = matches.get() {
                    #[cfg(test)]
                    eprintln!("Found binary expression match");
                    for capture in match_.captures {
                        let node = capture.node;
                        if let Some(operator_node) = node.child_by_field_name("operator") {
                            let operator = &wrapped_code[operator_node.byte_range()];
                            if operator == "*" {
                                found_mul = true;
                                break;
                            }
                        }
                    }
                    if found_mul {
                        break;
                    }
                    matches.advance();
                }

                if found_mul {
                    findings.push(
                        Finding::new(
                            "source-integer-overflow-mul-loop".to_string(),
                            Severity::High,
                            Confidence::High,
                            format!("Multiplication in loop in '{}'", loop_info.function_name),
                            format!(
                                "Function '{}' in contract '{}' performs multiplication inside a loop. \
                                 This can overflow in Solidity <0.8.0. Even in 0.8.0+, unchecked multiplication \
                                 in loops may revert unexpectedly, causing DoS. Use SafeMath or checked arithmetic.",
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
                    break; // Only report once per loop
                }
            }
        }

        Ok(findings)
    }

    fn check_mul_div_pattern(&self, source_repr: &SourceRepresentation) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let language = tree_sitter_solidity::LANGUAGE.into();

        let mul_div_query_str = r#"
        (binary_expression) @binexpr
        "#;

        let mul_div_query = Query::new(&language, mul_div_query_str)?;

        for (func_name, func_info) in &source_repr.functions {
            let mut parser = tree_sitter::Parser::new();
            parser.set_language(&language)?;

            let wrapped_code = format!("contract C {{ function f() public {} }}", func_info.body);

            if let Some(tree) = parser.parse(&wrapped_code, None) {
                let mut cursor = QueryCursor::new();
                let mut matches = cursor.matches(&mul_div_query, tree.root_node(), wrapped_code.as_bytes());

                #[cfg(test)]
                eprintln!("Parsed function body, has errors: {}", tree.root_node().has_error());

                matches.advance();
                while let Some(match_) = matches.get() {
                    #[cfg(test)]
                    eprintln!("Found binary_expression in function");

                    for capture in match_.captures {
                        let node = capture.node;

                        if let Some(operator_node) = node.child_by_field_name("operator") {
                            let operator = &wrapped_code[operator_node.byte_range()];

                            #[cfg(test)]
                            eprintln!("Binary operator: {}", operator);

                            if operator == "/" {
                                #[cfg(test)]
                                eprintln!("Found division");
                                if let Some(left_node) = node.child_by_field_name("left") {
                                    let mut actual_left = left_node;
                                    while let "expression" | "parenthesized_expression" = actual_left.kind() {
                                        let mut found = false;
                                        let mut cursor = actual_left.walk();
                                        for child in actual_left.children(&mut cursor) {
                                            if child.is_named() {
                                                actual_left = child;
                                                found = true;
                                                break;
                                            }
                                        }
                                        if !found {
                                            break;
                                        }
                                    }

                                    #[cfg(test)]
                                    eprintln!("Left operand kind: {}", actual_left.kind());

                                    if actual_left.kind() == "binary_expression" {
                                        if let Some(left_op_node) = actual_left.child_by_field_name("operator") {
                                            let left_op = &wrapped_code[left_op_node.byte_range()];
                                            if left_op == "*" {
                                                let snippet = &wrapped_code[node.byte_range()];

                        findings.push(
                            Finding::new(
                                "source-integer-overflow-mul-div".to_string(),
                                Severity::Medium,
                                Confidence::High,
                                format!("Multiplication before division in '{}'", func_name),
                                format!(
                                    "Function '{}' in contract '{}' multiplies before dividing (a * b / c). \
                                     The multiplication can overflow before the division is applied. \
                                     In Solidity <0.8.0, this can cause silent overflow. Consider reordering or using SafeMath.",
                                    func_name,
                                    source_repr.contract_name,
                                ),
                            )
                            .with_location(Location {
                                file: func_info.location.file.clone(),
                                line: func_info.location.line + node.start_position().row,
                                column: node.start_position().column,
                                end_line: None,
                                end_column: None,
                                snippet: Some(snippet.to_string()),
                                ir_position: None,
                            })
                            .with_contract(&source_repr.contract_name)
                            .with_function(func_name)
                            .with_confidence_score(Confidence::High, 0.85),
                        );
                                                return Ok(findings); // Only report once
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    matches.advance();
                }
            }
        }

        Ok(findings)
    }

    fn check_accumulation_in_loops(&self, source_repr: &SourceRepresentation) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let language = tree_sitter_solidity::LANGUAGE.into();

        let accumulation_query_str = r#"
        (augmented_assignment_expression) @aug_assign
        "#;

        let accumulation_query = Query::new(&language, accumulation_query_str)?;

        for loop_info in &source_repr.loops {
            let mut parser = tree_sitter::Parser::new();
            parser.set_language(&language)?;

            let wrapped_code = format!("contract C {{ function f() public {} }}", loop_info.body);

            if let Some(tree) = parser.parse(&wrapped_code, None) {
                let mut cursor = QueryCursor::new();
                let mut matches = cursor.matches(&accumulation_query, tree.root_node(), wrapped_code.as_bytes());

                let mut found_accumulation = false;
                matches.advance();
                while let Some(match_) = matches.get() {
                    #[cfg(test)]
                    eprintln!("Found augmented_assignment match");

                    for capture in match_.captures {
                        let node = capture.node;

                        let mut cursor = node.walk();
                        let mut operator = None;
                        for child in node.children(&mut cursor) {
                            let text = &wrapped_code[child.byte_range()];
                            if text == "+=" || text == "-=" || text == "*=" || text == "/=" {
                                operator = Some(text);
                                break;
                            }
                        }

                        #[cfg(test)]
                        eprintln!("Operator: {:?}", operator);

                        if let Some("+=") = operator {
                            if let Some(left_node) = node.child_by_field_name("left") {
                                let actual_left = if left_node.kind() == "expression" {
                                    if let Some(inner) = left_node.child(0) {
                                        inner
                                    } else {
                                        matches.advance();
                                        continue;
                                    }
                                } else {
                                    left_node
                                };

                                if actual_left.kind() == "identifier" {
                                    let var_name = &wrapped_code[actual_left.byte_range()];

                                    if var_name.len() == 1 && var_name.chars().next().unwrap().is_ascii_lowercase() {
                                        matches.advance();
                                        continue;
                                    }

                                    found_accumulation = true;
                                    break;
                                }
                            }
                        }
                    }
                    if found_accumulation {
                        break;
                    }
                    matches.advance();
                }

                if found_accumulation {
                    findings.push(
                        Finding::new(
                            "source-integer-overflow-accumulation-loop".to_string(),
                            Severity::Medium,
                            Confidence::Medium,
                            format!("Accumulation in loop in '{}'", loop_info.function_name),
                            format!(
                                "Function '{}' in contract '{}' accumulates values in a loop. \
                                 Repeated addition can overflow in Solidity <0.8.0. Ensure proper bounds checking \
                                 or use SafeMath/checked arithmetic.",
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
                        .with_confidence_score(Confidence::Medium, 0.75),
                    );
                    break; // Only report once per loop
                }
            }
        }

        Ok(findings)
    }
}

impl Default for SourceIntegerOverflowScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner for SourceIntegerOverflowScanner {
    fn id(&self) -> &'static str {
        "source-integer-overflow"
    }

    fn name(&self) -> &'static str {
        "Source-Level Integer Overflow Scanner"
    }

    fn description(&self) -> &'static str {
        "Detects integer overflow/underflow by analyzing Solidity source code using tree-sitter queries"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn scan(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        if let Some(version) = context.get_metadata::<crate::analysis::SolidityVersion>("solidity_version") {
            if version.has_builtin_overflow_protection() {
                return Ok(Vec::new());
            }
        }

        let contract_info = context.contract_info();

        let source = match &contract_info.source_code {
            Some(src) => src,
            None => return Ok(Vec::new()),
        };

        let contract_name = &contract_info.name;
        let file_path = contract_info.source_path
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
    fn test_detect_mul_in_loop() {
        let source = r#"
        pragma solidity ^0.7.6;
        contract MulInLoop {
            function calculateRewards(uint256[] calldata amounts, uint256 multiplier) external {
                for (uint256 i = 0; i < amounts.length; i++) {
                    uint256 reward = amounts[i] * multiplier;
                }
            }
        }
        "#;

        let contract_info = ContractInfo {
            name: "MulInLoop".to_string(),
            source_path: Some("test.sol".to_string()),
            source_code: Some(source.to_string()),
            compiler_version: None,
            optimization_enabled: false,
        };

        let bundle = crate::representations::RepresentationBundle::new();
        let mut context = AnalysisContext::new(bundle);
        context.set_contract_info(contract_info);

        let scanner = SourceIntegerOverflowScanner::new();
        let findings = scanner.scan(&context).unwrap();

        assert!(findings.iter().any(|f| f.scanner_id == "source-integer-overflow-mul-loop"));
    }

    #[test]
    fn test_detect_mul_div_pattern() {
        let source = r#"
        pragma solidity ^0.7.6;
        contract MulDiv {
            function calculate(uint256 a, uint256 b, uint256 c) external pure returns (uint256) {
                return (a * b) / c;
            }
        }
        "#;

        let contract_info = ContractInfo {
            name: "MulDiv".to_string(),
            source_path: Some("test.sol".to_string()),
            source_code: Some(source.to_string()),
            compiler_version: None,
            optimization_enabled: false,
        };

        let bundle = crate::representations::RepresentationBundle::new();
        let mut context = AnalysisContext::new(bundle);
        context.set_contract_info(contract_info);

        let scanner = SourceIntegerOverflowScanner::new();
        let findings = scanner.scan(&context).unwrap();

        assert!(findings.iter().any(|f| f.scanner_id == "source-integer-overflow-mul-div"));
    }

    #[test]
    fn test_detect_accumulation_in_loop() {
        let source = r#"
        pragma solidity ^0.7.6;
        contract AccumulationLoop {
            function sumValues(uint256[] calldata values) external pure returns (uint256) {
                uint256 total = 0;
                for (uint256 i = 0; i < values.length; i++) {
                    total += values[i];
                }
                return total;
            }
        }
        "#;

        let contract_info = ContractInfo {
            name: "AccumulationLoop".to_string(),
            source_path: Some("test.sol".to_string()),
            source_code: Some(source.to_string()),
            compiler_version: None,
            optimization_enabled: false,
        };

        let bundle = crate::representations::RepresentationBundle::new();
        let mut context = AnalysisContext::new(bundle);
        context.set_contract_info(contract_info);

        let scanner = SourceIntegerOverflowScanner::new();
        let findings = scanner.scan(&context).unwrap();

        assert!(findings.iter().any(|f| f.scanner_id == "source-integer-overflow-accumulation-loop"));
    }
}
