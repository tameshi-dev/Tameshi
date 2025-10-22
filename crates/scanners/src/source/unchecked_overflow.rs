
use crate::core::{Scanner, Finding, Severity, Confidence, AnalysisContext};
use crate::core::result::Location;
use anyhow::Result;
use tree_sitter::Node;

pub struct SourceUncheckedOverflowScanner;

impl SourceUncheckedOverflowScanner {
    pub fn new() -> Self {
        Self
    }

    fn has_arithmetic_ops(&self, text: &str) -> bool {
        text.contains("+=") ||
        text.contains("-=") ||
        text.contains("*=") ||
        text.contains("/=") ||
        text.contains(" + ") ||
        text.contains(" - ") ||
        text.contains(" * ") ||
        text.contains(" / ")
    }

    fn analyze_function<'a>(
        &self,
        function_node: Node<'a>,
        source: &str,
        contract_name: &str,
        file_path: &str,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let function_name = if let Some(name_node) = function_node.child_by_field_name("name") {
            name_node.utf8_text(source.as_bytes()).unwrap_or("unknown")
        } else {
            return findings;
        };

        let body = match function_node.child_by_field_name("body") {
            Some(b) => b,
            None => return findings,
        };

        let body_text = body.utf8_text(source.as_bytes()).unwrap_or("");

        if body_text.contains("unchecked") && body_text.contains("{") {
            if let Some(unchecked_start) = body_text.find("unchecked") {
                let after_unchecked = &body_text[unchecked_start..];
                if let Some(brace_start) = after_unchecked.find("{") {
                    let mut brace_count = 0;
                    let mut brace_end = None;
                    let block_start = unchecked_start + brace_start;

                    for (i, ch) in after_unchecked[brace_start..].char_indices() {
                        if ch == '{' {
                            brace_count += 1;
                        } else if ch == '}' {
                            brace_count -= 1;
                            if brace_count == 0 {
                                brace_end = Some(block_start + i + 1);
                                break;
                            }
                        }
                    }

                    if let Some(end) = brace_end {
                        let unchecked_block = &body_text[unchecked_start..end];

                        if self.has_arithmetic_ops(unchecked_block) {
                            let line_offset = body_text[..unchecked_start].matches('\n').count();
                            let line = body.start_position().row + 1 + line_offset;

                            let mut operations = Vec::new();
                            for line_text in unchecked_block.lines() {
                                if self.has_arithmetic_ops(line_text) {
                                    operations.push(line_text.trim().to_string());
                                }
                            }

                            if !operations.is_empty() {
                                let finding = Finding::new(
                                    "unchecked-arithmetic".to_string(),
                                    Severity::High,
                                    Confidence::High,
                                    format!("Unchecked arithmetic in '{}'", function_name),
                                    format!(
                                        "Function '{}' in contract '{}' contains unchecked arithmetic operations that can overflow/underflow. \
                                         In Solidity 0.8.0+, arithmetic is checked by default, but `unchecked` blocks disable this protection.\n\n\
                                         Operations in unchecked block:\n{}\n\n\
                                         Recommendation: \
                                         1. Only use `unchecked` when overflow/underflow is impossible or intentional\n\
                                         2. Add explicit bounds checking before arithmetic operations\n\
                                         3. Consider if gas savings justify the risk",
                                        function_name,
                                        contract_name,
                                        operations.join("\n")
                                    ),
                                )
                                .with_location(Location {
                                    file: file_path.to_string(),
                                    line,
                                    column: 1,
                                    end_line: Some(line + unchecked_block.matches('\n').count()),
                                    end_column: None,
                                    snippet: Some("unchecked { ... }".to_string()),
                                    ir_position: None,
                                })
                                .with_contract(contract_name)
                                .with_function(function_name);

                                findings.push(finding);
                            }
                        }
                    }
                }
            }
        }

        findings
    }

}

impl Scanner for SourceUncheckedOverflowScanner {
    fn id(&self) -> &'static str {
        "source-unchecked-overflow"
    }

    fn name(&self) -> &'static str {
        "Source Unchecked Overflow Scanner"
    }

    fn description(&self) -> &'static str {
        "Detects arithmetic operations in unchecked blocks that can overflow"
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
        let file_path = contract_info.source_path
            .as_deref()
            .unwrap_or("unknown.sol");

        let mut parser = tree_sitter::Parser::new();
        let language = tree_sitter_solidity::LANGUAGE.into();
        parser.set_language(&language)
            .expect("Failed to load Solidity grammar");

        let tree = match parser.parse(source, None) {
            Some(t) => t,
            None => return Ok(Vec::new()),
        };

        let root = tree.root_node();
        let mut findings = Vec::new();

        let mut cursor = root.walk();
        self.visit_node(&mut cursor, source, contract_name, file_path, &mut findings);

        Ok(findings)
    }

    fn required_representations(&self) -> crate::representations::RepresentationSet {
        crate::representations::RepresentationSet::new()
    }
}

impl SourceUncheckedOverflowScanner {
    fn visit_node(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &str,
        contract_name: &str,
        file_path: &str,
        findings: &mut Vec<Finding>,
    ) {
        let node = cursor.node();
        let kind = node.kind();

        if kind == "contract_declaration" {
            let current_contract = if let Some(name_node) = node.child_by_field_name("name") {
                name_node.utf8_text(source.as_bytes()).unwrap_or(contract_name)
            } else {
                contract_name
            };

            let mut func_cursor = node.walk();
            if func_cursor.goto_first_child() {
                loop {
                    if func_cursor.node().kind() == "contract_body" {
                        let mut body_cursor = func_cursor.node().walk();
                        if body_cursor.goto_first_child() {
                            loop {
                                if body_cursor.node().kind() == "function_definition" {
                                    let function_findings = self.analyze_function(
                                        body_cursor.node(),
                                        source,
                                        current_contract,
                                        file_path,
                                    );
                                    findings.extend(function_findings);
                                }

                                if !body_cursor.goto_next_sibling() {
                                    break;
                                }
                            }
                        }
                    }

                    if !func_cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
            return;
        }

        if cursor.goto_first_child() {
            loop {
                self.visit_node(cursor, source, contract_name, file_path, findings);
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
            cursor.goto_parent();
        }
    }
}

impl Default for SourceUncheckedOverflowScanner {
    fn default() -> Self {
        Self::new()
    }
}
