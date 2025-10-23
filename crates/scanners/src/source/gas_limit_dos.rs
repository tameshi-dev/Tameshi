use crate::core::result::Location;
use crate::core::{AnalysisContext, Confidence, Finding, Scanner, Severity};
use anyhow::Result;
use tree_sitter::{Node, TreeCursor};

pub struct SourceGasLimitDoSScanner;

impl SourceGasLimitDoSScanner {
    pub fn new() -> Self {
        Self
    }

    fn is_unbounded_loop(&self, for_node: Node, source: &str) -> Option<String> {
        let condition = for_node.child_by_field_name("condition")?;
        let condition_text = condition.utf8_text(source.as_bytes()).unwrap_or("");

        if condition_text.contains(".length") {
            if let Some(start) = condition_text.rfind(' ') {
                let array_part = &condition_text[start + 1..];
                if let Some(dot_pos) = array_part.find('.') {
                    return Some(array_part[..dot_pos].to_string());
                }
            }
        }

        None
    }

    fn has_expensive_operations(&self, body_text: &str) -> bool {
        let has_storage_ops = body_text.contains("+=")
            || body_text.contains("-=")
            || body_text.contains(" = ")
            || body_text.contains("push(")
            || body_text.contains("delete ");

        let has_external_calls = body_text.contains(".transfer(")
            || body_text.contains(".send(")
            || body_text.contains(".call{")
            || body_text.contains(".call(");

        has_storage_ops || has_external_calls
    }

    fn is_dynamic_array(&self, array_name: &str, function_node: Node, source: &str) -> bool {
        let func_text = function_node.utf8_text(source.as_bytes()).unwrap_or("");
        if func_text.contains(&format!("[] memory {}", array_name))
            || func_text.contains(&format!("[] calldata {}", array_name))
        {
            return true;
        }

        let dynamic_names = [
            "participants",
            "recipients",
            "addresses",
            "users",
            "investors",
            "voters",
        ];
        dynamic_names.contains(&array_name)
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

        let mut cursor = body.walk();
        self.find_for_loops(
            &mut cursor,
            source,
            function_node,
            function_name,
            contract_name,
            file_path,
            &mut findings,
        );

        findings
    }

    fn find_for_loops(
        &self,
        cursor: &mut TreeCursor,
        source: &str,
        function_node: Node,
        function_name: &str,
        contract_name: &str,
        file_path: &str,
        findings: &mut Vec<Finding>,
    ) {
        let node = cursor.node();

        if node.kind() == "for_statement" {
            if let Some(array_name) = self.is_unbounded_loop(node, source) {
                if self.is_dynamic_array(&array_name, function_node, source) {
                    if let Some(body_node) = node.child_by_field_name("body") {
                        let body_text = body_node.utf8_text(source.as_bytes()).unwrap_or("");

                        if self.has_expensive_operations(body_text) {
                            let line = node.start_position().row + 1;

                            let (severity, vuln_type, extra_desc) = if body_text
                                .contains(".transfer(")
                                || body_text.contains(".call{")
                            {
                                (Severity::Critical,
                                 "gas-limit-dos-external-call",
                                 "with external calls in the loop. This is extremely dangerous as each call consumes significant gas")
                            } else if body_text.contains("delete ") {
                                (Severity::High,
                                 "gas-limit-dos-delete",
                                 "that deletes array elements. Large arrays can cause transaction to fail")
                            } else {
                                (Severity::High,
                                 "gas-limit-dos",
                                 "with storage operations. Large arrays can exceed block gas limit")
                            };

                            let finding = Finding::new(
                                vuln_type.to_string(),
                                severity,
                                Confidence::High,
                                format!("Gas limit DoS in '{}'", function_name),
                                format!(
                                    "Function '{}' in contract '{}' contains an unbounded loop over '{}' {}. \
                                     If the array grows too large, the function will fail due to block gas limit. \
                                     This can be used by attackers to make the function permanently unusable (DoS).\n\n\
                                     Array: {}\n\
                                     Loop: {}\n\n\
                                     Recommendation: \
                                     1. Implement pagination (process fixed number of elements per transaction)\n\
                                     2. Use pull-over-push pattern for distributions\n\
                                     3. Set maximum array size limits",
                                    function_name,
                                    contract_name,
                                    array_name,
                                    extra_desc,
                                    array_name,
                                    node.utf8_text(source.as_bytes()).unwrap_or("").lines().next().unwrap_or("")
                                ),
                            )
                            .with_location(Location {
                                file: file_path.to_string(),
                                line,
                                column: node.start_position().column + 1,
                                end_line: Some(line),
                                end_column: Some(node.end_position().column + 1),
                                snippet: Some(format!("for (... < {}.length ...)", array_name)),
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

        if cursor.goto_first_child() {
            loop {
                self.find_for_loops(
                    cursor,
                    source,
                    function_node,
                    function_name,
                    contract_name,
                    file_path,
                    findings,
                );
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
            cursor.goto_parent();
        }
    }
}

impl Scanner for SourceGasLimitDoSScanner {
    fn id(&self) -> &'static str {
        "source-gas-limit-dos"
    }

    fn name(&self) -> &'static str {
        "Source Gas Limit DoS Scanner"
    }

    fn description(&self) -> &'static str {
        "Detects unbounded loops that could exceed block gas limit"
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

        let mut parser = tree_sitter::Parser::new();
        let language = tree_sitter_solidity::LANGUAGE.into();
        parser
            .set_language(&language)
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

impl SourceGasLimitDoSScanner {
    fn visit_node(
        &self,
        cursor: &mut TreeCursor,
        source: &str,
        contract_name: &str,
        file_path: &str,
        findings: &mut Vec<Finding>,
    ) {
        let node = cursor.node();
        let kind = node.kind();

        if kind == "contract_declaration" {
            let current_contract = if let Some(name_node) = node.child_by_field_name("name") {
                name_node
                    .utf8_text(source.as_bytes())
                    .unwrap_or(contract_name)
            } else {
                contract_name
            };

            let mut func_cursor = node.walk();
            if func_cursor.goto_first_child() {
                loop {
                    let child_kind = func_cursor.node().kind();

                    if child_kind == "contract_body" {
                        let mut body_cursor = func_cursor.node().walk();
                        if body_cursor.goto_first_child() {
                            loop {
                                let body_child_kind = body_cursor.node().kind();

                                if body_child_kind == "function_definition" {
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

impl Default for SourceGasLimitDoSScanner {
    fn default() -> Self {
        Self::new()
    }
}
