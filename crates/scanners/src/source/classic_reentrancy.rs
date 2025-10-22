
use crate::core::{Scanner, Finding, Severity, Confidence, AnalysisContext};
use crate::core::result::Location;
use anyhow::Result;
use tree_sitter::{Node, TreeCursor};

pub struct SourceClassicReentrancyScanner;

impl SourceClassicReentrancyScanner {
    pub fn new() -> Self {
        Self
    }

    fn is_external_call_text(&self, text: &str) -> bool {
        text.contains(".call(") ||
        text.contains(".call{") ||
        text.contains(".send(") ||
        text.contains(".transfer(") ||
        text.contains(".delegatecall(")
    }

    fn is_state_modification_text(&self, text: &str) -> bool {
        if text.trim_start().starts_with("uint ") ||
           text.trim_start().starts_with("address ") ||
           text.trim_start().starts_with("bool ") ||
           text.trim_start().starts_with("bytes") ||
           text.trim_start().starts_with("string ") ||
           text.trim_start().starts_with("int ") {
            return false;
        }

        if text.contains('=') && !text.contains("==") && !text.contains("!=") && !text.contains("=>") {
            let parts: Vec<&str> = text.split('=').collect();
            if parts.is_empty() {
                return false;
            }

            let left = parts[0].trim();

            if left.contains('[') && left.contains(']') {
                return true;
            }

            if left.contains('.') &&
               !left.starts_with("msg.") &&
               !left.starts_with("block.") &&
               !left.starts_with("tx.") {
                return true;
            }

            if !left.contains('.') && !left.contains('[') && !left.contains('(') {
                if left.chars().next().map(|c| c.is_lowercase()).unwrap_or(false) {
                    return true;
                }
            }
        }
        false
    }

    fn collect_statements<'a>(&self, function_body: Node<'a>, statements: &mut Vec<Node<'a>>) {
        let mut cursor = function_body.walk();

        if cursor.goto_first_child() {
            loop {
                let node = cursor.node();

                if node.kind() == "statement" {
                    statements.push(node);
                }

                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
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
            "unknown"
        };


        let body = match function_node.child_by_field_name("body") {
            Some(b) => b,
            None => {
                return findings;
            }
        };

        let mut statements = Vec::new();
        self.collect_statements(body, &mut statements);

        let mut external_call_indices = Vec::new();
        let mut state_mod_indices = Vec::new();

        for (idx, stmt) in statements.iter().enumerate() {
            let stmt_text = stmt.utf8_text(source.as_bytes()).unwrap_or("");

            if self.is_external_call_text(stmt_text) {
                external_call_indices.push((idx, *stmt, stmt_text));
            }

            if self.is_state_modification_text(stmt_text) {
                state_mod_indices.push((idx, *stmt, stmt_text));
            }
        }

        for (call_idx, call_node, call_text) in &external_call_indices {
            for (mod_idx, mod_node, mod_text) in &state_mod_indices {
                if mod_idx > call_idx {
                    let call_line = call_node.start_position().row + 1;
                    let mod_line = mod_node.start_position().row + 1;

                    let call_snippet = call_text.lines().next().unwrap_or(call_text).trim();
                    let mod_snippet = mod_text.lines().next().unwrap_or(mod_text).trim();

                    let finding = Finding::new(
                        "classic-reentrancy".to_string(),
                        Severity::High,
                        Confidence::High,
                        format!("Classic reentrancy in '{}'", function_name),
                        format!(
                            "Function '{}' in contract '{}' makes an external call at line {} and then modifies state at line {}. \
                             This is the classic reentrancy pattern that enabled attacks like The DAO exploit ($60M). \
                             The external call transfers control to untrusted code, which can reenter before state is finalized.\n\n\
                             External call: {}\n\
                             State modification: {}\n\n\
                             Recommendation: Follow the Checks-Effects-Interactions pattern - perform all state changes BEFORE external calls.",
                            function_name,
                            contract_name,
                            call_line,
                            mod_line,
                            call_snippet,
                            mod_snippet
                        ),
                    )
                    .with_location(Location {
                        file: file_path.to_string(),
                        line: call_line,
                        column: call_node.start_position().column + 1,
                        end_line: Some(call_line),
                        end_column: Some(call_node.end_position().column + 1),
                        snippet: Some(call_snippet.to_string()),
                        ir_position: None,
                    })
                    .with_contract(contract_name)
                    .with_function(function_name);

                    findings.push(finding);
                }
            }
        }

        findings
    }
}

impl Scanner for SourceClassicReentrancyScanner {
    fn id(&self) -> &'static str {
        "classic-reentrancy"
    }

    fn name(&self) -> &'static str {
        "Classic Reentrancy Scanner"
    }

    fn description(&self) -> &'static str {
        "Detects classic reentrancy pattern (external call followed by state modification)"
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
            None => {
                return Ok(Vec::new());
            }
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

impl SourceClassicReentrancyScanner {
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
                name_node.utf8_text(source.as_bytes()).unwrap_or(contract_name)
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

impl Default for SourceClassicReentrancyScanner {
    fn default() -> Self {
        Self::new()
    }
}
