
use crate::core::{Scanner, Finding, Severity, Confidence, AnalysisContext};
use crate::core::result::Location;
use anyhow::Result;
use tree_sitter::Node;

pub struct SourceDelegatecallScanner;

impl SourceDelegatecallScanner {
    pub fn new() -> Self {
        Self
    }

    fn is_immutable_or_constant(&self, var_name: &str, source: &str) -> bool {
        source.contains(&format!("immutable {}", var_name)) ||
        source.contains(&format!("{} immutable", var_name)) ||
        source.contains(&format!("constant {}", var_name)) ||
        source.contains(&format!("{} constant", var_name))
    }

    fn extract_delegatecall_target<'a>(&self, expr_text: &'a str) -> Option<&'a str> {
        if let Some(delegatecall_pos) = expr_text.find(".delegatecall(") {
            let before = &expr_text[..delegatecall_pos];
            let target = before.trim().split_whitespace().last()?;
            Some(target)
        } else {
            None
        }
    }

    fn is_function_parameter(&self, target: &str, function_node: Node, source: &str) -> bool {
        if let Some(params_node) = function_node.child_by_field_name("parameters") {
            let params_text = params_node.utf8_text(source.as_bytes()).unwrap_or("");
            params_text.contains(target)
        } else {
            false
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
            return findings;
        };

        let body = match function_node.child_by_field_name("body") {
            Some(b) => b,
            None => return findings,
        };

        let body_text = body.utf8_text(source.as_bytes()).unwrap_or("");

        if !body_text.contains("delegatecall(") {
            return findings;
        }

        for (line_idx, line) in body_text.lines().enumerate() {
            if line.contains("delegatecall(") {
                if let Some(target) = self.extract_delegatecall_target(line) {
                    let (severity, vuln_type, risk_level, recommendation) =
                        if self.is_function_parameter(target, function_node, source) {
                            (Severity::Critical,
                             "delegatecall-to-user-controlled",
                             "CRITICAL - User can execute arbitrary code",
                             "Remove user control over delegatecall target. Use a whitelist of approved addresses or make the target immutable.")
                        } else if self.is_immutable_or_constant(target, source) {
                            continue; // Don't report safe patterns
                        } else {
                            (Severity::High,
                             "delegatecall-to-mutable",
                             "HIGH - State variable can be changed",
                             "Make the delegatecall target immutable if using proxy pattern, or add strict access control for changing it.")
                        };

                    let actual_line = body.start_position().row + 1 + line_idx;

                    let finding = Finding::new(
                        vuln_type.to_string(),
                        severity,
                        Confidence::High,
                        format!("Unsafe delegatecall in '{}'", function_name),
                        format!(
                            "Function '{}' in contract '{}' uses delegatecall with target '{}'. \
                             Risk Level: {}\n\n\
                             Delegatecall executes code in the caller's context, allowing the called contract to:\n\
                             - Modify all storage variables\n\
                             - Change the contract owner\n\
                             - Drain funds\n\
                             - Destroy the contract via selfdestruct\n\n\
                             Target: {}\n\
                             Line: {}\n\n\
                             Recommendation: {}",
                            function_name,
                            contract_name,
                            target,
                            risk_level,
                            target,
                            line.trim(),
                            recommendation
                        ),
                    )
                    .with_location(Location {
                        file: file_path.to_string(),
                        line: actual_line,
                        column: 1,
                        end_line: Some(actual_line),
                        end_column: None,
                        snippet: Some(line.trim().to_string()),
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

impl Scanner for SourceDelegatecallScanner {
    fn id(&self) -> &'static str {
        "source-delegatecall"
    }

    fn name(&self) -> &'static str {
        "Source Delegatecall Scanner"
    }

    fn description(&self) -> &'static str {
        "Detects unsafe delegatecall patterns with controllable targets"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
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

impl SourceDelegatecallScanner {
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

impl Default for SourceDelegatecallScanner {
    fn default() -> Self {
        Self::new()
    }
}
