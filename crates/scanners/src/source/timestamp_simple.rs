
use crate::core::{Scanner, Finding, Severity, Confidence, AnalysisContext};
use crate::core::result::Location;
use anyhow::Result;
use tree_sitter::Node;

pub struct SimpleTimestampScanner;

impl SimpleTimestampScanner {
    pub fn new() -> Self {
        Self
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

        let func_text = function_node.utf8_text(source.as_bytes()).unwrap_or("");
        let is_view_or_pure = func_text.contains(" view") || func_text.contains(" pure");

        let looks_like_predicate = function_name.starts_with("is") && function_name.len() > 2 &&
                                  function_name.chars().nth(2).is_some_and(|c| c.is_uppercase()) &&
                                  is_view_or_pure;

        let body = match function_node.child_by_field_name("body") {
            Some(b) => b,
            None => return findings,
        };

        let body_text = body.utf8_text(source.as_bytes()).unwrap_or("");

        if body_text.contains("block.timestamp") || body_text.contains("now") {
            let body_start_line = body.start_position().row;

            for (line_idx, line) in body_text.lines().enumerate() {
                let line_num = body_start_line + line_idx + 1;

                if !line.contains("block.timestamp") && !line.contains("now") {
                    continue;
                }

                let has_modulo = line.contains('%');
                let has_equality = line.contains("==") || line.contains("!=");
                let in_if = line.trim_start().starts_with("if ") || line.contains(" if ");
                let in_return = line.contains("return ");
                let has_keccak = line.contains("keccak256") || line.contains("sha256");

                let is_randomness_pattern = has_keccak || (has_modulo && in_if);

                let is_require = line.contains("require") || line.contains("revert");
                let has_comparison = line.contains(" > ") || line.contains(" >= ") ||
                                    line.contains(" < ") || line.contains(" <= ");

                let is_defensive_timelock = is_require && has_comparison;

                let is_anti_spam = is_require && has_equality &&
                                  (line.contains("last") || line.contains("prev"));

                let is_simple_assignment = line.contains('=') &&
                                          !has_equality &&
                                          !in_if &&
                                          !in_return &&
                                          !has_modulo;

                let is_defensive = is_defensive_timelock || is_anti_spam;

                if is_simple_assignment {
                    continue;
                }

                if has_modulo || has_equality || in_if || in_return {
                    let (severity, confidence) = if is_randomness_pattern {
                        (Severity::High, 0.9)
                    } else if is_defensive {
                        (Severity::Low, 0.4)
                    } else if has_modulo {
                        (Severity::High, 0.85)
                    } else if in_if || in_return {
                        (Severity::Medium, 0.7)
                    } else {
                        (Severity::Medium, 0.6)
                    };

                    if looks_like_predicate && !is_randomness_pattern && confidence < 0.7 {
                        continue;
                    }

                    if is_view_or_pure && confidence < 0.6 {
                        continue;
                    }

                    let confidence_level = if confidence >= 0.8 {
                        Confidence::High
                    } else if confidence >= 0.6 {
                        Confidence::Medium
                    } else {
                        Confidence::Low
                    };

                    let description = if is_randomness_pattern {
                        format!(
                            "Function '{}' in contract '{}' uses block.timestamp for randomness generation at line {}. \
                            This is predictable and can be manipulated by miners within ~15 seconds.\n\n\
                            Vulnerable code: {}\n\n\
                            Recommendation: Use Chainlink VRF for secure randomness.",
                            function_name, contract_name, line_num, line.trim()
                        )
                    } else if is_defensive {
                        format!(
                            "Function '{}' in contract '{}' uses block.timestamp in a defensive pattern at line {}. \
                            While this appears to be for access control or rate limiting, verify it doesn't affect critical logic.\n\n\
                            Code: {}\n\n\
                            Note: This is likely a safe pattern but flagged for review.",
                            function_name, contract_name, line_num, line.trim()
                        )
                    } else if has_modulo {
                        format!(
                            "Function '{}' in contract '{}' uses block.timestamp with modulo operation at line {}. \
                            This is commonly used for randomness, which is predictable and manipulable.\n\n\
                            Vulnerable code: {}\n\n\
                            Recommendation: Use Chainlink VRF or commit-reveal schemes.",
                            function_name, contract_name, line_num, line.trim()
                        )
                    } else {
                        format!(
                            "Function '{}' in contract '{}' uses block.timestamp in conditional/comparison logic at line {}. \
                            Miners can manipulate timestamps within ~15 seconds.\n\n\
                            Vulnerable code: {}\n\n\
                            Recommendation: Use block.number for time-based logic when possible.",
                            function_name, contract_name, line_num, line.trim()
                        )
                    };

                    let mut finding = Finding::new(
                        self.id().to_string(),
                        severity,
                        confidence_level,
                        format!("Timestamp dependence in '{}'", function_name),
                        description,
                    )
                    .with_location(Location {
                        file: file_path.to_string(),
                        line: line_num,
                        column: 1,
                        end_line: Some(line_num),
                        end_column: None,
                        snippet: Some(line.trim().to_string()),
                        ir_position: None,
                    })
                    .with_contract(contract_name)
                    .with_function(function_name);

                    finding.confidence_score = confidence;

                    findings.push(finding);
                }
            }
        }

        findings
    }
}

impl Scanner for SimpleTimestampScanner {
    fn id(&self) -> &'static str {
        "simple-timestamp"
    }

    fn name(&self) -> &'static str {
        "Simple Timestamp Scanner"
    }

    fn description(&self) -> &'static str {
        "Detects dangerous timestamp usage using text pattern matching"
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

impl SimpleTimestampScanner {
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

impl Default for SimpleTimestampScanner {
    fn default() -> Self {
        Self::new()
    }
}
