use crate::core::result::Location;
use crate::core::{AnalysisContext, Confidence, Finding, Scanner, Severity};
use anyhow::Result;
use tree_sitter::{Node, TreeCursor};

pub struct SourceMissingAccessControlScanner;

impl SourceMissingAccessControlScanner {
    pub fn new() -> Self {
        Self
    }

    fn has_sensitive_operation(&self, text: &str) -> bool {
        text.contains(".transfer(")
            || text.contains(".send(")
            || text.contains(".call{value:")
            || text.contains("selfdestruct(")
            || text.contains("delegatecall(")
            || (text.contains("owner =") && !text.contains("owner =="))
            || (text.contains("admin =") && !text.contains("admin =="))
            || text.contains("_mint(")
            || text.contains("_burn(")
            || text.contains("totalSupply =")
            || text.contains("totalSupply +=")
            || text.contains("totalSupply -=")
    }

    fn has_access_control(&self, text: &str) -> bool {
        let mut cleaned_text = String::new();
        for line in text.lines() {
            if let Some(idx) = line.find("//") {
                cleaned_text.push_str(&line[..idx]);
            } else {
                cleaned_text.push_str(line);
            }
            cleaned_text.push('\n');
        }

        let text = &cleaned_text;

        (text.contains("require") && text.contains("msg.sender") && text.contains("owner"))
            || (text.contains("require") && text.contains("msg.sender") && text.contains("admin"))
            || (text.contains("revert") && text.contains("owner"))
            || (text.contains("revert") && text.contains("admin"))
            || (text.contains("revert") && text.contains("authorized"))
            || (text.contains("assert") && text.contains("msg.sender") && text.contains("owner"))
            || text.contains("OnlyOwner()")
            || text.contains("Unauthorized()")
            || text.contains("NotOwner()")
    }

    fn has_access_control_modifier(&self, function_node: Node, source: &str) -> bool {
        let func_text = function_node.utf8_text(source.as_bytes()).unwrap_or("");

        func_text.contains("onlyOwner")
            || func_text.contains("onlyAdmin")
            || func_text.contains("onlyRole")
            || func_text.contains("onlyGovernance")
            || func_text.contains("onlyMinter")
            || func_text.contains("onlyPauser")
            || func_text.contains("onlyController")
            || func_text.contains("auth")
            || func_text.contains("restricted")
    }

    fn is_self_operation(&self, func_name: &str, func_body: &str) -> bool {
        let name_lower = func_name.to_lowercase();

        if name_lower.contains("deposit") {
            return true;
        }

        if name_lower.contains("withdraw") {
            if func_body.contains("balances[msg.sender]")
                || func_body.contains("deposits[msg.sender]")
                || func_body.contains("stakes[msg.sender]")
            {
                return true;
            }
            if func_body.contains("uint _amount") || func_body.contains("uint256 _amount") {
                return false; // This needs access control!
            }
        }

        false
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
        if func_text.contains(" view ") || func_text.contains(" pure ") {
            return findings;
        }

        if func_text.contains(" private") || func_text.contains(" internal") {
            return findings;
        }

        if self.has_access_control_modifier(function_node, source) {
            return findings;
        }

        let body = match function_node.child_by_field_name("body") {
            Some(b) => b,
            None => return findings,
        };

        let body_text = body.utf8_text(source.as_bytes()).unwrap_or("");

        if !self.has_sensitive_operation(body_text) {
            return findings;
        }

        if self.has_access_control(body_text) {
            return findings;
        }

        if self.is_self_operation(function_name, body_text) {
            return findings;
        }

        let (vuln_type, severity, description) = if body_text.contains(".transfer(")
            || body_text.contains(".send(")
            || body_text.contains(".call{value:")
        {
            (
                "unprotected-ether-withdrawal",
                Severity::High,
                format!("Unprotected ether withdrawal in '{}'", function_name),
            )
        } else if body_text.contains("owner =") || body_text.contains("admin =") {
            (
                "unprotected-ownership-change",
                Severity::Critical,
                format!("Unprotected ownership change in '{}'", function_name),
            )
        } else if body_text.contains("selfdestruct") {
            (
                "unprotected-selfdestruct",
                Severity::Critical,
                format!("Unprotected selfdestruct in '{}'", function_name),
            )
        } else {
            (
                "missing-access-control",
                Severity::Medium,
                format!("Missing access control in '{}'", function_name),
            )
        };

        let mut sensitive_line = function_node.start_position().row + 1;
        for line in body_text.lines() {
            if self.has_sensitive_operation(line) {
                break;
            }
            sensitive_line += 1;
        }

        let finding = Finding::new(
            vuln_type.to_string(),
            severity,
            Confidence::High,
            description.clone(),
            format!(
                "Function '{}' in contract '{}' performs sensitive operations without access control. \
                 Any user can call this function and potentially drain funds or take control of the contract. \
                 This is similar to the Parity wallet hack pattern.\n\n\
                 Missing check: require(msg.sender == owner) or onlyOwner modifier\n\n\
                 Recommendation: Add proper access control to restrict this function to authorized users only.",
                function_name,
                contract_name
            ),
        )
        .with_location(Location {
            file: file_path.to_string(),
            line: sensitive_line,
            column: 1,
            end_line: Some(sensitive_line),
            end_column: None,
            snippet: Some(body_text.lines().find(|l| self.has_sensitive_operation(l))
                         .unwrap_or("").trim().to_string()),
            ir_position: None,
        })
        .with_contract(contract_name)
        .with_function(function_name);

        findings.push(finding);
        findings
    }
}

impl Scanner for SourceMissingAccessControlScanner {
    fn id(&self) -> &'static str {
        "source-missing-access-control"
    }

    fn name(&self) -> &'static str {
        "Source Missing Access Control Scanner"
    }

    fn description(&self) -> &'static str {
        "Detects functions with sensitive operations lacking proper access control"
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

impl SourceMissingAccessControlScanner {
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

impl Default for SourceMissingAccessControlScanner {
    fn default() -> Self {
        Self::new()
    }
}
