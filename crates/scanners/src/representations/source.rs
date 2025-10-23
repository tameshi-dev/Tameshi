//! Source-Level Representations extracted from tree-sitter AST
//!
//! This module provides structured representations of Solidity source code
//! by querying the tree-sitter AST using declarative S-expression queries.
//! These representations are used by source-level scanners to detect
//! vulnerabilities that are lost during IR transformation.
//!
//! This implementation follows the traverse crate's query-based approach
//! instead of imperative cursor-based traversal.

use anyhow::Result;
use std::collections::HashMap;
use streaming_iterator::StreamingIterator;
use tree_sitter::{Node, Parser, Query, QueryCursor};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLocation {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

impl SourceLocation {
    pub fn from_node(file: &str, node: &Node) -> Self {
        let start = node.start_position();
        let end = node.end_position();
        Self {
            file: file.to_string(),
            line: start.row + 1,
            column: start.column,
            end_line: end.row + 1,
            end_column: end.column,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub location: SourceLocation,
    pub modifiers: Vec<String>,
    pub visibility: String,
    pub state_mutability: String,
    pub parameters: Vec<Parameter>,
    pub returns: Vec<Parameter>,
    pub body: String,
}

#[derive(Debug, Clone)]
pub struct Parameter {
    pub name: String,
    pub type_name: String,
}

#[derive(Debug, Clone)]
pub struct LoopInfo {
    pub location: SourceLocation,
    pub loop_type: LoopType,
    pub condition: String,
    pub body: String,
    pub contains_external_calls: bool,
    pub contains_storage_writes: bool,
    pub iterates_over_length: bool,
    pub function_name: String, // Which function this loop belongs to
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoopType {
    For,
    While,
    DoWhile,
}

#[derive(Debug, Clone)]
pub struct ExternalCallInfo {
    pub location: SourceLocation,
    pub call_type: ExternalCallType,
    pub target: String,
    pub is_checked: bool,
    pub in_loop: bool,
}

#[derive(Debug, Clone)]
pub struct AssignmentInfo {
    pub location: SourceLocation,
    pub left_side: String,
    pub right_side: String,
    pub function_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalCallType {
    Call,
    DelegateCall,
    StaticCall,
    Transfer,
    Send,
    ERC20Transfer,
    ERC20TransferFrom,
}

#[derive(Debug, Clone)]
pub struct SourceRepresentation {
    pub source: String,
    pub file_path: String,
    pub contract_name: String,
    pub functions: HashMap<String, FunctionInfo>,
    pub loops: Vec<LoopInfo>,
    pub external_calls: Vec<ExternalCallInfo>,
    pub assignments: Vec<AssignmentInfo>,
    pub modifiers: HashMap<String, ModifierInfo>,
}

#[derive(Debug, Clone)]
pub struct ModifierInfo {
    pub name: String,
    pub location: SourceLocation,
    pub body: String,
    pub is_access_control: bool,
}

impl SourceRepresentation {
    pub fn from_source(source: &str, file_path: &str, contract_name: &str) -> Result<Self> {
        let mut parser = Parser::new();
        let language = tree_sitter_solidity::LANGUAGE.into();
        parser.set_language(&language)?;

        let tree = parser
            .parse(source, None)
            .ok_or_else(|| anyhow::anyhow!("Failed to parse source"))?;

        let root = tree.root_node();

        let mut extractor = SourceExtractor {
            source,
            file_path,
            contract_name,
            language,
            functions: HashMap::new(),
            loops: Vec::new(),
            external_calls: Vec::new(),
            assignments: Vec::new(),
            modifiers: HashMap::new(),
            current_function_name: None,
        };

        extractor.extract(&root)?;

        Ok(SourceRepresentation {
            source: source.to_string(),
            file_path: file_path.to_string(),
            contract_name: contract_name.to_string(),
            functions: extractor.functions,
            loops: extractor.loops,
            external_calls: extractor.external_calls,
            assignments: extractor.assignments,
            modifiers: extractor.modifiers,
        })
    }

    pub fn functions_with_modifier(&self, modifier_name: &str) -> Vec<&FunctionInfo> {
        self.functions
            .values()
            .filter(|f| f.modifiers.iter().any(|m| m == modifier_name))
            .collect()
    }

    pub fn loops_with_external_calls(&self) -> Vec<&LoopInfo> {
        self.loops
            .iter()
            .filter(|l| l.contains_external_calls)
            .collect()
    }

    pub fn unchecked_external_calls(&self) -> Vec<&ExternalCallInfo> {
        self.external_calls
            .iter()
            .filter(|c| !c.is_checked)
            .collect()
    }

    pub fn has_assignments_after_loop(&self, loop_info: &LoopInfo) -> bool {
        self.assignments.iter().any(|a| {
            a.function_name == loop_info.function_name
                && a.location.line > loop_info.location.end_line
        })
    }
}

const FUNCTION_QUERY: &str = r#"
(function_definition
  name: (identifier)? @func_name
  body: (function_body)? @func_body
) @function
"#;

const MODIFIER_QUERY: &str = r#"
(modifier_definition
  name: (identifier) @mod_name
  body: (_)? @mod_body
) @modifier
"#;

const LOOP_QUERY: &str = r#"
[
  (for_statement) @loop
  (while_statement) @loop
  (do_while_statement) @loop
]
"#;

const EXTERNAL_CALL_QUERY: &str = r#"
(call_expression) @call
"#;

const ASSIGNMENT_QUERY: &str = r#"
(assignment_expression
  left: (_) @left
  right: (_) @right
) @assignment
"#;

struct SourceExtractor<'a> {
    source: &'a str,
    file_path: &'a str,
    contract_name: &'a str,
    language: tree_sitter::Language,
    functions: HashMap<String, FunctionInfo>,
    loops: Vec<LoopInfo>,
    external_calls: Vec<ExternalCallInfo>,
    assignments: Vec<AssignmentInfo>,
    modifiers: HashMap<String, ModifierInfo>,
    current_function_name: Option<String>, // Track current function context
}

impl<'a> SourceExtractor<'a> {
    fn extract(&mut self, root: &Node) -> Result<()> {
        let contract_range = {
            let mut cursor = root.walk();
            let mut found_range = None;
            for child in root.children(&mut cursor) {
                if matches!(
                    child.kind(),
                    "contract_declaration" | "library_declaration" | "interface_declaration"
                ) {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = &self.source[name_node.byte_range()];
                        if name == self.contract_name {
                            found_range = Some(child.byte_range());
                            break;
                        }
                    }
                }
            }
            found_range
                .ok_or_else(|| anyhow::anyhow!("Contract {} not found", self.contract_name))?
        };

        let mut cursor = root.walk();
        for child in root.children(&mut cursor) {
            if child.byte_range() == contract_range {
                self.extract_modifiers_from_node(&child)?;

                self.extract_functions_from_node(&child)?;
                break;
            }
        }

        Ok(())
    }

    fn extract_modifiers_from_node(&mut self, contract: &Node) -> Result<()> {
        let query = Query::new(&self.language, MODIFIER_QUERY)?;
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, *contract, self.source.as_bytes());

        matches.advance();
        while let Some(match_) = matches.get() {
            let mut mod_name = None;
            let mut mod_body = None;
            let mut modifier_node = None;

            for capture in match_.captures {
                let capture_name = &query.capture_names()[capture.index as usize];
                match *capture_name {
                    "modifier" => modifier_node = Some(capture.node),
                    "mod_name" => mod_name = Some(capture.node),
                    "mod_body" => mod_body = Some(capture.node),
                    _ => {}
                }
            }

            if let (Some(modifier_node), Some(name_node)) = (modifier_node, mod_name) {
                let name = self.source[name_node.byte_range()].to_string();
                let body = mod_body
                    .map(|n| self.source[n.byte_range()].to_string())
                    .unwrap_or_default();

                let name_lower = name.to_lowercase();
                let is_access_control = name_lower.contains("only")
                    || name_lower.contains("auth")
                    || name_lower.contains("admin")
                    || name_lower.contains("owner")
                    || name_lower.contains("require");

                let modifier = ModifierInfo {
                    name: name.clone(),
                    location: SourceLocation::from_node(self.file_path, &modifier_node),
                    body,
                    is_access_control,
                };

                self.modifiers.insert(name, modifier);
            }
            matches.advance();
        }

        Ok(())
    }

    fn extract_functions_from_node(&mut self, contract: &Node) -> Result<()> {
        let query = Query::new(&self.language, FUNCTION_QUERY)?;
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, *contract, self.source.as_bytes());

        matches.advance();
        while let Some(match_) = matches.get() {
            let mut func_node = None;
            let mut func_name = None;
            let mut func_body = None;

            for capture in match_.captures {
                let capture_name = &query.capture_names()[capture.index as usize];
                match *capture_name {
                    "function" => func_node = Some(capture.node),
                    "func_name" => func_name = Some(capture.node),
                    "func_body" => func_body = Some(capture.node),
                    _ => {}
                }
            }

            if let Some(function_node) = func_node {
                let name = func_name
                    .map(|n| self.source[n.byte_range()].to_string())
                    .unwrap_or_else(|| "fallback".to_string());

                let body_text = func_body
                    .map(|n| self.source[n.byte_range()].to_string())
                    .unwrap_or_default();

                let modifiers = self.extract_modifiers_from_function(&function_node);

                let visibility = self.extract_visibility(&function_node);
                let state_mutability = self.extract_state_mutability(&function_node);

                let parameters =
                    self.extract_parameters_from_function(&function_node, "parameters")?;
                let returns =
                    self.extract_parameters_from_function(&function_node, "return_parameters")?;

                self.current_function_name = Some(name.clone());

                if let Some(body_node) = func_body {
                    self.extract_loops_from_node(&body_node)?;
                    self.extract_external_calls_from_node(&body_node, false)?;
                    self.extract_assignments_from_node(&body_node)?;
                }

                self.current_function_name = None;

                let func_info = FunctionInfo {
                    name: name.clone(),
                    location: SourceLocation::from_node(self.file_path, &function_node),
                    modifiers,
                    visibility,
                    state_mutability,
                    parameters,
                    returns,
                    body: body_text,
                };

                self.functions.insert(name, func_info);
            }
            matches.advance();
        }

        Ok(())
    }

    fn extract_modifiers_from_function(&self, function_node: &Node) -> Vec<String> {
        let mut modifiers = Vec::new();
        let mut cursor = function_node.walk();

        #[cfg(test)]
        {
            eprintln!("Extracting modifiers from function, children:");
            for child in function_node.children(&mut cursor) {
                eprintln!("  {} (named: {})", child.kind(), child.is_named());
            }
            cursor = function_node.walk();
        }

        for child in function_node.children(&mut cursor) {
            if child.kind() == "modifier_invocation" {
                let mut mod_cursor = child.walk();
                for mod_child in child.children(&mut mod_cursor) {
                    if mod_child.kind() == "identifier" && mod_child.is_named() {
                        let modifier_name = self.source[mod_child.byte_range()].to_string();
                        modifiers.push(modifier_name);
                        break; // Only get the first identifier (the modifier name)
                    }
                }
            }
        }
        modifiers
    }

    fn extract_parameters_from_function(
        &self,
        function_node: &Node,
        field_name: &str,
    ) -> Result<Vec<Parameter>> {
        let mut params = Vec::new();
        if let Some(params_node) = function_node.child_by_field_name(field_name) {
            let mut cursor = params_node.walk();
            for child in params_node.children(&mut cursor) {
                if child.kind() == "parameter" {
                    let type_name = child
                        .child_by_field_name("type")
                        .map(|n| self.source[n.byte_range()].to_string())
                        .unwrap_or_default();

                    let name = child
                        .child_by_field_name("name")
                        .map(|n| self.source[n.byte_range()].to_string())
                        .unwrap_or_default();

                    params.push(Parameter { name, type_name });
                }
            }
        }
        Ok(params)
    }

    fn extract_visibility(&self, node: &Node) -> String {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if matches!(child.kind(), "public" | "private" | "internal" | "external") {
                return self.source[child.byte_range()].to_string();
            }

            if child.kind() == "visibility" {
                return self.source[child.byte_range()].to_string();
            }
        }
        "internal".to_string()
    }

    fn extract_state_mutability(&self, node: &Node) -> String {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if matches!(child.kind(), "pure" | "view" | "payable") {
                return self.source[child.byte_range()].to_string();
            }
        }
        "".to_string()
    }

    fn extract_loops_from_node(&mut self, node: &Node) -> Result<()> {
        let query = Query::new(&self.language, LOOP_QUERY)?;
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, *node, self.source.as_bytes());

        matches.advance();
        while let Some(match_) = matches.get() {
            let mut loop_node = None;

            for capture in match_.captures {
                let capture_name = &query.capture_names()[capture.index as usize];
                if *capture_name == "loop" {
                    loop_node = Some(capture.node);
                }
            }

            if let Some(loop_node) = loop_node {
                let loop_type = match loop_node.kind() {
                    "for_statement" => LoopType::For,
                    "while_statement" => LoopType::While,
                    "do_while_statement" => LoopType::DoWhile,
                    _ => continue,
                };

                let condition = loop_node
                    .child_by_field_name("condition")
                    .map(|n| self.source[n.byte_range()].to_string())
                    .unwrap_or_default();

                let body = loop_node
                    .child_by_field_name("body")
                    .map(|n| self.source[n.byte_range()].to_string())
                    .unwrap_or_default();

                let contains_external_calls = self.contains_external_call(&loop_node);
                let contains_storage_writes = self.contains_storage_write(&loop_node);
                let iterates_over_length =
                    condition.contains(".length") || body.contains(".length");

                #[cfg(test)]
                eprintln!(
                    "Loop at line {}: external_calls={}, storage_writes={}, length={}",
                    loop_node.start_position().row + 1,
                    contains_external_calls,
                    contains_storage_writes,
                    iterates_over_length
                );

                let loop_info = LoopInfo {
                    location: SourceLocation::from_node(self.file_path, &loop_node),
                    loop_type,
                    condition,
                    body,
                    contains_external_calls,
                    contains_storage_writes,
                    iterates_over_length,
                    function_name: self.current_function_name.clone().unwrap_or_default(),
                };

                self.loops.push(loop_info);
            }
            matches.advance();
        }

        Ok(())
    }

    fn extract_external_calls_from_node(&mut self, node: &Node, in_loop: bool) -> Result<()> {
        let query = Query::new(&self.language, EXTERNAL_CALL_QUERY)?;
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, *node, self.source.as_bytes());

        matches.advance();
        while let Some(match_) = matches.get() {
            let mut call_node = None;

            for capture in match_.captures {
                let capture_name = &query.capture_names()[capture.index as usize];
                if *capture_name == "call" {
                    call_node = Some(capture.node);
                }
            }

            if let Some(call_node) = call_node {
                if let Some(function_node) = call_node.child_by_field_name("function") {
                    let method_name = self.extract_method_name(&function_node);

                    if let Some(method_name) = method_name {
                        let arg_count = self.count_call_arguments(&call_node);

                        let call_type = match method_name.as_str() {
                            "call" => ExternalCallType::Call,
                            "delegatecall" => ExternalCallType::DelegateCall,
                            "staticcall" => ExternalCallType::StaticCall,
                            "transfer" => {
                                if arg_count == 2 {
                                    ExternalCallType::ERC20Transfer
                                } else {
                                    ExternalCallType::Transfer
                                }
                            }
                            "send" => ExternalCallType::Send,
                            "transferFrom" => ExternalCallType::ERC20TransferFrom,
                            _ => {
                                matches.advance();
                                continue; // Not an external call we care about
                            }
                        };

                        let call_text = self.source[call_node.byte_range()].to_string();

                        let is_checked = self.is_call_checked(&call_node)?;

                        let call_info = ExternalCallInfo {
                            location: SourceLocation::from_node(self.file_path, &call_node),
                            call_type,
                            target: call_text,
                            is_checked,
                            in_loop,
                        };

                        self.external_calls.push(call_info);
                    }
                }
            }
            matches.advance();
        }

        Ok(())
    }

    fn extract_assignments_from_node(&mut self, node: &Node) -> Result<()> {
        let query = Query::new(&self.language, ASSIGNMENT_QUERY)?;
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, *node, self.source.as_bytes());

        matches.advance();
        while let Some(match_) = matches.get() {
            let mut assignment_node = None;
            let mut left_node = None;
            let mut right_node = None;

            for capture in match_.captures {
                let capture_name = &query.capture_names()[capture.index as usize];
                match *capture_name {
                    "assignment" => assignment_node = Some(capture.node),
                    "left" => left_node = Some(capture.node),
                    "right" => right_node = Some(capture.node),
                    _ => {}
                }
            }

            if let (Some(assign_node), Some(left), Some(right)) =
                (assignment_node, left_node, right_node)
            {
                let left_text = self.source[left.byte_range()].to_string();
                let right_text = self.source[right.byte_range()].to_string();

                let actual_left = if left.kind() == "expression" {
                    left.child(0).unwrap_or(left)
                } else {
                    left
                };

                #[cfg(test)]
                eprintln!(
                    "  Found assignment: {} = {}, left kind: {}",
                    &left_text[..std::cmp::min(30, left_text.len())],
                    &right_text[..std::cmp::min(20, right_text.len())],
                    actual_left.kind()
                );

                let should_track = matches!(
                    actual_left.kind(),
                    "identifier" | "member_expression" | "index_expression" | "array_access"
                );

                if should_track {
                    let assignment_info = AssignmentInfo {
                        location: SourceLocation::from_node(self.file_path, &assign_node),
                        left_side: left_text,
                        right_side: right_text,
                        function_name: self.current_function_name.clone().unwrap_or_default(),
                    };

                    #[cfg(test)]
                    eprintln!(
                        "    Tracking assignment in function '{}' at line {}",
                        assignment_info.function_name, assignment_info.location.line
                    );

                    self.assignments.push(assignment_info);
                }
            }
            matches.advance();
        }

        Ok(())
    }

    fn is_call_checked(&self, call_node: &Node) -> Result<bool> {
        let mut current = call_node.parent();
        let mut levels_up = 0;

        while let Some(parent) = current {
            if levels_up > 3 {
                break;
            }

            let parent_kind = parent.kind();
            let parent_text = self.source[parent.byte_range()].to_string();

            if (parent_kind == "variable_declaration" || parent_kind == "assignment_expression")
                && (parent_text.contains("bool")
                    || parent_text.contains("(") && parent_text.contains("success"))
            {
                return Ok(true);
            }

            if parent_text.contains("require(")
                || parent_text.contains("assert(")
                || parent_text.starts_with("if ")
                || parent_text.contains("\nif ")
            {
                return Ok(true);
            }

            current = parent.parent();
            levels_up += 1;
        }
        Ok(false)
    }

    fn count_call_arguments(&self, call_node: &Node) -> usize {
        let mut count = 0;
        let mut cursor = call_node.walk();

        for child in call_node.children(&mut cursor) {
            if child.kind() == "call_argument" {
                count += 1;
            }
        }

        count
    }

    fn extract_method_name(&self, function_node: &Node) -> Option<String> {
        if function_node.kind() == "member_expression" {
            if let Some(property_node) = function_node.child_by_field_name("property") {
                return Some(self.source[property_node.byte_range()].to_string());
            }
        }

        if function_node.kind() == "expression" {
            if let Some(inner_node) = function_node.child(0) {
                return self.extract_method_name(&inner_node);
            }
        }

        if function_node.kind() == "struct_expression" {
            if let Some(type_node) = function_node.child_by_field_name("type") {
                return self.extract_method_name(&type_node);
            }
        }

        None
    }

    fn contains_external_call(&self, node: &Node) -> bool {
        let query = Query::new(&self.language, EXTERNAL_CALL_QUERY)
            .expect("Failed to create external call query");
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, *node, self.source.as_bytes());

        let mut call_count = 0;
        let mut found = false;

        matches.advance();
        while let Some(match_) = matches.get() {
            for capture in match_.captures {
                let capture_name = &query.capture_names()[capture.index as usize];
                if *capture_name == "call" {
                    call_count += 1;
                    let call_node = capture.node;

                    if let Some(function_node) = call_node.child_by_field_name("function") {
                        if let Some(method_name) = self.extract_method_name(&function_node) {
                            #[cfg(test)]
                            eprintln!("  Found external call method: {}", method_name);

                            if matches!(
                                method_name.as_str(),
                                "call" | "delegatecall" | "transfer" | "send" | "staticcall"
                            ) {
                                found = true;
                            }
                        }
                    }
                }
            }
            matches.advance();
        }

        #[cfg(test)]
        eprintln!(
            "  Total call_expressions found: {}, is external: {}",
            call_count, found
        );

        found
    }

    fn contains_storage_write(&self, node: &Node) -> bool {
        let query = Query::new(&self.language, ASSIGNMENT_QUERY)
            .expect("Failed to create assignment query");
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, *node, self.source.as_bytes());

        let mut count = 0;

        matches.advance();
        while let Some(match_) = matches.get() {
            for capture in match_.captures {
                let capture_name = &query.capture_names()[capture.index as usize];
                if *capture_name == "left" {
                    #[cfg(test)]
                    eprintln!(
                        "  Found assignment left: {}",
                        &self.source[capture.node.byte_range()]
                            [..std::cmp::min(30, self.source[capture.node.byte_range()].len())]
                    );

                    let left_node = capture.node;

                    let actual_left_node = if left_node.kind() == "expression" {
                        left_node.child(0).unwrap_or(left_node)
                    } else {
                        left_node
                    };

                    #[cfg(test)]
                    eprintln!("    left node kind: {}", actual_left_node.kind());

                    match actual_left_node.kind() {
                        "identifier" | "member_expression" | "index_expression"
                        | "array_access" => {
                            count += 1;
                        }
                        _ => {}
                    }
                }
            }
            matches.advance();
        }

        #[cfg(test)]
        eprintln!("  Total storage writes: {}, threshold: >2", count);

        count > 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_function_with_modifiers() {
        let source = r#"
        contract Test {
            modifier onlyOwner() {
                require(msg.sender == owner);
                _;
            }

            function withdraw() external onlyOwner {
                msg.sender.call{value: 1 ether}("");
            }
        }
        "#;

        let repr = SourceRepresentation::from_source(source, "test.sol", "Test").unwrap();

        assert_eq!(repr.functions.len(), 1);
        let func = &repr.functions["withdraw"];
        assert_eq!(func.modifiers, vec!["onlyOwner"]);
        assert_eq!(func.visibility, "external");
    }

    #[test]
    fn test_extract_loops() {
        let source = r#"
        contract Test {
            function batchSend(address[] calldata recipients) external {
                for (uint256 i = 0; i < recipients.length; i++) {
                    recipients[i].call{value: 1 ether}("");
                }
            }
        }
        "#;

        let repr = SourceRepresentation::from_source(source, "test.sol", "Test").unwrap();

        assert_eq!(repr.loops.len(), 1);
        let loop_info = &repr.loops[0];
        assert_eq!(loop_info.loop_type, LoopType::For);
        assert!(loop_info.contains_external_calls);
        assert!(loop_info.iterates_over_length);
    }
}
