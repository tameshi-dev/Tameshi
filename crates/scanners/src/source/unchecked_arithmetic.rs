use crate::core::context::AnalysisContext;
/// Unchecked Arithmetic Scanner - Detects potentially vulnerable arithmetic operations in Solidity unchecked blocks
///
/// This scanner identifies arithmetic operations within unchecked blocks that could lead to
/// integer overflow/underflow vulnerabilities, particularly focusing on:
/// - State variable modifications
/// - Balance and allowance manipulations
/// - User-controllable arithmetic
/// - Loop counter manipulations
use crate::core::result::{Finding, FindingMetadata, Location};
use crate::core::scanner::Scanner;
use crate::core::severity::{Confidence, Severity};
use crate::representations::source::SourceRepresentation;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use streaming_iterator::StreamingIterator;
use tree_sitter::{Node, Query, QueryCursor};

#[derive(Debug, Clone)]
struct UncheckedOperation {
    location: Location,
    operator: String,
    left_operand: String,
    right_operand: String,
    function_name: String,
    is_state_variable: bool,
    is_user_controllable: bool,
    is_critical_operation: bool,
    has_validation: bool,
    operation_context: OperationContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OperationContext {
    BalanceModification,
    AllowanceModification,
    TotalSupplyModification,
    ArrayIndexManipulation,
    LoopCounter,
    GeneralArithmetic,
    MappingAccess,
    StateVariableUpdate,
}

pub struct UncheckedArithmeticScanner;

impl Default for UncheckedArithmeticScanner {
    fn default() -> Self {
        Self
    }
}

impl UncheckedArithmeticScanner {
    pub fn new() -> Self {
        Self
    }

    fn analyze_contract(
        &self,
        source_repr: &SourceRepresentation,
        contract_name: &str,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut analyzer = UncheckedAnalyzer::new(source_repr);

        let unchecked_operations = analyzer.extract_unchecked_operations()?;

        for operation in unchecked_operations {
            let severity = self.calculate_severity(&operation);
            let confidence = self.calculate_confidence(&operation);

            if severity >= Severity::Low {
                let title = self.generate_title(&operation);
                let description = self.generate_description(&operation);

                let mut finding = Finding::new(
                    "unchecked-arithmetic".to_string(),
                    severity,
                    confidence,
                    title,
                    description,
                )
                .with_location(operation.location)
                .with_contract(contract_name)
                .with_function(&operation.function_name)
                .with_swc_id("SWC-101".to_string());

                let mut metadata = FindingMetadata::default();
                metadata.affected_contracts.push(contract_name.to_string());
                metadata
                    .affected_functions
                    .push(operation.function_name.clone());

                if operation.is_state_variable {
                    metadata
                        .affected_variables
                        .push(operation.left_operand.clone());
                }

                if operation.is_critical_operation {
                    metadata
                        .references
                        .push("Critical financial operation".to_string());
                }
                if operation.is_user_controllable {
                    metadata
                        .references
                        .push("User-controllable input".to_string());
                }
                if !operation.has_validation {
                    metadata
                        .references
                        .push("No prior validation detected".to_string());
                }
                finding.metadata = Some(metadata);

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn calculate_severity(&self, operation: &UncheckedOperation) -> Severity {
        match operation.operation_context {
            OperationContext::BalanceModification | OperationContext::TotalSupplyModification => {
                if operation.operator == "-=" || operation.operator == "-" {
                    Severity::Critical
                } else {
                    Severity::High
                }
            }
            OperationContext::AllowanceModification => Severity::High,
            OperationContext::ArrayIndexManipulation => {
                if operation.is_user_controllable {
                    Severity::High
                } else {
                    Severity::Medium
                }
            }
            OperationContext::LoopCounter => {
                if operation.is_user_controllable || !operation.has_validation {
                    Severity::Medium
                } else {
                    Severity::Low
                }
            }
            OperationContext::StateVariableUpdate => {
                if operation.is_user_controllable {
                    Severity::High
                } else {
                    Severity::Medium
                }
            }
            OperationContext::MappingAccess => {
                if operation.is_critical_operation {
                    Severity::High
                } else {
                    Severity::Medium
                }
            }
            OperationContext::GeneralArithmetic => {
                if operation.is_user_controllable {
                    Severity::Medium
                } else {
                    Severity::Low
                }
            }
        }
    }

    fn calculate_confidence(&self, operation: &UncheckedOperation) -> Confidence {
        if operation.has_validation {
            Confidence::Low
        } else if operation.is_critical_operation || operation.is_user_controllable {
            Confidence::High
        } else {
            Confidence::Medium
        }
    }

    fn generate_title(&self, operation: &UncheckedOperation) -> String {
        match operation.operation_context {
            OperationContext::BalanceModification => {
                format!("Unchecked balance {} operation", operation.operator)
            }
            OperationContext::TotalSupplyModification => {
                format!("Unchecked totalSupply {} operation", operation.operator)
            }
            OperationContext::AllowanceModification => {
                format!("Unchecked allowance {} operation", operation.operator)
            }
            OperationContext::ArrayIndexManipulation => {
                "Unchecked array index arithmetic".to_string()
            }
            OperationContext::LoopCounter => "Unchecked loop counter arithmetic".to_string(),
            OperationContext::StateVariableUpdate => {
                format!("Unchecked state variable {} operation", operation.operator)
            }
            OperationContext::MappingAccess => {
                format!("Unchecked mapping {} operation", operation.operator)
            }
            OperationContext::GeneralArithmetic => {
                format!("Unchecked {} arithmetic operation", operation.operator)
            }
        }
    }

    fn generate_description(&self, operation: &UncheckedOperation) -> String {
        let mut description = format!(
            "An unchecked arithmetic operation '{}' was detected in function '{}'. ",
            operation.operator, operation.function_name
        );

        description.push_str(&format!(
            "The operation '{}' {} '{}' is performed within an unchecked block, ",
            operation.left_operand, operation.operator, operation.right_operand
        ));

        match operation.operator.as_str() {
            "-=" | "-" => {
                description.push_str(
                    "which could underflow if the right operand is greater than the left operand. ",
                );
            }
            "+=" | "+" => {
                description.push_str(
                    "which could overflow if the sum exceeds the maximum value for the type. ",
                );
            }
            "*=" | "*" => {
                description.push_str(
                    "which could overflow if the product exceeds the maximum value for the type. ",
                );
            }
            "/=" | "/" => {
                description.push_str("which could revert if the divisor is zero. ");
            }
            _ => {
                description.push_str("which bypasses Solidity's built-in overflow protection. ");
            }
        }

        match operation.operation_context {
            OperationContext::BalanceModification => {
                description.push_str("This operation modifies user balances, which is a critical financial operation. An underflow could grant users excessive balances.");
            }
            OperationContext::TotalSupplyModification => {
                description.push_str("This operation modifies the total supply, which could break protocol invariants if it overflows or underflows.");
            }
            OperationContext::AllowanceModification => {
                description.push_str("This operation modifies token allowances, which could lead to unauthorized token transfers.");
            }
            OperationContext::ArrayIndexManipulation => {
                description.push_str("Array index arithmetic without bounds checking could lead to out-of-bounds access or storage corruption.");
            }
            OperationContext::LoopCounter => {
                description.push_str("Loop counter arithmetic without overflow protection could cause infinite loops or skipped iterations.");
            }
            _ => {}
        }

        if operation.is_user_controllable {
            description.push_str(" The operands appear to be influenced by user input, increasing the risk of exploitation.");
        }

        if !operation.has_validation {
            description
                .push_str(" No validation checks were detected before this unchecked operation.");
        }

        description.push_str(" Consider using checked arithmetic or adding explicit validation before the operation.");

        description
    }
}

impl Scanner for UncheckedArithmeticScanner {
    fn id(&self) -> &'static str {
        "unchecked-arithmetic"
    }

    fn name(&self) -> &'static str {
        "Unchecked Arithmetic Vulnerability Scanner"
    }

    fn description(&self) -> &'static str {
        "Detects potentially vulnerable arithmetic operations within unchecked blocks that could lead to integer overflow/underflow"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn scan(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        let mut all_findings = Vec::new();

        if let Some(source_code) = context.source_code() {
            let file_path = context
                .contract_info()
                .source_path
                .clone()
                .unwrap_or_else(|| "unknown.sol".to_string());
            let contract_name = context.contract_info().name.clone();

            let source_repr =
                SourceRepresentation::from_source(source_code, &file_path, &contract_name)?;

            let findings = self.analyze_contract(&source_repr, &contract_name)?;
            all_findings.extend(findings);
        }

        Ok(all_findings)
    }
}

struct UncheckedAnalyzer<'a> {
    source_repr: &'a SourceRepresentation,
    state_variables: HashSet<String>,
    user_inputs: HashSet<String>,
    critical_names: HashSet<String>,
}

impl<'a> UncheckedAnalyzer<'a> {
    fn new(source_repr: &'a SourceRepresentation) -> Self {
        let mut critical_names = HashSet::new();
        critical_names.insert("balance".to_string());
        critical_names.insert("balances".to_string());
        critical_names.insert("allowance".to_string());
        critical_names.insert("allowances".to_string());
        critical_names.insert("totalSupply".to_string());
        critical_names.insert("total_supply".to_string());
        critical_names.insert("_totalSupply".to_string());

        let mut user_inputs = HashSet::new();
        user_inputs.insert("msg.sender".to_string());
        user_inputs.insert("msg.value".to_string());
        user_inputs.insert("tx.origin".to_string());

        Self {
            source_repr,
            state_variables: HashSet::new(),
            user_inputs,
            critical_names,
        }
    }

    fn extract_unchecked_operations(&mut self) -> Result<Vec<UncheckedOperation>> {
        let mut operations = Vec::new();

        let mut parser = tree_sitter::Parser::new();
        let language = tree_sitter_solidity::LANGUAGE.into();
        parser.set_language(&language)?;

        let tree = parser
            .parse(&self.source_repr.source, None)
            .ok_or_else(|| anyhow::anyhow!("Failed to parse source"))?;

        let root = tree.root_node();

        self.extract_state_variables(&root)?;

        for (func_name, func_info) in &self.source_repr.functions {
            let mut func_operations = self.extract_from_full_source(&root, func_name, func_info)?;
            operations.append(&mut func_operations);
        }

        Ok(operations)
    }

    fn extract_from_full_source(
        &self,
        root: &Node,
        function_name: &str,
        func_info: &crate::representations::source::FunctionInfo,
    ) -> Result<Vec<UncheckedOperation>> {
        let mut operations = Vec::new();

        let func_start_line = func_info.location.line;
        let func_end_line = func_info.location.end_line;

        self.find_unchecked_in_range(
            root,
            function_name,
            func_start_line,
            func_end_line,
            &mut operations,
        )?;

        Ok(operations)
    }

    fn find_unchecked_in_range(
        &self,
        node: &Node,
        function_name: &str,
        start_line: usize,
        end_line: usize,
        operations: &mut Vec<UncheckedOperation>,
    ) -> Result<()> {
        let node_start = node.start_position().row + 1;
        let node_end = node.end_position().row + 1;

        if node_start > end_line || node_end < start_line {
            return Ok(());
        }

        if node.kind() == "statement" {
            let mut stmt_cursor = node.walk();
            for stmt_child in node.children(&mut stmt_cursor) {
                if stmt_child.kind() == "block_statement" {
                    let mut has_unchecked = false;
                    let mut block_cursor = stmt_child.walk();

                    for block_child in stmt_child.children(&mut block_cursor) {
                        if block_child.kind() == "unchecked" {
                            has_unchecked = true;
                            break;
                        }
                    }

                    if has_unchecked {
                        let mut body_operations = self.extract_arithmetic_from_block(
                            &stmt_child,
                            function_name,
                            &self.source_repr.source,
                        )?;

                        for op in &mut body_operations {
                            op.has_validation =
                                self.check_prior_validation(stmt_child, &self.source_repr.source);
                        }

                        operations.append(&mut body_operations);
                    }
                }
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.find_unchecked_in_range(&child, function_name, start_line, end_line, operations)?;
        }

        Ok(())
    }

    fn extract_state_variables(&mut self, root: &Node) -> Result<()> {
        const STATE_VAR_QUERY: &str = r#"
        (state_variable_declaration
          name: (identifier) @var_name
        )
        "#;

        let query = Query::new(&tree_sitter_solidity::LANGUAGE.into(), STATE_VAR_QUERY)?;
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, *root, self.source_repr.source.as_bytes());

        matches.advance();
        while let Some(match_) = matches.get() {
            for capture in match_.captures {
                let var_name = &self.source_repr.source[capture.node.byte_range()];
                self.state_variables.insert(var_name.to_string());
            }
            matches.advance();
        }

        Ok(())
    }

    fn extract_from_node(
        &self,
        node: &Node,
        function_name: &str,
        source: &str,
    ) -> Result<Vec<UncheckedOperation>> {
        let mut operations = Vec::new();
        self.find_unchecked_blocks(node, function_name, source, &mut operations)?;
        Ok(operations)
    }

    fn find_unchecked_blocks(
        &self,
        node: &Node,
        function_name: &str,
        source: &str,
        operations: &mut Vec<UncheckedOperation>,
    ) -> Result<()> {
        let mut cursor = node.walk();

        for child in node.children(&mut cursor) {
            if child.kind() == "statement" {
                let mut stmt_cursor = child.walk();
                for stmt_child in child.children(&mut stmt_cursor) {
                    if stmt_child.kind() == "block_statement" {
                        let mut has_unchecked = false;
                        let mut block_cursor = stmt_child.walk();

                        for block_child in stmt_child.children(&mut block_cursor) {
                            if block_child.kind() == "unchecked" {
                                has_unchecked = true;
                                break;
                            }
                        }

                        if has_unchecked {
                            let mut body_operations = self.extract_arithmetic_from_block(
                                &stmt_child,
                                function_name,
                                source,
                            )?;

                            for op in &mut body_operations {
                                op.has_validation = self.check_prior_validation(stmt_child, source);
                            }

                            operations.append(&mut body_operations);
                        }
                    }
                }
            }

            self.find_unchecked_blocks(&child, function_name, source, operations)?;
        }

        Ok(())
    }

    fn extract_arithmetic_from_block(
        &self,
        block: &Node,
        function_name: &str,
        source: &str,
    ) -> Result<Vec<UncheckedOperation>> {
        let mut operations = Vec::new();

        const ARITHMETIC_QUERY: &str = r#"
        [
          (augmented_assignment_expression
            left: (_) @left
            right: (_) @right
          ) @assignment
          (binary_expression
            left: (_) @left
            operator: ["-" "+" "*" "/" "**" "%"] @op
            right: (_) @right
          ) @binary
          (update_expression
            operator: ["++" "--"] @op
            argument: (_) @operand
          ) @update
        ]
        "#;

        let query = Query::new(&tree_sitter_solidity::LANGUAGE.into(), ARITHMETIC_QUERY)?;
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, *block, source.as_bytes());

        matches.advance();
        while let Some(match_) = matches.get() {
            let mut left_node = None;
            let mut right_node = None;
            let mut op_node = None;
            let mut operand_node = None;
            let mut operation_node = None;

            for capture in match_.captures {
                let capture_name = &query.capture_names()[capture.index as usize];
                match *capture_name {
                    "left" => left_node = Some(capture.node),
                    "right" => right_node = Some(capture.node),
                    "op" => op_node = Some(capture.node),
                    "operand" => operand_node = Some(capture.node),
                    "assignment" | "binary" | "update" => operation_node = Some(capture.node),
                    _ => {}
                }
            }

            let operator = if let Some(op_node) = op_node {
                source[op_node.byte_range()].to_string()
            } else if let Some(assignment_node) = operation_node {
                if assignment_node.kind() == "augmented_assignment_expression" {
                    let text = source[assignment_node.byte_range()].to_string();
                    if text.contains("+=") {
                        "+=".to_string()
                    } else if text.contains("-=") {
                        "-=".to_string()
                    } else if text.contains("*=") {
                        "*=".to_string()
                    } else if text.contains("/=") {
                        "/=".to_string()
                    } else if text.contains("%=") {
                        "%=".to_string()
                    } else {
                        continue;
                    }
                } else {
                    continue;
                }
            } else {
                continue;
            };

            if !operator.is_empty() {
                let (left_operand, right_operand) =
                    if let (Some(left), Some(right)) = (left_node, right_node) {
                        (
                            source[left.byte_range()].to_string(),
                            source[right.byte_range()].to_string(),
                        )
                    } else if let Some(operand) = operand_node {
                        let operand_text = source[operand.byte_range()].to_string();
                        // Both ++ and -- use 1 as the operand
                        (operand_text.clone(), "1".to_string())
                    } else {
                        continue;
                    };

                let is_state_variable = self.is_state_variable(&left_operand);
                let is_user_controllable = self.is_user_controllable(&left_operand)
                    || self.is_user_controllable(&right_operand);
                let is_critical_operation = self.is_critical_operation(&left_operand);
                let operation_context = self.determine_context(&left_operand, &right_operand);

                if let Some(op_node) = operation_node {
                    let start = op_node.start_position();
                    let end = op_node.end_position();

                    let location = Location {
                        file: self.source_repr.file_path.clone(),
                        line: start.row + 1,
                        column: start.column,
                        end_line: Some(end.row + 1),
                        end_column: Some(end.column),
                        snippet: Some(source[op_node.byte_range()].to_string()),
                        ir_position: None,
                    };

                    operations.push(UncheckedOperation {
                        location,
                        operator,
                        left_operand,
                        right_operand,
                        function_name: function_name.to_string(),
                        is_state_variable,
                        is_user_controllable,
                        is_critical_operation,
                        has_validation: false,
                        operation_context,
                    });
                }
            }
            matches.advance();
        }

        Ok(operations)
    }

    fn check_prior_validation(&self, unchecked_node: Node, source: &str) -> bool {
        let unchecked_line = unchecked_node.start_position().row + 1;

        let mut current_node = unchecked_node.parent();
        while let Some(parent) = current_node {
            if parent.kind() == "function_definition" || parent.kind() == "function_body" {
                let parent_start_line = parent.start_position().row + 1;

                let lines: Vec<&str> = source.lines().collect();
                for line_num in parent_start_line..unchecked_line {
                    if line_num > 0 && line_num <= lines.len() {
                        let line = lines[line_num - 1];
                        if line.contains("require(") || line.contains("assert(") {
                            return true;
                        }
                    }
                }
                break;
            }
            current_node = parent.parent();
        }
        false
    }

    fn is_state_variable(&self, operand: &str) -> bool {
        for var in &self.state_variables {
            if operand.contains(var) {
                return true;
            }
        }
        operand.contains('[') && operand.contains(']')
    }

    fn is_user_controllable(&self, operand: &str) -> bool {
        for input in &self.user_inputs {
            if operand.contains(input) {
                return true;
            }
        }

        for param in ["amount", "value", "_amount", "_value"] {
            if operand.contains(param) {
                return true;
            }
        }

        false
    }

    fn is_critical_operation(&self, operand: &str) -> bool {
        let operand_lower = operand.to_lowercase();
        for critical in &self.critical_names {
            if operand_lower.contains(critical) {
                return true;
            }
        }
        false
    }

    fn determine_context(&self, left: &str, right: &str) -> OperationContext {
        let left_lower = left.to_lowercase();

        if left_lower.contains("balance") && !left_lower.contains("allowance") {
            OperationContext::BalanceModification
        } else if left_lower.contains("allowance") {
            OperationContext::AllowanceModification
        } else if left_lower.contains("totalsupply") || left_lower.contains("total_supply") {
            OperationContext::TotalSupplyModification
        } else if left.contains('[') && left.contains(']') {
            if left.chars().filter(|c| *c == '[').count() > 1 || right.contains('[') {
                OperationContext::ArrayIndexManipulation
            } else {
                OperationContext::MappingAccess
            }
        } else if left == "i" || left == "j" || left == "k" || left.starts_with("_i") {
            OperationContext::LoopCounter
        } else if self.is_state_variable(left) {
            OperationContext::StateVariableUpdate
        } else {
            OperationContext::GeneralArithmetic
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::{AnalysisContext, ContractInfo, ScannerConfig};
    use crate::representations::bundle::RepresentationBundle;

    #[test]
    fn test_unchecked_balance_subtraction() {
        let source = r#"
        pragma solidity ^0.8.0;

        contract VulnerableToken {
            mapping(address => uint256) public balances;

            function withdraw(uint256 amount) public {
                require(balances[msg.sender] >= amount, "Insufficient balance");
                unchecked {
                    balances[msg.sender] -= amount;
                }
                payable(msg.sender).transfer(amount);
            }
        }
        "#;

        let contract_info = ContractInfo {
            name: "VulnerableToken".to_string(),
            source_path: Some("test.sol".to_string()),
            source_code: None,
            compiler_version: None,
            optimization_enabled: false,
        };

        let bundle = RepresentationBundle::new();
        let config = ScannerConfig::default();
        let context = AnalysisContext::new_with_source(bundle, contract_info, config, source);

        let scanner = UncheckedArithmeticScanner::new();
        let findings = scanner.scan(&context).unwrap();

        assert!(!findings.is_empty());
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].title.contains("balance"));
        assert!(findings[0].description.contains("underflow"));
    }

    #[test]
    fn test_unchecked_loop_counter() {
        let source = r#"
        pragma solidity ^0.8.0;

        contract LoopTest {
            uint256[] public data;

            function processData(uint256 start, uint256 increment) public {
                unchecked {
                    for (uint256 i = start; i < data.length; i += increment) {
                        data[i] = i * 2;
                    }
                }
            }
        }
        "#;

        let contract_info = ContractInfo {
            name: "LoopTest".to_string(),
            source_path: Some("test.sol".to_string()),
            source_code: None,
            compiler_version: None,
            optimization_enabled: false,
        };

        let bundle = RepresentationBundle::new();
        let config = ScannerConfig::default();
        let context = AnalysisContext::new_with_source(bundle, contract_info, config, source);

        let scanner = UncheckedArithmeticScanner::new();
        let findings = scanner.scan(&context).unwrap();

        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.title.contains("loop counter")));
    }

    #[test]
    fn test_safe_unchecked_operation() {
        let source = r#"
        pragma solidity ^0.8.0;

        contract SafeContract {
            function safeOperation() public pure returns (uint256) {
                uint256 result;
                unchecked {
                    result = 10 + 5;
                }
                return result;
            }
        }
        "#;

        let contract_info = ContractInfo {
            name: "SafeContract".to_string(),
            source_path: Some("test.sol".to_string()),
            source_code: None,
            compiler_version: None,
            optimization_enabled: false,
        };

        let bundle = RepresentationBundle::new();
        let config = ScannerConfig::default();
        let context = AnalysisContext::new_with_source(bundle, contract_info, config, source);

        let scanner = UncheckedArithmeticScanner::new();
        let findings = scanner.scan(&context).unwrap();

        assert!(findings.is_empty() || findings.iter().all(|f| f.severity <= Severity::Low));
    }
}
