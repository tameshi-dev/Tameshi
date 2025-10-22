//! Denial of Service (DoS) vulnerability Scanner using IR analysis

use crate::core::{Confidence, Finding, Severity};
use thalir_core::{
    analysis::{
        cursor::ScannerCursor,
        pass::{Pass, PassManager, AnalysisID},
    },
    contract::Contract,
    instructions::{Instruction, CallTarget},
    values::{Value, Constant},
};
use anyhow::Result;
use std::collections::HashMap;

pub struct IRDoSVulnerabilityScanner {
    findings: Vec<Finding>,
}

impl IRDoSVulnerabilityScanner {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
        }
    }
    
    pub fn get_findings(&self) -> Vec<Finding> {
        self.findings.clone()
    }
    
    pub fn analyze(&mut self, contract: &Contract) -> Result<Vec<Finding>> {
        self.findings.clear();
        
        for (func_name, function) in &contract.functions {
            let mut cursor = ScannerCursor::at_entry(function);
            let loop_analysis: HashMap<thalir_core::block::BlockId, usize> = HashMap::new();
            let mut gas_consuming_operations = Vec::new();
            let mut external_calls = Vec::new();
            let array_operations = Vec::new();
            let mut unbounded_loops = Vec::new();
            
            for block_id in cursor.traverse_dom_order() {
                let block = function.body.blocks.get(&block_id).unwrap();
                
                for (idx, instruction) in block.instructions.iter().enumerate() {
                    match instruction {
                        Instruction::StorageStore { .. } => {
                            gas_consuming_operations.push((block_id, idx, "storage_write"));
                        }
                        
                        Instruction::StorageLoad { .. } => {
                            gas_consuming_operations.push((block_id, idx, "storage_read"));
                        }
                        
                        Instruction::Call { target, args, .. } => {
                            external_calls.push((block_id, idx, target, args.len()));
                        }
                        
                        
                        Instruction::Lt { result, left, right } |
                        Instruction::Gt { result, left, right } |
                        Instruction::Le { result, left, right } |
                        Instruction::Ge { result, left, right } => {
                            let has_backedge = match &block.terminator {
                                thalir_core::block::Terminator::Branch { then_block, else_block, .. } => {
                                    then_block <= &block_id || else_block <= &block_id
                                }
                                _ => false,
                            };

                            if has_backedge && self.is_potentially_unbounded_condition(left, right) {
                                unbounded_loops.push((block_id, idx, result));
                            }
                        }
                        
                        Instruction::Require { condition: _, message: _ } => {
                        }
                        
                        _ => {}
                    }
                }
            }
            
            self.analyze_gas_limit_dos(contract, func_name, &gas_consuming_operations, &unbounded_loops);
            self.analyze_external_call_dos(contract, func_name, &external_calls);
            self.analyze_array_dos(contract, func_name, &array_operations);
            self.analyze_unbounded_loops(contract, func_name, &unbounded_loops);
        }
        
        Ok(self.findings.clone())
    }
    
    fn is_potentially_unbounded_condition(&self, left: &Value, right: &Value) -> bool {
        match (left, right) {
            (Value::StorageRef(_), _) | (_, Value::StorageRef(_)) => true,
            
            (Value::Constant(Constant::Uint(val, _)), _) | (_, Value::Constant(Constant::Uint(val, _))) => {
                let val_str = val.to_string();
                if let Ok(val_u64) = val_str.parse::<u64>() {
                    val_u64 > 1000
                } else {
                    true // If we can't parse, assume it's large
                }
            }
            
            _ => false,
        }
    }
    
    fn is_dos_prone_require(&self, _condition: &Value, message: &str) -> bool {
        //
        //
        //
        let message_lower = message.to_lowercase();

        (message_lower.contains("transfer") && message_lower.contains("failed")) ||
        (message_lower.contains("call") && message_lower.contains("failed")) ||
        (message_lower.contains("send") && message_lower.contains("failed")) ||
        message_lower.contains("insufficient") ||
        message_lower.contains("reentrancy")

    }
    
    fn analyze_gas_limit_dos(
        &mut self,
        contract: &Contract,
        func_name: &str,
        gas_operations: &[(thalir_core::block::BlockId, usize, &str)],
        unbounded_loops: &[(thalir_core::block::BlockId, usize, &Value)]
    ) {
        let gas_op_count = gas_operations.len();
        let loop_count = unbounded_loops.len();

        if gas_op_count > 5 && loop_count > 0 {
            let severity = if gas_op_count > 10 || loop_count > 2 {
                Severity::High
            } else {
                Severity::Medium
            };

            if let Some((block_id, idx, _)) = gas_operations.first() {
                let location = super::provenance::get_instruction_location(
                    contract,
                    func_name,
                    *block_id,
                    *idx,
                );

                self.findings.push(Finding::new(
                    "gas-limit-dos".to_string(),
                    severity,
                    Confidence::High,
                    format!("Gas limit DoS vulnerability in '{}'", func_name),
                    format!(
                        "Function '{}' in contract '{}' has {} gas-consuming operations and {} potentially unbounded loops. This can cause transactions to exceed gas limits, resulting in denial of service",
                        func_name, contract.name, gas_op_count, loop_count
                    ),
                )
                .with_location(location)
                .with_contract(&contract.name)
                .with_function(func_name));
            }
        }

        else if gas_op_count > 3 && loop_count > 0 {
            if let Some((block_id, idx, _)) = gas_operations.first() {
                let location = super::provenance::get_instruction_location(
                    contract,
                    func_name,
                    *block_id,
                    *idx,
                );

                self.findings.push(Finding::new(
                    "moderate-gas-dos".to_string(),
                    Severity::Medium,
                    Confidence::Medium,
                    format!("Potential gas limit DoS in '{}'", func_name),
                    format!(
                        "Function '{}' in contract '{}' performs {} gas-consuming operations within loops, which could lead to out-of-gas conditions",
                        func_name, contract.name, gas_op_count
                    ),
                )
                .with_location(location)
                .with_contract(&contract.name)
                .with_function(func_name));
            }
        }
    }
    
    fn analyze_external_call_dos(
        &mut self,
        contract: &Contract,
        func_name: &str,
        external_calls: &[(thalir_core::block::BlockId, usize, &CallTarget, usize)]
    ) {
        if external_calls.is_empty() {
            return;
        }

        let call_count = external_calls.len();

        if call_count > 3 {
            if let Some((block_id, idx, _, _)) = external_calls.first() {
                let location = super::provenance::get_instruction_location(
                    contract,
                    func_name,
                    *block_id,
                    *idx,
                );

                self.findings.push(Finding::new(
                    "external-call-dos".to_string(),
                    Severity::High,
                    Confidence::Medium,
                    format!("External call DoS vulnerability in '{}'", func_name),
                    format!(
                        "Function '{}' in contract '{}' makes {} external calls. Each call can fail or consume excessive gas, causing denial of service. Consider implementing pull-over-push pattern",
                        func_name, contract.name, call_count
                    ),
                )
                .with_location(location)
                .with_contract(&contract.name)
                .with_function(func_name));
            }
        } else if call_count > 1 {
            if let Some((block_id, idx, _, _)) = external_calls.first() {
                let location = super::provenance::get_instruction_location(
                    contract,
                    func_name,
                    *block_id,
                    *idx,
                );

                self.findings.push(Finding::new(
                    "multiple-external-calls".to_string(),
                    Severity::Medium,
                    Confidence::Medium,
                    format!("Multiple external calls in '{}'", func_name),
                    format!(
                        "Function '{}' in contract '{}' makes {} external calls which could fail and block execution",
                        func_name, contract.name, call_count
                    ),
                )
                .with_location(location)
                .with_contract(&contract.name)
                .with_function(func_name));
            }
        }
    }
    
    fn analyze_array_dos(
        &mut self,
        contract: &Contract,
        func_name: &str,
        array_operations: &[(thalir_core::block::BlockId, usize, &Value, &Value)]
    ) {
        if array_operations.is_empty() {
            return;
        }

        let array_op_count = array_operations.len();

        if array_op_count > 5 {
            if let Some((block_id, idx, _, _)) = array_operations.first() {
                let location = super::provenance::get_instruction_location(
                    contract,
                    func_name,
                    *block_id,
                    *idx,
                );

                self.findings.push(Finding::new(
                    "array-dos".to_string(),
                    Severity::Medium,
                    Confidence::Medium,
                    format!("Array DoS vulnerability in '{}'", func_name),
                    format!(
                        "Function '{}' in contract '{}' performs {} array operations. Large arrays can cause out-of-gas conditions. Consider implementing pagination or gas-efficient data structures",
                        func_name, contract.name, array_op_count
                    ),
                )
                .with_location(location)
                .with_contract(&contract.name)
                .with_function(func_name));
            }
        }
    }
    
    fn analyze_unbounded_loops(
        &mut self,
        contract: &Contract,
        func_name: &str,
        unbounded_loops: &[(thalir_core::block::BlockId, usize, &Value)]
    ) {
        if unbounded_loops.is_empty() {
            return;
        }

        let loop_count = unbounded_loops.len();

        if let Some((block_id, idx, _)) = unbounded_loops.first() {
            let location = super::provenance::get_instruction_location(
                contract,
                func_name,
                *block_id,
                *idx,
            );

            self.findings.push(Finding::new(
                "unbounded-loop".to_string(),
                Severity::High,
                Confidence::High,
                format!("Unbounded loop vulnerability in '{}'", func_name),
                format!(
                    "Function '{}' in contract '{}' contains {} potentially unbounded loops. These can consume excessive gas and cause denial of service. Implement proper bounds checking and gas limits",
                    func_name, contract.name, loop_count
                ),
            )
            .with_location(location)
            .with_contract(&contract.name)
            .with_function(func_name));
        }
    }
}

impl Pass for IRDoSVulnerabilityScanner {
    fn name(&self) -> &'static str {
        "ir-dos-vulnerabilities"
    }
    
    fn run_on_contract(&mut self, contract: &mut Contract, _manager: &mut PassManager) -> Result<()> {
        self.analyze(contract)?;
        Ok(())
    }
    
    fn required_analyses(&self) -> Vec<AnalysisID> {
        vec![AnalysisID::ControlFlow, AnalysisID::DefUse]
    }
    
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

impl Default for IRDoSVulnerabilityScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::core::Scanner for IRDoSVulnerabilityScanner {
    fn id(&self) -> &'static str {
        "ir-dos-vulnerabilities"
    }

    fn name(&self) -> &'static str {
        "IR DoS Vulnerability Scanner"
    }

    fn description(&self) -> &'static str {
        "Detects Denial of Service vulnerabilities including gas limit issues, unbounded loops, and external call DoS"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn scan(&self, context: &crate::core::AnalysisContext) -> Result<Vec<Finding>> {
        let ir_contract = context.get_representation::<thalir_core::contract::Contract>()?;
        let mut scanner = Self::new();
        scanner.analyze(ir_contract)
    }

    fn required_representations(&self) -> crate::representations::RepresentationSet {
        crate::representations::RepresentationSet::new()
            .require::<thalir_core::contract::Contract>()
    }
}