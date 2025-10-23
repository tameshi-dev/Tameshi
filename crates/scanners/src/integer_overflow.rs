//! Integer overflow/underflow Scanner using IR analysis

use crate::core::{Confidence, Finding, Severity};
use thalir_core::{
    analysis::{
        cursor::ScannerCursor,
        pass::{Pass, PassManager, AnalysisID},
    },
    contract::Contract,
    instructions::Instruction,
    types::Type,
    block::{BlockId, Terminator},
};
use anyhow::Result;
use std::collections::{HashSet, HashMap};

pub struct IRIntegerOverflowScanner {
    findings: Vec<Finding>,
    loop_blocks_cache: HashMap<String, HashSet<BlockId>>,
}

impl IRIntegerOverflowScanner {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            loop_blocks_cache: HashMap::new(),
        }
    }
    
    pub fn get_findings(&self) -> Vec<Finding> {
        self.findings.clone()
    }
    
    pub fn analyze(&mut self, contract: &Contract) -> Result<Vec<Finding>> {
        self.findings.clear();
        self.loop_blocks_cache.clear();

        for (func_name, function) in &contract.functions {
            let loop_blocks = self.find_loop_blocks(function);
            self.loop_blocks_cache.insert(func_name.clone(), loop_blocks);

            let mut cursor = ScannerCursor::at_entry(function);
            let mut arithmetic_ops = Vec::new();
            let mut checked_ops = HashSet::new();

            for block_id in cursor.traverse_dom_order() {
                let block = function.body.blocks.get(&block_id).unwrap();

                for (idx, instruction) in block.instructions.iter().enumerate() {
                    match instruction {
                        Instruction::Add { result, left, right, ty } => {
                            arithmetic_ops.push((block_id, idx, "addition", result, left, right, ty));
                        }
                        Instruction::Sub { result, left, right, ty } => {
                            arithmetic_ops.push((block_id, idx, "subtraction", result, left, right, ty));
                        }
                        Instruction::Mul { result, left, right, ty } => {
                            arithmetic_ops.push((block_id, idx, "multiplication", result, left, right, ty));
                        }
                        Instruction::Div { result, left, right, ty } => {
                            arithmetic_ops.push((block_id, idx, "division", result, left, right, ty));
                        }

                        Instruction::CheckedAdd { result, .. } => {
                            checked_ops.insert(result);
                        }
                        Instruction::CheckedSub { result, .. } => {
                            checked_ops.insert(result);
                        }
                        Instruction::CheckedMul { result, .. } => {
                            checked_ops.insert(result);
                        }
                        Instruction::CheckedDiv { result, .. } => {
                            checked_ops.insert(result);
                        }
                        _ => {}
                    }
                }
            }

            for (block_id, idx, op_type, result, left, right, ty) in arithmetic_ops {
                if checked_ops.contains(result) {
                    continue;
                }

                let vulnerability = self.analyze_arithmetic_operation(
                    contract,
                    func_name,
                    op_type,
                    ty,
                    left,
                    right,
                    function,
                    block_id,
                    idx
                );

                if let Some(finding) = vulnerability {
                    self.findings.push(finding);
                }
            }
        }

        Ok(self.findings.clone())
    }

    fn find_loop_blocks(&self, function: &thalir_core::function::Function) -> HashSet<BlockId> {
        let mut loop_blocks = HashSet::new();

        for (block_id, block) in &function.body.blocks {
            match &block.terminator {
                Terminator::Branch { then_block, else_block, .. } => {
                    if then_block <= block_id {
                        loop_blocks.insert(*block_id);
                        loop_blocks.insert(*then_block);
                    }
                    if else_block <= block_id {
                        loop_blocks.insert(*block_id);
                        loop_blocks.insert(*else_block);
                    }
                }
                Terminator::Jump(target, _) => {
                    if target <= block_id {
                        loop_blocks.insert(*block_id);
                        loop_blocks.insert(*target);
                    }
                }
                _ => {}
            }
        }

        loop_blocks
    }
    
    fn analyze_arithmetic_operation(
        &self,
        contract: &Contract,
        func_name: &str,
        op_type: &str,
        ty: &Type,
        left: &thalir_core::values::Value,
        right: &thalir_core::values::Value,
        function: &thalir_core::function::Function,
        block_id: thalir_core::block::BlockId,
        idx: usize,
    ) -> Option<Finding> {
        let is_vulnerable_type = match ty {
            Type::Uint(_) => true,   // Unsigned integers can overflow
            Type::Int(_) => true,    // Signed integers can overflow/underflow
            _ => false,              // Other types are not vulnerable to integer overflow
        };

        if !is_vulnerable_type {
            return None;
        }

        let involves_external_data = self.involves_external_data(left, function) ||
                                    self.involves_external_data(right, function);

        let in_loop = self.is_in_loop_context(func_name, block_id);

        //

        let (should_flag, severity, confidence, risk_level) = match op_type {
            "multiplication" => {
                if involves_external_data && in_loop {
                    (true, Severity::High, Confidence::High, "high (loop + external data)")
                } else if involves_external_data {
                    (true, Severity::Medium, Confidence::Medium, "medium (external data)")
                } else {
                    (false, Severity::Low, Confidence::Low, "")
                }
            }
            "subtraction" => {
                if involves_external_data && in_loop {
                    (true, Severity::High, Confidence::High, "high (loop + external data)")
                } else if involves_external_data {
                    (true, Severity::High, Confidence::Medium, "high (external data, underflow risk)")
                } else {
                    (false, Severity::Low, Confidence::Low, "")
                }
            }
            "addition" => {
                if involves_external_data && in_loop {
                    (true, Severity::Medium, Confidence::High, "medium (loop + external data)")
                } else if involves_external_data {
                    (true, Severity::Medium, Confidence::Medium, "medium (external data)")
                } else {
                    (false, Severity::Low, Confidence::Low, "")
                }
            }
            "division" => {
                (false, Severity::Low, Confidence::Low, "")
            }
            _ => (false, Severity::Low, Confidence::Low, ""),
        };

        if !should_flag {
            return None;
        }

        let location = super::provenance::get_instruction_location(
            contract,
            func_name,
            block_id,
            idx,
        );

        let description = if in_loop {
            format!(
                "Function '{}' in contract '{}' performs unchecked {} on type {:?} with external data inside a loop. \
                 This is vulnerable to integer overflow/underflow in Solidity <0.8.0. Even in 0.8.0+, \
                 loop operations with external data should use explicit checks for gas efficiency and safety. Risk: {}",
                func_name, contract.name, op_type, ty, risk_level
            )
        } else {
            format!(
                "Function '{}' in contract '{}' performs unchecked {} on type {:?} with external data. \
                 This is vulnerable to integer overflow/underflow in Solidity <0.8.0. Consider using SafeMath or \
                 upgrading to Solidity 0.8.0+. Risk: {}",
                func_name, contract.name, op_type, ty, risk_level
            )
        };

        Some(Finding::new(
            format!("integer-overflow-{}", op_type),
            severity,
            confidence,
            format!("Potential integer overflow/underflow in '{}'", func_name),
            description,
        )
        .with_location(location)
        .with_contract(&contract.name)
        .with_function(func_name))
    }
    
    fn involves_external_data(&self, value: &thalir_core::values::Value, function: &thalir_core::function::Function) -> bool {
        use thalir_core::values::Value;
        
        match value {
            Value::Param(_) => true,
            
            Value::Temp(_) => {
                self.trace_value_to_external_source(value, function)
            }
            
            Value::Constant(_) => false,
            
            _ => false,
        }
    }
    
    fn trace_value_to_external_source(&self, value: &thalir_core::values::Value, function: &thalir_core::function::Function) -> bool {
        for (_block_id, block) in &function.body.blocks {
            for instruction in &block.instructions {
                match instruction {
                    Instruction::GetContext { result, .. } => {
                        if std::ptr::eq(result, value) {
                            return true;
                        }
                    }
                    
                    Instruction::StorageLoad { result, .. } |
                    Instruction::MappingLoad { result, .. } => {
                        if std::ptr::eq(result, value) {
                            return true;
                        }
                    }
                    
                    Instruction::Call { result, target: thalir_core::instructions::CallTarget::External(_), .. } => {
                        if std::ptr::eq(result, value) {
                            return true;
                        }
                    }
                    
                    _ => {}
                }
            }
        }
        
        false
    }
    
    fn is_in_loop_context(&self, func_name: &str, block_id: BlockId) -> bool {
        if let Some(loop_blocks) = self.loop_blocks_cache.get(func_name) {
            loop_blocks.contains(&block_id)
        } else {
            false
        }
    }
}

impl Pass for IRIntegerOverflowScanner {
    fn name(&self) -> &'static str {
        "ir-integer-overflow"
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

impl Default for IRIntegerOverflowScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::core::Scanner for IRIntegerOverflowScanner {
    fn id(&self) -> &'static str {
        "ir-integer-overflow"
    }

    fn name(&self) -> &'static str {
        "IR Integer Overflow Scanner"
    }

    fn description(&self) -> &'static str {
        "Detects potential integer overflow and underflow vulnerabilities in arithmetic operations"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn scan(&self, context: &crate::core::AnalysisContext) -> Result<Vec<Finding>> {
        if let Some(version) = context.get_metadata::<crate::analysis::SolidityVersion>("solidity_version") {
            if version.has_builtin_overflow_protection() {
                return Ok(Vec::new());
            }
        }

        let ir_contract = context.get_representation::<thalir_core::contract::Contract>()?;
        let mut scanner = Self::new();
        scanner.analyze(ir_contract)
    }

    fn required_representations(&self) -> crate::representations::RepresentationSet {
        crate::representations::RepresentationSet::new()
            .require::<thalir_core::contract::Contract>()
    }
}
