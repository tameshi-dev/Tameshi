//! Unchecked return value Scanner using IR analysis

use crate::core::{Confidence, Finding, Severity};
use thalir_core::{
    analysis::{
        cursor::ScannerCursor,
        pass::{Pass, PassManager, AnalysisID},
    },
    contract::Contract,
    instructions::{Instruction, CallTarget},
};
use anyhow::Result;

pub struct IRUncheckedReturnScanner {
    findings: Vec<Finding>,
}

impl IRUncheckedReturnScanner {
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
            
            for block_id in cursor.traverse_dom_order() {
                let block = function.body.blocks.get(&block_id).unwrap();
                
                for (idx, instruction) in block.instructions.iter().enumerate() {
                    if let Instruction::Call { result, target, .. } = instruction {
                        let is_external_or_delegatecall = match target {
                            CallTarget::External(_) => true,
                            CallTarget::Internal(name) if name.contains("delegatecall") || name.contains("call") => true,
                            _ => false,
                        };

                        if is_external_or_delegatecall
                            && !self.is_call_result_checked(result, function, block_id, idx) {
                            let location = super::provenance::get_instruction_location(
                                contract,
                                func_name,
                                block_id,
                                idx,
                            );

                            self.findings.push(Finding::new(
                                "unchecked-return".to_string(),
                                Severity::Medium,
                                Confidence::High,
                                format!("Unchecked return value in '{}'", func_name),
                                format!(
                                    "Function '{}' in contract '{}' ignores return value from external call to {:?}",
                                    func_name, contract.name, target
                                ),
                            )
                            .with_location(location)
                            .with_contract(&contract.name)
                            .with_function(func_name));
                        }
                    }
                }
            }
        }
        
        Ok(self.findings.clone())
    }
    
    fn is_call_result_checked(&self, result: &thalir_core::values::Value, function: &thalir_core::function::Function, current_block: thalir_core::block::BlockId, call_idx: usize) -> bool {

        let block = function.body.blocks.get(&current_block).unwrap();

        let mut found_intervening_call = false;
        let mut found_success_require = false;

        for instruction in &block.instructions[(call_idx + 1)..] {
            match instruction {
                Instruction::Call { target: CallTarget::External(_), .. } => {
                    found_intervening_call = true;
                }
                Instruction::Require { condition, message } => {
                    if !found_intervening_call {
                        let msg_lower = message.to_lowercase();
                        if msg_lower.contains("failed") ||
                           msg_lower.contains("success") ||
                           msg_lower.contains("transfer") ||
                           msg_lower.contains("call") {
                            found_success_require = true;
                        }

                        if self.value_uses_call_result(condition, result, function) {
                            return true;
                        }
                    }
                }
                _ => {}
            }
        }

        if found_success_require {
            return true;
        }

        let result_is_used = self.is_value_used_anywhere(result, function);
        if !result_is_used {
            return false;
        }

        for (_block_id, block) in &function.body.blocks {
            for instruction in &block.instructions {
                match instruction {
                    Instruction::Eq { left, right, .. } |
                    Instruction::Ne { left, right, .. } => {
                        if std::ptr::eq(left, result) || std::ptr::eq(right, result) {
                            return true;
                        }
                    }
                    _ => {}
                }
            }
        }

        false
    }

    fn is_value_used_anywhere(&self, value: &thalir_core::values::Value, function: &thalir_core::function::Function) -> bool {
        for (_block_id, block) in &function.body.blocks {
            for instruction in &block.instructions {
                match instruction {
                    Instruction::Require { condition, .. } => {
                        if std::ptr::eq(condition, value) {
                            return true;
                        }
                    }
                    Instruction::Eq { left, right, .. } |
                    Instruction::Ne { left, right, .. } |
                    Instruction::Lt { left, right, .. } |
                    Instruction::Gt { left, right, .. } |
                    Instruction::Le { left, right, .. } |
                    Instruction::Ge { left, right, .. } |
                    Instruction::And { left, right, .. } |
                    Instruction::Or { left, right, .. } => {
                        if std::ptr::eq(left, value) || std::ptr::eq(right, value) {
                            return true;
                        }
                    }
                    _ => {}
                }
            }
        }
        false
    }

    fn value_uses_call_result(&self, condition: &thalir_core::values::Value, result: &thalir_core::values::Value, function: &thalir_core::function::Function) -> bool {
        if std::ptr::eq(condition, result) {
            return true;
        }

        for (_block_id, block) in &function.body.blocks {
            for instruction in &block.instructions {
                match instruction {
                    Instruction::Eq { result: res, left, right } |
                    Instruction::Ne { result: res, left, right } |
                    Instruction::And { result: res, left, right } |
                    Instruction::Or { result: res, left, right } => {
                        if std::ptr::eq(res, condition)
                            && (std::ptr::eq(left, result) || std::ptr::eq(right, result)) {
                            return true;
                        }
                    }
                    _ => {}
                }
            }
        }

        false
    }
}

impl Pass for IRUncheckedReturnScanner {
    fn name(&self) -> &'static str {
        "ir-unchecked-return"
    }
    
    fn run_on_contract(&mut self, contract: &mut Contract, _manager: &mut PassManager) -> Result<()> {
        self.analyze(contract)?;
        Ok(())
    }
    
    fn required_analyses(&self) -> Vec<AnalysisID> {
        vec![AnalysisID::DefUse]
    }
    
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

impl Default for IRUncheckedReturnScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::core::Scanner for IRUncheckedReturnScanner {
    fn id(&self) -> &'static str {
        "ir-unchecked-return"
    }

    fn name(&self) -> &'static str {
        "IR Unchecked Return Scanner"
    }

    fn description(&self) -> &'static str {
        "Detects unchecked return values from external calls"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
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