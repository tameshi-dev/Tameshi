//! Dangerous functions Scanner using IR analysis

use crate::core::{Confidence, Finding, Severity};
use thalir_core::{
    analysis::{
        cursor::ScannerCursor,
        pass::{Pass, PassManager},
    },
    contract::Contract,
    instructions::{Instruction, CallTarget, BuiltinFunction},
};
use anyhow::Result;

pub struct IRDangerousFunctionsScanner {
    findings: Vec<Finding>,
}

impl IRDangerousFunctionsScanner {
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
                    match instruction {
                        Instruction::Call { target, .. } => {
                            match target {
                                CallTarget::Builtin(builtin) => {
                                    self.check_dangerous_builtin(contract, func_name, builtin, block_id, idx);
                                }
                                CallTarget::Internal(function_name) => {
                                    self.check_dangerous_internal_function(contract, func_name, function_name, block_id, idx);
                                }
                                _ => {}
                            }
                        }
                        Instruction::DelegateCall { .. } => {
                            let location = super::provenance::get_instruction_location(
                                contract,
                                func_name,
                                block_id,
                                idx,
                            );

                            self.findings.push(Finding::new(
                                "dangerous-delegatecall".to_string(),
                                Severity::High,
                                Confidence::High,
                                format!("Dangerous delegatecall in '{}'", func_name),
                                format!(
                                    "Function '{}' in contract '{}' uses delegatecall, which can be dangerous as it executes code in the current contract's context",
                                    func_name, contract.name
                                ),
                            )
                            .with_location(location)
                            .with_contract(&contract.name)
                            .with_function(func_name));
                        }
                        Instruction::Selfdestruct { .. } => {
                            let location = super::provenance::get_instruction_location(
                                contract,
                                func_name,
                                block_id,
                                idx,
                            );

                            self.findings.push(Finding::new(
                                "dangerous-selfdestruct".to_string(),
                                Severity::High,
                                Confidence::High,
                                format!("Dangerous selfdestruct in '{}'", func_name),
                                format!(
                                    "Function '{}' in contract '{}' uses selfdestruct, which permanently destroys the contract",
                                    func_name, contract.name
                                ),
                            )
                            .with_location(location)
                            .with_contract(&contract.name)
                            .with_function(func_name));
                        }
                        _ => {}
                    }
                }
            }
        }
        
        Ok(self.findings.clone())
    }
    
    fn check_dangerous_builtin(&mut self, _contract: &Contract, _func_name: &str, _builtin: &BuiltinFunction, _block_id: thalir_core::block::BlockId, _idx: usize) {
    }

    fn check_dangerous_internal_function(&mut self, contract: &Contract, func_name: &str, target_name: &str, block_id: thalir_core::block::BlockId, idx: usize) {
        let dangerous_patterns = [
            "selfdestruct",
            "suicide", // Old name for selfdestruct
            "delegatecall",
            "callcode", // Deprecated dangerous function
        ];

        for pattern in &dangerous_patterns {
            if target_name.to_lowercase().contains(pattern) {
                let location = super::provenance::get_instruction_location(
                    contract,
                    func_name,
                    block_id,
                    idx,
                );

                self.findings.push(Finding::new(
                    format!("dangerous-function-{}", pattern),
                    Severity::Medium,
                    Confidence::Medium,
                    format!("Potentially dangerous function call in '{}'", func_name),
                    format!(
                        "Function '{}' in contract '{}' calls function '{}' which may be dangerous",
                        func_name, contract.name, target_name
                    ),
                )
                .with_location(location)
                .with_contract(&contract.name)
                .with_function(func_name));
            }
        }
    }
}

impl Pass for IRDangerousFunctionsScanner {
    fn name(&self) -> &'static str {
        "ir-dangerous-functions"
    }
    
    fn run_on_contract(&mut self, contract: &mut Contract, _manager: &mut PassManager) -> Result<()> {
        self.analyze(contract)?;
        Ok(())
    }
    
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

impl Default for IRDangerousFunctionsScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::core::Scanner for IRDangerousFunctionsScanner {
    fn id(&self) -> &'static str {
        "ir-dangerous-functions"
    }

    fn name(&self) -> &'static str {
        "IR Dangerous Functions Scanner"
    }

    fn description(&self) -> &'static str {
        "Detects dangerous function calls like delegatecall, selfdestruct, and deprecated operations"
    }

    fn severity(&self) -> Severity {
        Severity::High
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