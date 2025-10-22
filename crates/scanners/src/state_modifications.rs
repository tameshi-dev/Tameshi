//! State modification analysis Scanner

use crate::core::{Confidence, Finding, Severity};
use thalir_core::{
    analysis::{
        cursor::ScannerCursor,
        pass::{Pass, PassManager},
    },
    contract::Contract,
    instructions::Instruction,
};
use anyhow::Result;

pub struct IRStateModificationScanner {
    findings: Vec<Finding>,
}

impl IRStateModificationScanner {
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
            let mut state_mod_count = 0;
            let mut first_mod_location: Option<(thalir_core::block::BlockId, usize)> = None;

            for block_id in cursor.traverse_dom_order() {
                let block = function.body.blocks.get(&block_id).unwrap();

                for (idx, instruction) in block.instructions.iter().enumerate() {
                    match instruction {
                        Instruction::StorageStore { .. } |
                        Instruction::MappingStore { .. } |
                        Instruction::ArrayStore { .. } => {
                            if first_mod_location.is_none() {
                                first_mod_location = Some((block_id, idx));
                            }
                            state_mod_count += 1;
                        }
                        _ => {}
                    }
                }
            }

            if state_mod_count > 10 {
                if let Some((block_id, idx)) = first_mod_location {
                    let location = super::provenance::get_instruction_location(
                        contract,
                        func_name,
                        block_id,
                        idx,
                    );

                    self.findings.push(Finding::new(
                        "excessive-state-mods".to_string(),
                        Severity::Low,
                        Confidence::Low,
                        format!("Excessive state modifications in '{}'", func_name),
                        format!(
                            "Function '{}' in contract '{}' has {} state modifications, which may indicate complexity issues",
                            func_name, contract.name, state_mod_count
                        ),
                    )
                    .with_location(location)
                    .with_contract(&contract.name)
                    .with_function(func_name));
                }
            }
        }
        
        Ok(self.findings.clone())
    }
}

impl Pass for IRStateModificationScanner {
    fn name(&self) -> &'static str {
        "ir-state-mods"
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

impl Default for IRStateModificationScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::core::Scanner for IRStateModificationScanner {
    fn id(&self) -> &'static str {
        "ir-state-modifications"
    }

    fn name(&self) -> &'static str {
        "IR State Modification Scanner"
    }

    fn description(&self) -> &'static str {
        "Detects suspicious patterns in state modifications such as excessive modifications"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
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