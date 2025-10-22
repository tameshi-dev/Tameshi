//! Cross-function reentrancy vulnerability Scanner using IR analysis

use crate::core::{Confidence, Finding, Severity};
use thalir_core::{
    analysis::{
        cursor::ScannerCursor,
        pass::{Pass, PassManager, AnalysisID},
    },
    contract::Contract,
    instructions::{Instruction, CallTarget, StorageKey},
};
use anyhow::Result;
use std::collections::HashMap;

pub struct IRCrossFunctionReentrancyScanner {
    findings: Vec<Finding>,
}

#[derive(Debug, Clone)]
struct FunctionState {
    external_calls: Vec<(thalir_core::block::BlockId, usize)>,
    state_writes: Vec<(thalir_core::block::BlockId, usize, StorageKey)>,
    state_reads: Vec<(thalir_core::block::BlockId, usize, StorageKey)>,
    modifies_storage: bool,
    has_external_calls: bool,
}

impl IRCrossFunctionReentrancyScanner {
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
        
        let mut function_states = HashMap::new();
        
        for (func_name, function) in &contract.functions {
            let mut state = FunctionState {
                external_calls: Vec::new(),
                state_writes: Vec::new(),
                state_reads: Vec::new(),
                modifies_storage: false,
                has_external_calls: false,
            };
            
            let mut cursor = ScannerCursor::at_entry(function);
            
            for block_id in cursor.traverse_dom_order() {
                let block = function.body.blocks.get(&block_id).unwrap();
                
                for (idx, instruction) in block.instructions.iter().enumerate() {
                    match instruction {
                        Instruction::Call { target, .. } => {
                            if self.is_external_call(target) {
                                state.external_calls.push((block_id, idx));
                                state.has_external_calls = true;
                            }
                        }
                        
                        Instruction::StorageStore { key, .. } => {
                            state.state_writes.push((block_id, idx, key.clone()));
                            state.modifies_storage = true;
                        }
                        
                        Instruction::StorageLoad { key, .. } => {
                            state.state_reads.push((block_id, idx, key.clone()));
                        }
                        
                        _ => {}
                    }
                }
            }
            
            function_states.insert(func_name.clone(), state);
        }
        
        self.analyze_cross_function_patterns(contract, &function_states);
        self.analyze_shared_state_risks(contract, &function_states);
        self.analyze_state_transition_risks(contract, &function_states);
        
        Ok(self.findings.clone())
    }
    
    fn is_external_call(&self, target: &CallTarget) -> bool {
        match target {
            CallTarget::External(_) => true,
            CallTarget::Library(_) => true,
            CallTarget::Internal(_) => false,
            CallTarget::Builtin(_) => false,
        }
    }
    
    fn analyze_cross_function_patterns(
        &mut self,
        contract: &Contract,
        function_states: &HashMap<String, FunctionState>
    ) {
        let mut risky_functions = Vec::new();

        for (func_name, state) in function_states {
            if state.has_external_calls && state.modifies_storage {
                risky_functions.push(func_name);
            }
        }

        if risky_functions.len() > 1 {
            self.findings.push(Finding::new(
                "cross-function-reentrancy-risk".to_string(),
                Severity::High,
                Confidence::High,
                "Cross-function reentrancy vulnerability".to_string(),
                format!(
                    "Contract '{}' has {} functions ({}) that both make external calls and modify storage. This creates risk for cross-function reentrancy attacks where one function can be re-entered while another is executing, leading to inconsistent state",
                    contract.name, risky_functions.len(), risky_functions.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                ),
            )
            .with_contract(&contract.name));
        }

        for func_name in &risky_functions {
            let state = &function_states[*func_name];

            if state.external_calls.len() > 1 && state.state_writes.len() > 2 {
                if let Some((block_id, idx)) = state.external_calls.first() {
                    let location = super::provenance::get_instruction_location(
                        contract,
                        func_name,
                        *block_id,
                        *idx,
                    );

                    self.findings.push(Finding::new(
                        "high-risk-reentrancy-function".to_string(),
                        Severity::High,
                        Confidence::High,
                        format!("High-risk reentrancy function '{}'", func_name),
                        format!(
                            "Function '{}' in contract '{}' makes {} external calls and performs {} state writes. This is a high-risk pattern for reentrancy attacks. Consider implementing checks-effects-interactions pattern",
                            func_name, contract.name, state.external_calls.len(), state.state_writes.len()
                        ),
                    )
                    .with_location(location)
                    .with_contract(&contract.name)
                    .with_function(func_name));
                }
            }
        }
    }
    
    fn analyze_shared_state_risks(
        &mut self,
        contract: &Contract,
        function_states: &HashMap<String, FunctionState>
    ) {
        let mut key_to_functions: HashMap<String, Vec<String>> = HashMap::new();
        
        for (func_name, state) in function_states {
            for (_, _, key) in &state.state_writes {
                let key_str = format!("{:?}", key);
                key_to_functions.entry(key_str).or_default().push(func_name.clone());
            }
            for (_, _, key) in &state.state_reads {
                let key_str = format!("{:?}", key);
                key_to_functions.entry(key_str).or_default().push(func_name.clone());
            }
        }
        
        for (key, accessing_functions) in key_to_functions {
            if accessing_functions.len() > 1 {
                let risky_functions: Vec<&String> = accessing_functions.iter()
                    .filter(|fname| function_states[*fname].has_external_calls)
                    .collect();
                
                if risky_functions.len() > 1 {
                    self.findings.push(Finding::new(
                        "shared-state-reentrancy".to_string(),
                        Severity::Medium,
                        Confidence::High,
                        "Shared state reentrancy risk".to_string(),
                        format!(
                            "Storage key '{}' in contract '{}' is accessed by {} functions that also make external calls ({}). This creates risk for cross-function reentrancy where one function's state changes affect another",
                            key, contract.name, risky_functions.len(), risky_functions.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                        ),
                    )
                    .with_contract(&contract.name));
                }
            }
        }
    }
    
    fn analyze_state_transition_risks(
        &mut self,
        contract: &Contract,
        function_states: &HashMap<String, FunctionState>
    ) {
        for (func_name, state) in function_states {
            if state.state_reads.is_empty() || state.external_calls.is_empty() || state.state_writes.is_empty() {
                continue;
            }
            
            let mut earliest_read = usize::MAX;
            let mut latest_call = 0;
            let mut earliest_write_after_call = usize::MAX;
            
            for (block_id, idx, _) in &state.state_reads {
                let position = self.calculate_instruction_position(*block_id, *idx);
                earliest_read = earliest_read.min(position);
            }
            
            for (block_id, idx) in &state.external_calls {
                let position = self.calculate_instruction_position(*block_id, *idx);
                latest_call = latest_call.max(position);
            }
            
            for (block_id, idx, _) in &state.state_writes {
                let position = self.calculate_instruction_position(*block_id, *idx);
                if position > latest_call {
                    earliest_write_after_call = earliest_write_after_call.min(position);
                }
            }
            
            if earliest_read < latest_call && earliest_write_after_call < usize::MAX {
                if let Some((block_id, idx)) = state.external_calls.first() {
                    let location = super::provenance::get_instruction_location(
                        contract,
                        func_name,
                        *block_id,
                        *idx,
                    );

                    self.findings.push(Finding::new(
                        "read-call-write-pattern".to_string(),
                        Severity::High,
                        Confidence::Medium,
                        format!("Dangerous state transition pattern in '{}'", func_name),
                        format!(
                            "Function '{}' in contract '{}' follows a read-call-write pattern: reads storage, makes external calls, then writes storage. This is vulnerable to reentrancy where the external call can modify state between read and write operations",
                            func_name, contract.name
                        ),
                    )
                    .with_location(location)
                    .with_contract(&contract.name)
                    .with_function(func_name));
                }
            }
        }
    }
    
    fn calculate_instruction_position(&self, block_id: thalir_core::block::BlockId, instruction_idx: usize) -> usize {
        let block_num = match block_id {
            thalir_core::block::BlockId(id) => id as usize,
        };
        block_num * 1000 + instruction_idx
    }
}

impl Pass for IRCrossFunctionReentrancyScanner {
    fn name(&self) -> &'static str {
        "ir-cross-function-reentrancy"
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

impl Default for IRCrossFunctionReentrancyScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::core::Scanner for IRCrossFunctionReentrancyScanner {
    fn id(&self) -> &'static str {
        "ir-cross-function-reentrancy"
    }

    fn name(&self) -> &'static str {
        "IR Cross-Function Reentrancy Scanner"
    }

    fn description(&self) -> &'static str {
        "Detects cross-function reentrancy vulnerabilities where multiple functions share state and can be re-entered"
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