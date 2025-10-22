//! Access control Scanner using IR analysis

use crate::core::{Confidence, Finding, Severity};
use thalir_core::{
    analysis::{
        cursor::ScannerCursor,
        pass::{Pass, PassManager, AnalysisID},
    },
    contract::Contract,
    instructions::Instruction,
    function::Visibility,
};
use anyhow::Result;
use std::collections::HashSet;

pub struct IRAccessControlScanner {
    findings: Vec<Finding>,
    source_code: Option<String>,
}

impl IRAccessControlScanner {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            source_code: None,
        }
    }

    pub fn with_source_code(mut self, source: String) -> Self {
        self.source_code = Some(source);
        self
    }
    
    pub fn get_findings(&self) -> Vec<Finding> {
        self.findings.clone()
    }
    
    pub fn analyze(&mut self, contract: &Contract) -> Result<Vec<Finding>> {
        self.findings.clear();

        let functions_with_modifiers = if let Some(ref source) = self.source_code {
            super::source::access_control::get_functions_with_modifiers(source, &contract.name)
        } else {
            std::collections::HashMap::new()
        };

        for (func_name, function) in &contract.functions {
            let base_func_name = func_name.split('_').next().unwrap_or(func_name);

            if functions_with_modifiers.contains_key(base_func_name) {
                continue;
            }
            if !self.is_public_state_changing_function(function) {
                continue;
            }
            
            let mut cursor = ScannerCursor::at_entry(function);
            let mut has_access_control = false;
            let mut has_state_modifications = false;
            let mut state_mod_instructions = Vec::new();
            let mut has_msg_sender_comparison = false;
            let mut has_require = false;
            let mut has_role_check = false;

            for block_id in cursor.traverse_dom_order() {
                let block = function.body.blocks.get(&block_id).unwrap();

                for (idx, instruction) in block.instructions.iter().enumerate() {
                    match instruction {
                        Instruction::Require { condition, message } => {
                            has_require = true;
                            if self.is_access_control_check(condition, function, message) {
                                has_access_control = true;
                            }
                        }

                        Instruction::Eq { left, right, .. } => {
                            if self.is_msg_sender_value(left, function) || self.is_msg_sender_value(right, function) {
                                has_msg_sender_comparison = true;
                            }
                        }

                        Instruction::MappingLoad { key, .. } => {
                            if self.is_msg_sender_value(key, function) {
                                has_role_check = true;
                            }
                        }
                        
                        Instruction::StorageStore { .. } => {
                            has_state_modifications = true;
                            state_mod_instructions.push((block_id, idx, instruction));
                        }

                        Instruction::MappingStore { key, .. } => {
                            let is_self_modification = self.is_msg_sender_value(key, function);

                            if !is_self_modification {
                                has_state_modifications = true;
                                state_mod_instructions.push((block_id, idx, instruction));
                            }
                        }

                        Instruction::ArrayStore { index, .. } => {
                            let is_self_modification = self.is_msg_sender_value(index, function);

                            if !is_self_modification {
                                has_state_modifications = true;
                                state_mod_instructions.push((block_id, idx, instruction));
                            }
                        }
                        
                        Instruction::Call { target, .. } => {
                            if let thalir_core::instructions::CallTarget::External(_) = target {
                                has_state_modifications = true;
                                state_mod_instructions.push((block_id, idx, instruction));
                            }
                        }
                        
                        Instruction::Selfdestruct { .. } => {
                            has_state_modifications = true;
                            state_mod_instructions.push((block_id, idx, instruction));
                        }
                        
                        _ => {}
                    }
                }
            }

            if has_msg_sender_comparison || has_role_check || has_require {
                has_access_control = true;
            }

            if has_state_modifications && !has_access_control {
                let has_critical_ops = state_mod_instructions.iter().any(|(_, _, instr)| {
                    matches!(instr,
                        Instruction::StorageStore { .. } |
                        Instruction::Call { target: thalir_core::instructions::CallTarget::External(_), .. } |
                        Instruction::Selfdestruct { .. }
                    )
                });

                if !has_critical_ops {
                    let func_lower = func_name.to_lowercase();

                    let is_permission_function = func_lower.contains("admin") ||
                                                 func_lower.contains("owner") ||
                                                 func_lower.contains("role") ||
                                                 func_lower.contains("grant") ||
                                                 func_lower.contains("revoke") ||
                                                 func_lower.contains("pause") ||
                                                 func_lower.contains("governance");

                    if is_permission_function {
                    } else {
                        let is_trivial_self_op = func_lower.contains("deposit") ||
                                                func_lower.contains("withdraw") ||
                                                func_lower.contains("claim") ||
                                                func_lower.contains("stake") ||
                                                func_lower.contains("unstake") ||
                                                func_lower.contains("test") ||  // Test functions
                                                func_lower.contains("simple") ||  // Simple example functions
                                                (state_mod_instructions.len() == 1 && !func_lower.contains("set"));  // Single operation, not a setter

                        if is_trivial_self_op {
                            continue;
                        }
                    }
                }

                let severity = self.determine_severity(func_name, &state_mod_instructions);
                let confidence = self.determine_confidence(func_name, function, &state_mod_instructions);

                let locations = state_mod_instructions.iter()
                    .map(|(block_id, idx, _)| {
                        super::provenance::get_instruction_location(
                            contract,
                            func_name,
                            *block_id,
                            *idx,
                        )
                    })
                    .collect();

                self.findings.push(Finding::new(
                    "missing-access-control".to_string(),
                    severity,
                    confidence,
                    format!("Missing access control in '{}'", func_name),
                    format!(
                        "Function '{}' in contract '{}' modifies contract state ({} operations) but lacks proper access control checks. This could allow unauthorized users to manipulate contract state",
                        func_name, contract.name, state_mod_instructions.len()
                    ),
                )
                .with_locations(locations)
                .with_contract(&contract.name)
                .with_function(func_name));
            }
            
            if has_access_control && has_state_modifications {
                self.check_weak_access_control(contract, func_name, function);
            }
        }
        
        Ok(self.findings.clone())
    }
    
    fn is_public_state_changing_function(&self, function: &thalir_core::function::Function) -> bool {
        match function.visibility {
            Visibility::Public | Visibility::External => true,
            Visibility::Internal | Visibility::Private => false,
        }
    }
    
    fn is_access_control_check(&self, condition: &thalir_core::values::Value, function: &thalir_core::function::Function, message: &str) -> bool {
        
        let message_lower = message.to_lowercase();
        let access_control_keywords = [
            "owner", "admin", "authorized", "permission", "access", "role", "only",
            "forbidden", "unauthorized", "denied", "caller", "sender"
        ];
        
        let has_access_keywords = access_control_keywords.iter()
            .any(|keyword| message_lower.contains(keyword));
        
        if has_access_keywords {
            return true;
        }
        
        if self.involves_msg_sender_check(condition, function) {
            return true;
        }
        
        if self.involves_role_check(condition, function) {
            return true;
        }
        
        false
    }
    
    fn involves_msg_sender_check(&self, condition: &thalir_core::values::Value, function: &thalir_core::function::Function) -> bool {
        for (_block_id, block) in &function.body.blocks {
            for instruction in &block.instructions {
                match instruction {
                    Instruction::Eq { result, left, right } => {
                        if std::ptr::eq(result, condition) {
                            if self.is_msg_sender_value(left, function) || 
                               self.is_msg_sender_value(right, function) {
                                return true;
                            }
                        }
                    }
                    
                    Instruction::Lt { result, left, right } |
                    Instruction::Gt { result, left, right } |
                    Instruction::Le { result, left, right } |
                    Instruction::Ge { result, left, right } |
                    Instruction::Ne { result, left, right } => {
                        if std::ptr::eq(result, condition) {
                            if self.is_msg_sender_value(left, function) || 
                               self.is_msg_sender_value(right, function) {
                                return true;
                            }
                        }
                    }
                    
                    _ => {}
                }
            }
        }
        
        false
    }
    
    fn is_msg_sender_value(&self, value: &thalir_core::values::Value, function: &thalir_core::function::Function) -> bool {

        let mut msg_sender_values: HashSet<*const thalir_core::values::Value> = HashSet::new();
        let mut worklist: Vec<*const thalir_core::values::Value> = Vec::new();

        for (_block_id, block) in &function.body.blocks {
            for instruction in &block.instructions {
                if let Instruction::GetContext { result, var } = instruction {
                    if let thalir_core::instructions::ContextVariable::MsgSender = var {
                        let ptr = result as *const thalir_core::values::Value;
                        msg_sender_values.insert(ptr);
                        worklist.push(ptr);
                    }
                }
            }
        }

        while let Some(current_ptr) = worklist.pop() {
            for (_block_id, block) in &function.body.blocks {
                for instruction in &block.instructions {
                    match instruction {
                        Instruction::Cast { result, value: src, .. } |
                        Instruction::ZeroExtend { result, value: src, .. } |
                        Instruction::SignExtend { result, value: src, .. } |
                        Instruction::Truncate { result, value: src, .. } => {
                            let src_ptr = src as *const thalir_core::values::Value;
                            if src_ptr == current_ptr {
                                let result_ptr = result as *const thalir_core::values::Value;
                                if msg_sender_values.insert(result_ptr) {
                                    worklist.push(result_ptr);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        let value_ptr = value as *const thalir_core::values::Value;
        msg_sender_values.contains(&value_ptr)
    }
    
    fn involves_role_check(&self, condition: &thalir_core::values::Value, function: &thalir_core::function::Function) -> bool {
        for (_block_id, block) in &function.body.blocks {
            for instruction in &block.instructions {
                match instruction {
                    Instruction::MappingLoad { result, key, .. } => {
                        if self.value_contributes_to_condition(result, condition, function) &&
                           self.is_msg_sender_value(key, function) {
                            return true;
                        }
                    }
                    _ => {}
                }
            }
        }
        
        false
    }
    
    fn value_contributes_to_condition(&self, value: &thalir_core::values::Value, condition: &thalir_core::values::Value, function: &thalir_core::function::Function) -> bool {
        std::ptr::eq(value, condition) || self.involves_msg_sender_check(condition, function)
    }
    
    fn determine_severity(&self, func_name: &str, state_modifications: &[(thalir_core::block::BlockId, usize, &Instruction)]) -> Severity {
        let func_lower = func_name.to_lowercase();

        let is_self_operation = func_lower.contains("withdraw") ||
                               func_lower.contains("deposit") ||
                               func_lower.contains("claim") ||
                               func_lower.contains("stake") ||
                               func_lower.contains("unstake");

        if is_self_operation {
            return Severity::Low;
        }

        let has_critical_ops = state_modifications.iter().any(|(_, _, instr)| {
            matches!(instr,
                Instruction::Selfdestruct { .. } |
                Instruction::Call { target: thalir_core::instructions::CallTarget::External(_), .. }
            )
        });

        let critical_function_patterns = [
            "setowner", "transferowner", "renounceowner",
            "mint", "burn", "destroy", "upgrade",
            "setadmin", "addadmin", "removeadmin", "admin", "governance",
            "emergency", "pause", "unpause", "freeze"
        ];

        let is_critical_function = critical_function_patterns.iter()
            .any(|pattern| func_lower.contains(pattern));

        let has_privileged_storage = state_modifications.iter().any(|(_, _, instr)| {
            match instr {
                Instruction::StorageStore { .. } => true,
                _ => false,
            }
        });

        if has_critical_ops || (is_critical_function && has_privileged_storage) {
            Severity::High
        } else if is_critical_function || state_modifications.len() > 2 {
            Severity::Medium
        } else {
            Severity::Low
        }
    }
    
    fn determine_confidence(&self, func_name: &str, function: &thalir_core::function::Function, state_modifications: &[(thalir_core::block::BlockId, usize, &Instruction)]) -> Confidence {
        let obvious_public_function = matches!(function.visibility, Visibility::Public | Visibility::External);
        let has_multiple_state_mods = state_modifications.len() > 1;

        let func_lower = func_name.to_lowercase();
        let is_constructor_like = func_lower.contains("constructor") || func_lower.contains("init");

        let is_self_operation = func_lower.contains("withdraw") ||
                               func_lower.contains("deposit") ||
                               func_lower.contains("claim") ||
                               func_lower.contains("stake") ||
                               func_lower.contains("unstake");

        if obvious_public_function && has_multiple_state_mods && !is_constructor_like && !is_self_operation {
            Confidence::High
        } else if obvious_public_function && !is_constructor_like && !is_self_operation {
            Confidence::Medium
        } else {
            Confidence::Low
        }
    }
    
    fn check_weak_access_control(&mut self, contract: &Contract, func_name: &str, function: &thalir_core::function::Function) {
        for (block_id, block) in &function.body.blocks {
            for (idx, instruction) in block.instructions.iter().enumerate() {
                if let Instruction::GetContext { result: _, var } = instruction {
                    if let thalir_core::instructions::ContextVariable::TxOrigin = var {
                        let location = super::provenance::get_instruction_location(
                            contract,
                            func_name,
                            *block_id,
                            idx,
                        );

                        self.findings.push(Finding::new(
                            "weak-access-control-tx-origin".to_string(),
                            Severity::Medium,
                            Confidence::High,
                            format!("Weak access control in '{}'", func_name),
                            format!(
                                "Function '{}' in contract '{}' uses tx.origin for access control, which is vulnerable to phishing attacks. Use msg.sender instead",
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
    }
}

impl Pass for IRAccessControlScanner {
    fn name(&self) -> &'static str {
        "ir-access-control"
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

impl Default for IRAccessControlScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::core::Scanner for IRAccessControlScanner {
    fn id(&self) -> &'static str {
        "ir-access-control"
    }

    fn name(&self) -> &'static str {
        "IR Access Control Scanner"
    }

    fn description(&self) -> &'static str {
        "Detects missing or weak access control patterns in public functions that modify state"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn scan(&self, context: &crate::core::AnalysisContext) -> Result<Vec<Finding>> {
        let ir_contract = context.get_representation::<thalir_core::contract::Contract>()?;

        let contract_info = context.contract_info();
        let mut scanner = Self::new();
        if let Some(ref source) = contract_info.source_code {
            scanner = scanner.with_source_code(source.clone());
        }

        scanner.analyze(ir_contract)
    }

    fn required_representations(&self) -> crate::representations::RepresentationSet {
        crate::representations::RepresentationSet::new()
            .require::<thalir_core::contract::Contract>()
    }
}