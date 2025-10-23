use anyhow::Result;
use std::collections::HashMap;
use std::fmt::Write;
use thalir_core::{
    block::BlockId,
    contract::Contract as IRContract,
    instructions::{CallTarget, Instruction},
    values::{Value, ValueId},
    Function,
};

pub struct IRFormatter {
    include_line_numbers: bool,
    simplify_names: bool,
    include_analysis: bool,
}

impl IRFormatter {
    pub fn new() -> Self {
        Self {
            include_line_numbers: true,
            simplify_names: true,
            include_analysis: true,
        }
    }

    pub fn format_for_vulnerability_detection(
        &self,
        contract: &IRContract,
        focus: VulnerabilityFocus,
    ) -> Result<String> {
        let mut output = String::new();

        writeln!(output, "# Vulnerability Analysis Context\n")?;
        writeln!(output, "Focus: {:?}\n", focus)?;

        match focus {
            VulnerabilityFocus::Reentrancy => {
                self.format_reentrancy_context(&mut output, contract)?;
            }
            VulnerabilityFocus::AccessControl => {
                self.format_access_control_context(&mut output, contract)?;
            }
            VulnerabilityFocus::IntegerOverflow => {
                self.format_arithmetic_context(&mut output, contract)?;
            }
            VulnerabilityFocus::UncheckedReturns => {
                self.format_call_context(&mut output, contract)?;
            }
            VulnerabilityFocus::General => {
                self.format_general_context(&mut output, contract)?;
            }
        }

        Ok(output)
    }

    fn format_reentrancy_context(&self, output: &mut String, contract: &IRContract) -> Result<()> {
        writeln!(output, "## Reentrancy Analysis\n")?;

        for (_name, func) in &contract.functions {
            let external_calls = self.find_external_calls(func);
            let state_modifications = self.find_state_modifications(func);

            if external_calls.is_empty() && state_modifications.is_empty() {
                continue;
            }

            writeln!(output, "### Function: {}", func.name())?;

            if !external_calls.is_empty() {
                writeln!(output, "\nExternal Calls:")?;
                for (block_id, inst_idx, call) in &external_calls {
                    writeln!(
                        output,
                        "  - Block {}, Inst {}: {}",
                        block_id,
                        inst_idx,
                        self.format_call_brief(call)?
                    )?;
                }
            }

            if !state_modifications.is_empty() {
                writeln!(output, "\nState Modifications:")?;
                for (block_id, inst_idx, modif) in &state_modifications {
                    writeln!(
                        output,
                        "  - Block {}, Inst {}: {}",
                        block_id,
                        inst_idx,
                        self.format_state_modification_brief(modif)?
                    )?;
                }
            }

            if !external_calls.is_empty() && !state_modifications.is_empty() {
                writeln!(output, "\nOrdering Analysis:")?;
                self.analyze_call_state_ordering(
                    output,
                    func,
                    &external_calls,
                    &state_modifications,
                )?;
            }

            writeln!(output)?;
        }

        Ok(())
    }

    fn format_access_control_context(
        &self,
        output: &mut String,
        contract: &IRContract,
    ) -> Result<()> {
        writeln!(output, "## Access Control Analysis\n")?;

        for (_name, func) in &contract.functions {
            let vis_str = format!("{:?}", func.visibility);
            if vis_str == "Private" || vis_str == "Internal" {
                continue;
            }

            writeln!(
                output,
                "### Function: {} ({:?})",
                func.name(),
                func.visibility
            )?;

            let checks = self.find_access_checks(func);
            if !checks.is_empty() {
                writeln!(output, "\nAccess Checks:")?;
                for (block_id, check) in checks {
                    writeln!(output, "  - Block {}: {}", block_id, check)?;
                }
            } else {
                writeln!(output, "\n⚠️ No explicit access checks found")?;
            }

            let sensitive_ops = self.find_sensitive_operations(func);
            if !sensitive_ops.is_empty() {
                writeln!(output, "\nSensitive Operations:")?;
                for (block_id, op) in sensitive_ops {
                    writeln!(output, "  - Block {}: {}", block_id, op)?;
                }
            }

            writeln!(output)?;
        }

        Ok(())
    }

    fn format_arithmetic_context(&self, output: &mut String, contract: &IRContract) -> Result<()> {
        writeln!(output, "## Arithmetic Operations Analysis\n")?;

        for (_name, func) in &contract.functions {
            let arithmetic_ops = self.find_arithmetic_operations(func);

            if arithmetic_ops.is_empty() {
                continue;
            }

            writeln!(output, "### Function: {}", func.name())?;
            writeln!(output, "\nArithmetic Operations:")?;

            for (block_id, inst_idx, op, checked) in arithmetic_ops {
                let status = if checked {
                    "✓ checked"
                } else {
                    "⚠️ unchecked"
                };
                writeln!(
                    output,
                    "  - Block {}, Inst {}: {} [{}]",
                    block_id, inst_idx, op, status
                )?;
            }

            writeln!(output)?;
        }

        Ok(())
    }

    fn format_call_context(&self, output: &mut String, contract: &IRContract) -> Result<()> {
        writeln!(output, "## Call Return Value Analysis\n")?;

        for (_name, func) in &contract.functions {
            let calls = self.find_external_calls(func);

            if calls.is_empty() {
                continue;
            }

            writeln!(output, "### Function: {}", func.name())?;
            writeln!(output, "\nExternal Calls:")?;

            for (block_id, inst_idx, call_inst) in calls {
                if let Instruction::Call { result, target, .. } = call_inst {
                    let status = if self.is_value_used(func, result) {
                        "✓ return value used"
                    } else {
                        "⚠️ return value ignored"
                    };

                    writeln!(
                        output,
                        "  - Block {}, Inst {}: call to {:?} [{}]",
                        block_id, inst_idx, target, status
                    )?;
                }
            }

            writeln!(output)?;
        }

        Ok(())
    }

    fn format_general_context(&self, output: &mut String, contract: &IRContract) -> Result<()> {
        writeln!(output, "## General IR Analysis\n")?;

        for (_name, func) in &contract.functions {
            writeln!(
                output,
                "### Function: {} ({:?})",
                func.name(),
                func.visibility
            )?;
            writeln!(output, "Blocks: {}", func.body.blocks.len())?;

            let mut inst_stats = HashMap::new();
            for block in func.body.blocks.values() {
                for inst in &block.instructions {
                    *inst_stats
                        .entry(self.instruction_category(inst))
                        .or_insert(0) += 1;
                }
            }

            writeln!(output, "\nInstruction Summary:")?;
            for (category, count) in inst_stats {
                writeln!(output, "  - {}: {}", category, count)?;
            }

            writeln!(output)?;
        }

        Ok(())
    }

    fn find_external_calls<'a>(
        &self,
        func: &'a Function,
    ) -> Vec<(BlockId, usize, &'a Instruction)> {
        let mut calls = Vec::new();

        for block in func.body.blocks.values() {
            for (idx, inst) in block.instructions.iter().enumerate() {
                if let Instruction::Call { target, .. } = inst {
                    if self.is_external_call(target) {
                        calls.push((block.id, idx, inst));
                    }
                }
            }
        }

        calls
    }

    fn find_state_modifications<'a>(
        &self,
        func: &'a Function,
    ) -> Vec<(BlockId, usize, &'a Instruction)> {
        let mut modifications = Vec::new();

        for block in func.body.blocks.values() {
            for (idx, inst) in block.instructions.iter().enumerate() {
                match inst {
                    Instruction::StorageStore { .. }
                    | Instruction::MappingStore { .. }
                    | Instruction::ArrayStore { .. } => {
                        modifications.push((block.id, idx, inst));
                    }
                    _ => {}
                }
            }
        }

        modifications
    }

    fn find_access_checks(&self, func: &Function) -> Vec<(BlockId, String)> {
        let mut checks = Vec::new();

        for block in func.body.blocks.values() {
            for inst in &block.instructions {
                match inst {
                    Instruction::Assert { condition, message }
                    | Instruction::Require { condition, message } => {
                        checks.push((
                            block.id,
                            format!(
                                "require({}): {}",
                                self.format_value_brief(condition),
                                message
                            ),
                        ));
                    }
                    _ => {}
                }
            }
        }

        checks
    }

    fn find_sensitive_operations(&self, func: &Function) -> Vec<(BlockId, String)> {
        let mut ops = Vec::new();

        for block in func.body.blocks.values() {
            for inst in &block.instructions {
                match inst {
                    Instruction::Call {
                        target,
                        value: Some(_),
                        ..
                    } => {
                        ops.push((block.id, format!("Value transfer to {:?}", target)));
                    }
                    Instruction::StorageStore { .. } => {
                        ops.push((block.id, "Storage modification".to_string()));
                    }
                    Instruction::Selfdestruct { .. } => {
                        ops.push((block.id, "Self destruct".to_string()));
                    }
                    _ => {}
                }
            }
        }

        ops
    }

    fn find_arithmetic_operations(&self, func: &Function) -> Vec<(BlockId, usize, String, bool)> {
        let mut ops = Vec::new();

        for block in func.body.blocks.values() {
            for (idx, inst) in block.instructions.iter().enumerate() {
                match inst {
                    Instruction::Add { left, right, .. }
                    | Instruction::Sub { left, right, .. }
                    | Instruction::Mul { left, right, .. }
                    | Instruction::Div { left, right, .. } => {
                        let op_name = match inst {
                            Instruction::Add { .. } => "add",
                            Instruction::Sub { .. } => "sub",
                            Instruction::Mul { .. } => "mul",
                            Instruction::Div { .. } => "div",
                            _ => "op",
                        };
                        let op_str = format!(
                            "{}({}, {})",
                            op_name,
                            self.format_value_brief(left),
                            self.format_value_brief(right)
                        );
                        ops.push((block.id, idx, op_str, false));
                    }
                    Instruction::CheckedAdd { left, right, .. }
                    | Instruction::CheckedSub { left, right, .. }
                    | Instruction::CheckedMul { left, right, .. }
                    | Instruction::CheckedDiv { left, right, .. } => {
                        let op_name = match inst {
                            Instruction::CheckedAdd { .. } => "checked_add",
                            Instruction::CheckedSub { .. } => "checked_sub",
                            Instruction::CheckedMul { .. } => "checked_mul",
                            Instruction::CheckedDiv { .. } => "checked_div",
                            _ => "checked_op",
                        };
                        let op_str = format!(
                            "{}({}, {})",
                            op_name,
                            self.format_value_brief(left),
                            self.format_value_brief(right)
                        );
                        ops.push((block.id, idx, op_str, true));
                    }
                    _ => {}
                }
            }
        }

        ops
    }

    fn analyze_call_state_ordering(
        &self,
        output: &mut String,
        _func: &Function,
        calls: &[(BlockId, usize, &Instruction)],
        state_mods: &[(BlockId, usize, &Instruction)],
    ) -> Result<()> {
        for (call_block, call_idx, _) in calls {
            for (mod_block, mod_idx, _) in state_mods {
                if call_block == mod_block && call_idx < mod_idx {
                    writeln!(
                        output,
                        "  ⚠️ External call at {}.{} before state modification at {}.{}",
                        call_block, call_idx, mod_block, mod_idx
                    )?;
                } else if call_block.0 < mod_block.0 {
                    writeln!(
                        output,
                        "  ⚠️ External call in block {} before state modification in block {}",
                        call_block, mod_block
                    )?;
                }
            }
        }

        Ok(())
    }

    fn is_external_call(&self, target: &CallTarget) -> bool {
        match target {
            CallTarget::External(_) => true,
            CallTarget::Internal(_) | CallTarget::Library(_) | CallTarget::Builtin(_) => false,
        }
    }

    fn is_value_used(&self, func: &Function, value: &Value) -> bool {
        if let Value::Register(id) = value {
            for block in func.body.blocks.values() {
                for inst in &block.instructions {
                    if self.instruction_uses_value(inst, *id) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn instruction_uses_value(&self, inst: &Instruction, value_id: ValueId) -> bool {
        if let Instruction::Assign {
            value: Value::Register(id),
            ..
        } = inst
        {
            return *id == value_id;
        }
        false
    }

    fn instruction_category(&self, inst: &Instruction) -> &'static str {
        match inst {
            Instruction::Call { .. }
            | Instruction::DelegateCall { .. }
            | Instruction::StaticCall { .. } => "Calls",

            Instruction::StorageStore { .. }
            | Instruction::MappingStore { .. }
            | Instruction::Add { .. }
            | Instruction::Sub { .. }
            | Instruction::Mul { .. }
            | Instruction::Div { .. } => "Arithmetic",

            Instruction::Assert { .. } | Instruction::Require { .. } => "Checks",

            _ => "Other",
        }
    }

    fn format_call_brief(&self, inst: &Instruction) -> Result<String> {
        if let Instruction::Call { target, args, .. } = inst {
            Ok(format!("call({:?}) with {} args", target, args.len()))
        } else {
            Ok("not a call".to_string())
        }
    }

    fn format_state_modification_brief(&self, inst: &Instruction) -> Result<String> {
        match inst {
            Instruction::StorageStore { key, value } => {
                Ok(format!("storage[{:?}] = {:?}", key, value))
            }
            Instruction::MappingStore {
                mapping,
                key,
                value,
            } => Ok(format!("mapping[{:?}][{:?}] = {:?}", mapping, key, value)),
            _ => Ok("state modification".to_string()),
        }
    }

    fn format_value_brief(&self, value: &Value) -> String {
        match value {
            Value::Register(id) => format!("r{:?}", id),
            Value::Variable(id) => format!("v{:?}", id),
            Value::Temp(id) => format!("t{:?}", id),
            Value::Constant(c) => format!("#{:?}", c),
            _ => "value".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum VulnerabilityFocus {
    Reentrancy,
    AccessControl,
    IntegerOverflow,
    UncheckedReturns,
    General,
}

impl Default for IRFormatter {
    fn default() -> Self {
        Self::new()
    }
}
