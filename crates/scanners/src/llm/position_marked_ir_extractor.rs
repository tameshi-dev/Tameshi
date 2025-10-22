use anyhow::Result;
use thalir_core::{
    block::{BasicBlock, Terminator},
    contract::Contract as IRContract,
    instructions::{CallTarget, Instruction},
    values::Value,
    Function,
};
use std::fmt::Write;

use super::representation::{
    RepresentationConfig, RepresentationExtractor, RepresentationSnippet, SnippetMetadata,
    TokenEstimator,
};
use crate::core::context::AnalysisContext;

#[derive(Debug)]
pub struct PositionMarkedIRExtractor {
    config: RepresentationConfig,
    include_types: bool,
    include_cfg: bool,
    simplify_ir: bool,
    include_position_markers: bool,
}

impl PositionMarkedIRExtractor {
    pub fn new(config: RepresentationConfig) -> Self {
        Self {
            config,
            include_types: true,
            include_cfg: true,
            simplify_ir: true,
            include_position_markers: true,
        }
    }

    pub fn with_options(
        config: RepresentationConfig,
        include_types: bool,
        include_cfg: bool,
        simplify_ir: bool,
    ) -> Self {
        Self {
            config,
            include_types,
            include_cfg,
            simplify_ir,
            include_position_markers: true,
        }
    }

    pub fn extract_from_ir(&self, contract: &IRContract) -> Result<RepresentationSnippet> {
        let mut output = String::new();
        let mut included_functions = Vec::new();
        let mut token_count = 0;
        let mut was_truncated = false;

        writeln!(output, "# Position-Marked IR Analysis for Contract: {}", contract.name)?;
        writeln!(output, "## IMPORTANT: Position markers [N] indicate temporal ordering")?;
        writeln!(output, "## For reentrancy: External call at [X] before state write at [Y] where X < Y = VULNERABLE\n")?;

        for (_name, func) in &contract.functions {
            let func_repr = self.format_function_with_positions(func)?;
            let func_tokens = TokenEstimator::estimate(&func_repr);

            if token_count + func_tokens > self.config.max_tokens {
                was_truncated = true;
                writeln!(output, "\n... (truncated due to token limit)")?;
                break;
            }

            output.push_str(&func_repr);
            token_count += func_tokens;
            included_functions.push(func.name().to_string());
        }

        Ok(RepresentationSnippet {
            content: output,
            token_count,
            metadata: SnippetMetadata {
                representation_type: "position_marked_ir".to_string(),
                extraction_strategy: "ir_with_ordering".to_string(),
                was_truncated,
                included_functions,
                included_contracts: vec![contract.name.clone()],
                source_location: None,
            },
        })
    }

    fn format_function_with_positions(&self, function: &Function) -> Result<String> {
        let mut output = String::new();

        writeln!(output, "\n### Function: {} ({:?})", function.name(), function.visibility)?;

        if !function.signature.params.is_empty() {
            writeln!(output, "Parameters:")?;
            for param in &function.signature.params {
                writeln!(output, "  {} : {:?}", param.name, param.param_type)?;
            }
        }

        if !function.signature.returns.is_empty() {
            writeln!(output, "Returns: {:?}", function.signature.returns)?;
        }

        let analysis = self.analyze_ordering(function);
        if !analysis.is_empty() {
            writeln!(output, "\n⚠️  ORDERING ANALYSIS:")?;
            writeln!(output, "{}", analysis)?;
        }

        writeln!(output, "\nInstructions (with position markers):")?;

        let mut global_pos = 0;

        for block in function.body.blocks.values() {
            self.format_block_with_positions(&mut output, block, &mut global_pos)?;
        }

        Ok(output)
    }

    fn analyze_ordering(&self, function: &Function) -> String {
        let mut analysis = String::new();
        let mut external_call_positions = Vec::new();
        let mut state_mod_positions = Vec::new();

        let mut global_pos = 0;

        for block in function.body.blocks.values() {
            for inst in &block.instructions {
                match inst {
                    Instruction::Call { target: CallTarget::External(_), .. } => {
                        external_call_positions.push(global_pos);
                    }
                    Instruction::StorageStore { .. } | Instruction::MappingStore { .. } => {
                        state_mod_positions.push(global_pos);
                    }
                    _ => {}
                }
                global_pos += 1;
            }
        }

        if !external_call_positions.is_empty() && !state_mod_positions.is_empty() {
            for &call_pos in &external_call_positions {
                for &mod_pos in &state_mod_positions {
                    if mod_pos > call_pos {
                        analysis.push_str(&format!(
                            "  - External call at position [{}] BEFORE state modification at [{}] → REENTRANCY RISK\n",
                            call_pos, mod_pos
                        ));
                    }
                }
            }
        }

        if !external_call_positions.is_empty() {
            analysis.push_str(&format!(
                "  - External calls at positions: {:?}\n",
                external_call_positions
            ));
        }

        if !state_mod_positions.is_empty() {
            analysis.push_str(&format!(
                "  - State modifications at positions: {:?}\n",
                state_mod_positions
            ));
        }

        analysis
    }

    fn format_block_with_positions(
        &self,
        output: &mut String,
        block: &BasicBlock,
        global_pos: &mut usize,
    ) -> Result<()> {
        writeln!(output, "\nBlock {} {{", block.id)?;

        if !block.params.is_empty() {
            write!(output, "  params: ")?;
            for (i, param) in block.params.iter().enumerate() {
                if i > 0 {
                    write!(output, ", ")?;
                }
                write!(output, "{}: {:?}", param.name, param.param_type)?;
            }
            writeln!(output)?;
        }

        for inst in &block.instructions {
            write!(output, "  [{}] ", global_pos)?;
            self.format_instruction(output, inst)?;
            writeln!(output)?;
            *global_pos += 1;
        }

        write!(output, "  ")?;
        self.format_terminator(output, &block.terminator)?;
        writeln!(output)?;

        writeln!(output, "}}")?;

        Ok(())
    }

    fn format_instruction(&self, output: &mut String, inst: &Instruction) -> Result<()> {
        match inst {
            Instruction::Call { result, target, .. } => {
                match target {
                    CallTarget::External(addr) => {
                        write!(output, "🔴 EXTERNAL_CALL {} = call External({})",
                               self.format_value(result), self.format_value(addr))?
                    }
                    CallTarget::Internal(name) => {
                        write!(output, "{} = call Internal({})",
                               self.format_value(result), name)?
                    }
                    CallTarget::Builtin(name) => {
                        write!(output, "{} = call Builtin({:?})",
                               self.format_value(result), name)?
                    }
                    CallTarget::Library(name) => {
                        write!(output, "{} = call Library({})",
                               self.format_value(result), name)?
                    }
                }
            }

            Instruction::StorageStore { key, value } => {
                write!(output, "🟡 STATE_WRITE storage_store {} <- {}",
                       self.format_storage_key(key), self.format_value(value))?
            }

            Instruction::MappingStore { mapping, key, value } => {
                write!(output, "🟡 STATE_WRITE mapping_store {}[{}] <- {}",
                       self.format_value(mapping),
                       self.format_value(key),
                       self.format_value(value))?
            }

            Instruction::Assign { result, value } => {
                write!(output, "{} = {}",
                       self.format_value(result),
                       self.format_value(value))?
            }

            Instruction::Add { result, left, right, .. } => {
                write!(output, "{} = add {}, {}",
                       self.format_value(result),
                       self.format_value(left),
                       self.format_value(right))?
            }

            Instruction::Sub { result, left, right, .. } => {
                write!(output, "{} = sub {}, {}",
                       self.format_value(result),
                       self.format_value(left),
                       self.format_value(right))?
            }

            Instruction::StorageLoad { result, key } => {
                write!(output, "{} = storage_load {:?}",
                       self.format_value(result), key)?
            }

            Instruction::MappingLoad { result, mapping, key } => {
                write!(output, "{} = mapping_load {}[{}]",
                       self.format_value(result),
                       self.format_value(mapping),
                       self.format_value(key))?
            }

            Instruction::Require { condition, message } => {
                write!(output, "require {} \"{}\"",
                       self.format_value(condition), message)?
            }

            Instruction::Assert { condition, message } => {
                write!(output, "assert {} \"{}\"",
                       self.format_value(condition), message)?
            }

            _ => write!(output, "{:?}", inst)?,
        }
        Ok(())
    }

    fn format_terminator(&self, output: &mut String, term: &Terminator) -> Result<()> {
        match term {
            Terminator::Return(val) => {
                if let Some(v) = val {
                    write!(output, "return {}", self.format_value(v))?
                } else {
                    write!(output, "return")?
                }
            }

            Terminator::Jump(target, args) => {
                write!(output, "jump {} (", target)?;
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        write!(output, ", ")?;
                    }
                    write!(output, "{}", self.format_value(arg))?;
                }
                write!(output, ")")?
            }

            Terminator::Branch { condition, then_block, else_block, .. } => {
                write!(output, "branch {} ? block_{} : block_{}",
                       self.format_value(condition), then_block, else_block)?
            }

            Terminator::Switch { value, default, cases } => {
                write!(output, "switch {} {{", self.format_value(value))?;
                for (case_val, target) in cases {
                    write!(output, " {}: {},", self.format_value(case_val), target)?;
                }
                write!(output, " default: {} }}", default)?
            }

            Terminator::Revert(msg) => write!(output, "revert \"{}\"", msg)?,
            Terminator::Panic(msg) => write!(output, "panic \"{}\"", msg)?,
            Terminator::Invalid => write!(output, "invalid")?,
        }
        Ok(())
    }

    fn format_value(&self, value: &Value) -> String {
        use thalir_core::values::{TempId, ParamId, GlobalId, VarId, StorageRefId, MemoryRefId};

        match value {
            Value::Register(id) => format!("%{:?}", id),
            Value::Variable(VarId(id)) => format!("v{}", id),
            Value::Temp(TempId(id)) => format!("temp_{}", id),
            Value::Param(ParamId(id)) => format!("param_{}", id),
            Value::BlockParam(bp) => format!("bp{}_{}", bp.block.0, bp.index),
            Value::Constant(c) => self.format_constant(c),
            Value::StorageRef(StorageRefId(id)) => format!("storage[{}]", id),
            Value::MemoryRef(MemoryRefId(id)) => format!("mem[{}]", id),
            Value::Global(GlobalId(id)) => format!("@global_{}", id),
            Value::Undefined => "undef".to_string(),
        }
    }

    fn format_constant(&self, constant: &thalir_core::values::Constant) -> String {
        use thalir_core::values::Constant;

        match constant {
            Constant::Uint(val, bits) => format!("uint{}({})", bits, val),
            Constant::Int(val, bits) => format!("int{}({})", bits, val),
            Constant::Bool(b) => b.to_string(),
            Constant::String(s) => format!("\"{}\"", s),
            Constant::Bytes(b) => format!("bytes[{}]", b.len()),
            Constant::Address(addr) => format!("address({:?})", addr),
            Constant::Null => "null".to_string(),
        }
    }

    fn format_storage_key(&self, key: &thalir_core::instructions::StorageKey) -> String {
        use thalir_core::instructions::StorageKey;

        match key {
            StorageKey::Slot(slot) => format!("Slot({})", slot),
            StorageKey::Dynamic(val) => format!("Dynamic({})", self.format_value(val)),
            StorageKey::Computed(val) => format!("Computed({})", self.format_value(val)),
            StorageKey::MappingKey { base, key } => format!("mapping[{}][{}]", base, self.format_value(key)),
            StorageKey::ArrayElement { base, index } => format!("array[{}][{}]", base, self.format_value(index)),
        }
    }
}

impl RepresentationExtractor for PositionMarkedIRExtractor {
    fn extract(&self, context: &AnalysisContext) -> Result<RepresentationSnippet> {
        match context.get_representation::<IRContract>() {
            Ok(contract) => {
                tracing::debug!(
                    "Extracting position-marked IR for contract: {}",
                    contract.name
                );

                self.extract_from_ir(&contract)
            }
            Err(e) => {
                tracing::warn!("Tameshi IR not available in context: {}", e);
                Ok(RepresentationSnippet::placeholder())
            }
        }
    }

    fn extract_focused(
        &self,
        _context: &AnalysisContext,
        _focus: &super::representation::Focus,
    ) -> Result<RepresentationSnippet> {
        Ok(RepresentationSnippet::placeholder())
    }

    fn representation_type(&self) -> &str {
        "position_marked_ir"
    }
}
