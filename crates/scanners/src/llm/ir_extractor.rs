use anyhow::Result;
use thalir_core::{
    block::{BasicBlock, Terminator},
    contract::Contract as IRContract,
    instructions::Instruction,
    types::Type,
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
pub struct IRExtractor {
    config: RepresentationConfig,
    include_types: bool,
    include_cfg: bool,
    include_dominance: bool,
    simplify_ir: bool,
}

impl IRExtractor {
    pub fn new(config: RepresentationConfig) -> Self {
        Self {
            config,
            include_types: true,
            include_cfg: true,
            include_dominance: false,
            simplify_ir: true,
        }
    }

    pub fn with_options(
        config: RepresentationConfig,
        include_types: bool,
        include_cfg: bool,
        include_dominance: bool,
        simplify_ir: bool,
    ) -> Self {
        Self {
            config,
            include_types,
            include_cfg,
            include_dominance,
            simplify_ir,
        }
    }

    pub fn extract_from_ir(&self, contract: &IRContract) -> Result<RepresentationSnippet> {
        let mut output = String::new();
        let mut included_functions = Vec::new();
        let mut token_count = 0;
        let mut was_truncated = false;

        writeln!(output, "# Tameshi IR Analysis for Contract")?;
        writeln!(output, "## SSA Form Intermediate Representation\n")?;

        for (_name, func) in &contract.functions {
            let func_repr = self.format_function(func)?;
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
                representation_type: "cranelift_ir".to_string(),
                extraction_strategy: "ir_ssa".to_string(),
                was_truncated,
                included_functions,
                included_contracts: vec![],
                source_location: None,
            },
        })
    }

    fn format_function(&self, function: &Function) -> Result<String> {
        let mut output = String::new();

        writeln!(output, "\n### Function: {}", function.name())?;
        writeln!(output, "Visibility: {:?}", function.visibility)?;

        if !function.signature.params.is_empty() {
            writeln!(output, "Parameters:")?;
            for param in &function.signature.params {
                writeln!(output, "  {} : {:?}", param.name, param.param_type)?;
            }
        }

        if !function.signature.returns.is_empty() {
            writeln!(output, "Returns: {:?}", function.signature.returns)?;
        }

        writeln!(output, "\nBlocks:")?;

        for block in function.body.blocks.values() {
            self.format_block(&mut output, block)?;
        }

        Ok(output)
    }

    fn format_block(&self, output: &mut String, block: &BasicBlock) -> Result<()> {
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
            write!(output, "  ")?;
            self.format_instruction(output, inst)?;
            writeln!(output)?;
        }

        write!(output, "  ")?;
        self.format_terminator(output, &block.terminator)?;
        writeln!(output)?;

        writeln!(output, "}}")?;

        Ok(())
    }

    fn format_instruction(&self, output: &mut String, inst: &Instruction) -> Result<()> {
        match inst {
            Instruction::Assign { result, value } => write!(
                output,
                "{} = {}",
                self.format_value(result),
                self.format_value(value)
            )?,

            Instruction::Call {
                result,
                target,
                args,
                ..
            } => {
                write!(
                    output,
                    "{} = call {:?} (",
                    self.format_value(result),
                    target
                )?;
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        write!(output, ", ")?;
                    }
                    write!(output, "{}", self.format_value(arg))?;
                }
                write!(output, ")")?
            }

            Instruction::Add {
                result,
                left,
                right,
                ..
            } => write!(
                output,
                "{} = add {}, {}",
                self.format_value(result),
                self.format_value(left),
                self.format_value(right)
            )?,

            Instruction::Sub {
                result,
                left,
                right,
                ..
            } => write!(
                output,
                "{} = sub {}, {}",
                self.format_value(result),
                self.format_value(left),
                self.format_value(right)
            )?,

            Instruction::StorageStore { key, value } => write!(
                output,
                "storage_store {:?} <- {}",
                key,
                self.format_value(value)
            )?,

            Instruction::StorageLoad { result, key } => write!(
                output,
                "{} = storage_load {:?}",
                self.format_value(result),
                key
            )?,

            Instruction::MappingStore {
                mapping,
                key,
                value,
            } => write!(
                output,
                "mapping_store {}[{}] <- {}",
                self.format_value(mapping),
                self.format_value(key),
                self.format_value(value)
            )?,

            Instruction::MappingLoad {
                result,
                mapping,
                key,
            } => write!(
                output,
                "{} = mapping_load {}[{}]",
                self.format_value(result),
                self.format_value(mapping),
                self.format_value(key)
            )?,

            Instruction::Assert { condition, message } => write!(
                output,
                "assert {} \"{}\"",
                self.format_value(condition),
                message
            )?,

            Instruction::Require { condition, message } => write!(
                output,
                "require {} \"{}\"",
                self.format_value(condition),
                message
            )?,

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

            Terminator::Branch {
                condition,
                then_block,
                else_block,
                ..
            } => write!(
                output,
                "branch {} ? {} : {}",
                self.format_value(condition),
                then_block,
                else_block
            )?,

            Terminator::Switch {
                value,
                default,
                cases,
            } => {
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
        match value {
            Value::Register(id) => format!("%{:?}", id),
            Value::Variable(id) => format!("v{:?}", id),
            Value::Temp(id) => format!("t{:?}", id),
            Value::Param(id) => format!("p{:?}", id),
            Value::BlockParam(id) => format!("bp{:?}", id),
            Value::Constant(c) => format!("#{:?}", c),
            Value::StorageRef(id) => format!("storage{:?}", id),
            Value::MemoryRef(id) => format!("mem{:?}", id),
            Value::Global(id) => format!("@{:?}", id),
            Value::Undefined => "undef".to_string(),
        }
    }

    fn format_type(&self, ty: &Type) -> String {
        if !self.include_types {
            return String::new();
        }

        match ty {
            Type::Bool => "bool".to_string(),
            Type::Int(width) => format!("i{}", width),
            Type::Uint(width) => format!("u{}", width),
            Type::Address => "address".to_string(),
            Type::Bytes(size) => format!("bytes{}", size),
            Type::String => "string".to_string(),
            Type::Array(elem, size) => {
                if let Some(s) = size {
                    format!("[{}; {}]", self.format_type(elem), s)
                } else {
                    format!("[{}]", self.format_type(elem))
                }
            }
            Type::Mapping(key, value) => {
                format!(
                    "mapping({} => {})",
                    self.format_type(key),
                    self.format_type(value)
                )
            }
            Type::Struct(id) => format!("struct_{:?}", id),
            Type::Enum(id) => format!("enum_{:?}", id),
            Type::Contract(id) => format!("contract_{:?}", id),
            Type::Function(_) => "function".to_string(),
            Type::StoragePointer(inner) => format!("storage*{}", self.format_type(inner)),
            Type::MemoryPointer(inner) => format!("memory*{}", self.format_type(inner)),
            Type::CalldataPointer(inner) => format!("calldata*{}", self.format_type(inner)),
            Type::Bytes4 => "bytes4".to_string(),
            Type::Bytes20 => "bytes20".to_string(),
            Type::Bytes32 => "bytes32".to_string(),
            Type::ClifType(_) => "clif_type".to_string(),
        }
    }
}

impl RepresentationExtractor for IRExtractor {
    fn extract(&self, context: &AnalysisContext) -> Result<RepresentationSnippet> {
        match context.get_representation::<IRContract>() {
            Ok(contract) => {
                tracing::debug!(
                    "Successfully retrieved Tameshi IR contract: {}",
                    contract.name
                );

                let emitter = thalir_emit::ThalIREmitter::new(vec![contract.clone()]);
                let ir_content = emitter.emit_to_string(self.include_types);

                let token_count = TokenEstimator::estimate(&ir_content);

                let metadata = SnippetMetadata {
                    representation_type: "cranelift_ir".to_string(),
                    extraction_strategy: "textual_format".to_string(),
                    source_location: None,
                    included_functions: contract.functions.keys().cloned().collect(),
                    included_contracts: vec![contract.name.clone()],
                    was_truncated: false,
                };

                let snippet = RepresentationSnippet {
                    content: ir_content,
                    metadata,
                    token_count,
                };

                tracing::debug!(
                    "Successfully extracted IR content, token count: {}",
                    snippet.token_count
                );
                Ok(snippet)
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
        "cranelift_ir"
    }
}

