use anyhow::Result;
use clap::{Parser, Subcommand};

mod commands;
use commands::{scan::ScanCommand, transform::TransformCommand, analyze::AnalyzeArgs};

#[derive(Parser)]
#[command(name = "tameshi")]
#[command(about = "Unified CLI for Solidity analysis and ThalIR")]
#[command(version = "0.2.0")]
#[command(author = "Tameshi Team")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Transform {
        #[command(subcommand)]
        subcommand: TransformCommand,
    },

    Scan {
        #[command(subcommand)]
        subcommand: ScanCommand,
    },

    Analyze(AnalyzeArgs),

    Pipeline {
        #[arg(short, long)]
        input: std::path::PathBuf,

        #[arg(short, long)]
        output: std::path::PathBuf,

        #[arg(short, long)]
        verbose: bool,

        #[arg(long)]
        annotated: bool,

        #[arg(long, requires = "annotated")]
        ascii_markers: bool,
    },

    Debug {
        #[arg(short, long)]
        input: std::path::PathBuf,

        #[arg(short, long)]
        verbose: bool,
    },

    Validate {
        #[arg(short, long)]
        input: std::path::PathBuf,

        #[arg(short, long)]
        verbose: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Transform { subcommand } => subcommand.execute(),
        Commands::Scan { subcommand } => subcommand.execute(),
        Commands::Analyze(args) => {
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(commands::analyze::execute(args))
        },
        Commands::Pipeline {
            input,
            output,
            verbose,
            annotated,
            ascii_markers,
        } => run_pipeline(input, output, verbose, annotated, ascii_markers),
        Commands::Debug { input, verbose } => run_debug_dump(input, verbose),
        Commands::Validate { input, verbose } => run_validate(input, verbose),
    }
}

fn run_pipeline(
    input: std::path::PathBuf,
    output: std::path::PathBuf,
    verbose: bool,
    annotated: bool,
    ascii_markers: bool,
) -> Result<()> {
    use colored::*;
    use std::fs;
    use std::time::Instant;
    use thalir_transform::transform_solidity_to_ir;

    println!(
        "{}",
        "🚀 Full Pipeline: Solidity → ThalIR"
            .bright_blue()
            .bold()
    );
    println!("{}", "=".repeat(50).bright_blue());
    println!("📁 Input: {}", input.display());
    println!("📁 Output: {}", output.display());
    if annotated {
        println!("✨ Mode: Annotated ThalIR{}", if ascii_markers { " (ASCII)" } else { "" });
    }

    let start = Instant::now();

    if verbose {
        println!("\n⚡ Step 1: Loading Solidity source...");
    }
    let solidity_content = fs::read_to_string(&input)?;

    if verbose {
        println!("⚡ Step 2: Transforming to ThalIR...");
    }
    let contracts = transform_solidity_to_ir(&solidity_content)?;

    if verbose {
        println!("💾 Writing ThalIR output...");
    }

    let ir_output = if annotated {
        use thalir_emit::{AnnotatedIREmitter, annotated_ir_emitter::AnnotationConfig};
        let config = AnnotationConfig {
            emit_position_markers: true,
            emit_visual_cues: true,
            use_ascii_cues: ascii_markers,
            emit_ordering_analysis: true,
            emit_function_headers: true,
        };
        let emitter = AnnotatedIREmitter::new(contracts.clone())
            .with_annotation_config(config);
        emitter.emit_to_string(false)
    } else {
        use thalir_emit::ThalIREmitter;
        let emitter = ThalIREmitter::new(contracts.clone());
        emitter.emit_to_string(false)
    };

    fs::write(&output, ir_output)?;

    let elapsed = start.elapsed();

    println!(
        "\n✅ {} Pipeline completed successfully!",
        "SUCCESS:".bright_green().bold()
    );
    println!("   Time: {:.3}s", elapsed.as_secs_f64());
    println!("   Contracts: {}", contracts.len());
    println!("   Output: {}", output.display());

    Ok(())
}

fn run_debug_dump(input: std::path::PathBuf, verbose: bool) -> Result<()> {
    use colored::*;
    use std::fs;
    use thalir_transform::transform_solidity_to_ir;

    println!("{}", "🔍 Debug IR Dump".bright_cyan().bold());
    println!("{}", "=".repeat(50).bright_cyan());
    println!("📁 Input: {}", input.display());

    if verbose {
        println!("\n⚡ Loading Solidity source...");
    }
    let solidity_content = fs::read_to_string(&input)?;

    if verbose {
        println!("⚡ Transforming to Cranelift IR...");
    }
    let contracts = transform_solidity_to_ir(&solidity_content)?;

    if contracts.is_empty() {
        println!("⚠️  No contracts found in input");
        return Ok(());
    }

    println!("\n✅ Found {} contracts", contracts.len());

    for (contract_idx, contract) in contracts.iter().enumerate() {
        println!(
            "\n{}",
            format!("📄 Contract {} IR:", contract_idx)
                .bright_green()
                .bold()
        );
        println!("{}", "─".repeat(60).bright_green());

        println!("Contract name: {}", contract.name);
        println!("Functions: {}", contract.functions.len());

        for (func_name, function) in &contract.functions {
            println!(
                "\n{}",
                format!("🔧 Function: {}", func_name).bright_yellow()
            );
            println!("Entry block: {:?}", function.body.entry_block);
            println!("Blocks: {}", function.body.blocks.len());

            for (block_id, block) in &function.body.blocks {
                println!("\n  {}", format!("Block {:?}:", block_id).bright_blue());
                for (instr_idx, instruction) in block.instructions.iter().enumerate() {
                    println!(
                        "    [{}] {}",
                        instr_idx,
                        format_instruction_debug(instruction)
                    );
                }
                println!("    → {}", format_terminator_debug(&block.terminator));
            }
        }
    }

    Ok(())
}

fn format_instruction_debug(instruction: &thalir_core::instructions::Instruction) -> String {
    use thalir_core::instructions::Instruction;
    match instruction {
        Instruction::GetContext { result, var } => {
            format!("{} = GetContext({:?})", format_value_debug(result), var)
        }
        Instruction::Add {
            result,
            left,
            right,
            ..
        } => {
            format!(
                "{} = Add({}, {})",
                format_value_debug(result),
                format_value_debug(left),
                format_value_debug(right)
            )
        }
        Instruction::Require { condition, message } => {
            format!(
                "Require({}, \"{}\")",
                format_value_debug(condition),
                message
            )
        }
        Instruction::StorageStore { key, value, .. } => {
            format!("StorageStore({:?}, {})", key, format_value_debug(value))
        }
        Instruction::StorageLoad { result, key, .. } => {
            format!("{} = StorageLoad({:?})", format_value_debug(result), key)
        }
        _ => format!("{:?}", instruction), // Fallback to Debug formatting
    }
}

fn format_value_debug(value: &thalir_core::values::Value) -> String {
    use thalir_core::values::Value;
    match value {
        Value::Temp(id) => format!("temp_{:?}", id),
        Value::Param(id) => format!("param_{:?}", id),
        Value::Register(id) => format!("reg_{:?}", id),
        Value::Constant(constant) => format!("const({:?})", constant),
        Value::Variable(id) => format!("var_{:?}", id),
        Value::BlockParam(id) => format!("block_param_{:?}", id),
        Value::StorageRef(id) => format!("storage_ref_{:?}", id),
        Value::MemoryRef(id) => format!("memory_ref_{:?}", id),
        Value::Global(id) => format!("global_{:?}", id),
        _ => format!("{:?}", value), // Fallback for any future variants
    }
}

fn format_terminator_debug(terminator: &thalir_core::block::Terminator) -> String {
    use thalir_core::block::Terminator;
    match terminator {
        Terminator::Return(Some(value)) => format!("Return({})", format_value_debug(value)),
        Terminator::Return(None) => "Return()".to_string(),
        Terminator::Branch {
            condition,
            then_block,
            else_block,
            ..
        } => {
            format!(
                "Branch({}, {:?}, {:?})",
                format_value_debug(condition),
                then_block,
                else_block
            )
        }
        Terminator::Jump(block_id, _) => format!("Jump({:?})", block_id),
        Terminator::Revert(msg) => format!("Revert(\"{}\")", msg),
        Terminator::Switch {
            value,
            cases,
            default,
            ..
        } => {
            format!(
                "Switch({}, {} cases, default: {:?})",
                format_value_debug(value),
                cases.len(),
                default
            )
        }
        Terminator::Panic(msg) => format!("Panic(\"{}\")", msg),
        Terminator::Invalid => "Invalid".to_string(),
    }
}

fn run_validate(input: std::path::PathBuf, verbose: bool) -> Result<()> {
    use colored::*;
    use std::fs;

    println!("{}", "🔍 Validating ThalIR".bright_cyan().bold());
    println!("{}", "═".repeat(50).bright_cyan());
    println!("📁 Input: {}", input.display());
    println!();

    if verbose {
        println!("⚡ Reading IR file...");
    }

    let ir_content = fs::read_to_string(&input)?;

    if verbose {
        println!("⚡ Parsing with Pest parser...");
    }

    match thalir_parser::parse(&ir_content) {
        Ok(pairs) => {
            let count = pairs.count();
            println!("{}", "✅ VALID".bright_green().bold());
            println!("   Parsed {} top-level elements", count);

            if verbose {
                println!("\n📊 Parser output:");
                if let Ok(pairs) = thalir_parser::parse(&ir_content) {
                    for pair in pairs {
                        println!("   - {:?}", pair.as_rule());
                    }
                }
            }

            Ok(())
        }
        Err(e) => {
            println!("{}", "❌ INVALID".bright_red().bold());
            println!("\n{}", "Parse Error:".bright_red());
            println!("{}", e);
            Err(anyhow::anyhow!("Parse validation failed"))
        }
    }
}
