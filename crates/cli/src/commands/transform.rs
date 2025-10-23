use anyhow::{Context, Result};
use clap::{Args, Subcommand, ValueEnum};
use colored::*;
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Subcommand)]
pub enum TransformCommand {
    Sol2ir(TransformArgs),
}

#[derive(Args)]
pub struct TransformArgs {
    #[arg(short, long, conflicts_with_all = &["stdin", "dir"])]
    input: Option<PathBuf>,

    #[arg(long, conflicts_with_all = &["input", "dir"])]
    stdin: bool,

    #[arg(short, long, conflicts_with = "stdout")]
    output: Option<PathBuf>,

    #[arg(long, conflicts_with = "output")]
    stdout: bool,

    #[arg(short = 'd', long, conflicts_with_all = &["input", "stdin"])]
    dir: Option<PathBuf>,

    #[arg(long, requires = "dir")]
    out_dir: Option<PathBuf>,

    #[arg(short = 'f', long, value_enum, default_value = "json")]
    format: OutputFormat,

    #[arg(short, long)]
    verbose: bool,

    #[arg(long)]
    pretty: bool,

    #[arg(long)]
    with_types: bool,

    #[arg(long)]
    annotated: bool,

    #[arg(long, requires = "annotated")]
    ascii_markers: bool,
}

#[derive(ValueEnum, Clone, PartialEq)]
pub enum OutputFormat {
    Json,
    JsonPretty,
    Text,
    Debug,
}

impl TransformCommand {
    pub fn execute(&self) -> Result<()> {
        match self {
            TransformCommand::Sol2ir(args) => transform_sol_to_cranelift_ir(args),
        }
    }
}

fn read_input(args: &TransformArgs) -> Result<String> {
    if args.stdin {
        let mut buffer = String::new();
        io::stdin()
            .read_to_string(&mut buffer)
            .context("Failed to read from stdin")?;
        Ok(buffer)
    } else if let Some(path) = &args.input {
        fs::read_to_string(path).with_context(|| format!("Failed to read file: {}", path.display()))
    } else {
        anyhow::bail!("No input source specified (use --input or --stdin)")
    }
}

fn write_output(args: &TransformArgs, content: &str) -> Result<()> {
    if args.stdout {
        io::stdout()
            .write_all(content.as_bytes())
            .context("Failed to write to stdout")?;
        if !matches!(args.format, OutputFormat::Json | OutputFormat::JsonPretty) {
            println!();
        }
    } else if let Some(path) = &args.output {
        fs::write(path, content)
            .with_context(|| format!("Failed to write to file: {}", path.display()))?;
        if args.verbose {
            println!("✅ Output written to: {}", path.display());
        }
    } else {
        io::stdout()
            .write_all(content.as_bytes())
            .context("Failed to write to stdout")?;
    }
    Ok(())
}

fn transform_sol_to_cranelift_ir(args: &TransformArgs) -> Result<()> {
    use thalir_transform::transform_solidity_to_ir;

    if !args.stdout && args.verbose {
        println!("{}", "🔄 Transforming Solidity to ThalIR...".cyan().bold());
    }

    if let Some(ref dir) = args.dir {
        if !dir.exists() {
            return Err(anyhow::anyhow!(
                "Input directory does not exist: {}",
                dir.display()
            ));
        }
        if !dir.is_dir() {
            return Err(anyhow::anyhow!(
                "Input path is not a directory: {}",
                dir.display()
            ));
        }

        if args.verbose {
            println!("📁 Processing directory: {}", dir.display());
        }

        let out_dir = args
            .out_dir
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("--out-dir is required when using --dir"))?;

        fs::create_dir_all(out_dir)?;

        let pattern = dir.join("**/*.sol");
        let files: Vec<_> = glob::glob(pattern.to_str().unwrap())?
            .filter_map(Result::ok)
            .collect();

        if files.is_empty() {
            return Err(anyhow::anyhow!(
                "No .sol files found in directory: {}",
                dir.display()
            ));
        }

        if args.verbose {
            println!("Found {} Solidity files", files.len());
        }

        let start = Instant::now();
        let mut success_count = 0;
        let mut error_count = 0;
        let mut errors = Vec::new();

        for file_path in files {
            let relative_path = file_path.strip_prefix(dir).unwrap_or(&file_path);
            let extension = match args.format {
                OutputFormat::Json | OutputFormat::JsonPretty => "json",
                OutputFormat::Text => "ir",
                OutputFormat::Debug => "debug",
            };
            let output_path = out_dir.join(relative_path).with_extension(extension);

            if let Some(parent) = output_path.parent() {
                fs::create_dir_all(parent)?;
            }

            if args.verbose {
                print!("  Processing {}... ", file_path.display());
            }

            let content = match fs::read_to_string(&file_path) {
                Ok(c) => c,
                Err(e) => {
                    error_count += 1;
                    let error_msg = format!("{}: {}", file_path.display(), e);
                    errors.push(error_msg.clone());
                    if args.verbose {
                        println!("❌ Failed to read: {}", error_msg);
                    }
                    continue;
                }
            };

            match transform_solidity_to_ir(&content) {
                Ok(contracts) => {
                    let output = match format_ir_output(
                        &contracts,
                        &args.format,
                        args.pretty,
                        args.with_types,
                        args.annotated,
                        args.ascii_markers,
                    ) {
                        Ok(o) => o,
                        Err(e) => {
                            error_count += 1;
                            let error_msg =
                                format!("{}: Failed to format output: {}", file_path.display(), e);
                            errors.push(error_msg.clone());
                            if args.verbose {
                                println!("❌ {}", error_msg);
                            }
                            continue;
                        }
                    };

                    if let Err(e) = fs::write(&output_path, output) {
                        error_count += 1;
                        let error_msg =
                            format!("{}: Failed to write output: {}", output_path.display(), e);
                        errors.push(error_msg.clone());
                        if args.verbose {
                            println!("❌ {}", error_msg);
                        }
                        continue;
                    }

                    success_count += 1;
                    if args.verbose {
                        println!("✅");
                    }
                }
                Err(e) => {
                    error_count += 1;
                    let error_msg = format!("{}: {}", file_path.display(), e);
                    errors.push(error_msg.clone());
                    if args.verbose {
                        println!("❌ {}", error_msg);
                    }
                }
            }
        }

        let elapsed = start.elapsed();
        println!("\n📊 Batch Processing Complete:");
        println!("   Successful: {} files", success_count);
        if error_count > 0 {
            println!("   Failed: {} files", error_count);
            if !args.verbose && !errors.is_empty() {
                println!("\n❌ Errors encountered:");
                for (i, error) in errors.iter().take(10).enumerate() {
                    println!("   {}. {}", i + 1, error);
                }
                if errors.len() > 10 {
                    println!("   ... and {} more errors", errors.len() - 10);
                }
            }
        }
        println!("   Time: {:.2}s", elapsed.as_secs_f64());

        if error_count > 0 && !args.verbose {
            println!("\n💡 Use --verbose for detailed error messages");
        }

        return Ok(());
    }

    if let Some(ref input_path) = args.input {
        if !input_path.exists() {
            return Err(anyhow::anyhow!(
                "Input file does not exist: {}",
                input_path.display()
            ));
        }
        if !input_path.is_file() {
            return Err(anyhow::anyhow!(
                "Input path is not a file: {}",
                input_path.display()
            ));
        }
        let extension = input_path.extension().and_then(|ext| ext.to_str());
        if extension != Some("sol") && !args.stdin {
            eprintln!(
                "⚠️  Warning: Input file does not have .sol extension: {}",
                input_path.display()
            );
        }
    }

    let input = read_input(args)?;

    if input.trim().is_empty() {
        return Err(anyhow::anyhow!("Input is empty"));
    }

    let start = Instant::now();

    let contracts = transform_solidity_to_ir(&input)
        .map_err(|e| anyhow::anyhow!("Transformation failed: {}", e))
        .context("Failed to transform Solidity to ThalIR")?;

    if contracts.is_empty() && args.verbose {
        eprintln!("⚠️  Warning: No contracts found in input");
    }

    let output = format_ir_output(
        &contracts,
        &args.format,
        args.pretty,
        args.with_types,
        args.annotated,
        args.ascii_markers,
    )
    .context("Failed to format IR output")?;

    write_output(args, &output).context("Failed to write output")?;

    if args.verbose && !args.stdout {
        let elapsed = start.elapsed();
        println!("✅ Transformation completed in {}ms", elapsed.as_millis());
        println!("📊 Generated {} contracts", contracts.len());
    }

    Ok(())
}

fn format_ir_output(
    contracts: &[thalir_core::contract::Contract],
    format: &OutputFormat,
    pretty: bool,
    with_types: bool,
    annotated: bool,
    ascii_markers: bool,
) -> Result<String> {
    use thalir_emit::{annotated_ir_emitter::AnnotationConfig, AnnotatedIREmitter, ThalIREmitter};

    match format {
        OutputFormat::Json | OutputFormat::JsonPretty => {
            if *format == OutputFormat::JsonPretty || pretty {
                serde_json::to_string_pretty(&contracts)
                    .context("Failed to serialize contracts to JSON")
            } else {
                serde_json::to_string(&contracts).context("Failed to serialize contracts to JSON")
            }
        }
        OutputFormat::Text => {
            if annotated {
                let config = AnnotationConfig {
                    emit_position_markers: true,
                    emit_visual_cues: true,
                    use_ascii_cues: ascii_markers,
                    emit_ordering_analysis: true,
                    emit_function_headers: true,
                };
                let emitter =
                    AnnotatedIREmitter::new(contracts.to_vec()).with_annotation_config(config);
                Ok(emitter.emit_to_string(with_types))
            } else {
                let emitter = ThalIREmitter::new(contracts.to_vec());
                Ok(emitter.emit_to_string(with_types))
            }
        }
        OutputFormat::Debug => Ok(format!("{:#?}", contracts)),
    }
}
