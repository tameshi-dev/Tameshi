//! Vulnerability scanning command with multi-scanner orchestration.
//!
//! ## Architecture: Layered Scanning Strategy
//!
//! Tameshi uses a three-tier scanning approach, each with different trade-offs:
//!
//! ### 1. Source-Level Scanners (Fast, High Recall)
//! - Parse Solidity AST with tree-sitter
//! - Detect syntactic patterns (e.g., "unchecked return value")
//! - **Pro**: Extremely fast, good for CI/CD gates
//! - **Con**: High false positive rate due to lack of semantic understanding
//!
//! ### 2. IR-Level Scanners (Balanced, High Precision)
//! - Transform to intermediate representation
//! - Perform data flow and control flow analysis
//! - **Pro**: Understands program semantics, low false positives
//! - **Con**: Transformation overhead, ~10x slower than source scanning
//!
//! ### 3. LLM-Powered Scanners (Slow, Experimental)
//! - Feed code representations to language models
//! - Leverage models' pattern recognition for novel vulnerabilities
//! - **Pro**: Can detect patterns not explicitly programmed
//! - **Con**: Expensive, non-deterministic, requires careful prompt engineering
//!
//! ## Why Not Just Use One Approach?
//!
//! Different vulnerability classes have different detection requirements:
//!
//! - **Reentrancy**: Needs data flow analysis → IR scanners excel
//! - **Unchecked returns**: Pure syntactic pattern → Source scanners sufficient
//! - **Business logic flaws**: Context-dependent → LLM scanners show promise
//!
//! By combining all three, we maximize coverage while keeping analysis time reasonable.
//! Users can disable expensive tiers for faster iteration.
//!
//! ## Representation Bundle Pattern
//!
//! Rather than transforming once per scanner, we build all representations up front
//! (source AST, IR, call graph) and pass them as a bundle. Scanners pull what they need.
//! This amortizes transformation costs across all scanners.

use anyhow::{Context as AnyhowContext, Result};
use clap::{Subcommand, ValueEnum};
use std::fs;
use std::path::PathBuf;
use tameshi_scanners::{
    analysis::{parse_solidity_version, OpenZeppelinPatternRecognizer},
    core::{Scanner, ScannerConfig},
    AnalysisContext, Confidence, ContractInfo, Finding, IRAccessControlScanner,
    IRCrossFunctionReentrancyScanner, IRDangerousFunctionsScanner, IRDoSVulnerabilityScanner,
    IRIntegerOverflowScanner, IRPriceManipulationScanner, IRReentrancyScanner,
    IRStateModificationScanner, IRTimeVulnerabilityScanner, IRUncheckedReturnScanner,
    RepresentationBundle, ScanningEngine, Severity, SimpleTimestampScanner,
    SourceClassicReentrancyScanner, SourceDangerousFunctionsScanner, SourceDelegatecallScanner,
    SourceDoSVulnerabilitiesScanner, SourceGasLimitDoSScanner, SourceIntegerOverflowScanner,
    SourceLoopReentrancyScanner, SourceMissingAccessControlScanner, SourceUncheckedOverflowScanner,
    SourceUncheckedReturnScanner,
};
use walkdir::WalkDir;

#[cfg(feature = "llm")]
use tameshi_scanners::llm_scanners;

#[cfg(feature = "llm")]
use tameshi_scanners::llm::provider::OpenAIProvider;

#[derive(Subcommand, Clone)]
pub enum ScanCommand {
    Run {
        #[arg(short, long)]
        input: PathBuf,

        #[arg(long, value_enum, default_value_t = ScannerSuite::Deterministic)]
        suite: ScannerSuite,

        #[cfg(feature = "llm")]
        #[arg(long)]
        llm: bool,

        #[cfg(feature = "llm")]
        #[arg(long, value_enum, requires = "llm")]
        llm_suite: Option<LLMScannerSuite>,

        #[cfg(feature = "llm")]
        #[arg(long, value_enum, requires = "llm")]
        llm_scanner: Option<LLMScannerType>,

        #[cfg(feature = "llm")]
        #[arg(long, requires = "llm")]
        model: Option<String>,

        #[cfg(feature = "llm")]
        #[arg(long, requires = "llm")]
        dump_prompt: bool,

        #[cfg(feature = "llm")]
        #[arg(long, requires = "llm")]
        dump_response: bool,

        #[arg(long, value_enum, default_value_t = OutputFormat::Console)]
        format: OutputFormat,

        #[arg(long, value_enum, default_value_t = ConfidenceLevel::Medium)]
        min_confidence: ConfidenceLevel,

        #[arg(short, long)]
        verbose: bool,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum, Debug)]
pub enum ScannerSuite {
    Deterministic,
    All,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum, Debug)]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
}

impl ConfidenceLevel {
    pub fn threshold(&self) -> f64 {
        match self {
            ConfidenceLevel::Low => 0.3,
            ConfidenceLevel::Medium => 0.6,
            ConfidenceLevel::High => 0.9,
        }
    }
}

#[cfg(feature = "llm")]
#[derive(Copy, Clone, PartialEq, Eq, ValueEnum, Debug)]
pub enum LLMScannerSuite {
    Basic,
    Comprehensive,
    All,
}

#[cfg(feature = "llm")]
impl From<LLMScannerSuite> for llm_scanners::LLMScannerSuite {
    fn from(suite: LLMScannerSuite) -> Self {
        match suite {
            LLMScannerSuite::Basic => llm_scanners::LLMScannerSuite::Basic,
            LLMScannerSuite::Comprehensive => llm_scanners::LLMScannerSuite::Comprehensive,
            LLMScannerSuite::All => llm_scanners::LLMScannerSuite::All,
        }
    }
}

#[cfg(feature = "llm")]
#[derive(Copy, Clone, PartialEq, Eq, ValueEnum, Debug)]
pub enum LLMScannerType {
    Comprehensive,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum, Debug)]
pub enum OutputFormat {
    Console,
    Json,
    Markdown,
}

impl ScanCommand {
    pub fn execute(&self) -> Result<()> {
        match self {
            ScanCommand::Run {
                input,
                suite,
                #[cfg(feature = "llm")]
                llm,
                #[cfg(feature = "llm")]
                llm_suite,
                #[cfg(feature = "llm")]
                llm_scanner,
                #[cfg(feature = "llm")]
                model,
                #[cfg(feature = "llm")]
                dump_prompt,
                #[cfg(feature = "llm")]
                dump_response,
                format,
                min_confidence,
                verbose,
            } => {
                #[cfg(feature = "llm")]
                if *llm {
                    let model_name = model.clone().unwrap_or_else(|| "o1-mini".to_string());

                    if let Some(suite_type) = llm_suite {
                        if input.is_file() {
                            scan_single_file_with_llm_suite(
                                input,
                                *suite_type,
                                &model_name,
                                *dump_prompt,
                                *dump_response,
                                *format,
                                *verbose,
                            )?;
                        } else {
                            anyhow::bail!("LLM scanning currently only supports single files");
                        }
                    } else {
                        let scanner_type = llm_scanner.unwrap_or(LLMScannerType::Comprehensive);
                        if input.is_file() {
                            scan_single_file_with_llm(
                                input,
                                scanner_type,
                                &model_name,
                                *dump_prompt,
                                *dump_response,
                                *format,
                                *verbose,
                            )?;
                        } else {
                            anyhow::bail!("LLM scanning currently only supports single files");
                        }
                    }
                } else {
                    if input.is_file() {
                        scan_single_file(input, *suite, *format, *min_confidence, *verbose)?;
                    } else if input.is_dir() {
                        scan_directory(input, *suite, *format, *min_confidence, *verbose)?;
                    } else {
                        anyhow::bail!("Input path does not exist: {}", input.display());
                    }
                }

                #[cfg(not(feature = "llm"))]
                {
                    if input.is_file() {
                        scan_single_file(input, *suite, *format, *min_confidence, *verbose)?;
                    } else if input.is_dir() {
                        scan_directory(input, *suite, *format, *min_confidence, *verbose)?;
                    } else {
                        anyhow::bail!("Input path does not exist: {}", input.display());
                    }
                }
            }
        }
        Ok(())
    }
}

fn scan_single_file(
    path: &PathBuf,
    suite: ScannerSuite,
    format: OutputFormat,
    min_confidence: ConfidenceLevel,
    verbose: bool,
) -> Result<()> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read file: {}", path.display()))?;

    if verbose {
        println!("🔄 Transforming {} to Tameshi IR...", path.display());
    }

    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown.sol");

    let contracts =
        thalir_transform::transform_solidity_to_ir_with_filename(&content, Some(filename))
            .with_context(|| {
                format!(
                    "Failed to transform Solidity to Tameshi IR: {}",
                    path.display()
                )
            })?;

    if contracts.is_empty() {
        if verbose {
            println!("⚠️  No contracts found in {}", path.display());
        }
        return Ok(());
    }

    let engine = create_scanning_engine(suite)?;
    let mut all_findings = Vec::new();

    for contract in contracts {
        if should_skip_contract(&contract.name) {
            if verbose {
                println!("⏭️  Skipping non-vulnerable contract: {}", contract.name);
            }
            continue;
        }

        if verbose {
            println!("🔍 Scanning contract: {}", contract.name);
        }

        let bundle = RepresentationBundle::new().add(contract.clone());

        let mut context = AnalysisContext::new(bundle.clone());

        let contract_info = ContractInfo {
            name: contract.name.clone(),
            source_code: Some(content.clone()),
            source_path: Some(path.to_string_lossy().to_string()),
            ..Default::default()
        };
        context.set_contract_info(contract_info);

        if let Some(version) = parse_solidity_version(&content) {
            if verbose {
                println!(
                    "   📋 Solidity version: {}.{}.{}",
                    version.major, version.minor, version.patch
                );
            }
            context.set_metadata("solidity_version".to_string(), version);
        }

        let source_loop_scanner = SourceLoopReentrancyScanner::new();
        let source_classic_reentrancy_scanner = SourceClassicReentrancyScanner::new();
        let source_overflow_scanner = SourceIntegerOverflowScanner::new();
        let source_unchecked_scanner = SourceUncheckedReturnScanner::new();
        let source_dangerous_scanner = SourceDangerousFunctionsScanner::new();
        let source_dos_scanner = SourceDoSVulnerabilitiesScanner::new();
        let source_missing_access_control_scanner = SourceMissingAccessControlScanner::new();
        let source_gas_limit_dos_scanner = SourceGasLimitDoSScanner::new();
        let source_delegatecall_scanner = SourceDelegatecallScanner::new();
        let source_unchecked_overflow_scanner = SourceUncheckedOverflowScanner::new();
        let simple_timestamp_scanner = SimpleTimestampScanner::new();
        let access_control_scanner =
            IRAccessControlScanner::new().with_source_code(content.clone());

        let source_findings = source_loop_scanner.scan(&context)?;
        all_findings.extend(source_findings);

        let classic_reentrancy_findings = source_classic_reentrancy_scanner.scan(&context)?;
        all_findings.extend(classic_reentrancy_findings);

        let overflow_findings = source_overflow_scanner.scan(&context)?;
        all_findings.extend(overflow_findings);

        let unchecked_findings = source_unchecked_scanner.scan(&context)?;
        all_findings.extend(unchecked_findings);

        let dangerous_findings = source_dangerous_scanner.scan(&context)?;
        all_findings.extend(dangerous_findings);

        let dos_findings = source_dos_scanner.scan(&context)?;
        all_findings.extend(dos_findings);

        let source_missing_ac_findings = source_missing_access_control_scanner.scan(&context)?;
        all_findings.extend(source_missing_ac_findings);

        let gas_limit_dos_findings = source_gas_limit_dos_scanner.scan(&context)?;
        all_findings.extend(gas_limit_dos_findings);

        let delegatecall_findings = source_delegatecall_scanner.scan(&context)?;
        all_findings.extend(delegatecall_findings);

        let unchecked_overflow_findings = source_unchecked_overflow_scanner.scan(&context)?;
        all_findings.extend(unchecked_overflow_findings);

        let simple_timestamp_findings = simple_timestamp_scanner.scan(&context)?;
        all_findings.extend(simple_timestamp_findings);

        let ac_findings = access_control_scanner.scan(&context)?;
        all_findings.extend(ac_findings);

        let ir_overflow_scanner = IRIntegerOverflowScanner::new();
        let ir_overflow_findings = ir_overflow_scanner.scan(&context)?;
        all_findings.extend(ir_overflow_findings);

        let report = engine.run(bundle)?;
        all_findings.extend(report.findings().to_vec());
    }

    eprintln!("\n=== ALL FINDINGS BEFORE FILTERING ===");
    for f in &all_findings {
        eprintln!(
            "  Scanner: {} | Type: {} | Confidence: {} | Score: {}",
            f.scanner_id, f.finding_type, f.confidence, f.confidence_score
        );
    }

    let confidence_threshold = min_confidence.threshold();
    let mut filtered_findings: Vec<_> = all_findings
        .into_iter()
        .filter(|f| f.confidence_score >= confidence_threshold)
        .collect();

    eprintln!(
        "\n=== AFTER CONFIDENCE FILTER: {} findings ===",
        filtered_findings.len()
    );

    if verbose {
        println!(
            "🎯 Confidence filtering: {} findings (threshold: {:.1})",
            filtered_findings.len(),
            confidence_threshold
        );
    }

    let before_function_filter = filtered_findings.len();
    filtered_findings.retain(|f| !should_skip_finding(f));

    eprintln!(
        "\n=== AFTER FUNCTION FILTER: {} findings (removed {}) ===",
        filtered_findings.len(),
        before_function_filter - filtered_findings.len()
    );

    if verbose && before_function_filter > filtered_findings.len() {
        println!(
            "🔧 Function pattern filtering: removed {} non-vulnerable patterns",
            before_function_filter - filtered_findings.len()
        );
    }

    let secure_recognizer = OpenZeppelinPatternRecognizer::default();
    let before_secure_filter = filtered_findings.len();
    filtered_findings.retain(|f| {
        let keep = !secure_recognizer.is_likely_false_positive(f, Some(&content));
        if !keep {
            eprintln!(
                "  OpenZeppelin filter removing: {} | {}",
                f.scanner_id, f.finding_type
            );
        }
        keep
    });

    eprintln!(
        "\n=== AFTER SECURE PATTERN FILTER: {} findings (removed {}) ===",
        filtered_findings.len(),
        before_secure_filter - filtered_findings.len()
    );

    if verbose && before_secure_filter > filtered_findings.len() {
        println!(
            "🛡️  Secure pattern filtering: removed {} OpenZeppelin false positives",
            before_secure_filter - filtered_findings.len()
        );
    }

    let config = ScannerConfig::default();
    let combined_report =
        tameshi_scanners::ScanReport::new(filtered_findings).with_deduplication(&config);
    output_report(&combined_report, format, verbose, Some(path))?;
    Ok(())
}

fn scan_directory(
    dir: &PathBuf,
    suite: ScannerSuite,
    format: OutputFormat,
    min_confidence: ConfidenceLevel,
    verbose: bool,
) -> Result<()> {
    if verbose {
        println!("🔍 Scanning directory: {}", dir.display());
    }

    let solidity_files = find_solidity_files(dir)?;

    if solidity_files.is_empty() {
        println!("⚠️  No Solidity files found in {}", dir.display());
        return Ok(());
    }

    if verbose {
        println!("📁 Found {} Solidity files", solidity_files.len());
    }

    let engine = create_scanning_engine(suite)?;
    let mut all_findings = std::collections::HashMap::new();

    for file_path in solidity_files {
        let content = match fs::read_to_string(&file_path) {
            Ok(content) => content,
            Err(e) => {
                eprintln!("Warning: Failed to read {}: {}", file_path.display(), e);
                continue;
            }
        };

        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown.sol");

        let contracts = match thalir_transform::transform_solidity_to_ir_with_filename(
            &content,
            Some(filename),
        ) {
            Ok(contracts) => contracts,
            Err(e) => {
                if verbose {
                    eprintln!(
                        "Warning: Failed to transform {}: {}",
                        file_path.display(),
                        e
                    );
                }
                continue;
            }
        };

        if contracts.is_empty() {
            continue;
        }

        let mut file_findings = Vec::new();
        for contract in contracts {
            let bundle = RepresentationBundle::new().add(contract);
            let report = engine.run(bundle)?;
            file_findings.extend(report.findings().to_vec());
        }

        let confidence_threshold = min_confidence.threshold();
        let filtered_findings: Vec<_> = file_findings
            .into_iter()
            .filter(|f| f.confidence_score >= confidence_threshold)
            .collect();

        if !filtered_findings.is_empty() {
            all_findings.insert(file_path, filtered_findings);
        }
    }

    output_directory_report(&all_findings, format, verbose)?;
    Ok(())
}

fn create_scanning_engine(suite: ScannerSuite) -> Result<ScanningEngine> {
    let config = ScannerConfig::default();
    let mut engine = ScanningEngine::new(config);

    match suite {
        ScannerSuite::Deterministic => {
            engine = engine.add_scanner(IRReentrancyScanner::new());
            engine = engine.add_scanner(IRUncheckedReturnScanner::new());
            engine = engine.add_scanner(IRStateModificationScanner::new());
            engine = engine.add_scanner(IRDangerousFunctionsScanner::new());
            engine = engine.add_scanner(IRTimeVulnerabilityScanner::new());
            engine = engine.add_scanner(IRDoSVulnerabilityScanner::new());
            engine = engine.add_scanner(IRPriceManipulationScanner::new());
            engine = engine.add_scanner(IRCrossFunctionReentrancyScanner::new());
        }
        ScannerSuite::All => {
            engine = engine.add_scanner(IRReentrancyScanner::new());
            engine = engine.add_scanner(IRUncheckedReturnScanner::new());
            engine = engine.add_scanner(IRStateModificationScanner::new());
            engine = engine.add_scanner(IRDangerousFunctionsScanner::new());
            engine = engine.add_scanner(IRTimeVulnerabilityScanner::new());
            engine = engine.add_scanner(IRDoSVulnerabilityScanner::new());
            engine = engine.add_scanner(IRPriceManipulationScanner::new());
            engine = engine.add_scanner(IRCrossFunctionReentrancyScanner::new());
        }
    }

    Ok(engine)
}

fn find_solidity_files(dir: &PathBuf) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    for entry in WalkDir::new(dir) {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() && path.extension().is_some_and(|ext| ext == "sol") {
            files.push(path.to_path_buf());
        }
    }

    Ok(files)
}

fn output_report(
    report: &tameshi_scanners::ScanReport,
    format: OutputFormat,
    verbose: bool,
    file_path: Option<&PathBuf>,
) -> Result<()> {
    match format {
        OutputFormat::Console => {
            if let Some(path) = file_path {
                println!("\n📄 Scan results for: {}", path.display());
            }

            if let Some(stats) = report.deduplication_stats() {
                if stats.removed_count > 0 {
                    println!(
                        "🔄 Deduplication: Removed {} duplicate findings ({:.1}%)",
                        stats.removed_count,
                        stats.reduction_percentage()
                    );
                }
            }

            let findings = report.findings();
            if findings.is_empty() {
                println!("✅ No vulnerabilities found");
            } else {
                println!("⚠️  Found {} potential vulnerabilities:", findings.len());
                for (i, finding) in findings.iter().enumerate() {
                    println!(
                        "\n{}. {} {}: {}",
                        i + 1,
                        finding.severity.emoji(),
                        finding.severity,
                        finding.title
                    );
                    if verbose {
                        println!("   Scanner: {}", finding.scanner_id);
                        println!("   Confidence: {}", finding.confidence);
                        println!("   Description: {}", finding.description);

                        if !finding.locations.is_empty() {
                            println!("   Locations:");
                            for loc in &finding.locations {
                                println!("     - {}:{}:{}", loc.file, loc.line, loc.column);
                            }
                        }
                    }
                }
            }
        }
        OutputFormat::Json => {
            let json = report.to_json()?;
            println!("{}", json);
        }
        OutputFormat::Markdown => {
            let markdown = report.to_markdown();
            println!("{}", markdown);
        }
    }
    Ok(())
}

fn output_directory_report(
    all_findings: &std::collections::HashMap<PathBuf, Vec<tameshi_scanners::Finding>>,
    format: OutputFormat,
    verbose: bool,
) -> Result<()> {
    match format {
        OutputFormat::Console => {
            if all_findings.is_empty() {
                println!("✅ No vulnerabilities found in any files");
            } else {
                println!("\n📊 Directory Scan Summary:");
                println!("   Files with findings: {}", all_findings.len());

                let total_findings: usize = all_findings.values().map(|v| v.len()).sum();
                println!("   Total findings: {}", total_findings);

                println!("\n📋 Detailed Results:");
                for (file_path, findings) in all_findings {
                    println!("\n📄 {}", file_path.display());
                    for (i, finding) in findings.iter().enumerate() {
                        println!(
                            "  {}. {} {}: {}",
                            i + 1,
                            finding.severity.emoji(),
                            finding.severity,
                            finding.title
                        );
                        if verbose {
                            println!("     Scanner: {}", finding.scanner_id);
                            println!("     Description: {}", finding.description);
                        }
                    }
                }
            }
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(all_findings)?;
            println!("{}", json);
        }
        OutputFormat::Markdown => {
            println!("# Directory Scan Report\n");
            if all_findings.is_empty() {
                println!("✅ No vulnerabilities found in any files");
            } else {
                let total_findings: usize = all_findings.values().map(|v| v.len()).sum();
                println!("## Summary\n");
                println!("- Files scanned with findings: {}", all_findings.len());
                println!("- Total findings: {}\n", total_findings);

                println!("## Detailed Results\n");
                for (file_path, findings) in all_findings {
                    println!("### 📄 File: `{}`\n", file_path.display());
                    for finding in findings {
                        println!(
                            "- **{} {}**: {}",
                            finding.severity.emoji(),
                            finding.severity,
                            finding.title
                        );
                        println!("  - **Scanner**: {}", finding.scanner_id);
                        println!("  - **Description**: {}\n", finding.description);
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(feature = "llm")]
fn scan_single_file_with_llm(
    path: &PathBuf,
    scanner_type: LLMScannerType,
    model: &str,
    dump_prompt: bool,
    dump_response: bool,
    format: OutputFormat,
    verbose: bool,
) -> Result<()> {
    use std::sync::Arc;
    use tameshi_scanners::llm::provider::OpenAIProvider;
    use tameshi_scanners::llm_scanners::LLMComprehensiveScanner;

    let api_key = std::env::var("OPENAI_API_KEY").context(
        "OPENAI_API_KEY environment variable not set. Set it with: export OPENAI_API_KEY=sk-...",
    )?;

    if verbose {
        println!("🤖 Using LLM comprehensive scanner");
        println!("🧠 Using model: {}", model);
    }

    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read file: {}", path.display()))?;

    if verbose {
        println!("🔄 Transforming {} to Tameshi IR...", path.display());
    }

    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown.sol");

    let contracts =
        thalir_transform::transform_solidity_to_ir_with_filename(&content, Some(filename))
            .with_context(|| {
                format!(
                    "Failed to transform Solidity to Tameshi IR: {}",
                    path.display()
                )
            })?;

    if contracts.is_empty() {
        println!("⚠️  No contracts found in {}", path.display());
        return Ok(());
    }

    match scanner_type {
        LLMScannerType::Comprehensive => {
            std::env::set_var("OPENAI_API_KEY", &api_key);

            let provider = Arc::new(OpenAIProvider::new(Some(model.to_string()))?);

            let scanner = LLMComprehensiveScanner::new(provider)
                .with_dump_prompt(dump_prompt)
                .with_dump_response(dump_response);

            println!("\n{}", "=".repeat(60).bright_cyan());
            println!(
                "{}",
                format!("🤖 LLM Comprehensive Security Analysis ({})", model)
                    .bright_cyan()
                    .bold()
            );
            println!("{}", "=".repeat(60).bright_cyan());

            let contract_name = if let Some(contract) = contracts.first() {
                contract.name.clone()
            } else {
                "Unknown".to_string()
            };

            if verbose {
                println!("\n📊 Analyzing contract: {}", contract_name.bright_yellow());
                println!("📄 Source code: {} bytes", content.len());
            }

            let runtime = tokio::runtime::Runtime::new()?;
            let findings = runtime.block_on(scanner.analyze_source(&content, &contract_name))?;

            if findings.is_empty() {
                println!("  ✅ No vulnerabilities detected");
            } else {
                println!(
                    "\n  ⚠️  Found {} potential security issue(s):",
                    findings.len()
                );
                for finding in &findings {
                    println!(
                        "\n  {} {} - {}",
                        finding.severity.emoji(),
                        finding.severity.to_string().bold(),
                        finding.title.bright_white().bold()
                    );
                    println!("    Confidence: {}", finding.confidence);
                    println!("    {}", finding.description.dimmed());

                    if !finding.locations.is_empty() {
                        println!("    Locations:");
                        for loc in &finding.locations {
                            println!("      📍 {}:{}:{}", loc.file, loc.line, loc.column);
                        }
                    }
                }
            }
        }
    }

    println!("\n{}", "=".repeat(60).bright_cyan());
    Ok(())
}

#[cfg(feature = "llm")]
fn create_llm_scanners(
    suite: LLMScannerSuite,
    model: &str,
    dump_prompt: bool,
    dump_response: bool,
) -> Result<Vec<std::sync::Arc<dyn tameshi_scanners::core::Scanner>>> {
    use std::sync::Arc;

    let api_key = std::env::var("OPENAI_API_KEY").context(
        "OPENAI_API_KEY environment variable not set. Set it with: export OPENAI_API_KEY=sk-...",
    )?;

    std::env::set_var("OPENAI_API_KEY", &api_key);
    let provider = Arc::new(OpenAIProvider::new(Some(model.to_string()))?);

    let lib_suite: llm_scanners::LLMScannerSuite = suite.into();
    llm_scanners::LLMScannerSuiteBuilder::new(lib_suite)
        .with_provider(provider)
        .with_dump_prompt(dump_prompt)
        .with_dump_response(dump_response)
        .build()
}

#[cfg(feature = "llm")]
fn scan_single_file_with_llm_suite(
    path: &PathBuf,
    suite: LLMScannerSuite,
    model: &str,
    dump_prompt: bool,
    dump_response: bool,
    format: OutputFormat,
    verbose: bool,
) -> Result<()> {
    use tameshi_scanners::core::context::{AnalysisContext, ContractInfo};

    if verbose {
        println!("🤖 Using LLM scanner suite: {:?}", suite);
        println!("🧠 Using model: {}", model);
    }

    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read file: {}", path.display()))?;

    if verbose {
        println!("🔄 Transforming {} to Tameshi IR...", path.display());
    }

    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown.sol");

    let contracts =
        thalir_transform::transform_solidity_to_ir_with_filename(&content, Some(filename))
            .with_context(|| {
                format!(
                    "Failed to transform Solidity to Tameshi IR: {}",
                    path.display()
                )
            })?;

    if contracts.is_empty() {
        println!("⚠️  No contracts found in {}", path.display());
        return Ok(());
    }

    let scanners = create_llm_scanners(suite, model, dump_prompt, dump_response)?;

    println!("\n{}", "=".repeat(60).bright_cyan());
    println!(
        "{}",
        format!("🤖 LLM Scanner Suite: {:?} ({})", suite, model)
            .bright_cyan()
            .bold()
    );
    println!("{}", "=".repeat(60).bright_cyan());

    for scanner in scanners {
        println!(
            "\n{}",
            format!("▶ Running: {}", scanner.name())
                .bright_yellow()
                .bold()
        );
        println!("{}", format!("  {}", scanner.description()).dimmed());

        for contract in &contracts {
            if verbose {
                println!("\n📊 Analyzing contract: {}", contract.name.bright_yellow());
            }

            let bundle = create_representation_bundle(vec![contract.clone()]);
            let mut context = AnalysisContext::new(bundle);

            let mut contract_info = ContractInfo::default();
            contract_info.name = contract.name.clone();
            contract_info.source_code = Some(content.clone());
            contract_info.source_path = Some(path.to_string_lossy().to_string());
            context.set_contract_info(contract_info);

            if let Some(version) = parse_solidity_version(&content) {
                context.set_metadata("solidity_version".to_string(), version);
            }

            let findings = scanner.scan(&context)?;

            if findings.is_empty() {
                println!("  ✅ No vulnerabilities detected");
            } else {
                println!("\n  ⚠️  Found {} potential issue(s):", findings.len());
                for finding in &findings {
                    println!(
                        "\n  {} {} - {}",
                        finding.severity.emoji(),
                        finding.severity.to_string().bold(),
                        finding.title.bright_white().bold()
                    );
                    println!("    Confidence: {}", finding.confidence);
                    println!("    {}", finding.description.dimmed());

                    if !finding.locations.is_empty() {
                        println!("    Locations:");
                        for loc in &finding.locations {
                            println!("      📍 {}:{}:{}", loc.file, loc.line, loc.column);
                        }
                    }
                }
            }
        }
    }

    println!("\n{}", "=".repeat(60).bright_cyan());
    Ok(())
}

fn should_skip_contract(name: &str) -> bool {
    if name.starts_with("Attack") || name.starts_with("Exploit") {
        return true;
    }

    if name.starts_with("Test") || name.starts_with("Mock") {
        return true;
    }

    if name.starts_with("Secure") || name.starts_with("Fixed") || name.starts_with("Safe") {
        return true;
    }

    if name.starts_with("Example") || name.ends_with("Example") {
        return true;
    }

    false
}
fn should_skip_finding(finding: &Finding) -> bool {
    if finding.confidence_score < 0.3 {
        return true;
    }

    if let Some(metadata) = &finding.metadata {
        for func_name in &metadata.affected_functions {
            if func_name == "constructor" || func_name.contains("Constructor") {
                return true;
            }

            let lower_name = func_name.to_lowercase();

            if finding.scanner_id == "simple-timestamp" {
                if lower_name.starts_with("is") && finding.severity < Severity::High {
                    return true;
                }
                if lower_name.starts_with("get")
                    || lower_name.starts_with("has")
                    || lower_name.starts_with("can")
                    || lower_name.starts_with("check")
                {
                    return true;
                }
            } else if lower_name.starts_with("get")
                || lower_name.starts_with("is")
                || lower_name.starts_with("has")
                || lower_name.starts_with("can")
                || lower_name.starts_with("check")
            {
                return true;
            }

            if lower_name.contains("balance") && lower_name.contains("of") {
                return true;
            }
            if lower_name.contains("allowance") {
                return true;
            }

            if lower_name == "decimals"
                || lower_name == "symbol"
                || lower_name == "name"
                || lower_name == "totalsupply"
                || lower_name == "owner"
            {
                return true;
            }
        }
    }

    if finding.severity == Severity::Informational && finding.confidence == Confidence::Low {
        return true;
    }

    false
}
