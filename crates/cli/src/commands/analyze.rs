//! Combined analysis command that runs all scanners with correlation
//!
//! This command performs comprehensive vulnerability scanning using both
//! deterministic and LLM-based scanners, then correlates findings for
//! high-confidence cross-validated results.

use anyhow::{Context, Result};
use clap::Args;
use colored::*;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use std::collections::HashMap;

use tameshi_scanners::{
    core::{
        AnalysisContext,
        ScannerConfig,
        get_cross_validated_findings,
        merge_correlated_findings,
        CorrelationConfig,
        Finding,
        Severity,
        Confidence,
        Scanner,
    },
    representations::{
        RepresentationBundle,
    },
    reentrancy::IRReentrancyScanner,
    access_control::IRAccessControlScanner,
    time_vulnerabilities::IRTimeVulnerabilityScanner,
    integer_overflow::IRIntegerOverflowScanner,
    dos_vulnerabilities::IRDoSVulnerabilityScanner,
    llm_scanners::LLMComprehensiveScanner,
    llm::provider::{OpenAIProvider, LLMProvider},
};

use thalir_transform::solidity_to_ir::transform_solidity_to_ir;
use thalir_core::contract::Contract as IRContract;

#[derive(Args, Debug)]
pub struct AnalyzeArgs {
    #[arg(value_name = "INPUT")]
    pub input: PathBuf,

    #[arg(short, long, default_value = "text")]
    pub format: OutputFormat,

    #[arg(short = 's', long, default_value = "low")]
    pub min_severity: String,

    #[arg(short = 'c', long, default_value = "low")]
    pub min_confidence: String,

    #[arg(long)]
    pub cross_validated_only: bool,

    #[arg(long, default_value = "0.7")]
    pub correlation_threshold: f64,

    #[arg(short, long)]
    pub verbose: bool,

    #[arg(long)]
    pub openai_api_key: Option<String>,

    #[arg(long, default_value = "gpt-4o")]
    pub model: String,

    #[arg(short, long)]
    pub output: Option<PathBuf>,

    #[arg(long)]
    pub detailed_report: bool,

    #[arg(long)]
    pub no_llm: bool,

    #[arg(long)]
    pub llm_only: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum OutputFormat {
    Text,
    Json,
    Markdown,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(OutputFormat::Text),
            "json" => Ok(OutputFormat::Json),
            "markdown" | "md" => Ok(OutputFormat::Markdown),
            _ => Err(format!("Unknown output format: {}", s)),
        }
    }
}

pub async fn execute(args: AnalyzeArgs) -> Result<()> {
    let start = Instant::now();

    let min_severity = parse_severity(&args.min_severity)?;
    let min_confidence = parse_confidence(&args.min_confidence)?;

    let source_code = std::fs::read_to_string(&args.input)
        .with_context(|| format!("Failed to read file: {:?}", args.input))?;

    if args.verbose {
        println!("{}", "🔍 Starting comprehensive security analysis...".bright_blue());
        println!("📁 Analyzing: {}", args.input.display());
    }

    let ir_contract = transform_to_ir(&source_code, &args)?;
    let contract_name = ir_contract.name.clone();

    let context = create_context(ir_contract, source_code.clone())?;

    let mut all_findings = Vec::new();

    if !args.llm_only {
        if args.verbose {
            println!("\n{}", "🔧 Running deterministic scanners...".cyan());
        }
        let deterministic_findings = run_deterministic_scanners(&context, &args)?;
        println!("  Found {} potential issues", deterministic_findings.len());
        all_findings.extend(deterministic_findings);
    }

    if !args.no_llm {
        let api_key = args.openai_api_key.clone()
            .or_else(|| std::env::var("OPENAI_API_KEY").ok());

        if let Some(api_key) = api_key {
            if args.verbose {
                println!("\n{}", "🤖 Running LLM-powered scanners...".cyan());
            }
            let llm_findings = run_llm_scanners(&source_code, &contract_name, &api_key, &args.model, &args).await?;
            println!("  Found {} potential issues", llm_findings.len());
            all_findings.extend(llm_findings);
        } else {
            eprintln!("{}", "⚠️  No OpenAI API key provided (use --openai-api-key or set OPENAI_API_KEY), skipping LLM scanners".yellow());
        }
    }

    if args.verbose {
        println!("\n{}", "🔄 Correlating findings across scanners...".cyan());
    }

    let correlation_config = CorrelationConfig {
        threshold: args.correlation_threshold.min(0.5),  // Use 0.5 as max for better correlation
        boost_confidence: true,
        strategies: vec![
            tameshi_scanners::core::CorrelationStrategy::Location,
            tameshi_scanners::core::CorrelationStrategy::Pattern,
            tameshi_scanners::core::CorrelationStrategy::Semantic,
        ],
    };

    let correlated_result = tameshi_scanners::core::correlate_findings_with_config(
        all_findings.clone(),
        correlation_config
    )?;

    let final_findings = if args.cross_validated_only {
        get_cross_validated_findings(all_findings)?
    } else {
        merge_correlated_findings(all_findings)?
    };

    let filtered_findings = filter_findings(final_findings, min_severity, min_confidence);

    let output = match args.format {
        OutputFormat::Text => generate_text_output(&filtered_findings, &correlated_result, &args),
        OutputFormat::Json => generate_json_output(&filtered_findings, &correlated_result),
        OutputFormat::Markdown => generate_markdown_output(&filtered_findings, &correlated_result, &args),
    }?;

    if let Some(output_path) = args.output {
        std::fs::write(output_path, output)?;
    } else {
        println!("{}", output);
    }

    if args.verbose {
        let elapsed = start.elapsed();
        println!("\n{}", "✅ Analysis complete!".green().bold());
        println!("⏱️  Time: {:.2}s", elapsed.as_secs_f64());
        println!("📊 Statistics:");
        println!("  • Total findings: {}", correlated_result.statistics.total_findings);
        println!("  • Correlated findings: {}", correlated_result.statistics.correlated_findings);
        println!("  • Cross-validated groups: {}", correlated_result.statistics.deterministic_llm_correlations);
        println!("  • High confidence findings: {}",
            filtered_findings.iter().filter(|f| f.confidence == Confidence::High).count());
    }

    Ok(())
}

fn parse_severity(s: &str) -> Result<Severity> {
    match s.to_lowercase().as_str() {
        "critical" => Ok(Severity::Critical),
        "high" => Ok(Severity::High),
        "medium" => Ok(Severity::Medium),
        "low" => Ok(Severity::Low),
        "informational" | "info" => Ok(Severity::Informational),
        _ => Err(anyhow::anyhow!("Invalid severity: {}", s)),
    }
}

fn parse_confidence(s: &str) -> Result<Confidence> {
    match s.to_lowercase().as_str() {
        "high" => Ok(Confidence::High),
        "medium" => Ok(Confidence::Medium),
        "low" => Ok(Confidence::Low),
        _ => Err(anyhow::anyhow!("Invalid confidence: {}", s)),
    }
}

fn transform_to_ir(source: &str, args: &AnalyzeArgs) -> Result<IRContract> {
    if args.verbose {
        println!("{}", "📝 Parsing and transforming to IR...".cyan());
    }

    let contracts = transform_solidity_to_ir(source)
        .context("Failed to transform Solidity to IR")?;

    Ok(contracts.into_iter().next()
        .ok_or_else(|| anyhow::anyhow!("No contracts found in source"))?)
}

fn create_context(ir: IRContract, _source: String) -> Result<AnalysisContext> {
    let bundle = RepresentationBundle::new()
        .add(ir);

    let context = AnalysisContext::with_config(bundle, ScannerConfig::default());

    Ok(context)
}

fn run_deterministic_scanners(context: &AnalysisContext, _args: &AnalyzeArgs) -> Result<Vec<Finding>> {
    let scanners: Vec<Box<dyn Scanner>> = vec![
        Box::new(IRReentrancyScanner::new()),
        Box::new(IRAccessControlScanner::new()),
        Box::new(IRTimeVulnerabilityScanner::new()),
        Box::new(IRIntegerOverflowScanner::new()),
        Box::new(IRDoSVulnerabilityScanner::new()),
    ];

    let mut all_findings = Vec::new();
    for scanner in scanners {
        match scanner.scan(context) {
            Ok(findings) => all_findings.extend(findings),
            Err(e) => eprintln!("Scanner {} failed: {}", scanner.id(), e),
        }
    }

    Ok(all_findings)
}

async fn run_llm_scanners(
    source_code: &str,
    contract_name: &str,
    _api_key: &str,
    model: &str,
    _args: &AnalyzeArgs,
) -> Result<Vec<Finding>> {
    let provider: Arc<dyn LLMProvider> = Arc::new(
        OpenAIProvider::new(Some(model.to_string()))?
    );

    let llm_comprehensive = LLMComprehensiveScanner::new(provider.clone());

    let findings = llm_comprehensive.analyze_source(source_code, contract_name).await?;

    Ok(findings)
}

fn filter_findings(
    findings: Vec<Finding>,
    min_severity: Severity,
    min_confidence: Confidence,
) -> Vec<Finding> {
    findings.into_iter()
        .filter(|f| f.severity >= min_severity && f.confidence >= min_confidence)
        .collect()
}

fn generate_text_output(
    findings: &[Finding],
    correlation_result: &tameshi_scanners::core::CorrelationResult,
    args: &AnalyzeArgs,
) -> Result<String> {
    use std::fmt::Write;
    let mut output = String::new();

    writeln!(&mut output, "\n{}", "════════════════════════════════════════".bright_blue())?;
    writeln!(&mut output, "{}", "     SECURITY ANALYSIS REPORT".bright_blue().bold())?;
    writeln!(&mut output, "{}", "════════════════════════════════════════".bright_blue())?;

    if findings.is_empty() {
        writeln!(&mut output, "\n{}", "✨ No vulnerabilities found!".green())?;
        return Ok(output);
    }

    let mut by_severity: HashMap<Severity, Vec<&Finding>> = HashMap::new();
    for finding in findings {
        by_severity.entry(finding.severity).or_insert_with(Vec::new).push(finding);
    }

    for severity in [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Informational] {
        if let Some(severity_findings) = by_severity.get(&severity) {
            let severity_color = match severity {
                Severity::Critical => "CRITICAL".red().bold(),
                Severity::High => "HIGH".bright_red(),
                Severity::Medium => "MEDIUM".yellow(),
                Severity::Low => "LOW".bright_yellow(),
                Severity::Informational => "INFO".bright_blue(),
            };

            writeln!(&mut output, "\n{} {} Issues ({})",
                "▶".bright_white(),
                severity_color,
                severity_findings.len()
            )?;
            writeln!(&mut output, "{}", "─".repeat(40).bright_black())?;

            for finding in severity_findings {
                let confidence_str = match finding.confidence {
                    Confidence::High => "●●●".green(),
                    Confidence::Medium => "●●○".yellow(),
                    Confidence::Low => "●○○".bright_black(),
                };

                writeln!(&mut output, "\n  {} {} {}",
                    "•".bright_white(),
                    finding.title.bright_white().bold(),
                    confidence_str
                )?;

                let scanner_type = if finding.scanner_id.contains("llm") {
                    "[LLM]".bright_cyan()
                } else {
                    "[Deterministic]".bright_green()
                };
                writeln!(&mut output, "    Scanner: {} {}", scanner_type, finding.scanner_id)?;

                if let Some(ref provenance) = finding.provenance {
                    match &provenance.validation_status {
                        tameshi_scanners::core::provenance::ValidationStatus::Confirmed { confirming_scanners, .. } => {
                            writeln!(&mut output, "    {} Cross-validated by: {}",
                                "✓".green(),
                                confirming_scanners.join(", ")
                            )?;
                        }
                        _ => {}
                    }
                }

                writeln!(&mut output, "    {}", finding.description.bright_black())?;

                if !finding.locations.is_empty() {
                    for loc in &finding.locations[..finding.locations.len().min(3)] {
                        if let Some(ref ir_pos) = loc.ir_position {
                            writeln!(&mut output, "    📍 Solidity: {}:{}:{}",
                                loc.file, loc.line, loc.column
                            )?;
                            writeln!(&mut output, "       IR: {} @ [{}] in block {}",
                                ir_pos.function, ir_pos.position, ir_pos.block_id
                            )?;
                        } else {
                            writeln!(&mut output, "    📍 {}:{}:{}",
                                loc.file, loc.line, loc.column
                            )?;
                        }
                    }
                }
            }
        }
    }

    if args.detailed_report {
        writeln!(&mut output, "\n{}", "═══════════════════════════════".bright_blue())?;
        writeln!(&mut output, "{}", "     CORRELATION ANALYSIS".bright_blue().bold())?;
        writeln!(&mut output, "{}", "═══════════════════════════════".bright_blue())?;

        writeln!(&mut output, "\n{}", "📊 Correlation Table:".bright_cyan())?;
        writeln!(&mut output, "{}", "─".repeat(80).bright_black())?;

        for group in &correlation_result.correlation_groups {
            if group.is_cross_validated() {
                let mut det_finding = None;
                let mut llm_finding = None;

                for finding in group.findings.values() {
                    if finding.scanner_id.contains("llm") {
                        llm_finding = Some(finding);
                    } else {
                        det_finding = Some(finding);
                    }
                }

                if let (Some(det), Some(llm)) = (det_finding, llm_finding) {
                    let avg_confidence = (det.confidence_score + llm.confidence_score) / 2.0;
                    let strategy = group.correlation_strategy.as_deref().unwrap_or("Mixed");

                    writeln!(&mut output, "\n  {} Correlated Finding:",
                        "▶".bright_white())?;
                    writeln!(&mut output, "    {} Deterministic: {} ({})",
                        "•".bright_green(),
                        det.title.bright_white(),
                        det.severity
                    )?;
                    writeln!(&mut output, "    {} LLM: {} ({})",
                        "•".bright_cyan(),
                        llm.title.bright_white(),
                        llm.severity
                    )?;
                    writeln!(&mut output, "    {} Confidence: {:.0}%",
                        "•".bright_yellow(),
                        avg_confidence * 100.0
                    )?;
                    writeln!(&mut output, "    {} Correlation Score: {:.2}",
                        "•".bright_magenta(),
                        group.average_correlation()
                    )?;
                    writeln!(&mut output, "    {} Strategy: {}",
                        "•".bright_blue(),
                        strategy.bright_white()
                    )?;
                }
            }
        }

        writeln!(&mut output)?;
        writeln!(&mut output, "{}", correlation_result.generate_report())?;
    }

    Ok(output)
}

fn generate_json_output(
    findings: &[Finding],
    correlation_result: &tameshi_scanners::core::CorrelationResult,
) -> Result<String> {
    #[derive(serde::Serialize)]
    struct AnalysisReport {
        summary: Summary,
        findings: Vec<Finding>,
        correlation_statistics: CorrelationStats,
    }

    #[derive(serde::Serialize)]
    struct Summary {
        total_findings: usize,
        critical: usize,
        high: usize,
        medium: usize,
        low: usize,
        informational: usize,
        cross_validated: usize,
    }

    #[derive(serde::Serialize)]
    struct CorrelationStats {
        total_findings: usize,
        correlated_findings: usize,
        correlation_groups: usize,
        average_group_size: f64,
        deterministic_llm_correlations: usize,
    }

    let summary = Summary {
        total_findings: findings.len(),
        critical: findings.iter().filter(|f| f.severity == Severity::Critical).count(),
        high: findings.iter().filter(|f| f.severity == Severity::High).count(),
        medium: findings.iter().filter(|f| f.severity == Severity::Medium).count(),
        low: findings.iter().filter(|f| f.severity == Severity::Low).count(),
        informational: findings.iter().filter(|f| f.severity == Severity::Informational).count(),
        cross_validated: correlation_result.statistics.deterministic_llm_correlations,
    };

    let correlation_stats = CorrelationStats {
        total_findings: correlation_result.statistics.total_findings,
        correlated_findings: correlation_result.statistics.correlated_findings,
        correlation_groups: correlation_result.statistics.correlation_groups,
        average_group_size: correlation_result.statistics.average_group_size,
        deterministic_llm_correlations: correlation_result.statistics.deterministic_llm_correlations,
    };

    let report = AnalysisReport {
        summary,
        findings: findings.to_vec(),
        correlation_statistics: correlation_stats,
    };

    Ok(serde_json::to_string_pretty(&report)?)
}

fn generate_markdown_output(
    findings: &[Finding],
    correlation_result: &tameshi_scanners::core::CorrelationResult,
    args: &AnalyzeArgs,
) -> Result<String> {
    use std::fmt::Write;
    let mut output = String::new();

    writeln!(&mut output, "# Security Analysis Report")?;
    writeln!(&mut output, "\n**File:** `{}`", args.input.display())?;
    writeln!(&mut output, "**Date:** {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"))?;

    writeln!(&mut output, "\n## Summary")?;
    writeln!(&mut output, "\n| Severity | Count |")?;
    writeln!(&mut output, "|----------|-------|")?;

    for severity in [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Informational] {
        let count = findings.iter().filter(|f| f.severity == severity).count();
        if count > 0 {
            writeln!(&mut output, "| {} | {} |", severity, count)?;
        }
    }

    writeln!(&mut output, "\n**Cross-validated findings:** {}",
        correlation_result.statistics.deterministic_llm_correlations)?;

    writeln!(&mut output, "\n## Findings")?;

    for (i, finding) in findings.iter().enumerate() {
        let severity_badge = match finding.severity {
            Severity::Critical => "🔴 **CRITICAL**",
            Severity::High => "🟠 **HIGH**",
            Severity::Medium => "🟡 **MEDIUM**",
            Severity::Low => "🟢 **LOW**",
            Severity::Informational => "🔵 **INFO**",
        };

        writeln!(&mut output, "\n### {}. {} {}", i + 1, severity_badge, finding.title)?;

        writeln!(&mut output, "\n**Confidence:** {}",
            match finding.confidence {
                Confidence::High => "High ●●●",
                Confidence::Medium => "Medium ●●○",
                Confidence::Low => "Low ●○○",
            }
        )?;

        writeln!(&mut output, "\n**Scanner:** {} ({})",
            finding.scanner_id,
            if finding.scanner_id.contains("llm") { "LLM-based" } else { "Deterministic" }
        )?;

        if let Some(ref swc_id) = finding.swc_id {
            writeln!(&mut output, "**SWC ID:** {}", swc_id)?;
        }

        writeln!(&mut output, "\n**Description:**\n{}", finding.description)?;

        if !finding.locations.is_empty() {
            writeln!(&mut output, "\n**Locations:**")?;

            let mut solidity_only = Vec::new();
            let mut with_ir = Vec::new();

            for loc in &finding.locations {
                if loc.ir_position.is_some() {
                    with_ir.push(loc);
                } else {
                    solidity_only.push(loc);
                }
            }

            if !with_ir.is_empty() {
                writeln!(&mut output, "\n**Dual Coordinates (Solidity + IR):**")?;
                for loc in with_ir {
                    writeln!(&mut output, "- **Solidity:** `{}:{}:{}`",
                        loc.file, loc.line, loc.column)?;
                    if let Some(ref ir_pos) = loc.ir_position {
                        writeln!(&mut output, "  **IR:** Function `{}` | Position `[{}]` | Block `{}` {}",
                            ir_pos.function,
                            ir_pos.position,
                            ir_pos.block_id,
                            ir_pos.operation.as_ref()
                                .map(|op| format!("| Operation `{}`", op))
                                .unwrap_or_default()
                        )?;
                    }
                }
            }

            if !solidity_only.is_empty() {
                writeln!(&mut output, "\n**Solidity Locations:**")?;
                for loc in solidity_only {
                    writeln!(&mut output, "- `{}:{}:{}`", loc.file, loc.line, loc.column)?;
                }
            }
        }

        if let Some(ref metadata) = finding.metadata {
            if let Some(ref recommendation) = metadata.recommendation {
                writeln!(&mut output, "\n**Recommendation:**\n{}", recommendation)?;
            }
        }
    }

    if args.detailed_report {
        writeln!(&mut output, "\n## Correlation Analysis")?;

        let mut has_correlations = false;
        for group in &correlation_result.correlation_groups {
            if group.is_cross_validated() {
                has_correlations = true;

                let mut det_finding = None;
                let mut llm_finding = None;

                for finding in group.findings.values() {
                    if finding.scanner_id.contains("llm") {
                        llm_finding = Some(finding);
                    } else {
                        det_finding = Some(finding);
                    }
                }

                if let (Some(det), Some(llm)) = (det_finding, llm_finding) {
                    let avg_confidence = (det.confidence_score + llm.confidence_score) / 2.0;
                    let strategy = group.correlation_strategy.as_deref().unwrap_or("Mixed");

                    writeln!(&mut output, "\n### 🔗 Correlated Finding\n")?;

                    writeln!(&mut output, "| **Attribute** | **Deterministic Scanner** | **LLM Scanner** |")?;
                    writeln!(&mut output, "|---------------|---------------------------|-----------------|")?;
                    writeln!(&mut output, "| **Scanner ID** | {} | {} |", det.scanner_id, llm.scanner_id)?;
                    writeln!(&mut output, "| **Severity** | {} | {} |", det.severity, llm.severity)?;
                    writeln!(&mut output, "| **Confidence** | {} ({:.0}%) | {} ({:.0}%) |",
                        det.confidence, det.confidence_score * 100.0,
                        llm.confidence, llm.confidence_score * 100.0
                    )?;
                    writeln!(&mut output, "| **Title** | {} | {} |",
                        det.title.replace('|', "\\|"),
                        llm.title.replace('|', "\\|")
                    )?;

                    writeln!(&mut output, "\n#### Deterministic Scanner Description")?;
                    writeln!(&mut output)?;
                    for line in det.description.lines() {
                        writeln!(&mut output, "> {}", line)?;
                    }

                    writeln!(&mut output, "\n#### LLM Scanner Description")?;
                    writeln!(&mut output)?;
                    for line in llm.description.lines() {
                        writeln!(&mut output, "> {}", line)?;
                    }

                    writeln!(&mut output, "\n**📊 Correlation Metrics:**")?;
                    writeln!(&mut output, "- **Overall Confidence:** {:.0}%", avg_confidence * 100.0)?;
                    writeln!(&mut output, "- **Correlation Score:** {:.2}", group.average_correlation())?;
                    writeln!(&mut output, "- **Correlation Strategy:** {}", strategy)?;
                    writeln!(&mut output, "\n---")?;
                }
            }
        }

        if !has_correlations {
            writeln!(&mut output, "\n*No cross-validated correlations found between deterministic and LLM scanners.*")?;
        }

        writeln!(&mut output)?;
        writeln!(&mut output, "### Detailed Statistics")?;
        writeln!(&mut output)?;
        writeln!(&mut output, "- **Total findings:** {}", correlation_result.statistics.total_findings)?;
        writeln!(&mut output, "- **Correlated findings:** {} ({:.1}%)",
            correlation_result.statistics.correlated_findings,
            (correlation_result.statistics.correlated_findings as f64 /
             correlation_result.statistics.total_findings as f64) * 100.0)?;
        writeln!(&mut output, "- **Correlation groups:** {}", correlation_result.statistics.correlation_groups)?;
        writeln!(&mut output, "- **Average group size:** {:.1}", correlation_result.statistics.average_group_size)?;
        writeln!(&mut output, "- **Cross-validated groups:** {}",
            correlation_result.statistics.deterministic_llm_correlations)?;
    }

    Ok(output)
}