use crate::core::analysis_response::AnalysisResponse;
use crate::core::analysis_request::OutputFormat;
use crate::core::{Finding, Severity};
use anyhow::Result;

pub struct ReportGenerator;

impl ReportGenerator {
    pub fn generate(response: &AnalysisResponse, format: OutputFormat) -> Result<String> {
        match format {
            OutputFormat::Markdown => Self::generate_markdown(response),
            OutputFormat::Json => Self::generate_json(response),
            OutputFormat::Sarif => Self::generate_sarif(response),
            OutputFormat::Lsp => Self::generate_lsp(response),
        }
    }

    fn generate_markdown(response: &AnalysisResponse) -> Result<String> {
        let mut report = String::new();

        report.push_str("# Security Analysis Report\n\n");
        report.push_str(&format!("**Generated**: {}\n", response.metadata.timestamp.format("%Y-%m-%d %H:%M:%S UTC")));
        report.push_str(&format!("**Engine Version**: {}\n", response.metadata.engine_version));
        report.push_str(&format!("**Source**: {}\n", response.metadata.source_info.source_type));
        if let Some(ref path) = response.metadata.source_info.file_path {
            report.push_str(&format!("**File**: `{}`\n", path));
        }
        report.push_str("\n");

        report.push_str("## Executive Summary\n\n");
        report.push_str(&format!("- **Total Findings**: {}\n", response.summary.total_findings));
        report.push_str(&format!("- **Critical**: {}\n", response.summary.by_severity.critical));
        report.push_str(&format!("- **High**: {}\n", response.summary.by_severity.high));
        report.push_str(&format!("- **Medium**: {}\n", response.summary.by_severity.medium));
        report.push_str(&format!("- **Low**: {}\n", response.summary.by_severity.low));
        report.push_str("\n");

        report.push_str(&format!("**Correlation Summary**: {}\n\n", response.summary.correlation_summary));

        report.push_str("### Scanner Breakdown\n\n");
        report.push_str("| Scanner Type | Findings | Percentage |\n");
        report.push_str("|--------------|----------|------------|\n");

        let total = response.summary.total_findings as f64;
        if total > 0.0 {
            report.push_str(&format!("| Deterministic | {} | {:.1}% |\n",
                response.summary.by_scanner_type.deterministic,
                (response.summary.by_scanner_type.deterministic as f64 / total) * 100.0));
            report.push_str(&format!("| LLM-Based | {} | {:.1}% |\n",
                response.summary.by_scanner_type.llm_based,
                (response.summary.by_scanner_type.llm_based as f64 / total) * 100.0));
            report.push_str(&format!("| Correlated | {} | {:.1}% |\n",
                response.summary.by_scanner_type.correlated,
                (response.summary.by_scanner_type.correlated as f64 / total) * 100.0));
            report.push_str(&format!("| Cross-Validated | {} | {:.1}% |\n",
                response.summary.by_scanner_type.cross_validated,
                (response.summary.by_scanner_type.cross_validated as f64 / total) * 100.0));
        }
        report.push_str("\n");

        if response.correlation_statistics.total_correlations > 0 {
            report.push_str("## Correlation Analysis\n\n");
            report.push_str(&format!("- **Total Correlations**: {}\n", response.correlation_statistics.total_correlations));
            report.push_str(&format!("- **Correlation Rate**: {:.1}%\n", response.correlation_statistics.correlation_rate * 100.0));
            report.push_str(&format!("- **Average Correlation Score**: {:.2}\n", response.correlation_statistics.average_correlation_score));
            report.push_str(&format!("- **Cross-Validated Findings**: {}\n\n", response.correlation_statistics.cross_validated_count));

            if !response.correlation_statistics.strategy_breakdown.is_empty() {
                report.push_str("### Correlation Strategies Used\n\n");
                report.push_str("| Strategy | Count |\n");
                report.push_str("|----------|-------|\n");
                for (strategy, count) in &response.correlation_statistics.strategy_breakdown {
                    report.push_str(&format!("| {} | {} |\n", strategy, count));
                }
                report.push_str("\n");
            }
        }

        if !response.cross_validation.confirmed_findings.is_empty() {
            report.push_str("## Cross-Validated Findings\n\n");
            report.push_str("These vulnerabilities were confirmed by both deterministic and LLM-based scanners:\n\n");

            for (idx, cv_finding) in response.cross_validation.confirmed_findings.iter().enumerate() {
                report.push_str(&format!("### {}. {}\n\n", idx + 1, cv_finding.deterministic_finding.title));
                report.push_str(&format!("> **Correlation Score**: {:.2}\n", cv_finding.correlation_score));
                report.push_str(&format!("> **Strategy**: {}\n", cv_finding.correlation_strategy));
                report.push_str(&format!("> **Confidence Boost**: +{:.1}%\n\n", cv_finding.confidence_change.increase_percentage));

                report.push_str("**Deterministic Scanner**:\n");
                report.push_str(&format!("> {}\n\n", Self::format_finding_description(&cv_finding.deterministic_finding)));

                report.push_str("**LLM Scanner**:\n");
                report.push_str(&format!("> {}\n\n", Self::format_finding_description(&cv_finding.llm_finding)));

                report.push_str("---\n\n");
            }
        }

        if !response.deterministic_findings.is_empty() {
            report.push_str("## Deterministic Scanner Findings\n\n");
            Self::append_findings_table(&mut report, &response.deterministic_findings);
        }

        if !response.llm_findings.is_empty() {
            report.push_str("## LLM Scanner Findings\n\n");
            Self::append_findings_table(&mut report, &response.llm_findings);
        }

        report.push_str("## Performance Metrics\n\n");
        report.push_str(&format!("- **Total Duration**: {:.2}s\n", response.performance_metrics.total_duration.as_secs_f64()));
        report.push_str(&format!("- **Deterministic Scanners**: {:.2}s\n", response.performance_metrics.deterministic_duration.as_secs_f64()));
        report.push_str(&format!("- **LLM Scanners**: {:.2}s\n", response.performance_metrics.llm_duration.as_secs_f64()));
        report.push_str(&format!("- **Correlation**: {:.2}s\n", response.performance_metrics.correlation_duration.as_secs_f64()));
        report.push_str("\n");

        Ok(report)
    }

    fn generate_json(response: &AnalysisResponse) -> Result<String> {
        serde_json::to_string_pretty(response)
            .map_err(|e| anyhow::anyhow!("Failed to serialize to JSON: {}", e))
    }

    fn generate_sarif(response: &AnalysisResponse) -> Result<String> {
        Ok("SARIF format not yet implemented".to_string())
    }

    fn generate_lsp(response: &AnalysisResponse) -> Result<String> {
        Ok("LSP format not yet implemented".to_string())
    }

    fn append_findings_table(report: &mut String, findings: &[Finding]) {
        report.push_str("| # | Severity | Confidence | Finding | Scanner |\n");
        report.push_str("|---|----------|------------|---------|----------|\n");

        for (idx, finding) in findings.iter().enumerate() {
            let severity_emoji = match finding.severity {
                Severity::Critical => "🔴",
                Severity::High => "🟠",
                Severity::Medium => "🟡",
                Severity::Low => "🔵",
                Severity::Informational => "⚪",
            };

            report.push_str(&format!(
                "| {} | {} {} | {:?} | {} | {} |\n",
                idx + 1,
                severity_emoji,
                format!("{:?}", finding.severity),
                finding.confidence,
                Self::truncate(&finding.title, 60),
                Self::truncate(&finding.scanner_id, 30)
            ));
        }

        report.push_str("\n");

        for (idx, finding) in findings.iter().enumerate() {
            report.push_str(&format!("### {}. {}\n\n", idx + 1, finding.title));
            report.push_str(&format!("> {}\n\n", Self::format_finding_description(finding)));

            if !finding.locations.is_empty() {
                for location in &finding.locations {
                    report.push_str(&format!("> **Location**: {}:{}:{}\n",
                        location.file,
                        location.line,
                        location.column));

                    if let Some(ref ir_pos) = location.ir_position {
                        report.push_str(&format!("> **IR Position**: Function `{}`, Position [{}]\n",
                            ir_pos.function,
                            ir_pos.position));
                    }
                }
                report.push_str("\n");
            }
        }
    }

    fn format_finding_description(finding: &Finding) -> String {
        finding.description
            .lines()
            .map(|line| line.trim())
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn truncate(s: &str, max_len: usize) -> String {
        if s.len() <= max_len {
            s.to_string()
        } else {
            format!("{}...", &s[..max_len - 3])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate() {
        assert_eq!(ReportGenerator::truncate("short", 10), "short");
        assert_eq!(ReportGenerator::truncate("this is a very long string", 10), "this is...");
    }
}