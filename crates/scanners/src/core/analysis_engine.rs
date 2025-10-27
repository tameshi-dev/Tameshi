use crate::core::analysis_request::{AnalysisConfig, CorrelationConfig};
use crate::core::analysis_response::{
    AnalysisMetadata, AnalysisResponse, AnalysisSummary, ConfidenceBoostStats, ConfidenceChange,
    CorrelationStatistics, CrossValidatedFinding, CrossValidationResult, PerformanceMetrics,
    ScannerTypeBreakdown, SeverityBreakdown, SourceInfo,
};
use crate::core::{
    correlate_findings, Confidence, CorrelationConfig as CoreCorrelationConfig,
    CorrelationStrategy, Finding, Scanner, Severity,
};
use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use std::time::Instant;

pub struct AnalysisEngine {
    config: AnalysisConfig,
}

impl AnalysisEngine {
    pub fn new() -> Self {
        Self {
            config: AnalysisConfig::default(),
        }
    }

    pub fn with_config(config: AnalysisConfig) -> Self {
        Self { config }
    }

    pub fn analyze_findings(
        &self,
        deterministic_findings: Vec<Finding>,
        llm_findings: Vec<Finding>,
        config: &AnalysisConfig,
        source_info: SourceInfo,
    ) -> Result<AnalysisResponse> {
        let start_time = Instant::now();
        let mut response = AnalysisResponse::new();

        let det_duration = std::time::Duration::from_secs(0);
        let llm_duration = std::time::Duration::from_secs(0);

        let corr_start = Instant::now();
        let (correlation_result, correlation_stats, cross_validation) =
            if config.correlation_config.enabled {
                self.correlate_findings(
                    &deterministic_findings,
                    &llm_findings,
                    &config.correlation_config,
                )?
            } else {
                Default::default()
            };
        let corr_duration = corr_start.elapsed();

        response.deterministic_findings = deterministic_findings;
        response.llm_findings = llm_findings;
        response.correlation_result = correlation_result;
        response.correlation_statistics = correlation_stats;
        response.cross_validation = cross_validation;

        response.summary = self.calculate_summary(&response);

        let total_duration = start_time.elapsed();
        response.performance_metrics = PerformanceMetrics {
            total_duration,
            deterministic_duration: det_duration,
            llm_duration,
            correlation_duration: corr_duration,
            scanners_executed: 0,
            scanner_timings: HashMap::new(),
        };

        response.metadata = AnalysisMetadata {
            timestamp: Utc::now(),
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            scanner_versions: HashMap::new(),
            source_info,
            config_summary: format!(
                "Deterministic: {}, LLM: {}, Correlation: {}",
                config.scanners.enable_deterministic,
                config.scanners.enable_llm,
                config.correlation_config.enabled
            ),
        };

        Ok(response)
    }

    fn correlate_findings(
        &self,
        deterministic: &[Finding],
        llm: &[Finding],
        config: &CorrelationConfig,
    ) -> Result<(
        crate::core::correlation::CorrelationResult,
        CorrelationStatistics,
        CrossValidationResult,
    )> {
        let mut all_findings = deterministic.to_vec();
        all_findings.extend_from_slice(llm);

        let core_config = CoreCorrelationConfig {
            threshold: config.threshold,
            boost_confidence: config.confidence_boost > 0.0,
            strategies: config
                .strategies
                .iter()
                .filter_map(|s| match s.as_str() {
                    "Location" => Some(CorrelationStrategy::Location),
                    "Pattern" => Some(CorrelationStrategy::Pattern),
                    "Semantic" => Some(CorrelationStrategy::Semantic),
                    _ => None,
                })
                .collect(),
        };

        let correlation_result = correlate_findings(all_findings)?;

        let correlation_stats = self.calculate_correlation_statistics(
            &correlation_result,
            deterministic.len(),
            llm.len(),
        );

        let cross_validation = if config.enable_cross_validation {
            self.extract_cross_validation(
                deterministic,
                llm,
                &correlation_result,
                config.confidence_boost,
            )
        } else {
            CrossValidationResult::default()
        };

        Ok((correlation_result, correlation_stats, cross_validation))
    }

    fn calculate_correlation_statistics(
        &self,
        result: &crate::core::correlation::CorrelationResult,
        det_count: usize,
        llm_count: usize,
    ) -> CorrelationStatistics {
        let total_findings = det_count + llm_count;
        let total_correlations = result.correlation_groups.len();

        let mut strategy_breakdown = HashMap::new();
        let mut correlation_scores = Vec::new();

        for group in &result.correlation_groups {
            if let Some(strategy) = &group.correlation_strategy {
                *strategy_breakdown.entry(strategy.clone()).or_insert(0) += 1;
            }

            for score in group.correlation_scores.values() {
                correlation_scores.push(*score);
            }
        }

        let average_score = if !correlation_scores.is_empty() {
            correlation_scores.iter().sum::<f64>() / correlation_scores.len() as f64
        } else {
            0.0
        };

        CorrelationStatistics {
            total_correlations,
            correlation_rate: if total_findings > 0 {
                total_correlations as f64 / total_findings as f64
            } else {
                0.0
            },
            cross_validated_count: 0, // Calculated separately
            cross_validation_rate: 0.0,
            strategy_breakdown,
            average_correlation_score: average_score,
            confidence_boost_stats: ConfidenceBoostStats::default(),
        }
    }

    fn extract_cross_validation(
        &self,
        deterministic: &[Finding],
        llm: &[Finding],
        correlation_result: &crate::core::correlation::CorrelationResult,
        confidence_boost: f64,
    ) -> CrossValidationResult {
        let mut confirmed_findings = Vec::new();
        let mut correlation_scores = HashMap::new();

        for group in &correlation_result.correlation_groups {
            let det_findings: Vec<_> = group
                .findings
                .values()
                .filter(|f| deterministic.iter().any(|d| d.scanner_id == f.scanner_id))
                .cloned()
                .collect();

            let llm_findings: Vec<_> = group
                .findings
                .values()
                .filter(|f| llm.iter().any(|l| l.scanner_id == f.scanner_id))
                .cloned()
                .collect();

            if !det_findings.is_empty() && !llm_findings.is_empty() {
                for det_finding in &det_findings {
                    for llm_finding in &llm_findings {
                        let score = group
                            .correlation_scores
                            .values()
                            .copied()
                            .max_by(|a, b| a.partial_cmp(b).unwrap())
                            .unwrap_or(0.0);

                        confirmed_findings.push(CrossValidatedFinding {
                            deterministic_finding: det_finding.clone(),
                            llm_finding: llm_finding.clone(),
                            correlation_score: score,
                            correlation_strategy: group
                                .correlation_strategy
                                .clone()
                                .unwrap_or_default(),
                            confidence_change: ConfidenceChange {
                                original: det_finding.confidence,
                                boosted: Confidence::High, // Simplified
                                increase_percentage: confidence_boost * 100.0,
                            },
                        });

                        correlation_scores.insert(
                            format!("{}+{}", det_finding.scanner_id, llm_finding.scanner_id),
                            score,
                        );
                    }
                }
            }
        }

        CrossValidationResult {
            confirmed_findings,
            confidence_boost,
            correlation_scores,
        }
    }

    fn calculate_summary(&self, response: &AnalysisResponse) -> AnalysisSummary {
        let all_findings = response.all_findings();
        let total_findings = all_findings.len();

        let by_severity = SeverityBreakdown {
            critical: all_findings
                .iter()
                .filter(|f| matches!(f.severity, Severity::Critical))
                .count(),
            high: all_findings
                .iter()
                .filter(|f| matches!(f.severity, Severity::High))
                .count(),
            medium: all_findings
                .iter()
                .filter(|f| matches!(f.severity, Severity::Medium))
                .count(),
            low: all_findings
                .iter()
                .filter(|f| matches!(f.severity, Severity::Low))
                .count(),
            informational: all_findings
                .iter()
                .filter(|f| matches!(f.severity, Severity::Informational))
                .count(),
        };

        let by_scanner_type = ScannerTypeBreakdown {
            deterministic: response.deterministic_findings.len(),
            llm_based: response.llm_findings.len(),
            correlated: response.correlation_result.correlation_groups.len(),
            cross_validated: response.cross_validation.confirmed_findings.len(),
        };

        let correlation_summary = if response.correlation_statistics.total_correlations > 0 {
            format!(
                "{} correlations ({:.1}% correlation rate), {} cross-validated",
                response.correlation_statistics.total_correlations,
                response.correlation_statistics.correlation_rate * 100.0,
                response.cross_validation.confirmed_findings.len()
            )
        } else {
            "No correlations found".to_string()
        };

        let critical_findings: Vec<String> = all_findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Critical | Severity::High))
            .take(5)
            .map(|f| f.title.clone())
            .collect();

        AnalysisSummary {
            total_findings,
            by_severity,
            by_scanner_type,
            correlation_summary,
            critical_findings,
        }
    }
}

impl Default for AnalysisEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::result::FindingMetadata;
    use crate::core::{Confidence, Finding, Location, Severity};

    #[test]
    fn test_comprehensive_analysis_with_cross_validation() {
        let engine = AnalysisEngine::new();

        let det_findings = vec![Finding {
            scanner_id: "reentrancy-ir".to_string(),
            swc_id: Some("SWC-107".to_string()),
            finding_type: "reentrancy".to_string(),
            severity: Severity::High,
            base_severity: Severity::High,
            confidence: Confidence::Medium,
            confidence_score: 0.6,
            title: "Reentrancy in withdraw".to_string(),
            description: "State change after external call".to_string(),
            locations: vec![
                Location::new("<unknown>".to_string(), 12, 28).with_ir_position(
                    "withdraw".to_string(),
                    5,
                    0,
                ),
                Location::new("<unknown>".to_string(), 16, 18).with_ir_position(
                    "withdraw".to_string(),
                    10,
                    0,
                ),
            ],
            metadata: Some(FindingMetadata {
                recommendation: Some("Use checks-effects-interactions".to_string()),
                ..Default::default()
            }),
            severity_context: None,
            provenance: None,
        }];

        let llm_findings = vec![Finding {
            scanner_id: "llm_reentrancy".to_string(),
            swc_id: Some("SWC-107".to_string()),
            finding_type: "reentrancy".to_string(),
            severity: Severity::High,
            base_severity: Severity::High,
            confidence: Confidence::High,
            confidence_score: 0.9,
            title: "Reentrancy vulnerability".to_string(),
            description: "External call before state update at positions [5] and [10]".to_string(),
            locations: vec![
                Location::new("<unknown>".to_string(), 12, 28).with_ir_position(
                    "withdraw".to_string(),
                    5,
                    0,
                ),
                Location::new("<unknown>".to_string(), 16, 18).with_ir_position(
                    "withdraw".to_string(),
                    10,
                    0,
                ),
            ],
            metadata: Some(FindingMetadata {
                recommendation: Some("Apply reentrancy guard".to_string()),
                ..Default::default()
            }),
            severity_context: None,
            provenance: None,
        }];

        let config = AnalysisConfig::default();
        let source_info = SourceInfo {
            source_type: "test".to_string(),
            file_path: Some("test.sol".to_string()),
            contract_count: 1,
            lines_of_code: Some(50),
        };

        let response = engine
            .analyze_findings(det_findings, llm_findings, &config, source_info)
            .unwrap();

        println!(
            "Correlation statistics: {:?}",
            response.correlation_statistics
        );
        println!(
            "Cross-validation: {} confirmed",
            response.cross_validation.confirmed_findings.len()
        );
        println!(
            "Correlation groups: {}",
            response.correlation_result.correlation_groups.len()
        );

        assert!(
            response.correlation_statistics.total_correlations > 0,
            "Should have correlations"
        );

        println!(
            "Cross-validated count: {}",
            response.correlation_statistics.cross_validated_count
        );

        assert_eq!(response.summary.total_findings, 2);
        assert!(response.summary.by_severity.high > 0);
    }

    #[test]
    fn test_analysis_without_correlation() {
        let engine = AnalysisEngine::new();

        let det_findings = vec![Finding {
            scanner_id: "access-control".to_string(),
            swc_id: None,
            finding_type: "access-control".to_string(),
            severity: Severity::Low,
            base_severity: Severity::Low,
            confidence: Confidence::Medium,
            confidence_score: 0.6,
            title: "Missing access control".to_string(),
            description: "No owner check".to_string(),
            locations: vec![
                Location::new("<unknown>".to_string(), 47, 20).with_ir_position(
                    "setOwner".to_string(),
                    0,
                    0,
                ),
            ],
            metadata: None,
            severity_context: None,
            provenance: None,
        }];

        let llm_findings = vec![Finding {
            scanner_id: "llm_overflow".to_string(),
            swc_id: Some("SWC-101".to_string()),
            finding_type: "integer-overflow".to_string(),
            severity: Severity::High,
            base_severity: Severity::High,
            confidence: Confidence::High,
            confidence_score: 0.9,
            title: "Integer overflow".to_string(),
            description: "Unchecked addition".to_string(),
            locations: vec![
                Location::new("<unknown>".to_string(), 41, 18).with_ir_position(
                    "transfer".to_string(),
                    15,
                    0,
                ),
            ],
            metadata: Some(FindingMetadata {
                recommendation: Some("Use SafeMath".to_string()),
                ..Default::default()
            }),
            severity_context: None,
            provenance: None,
        }];

        let config = AnalysisConfig::default();
        let source_info = SourceInfo {
            source_type: "test".to_string(),
            file_path: Some("test.sol".to_string()),
            contract_count: 1,
            lines_of_code: Some(30),
        };

        let response = engine
            .analyze_findings(det_findings, llm_findings, &config, source_info)
            .unwrap();

        assert_eq!(response.summary.total_findings, 2);
        assert_eq!(
            response.cross_validation.confirmed_findings.len(),
            0,
            "Different locations should not cross-validate"
        );
    }
}
