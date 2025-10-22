use crate::core::{Finding, Severity, Confidence};
use crate::core::correlation::{CorrelationResult, CorrelationGroup};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResponse {
    pub summary: AnalysisSummary,

    pub deterministic_findings: Vec<Finding>,

    pub llm_findings: Vec<Finding>,

    pub correlation_result: CorrelationResult,

    pub correlation_statistics: CorrelationStatistics,

    pub cross_validation: CrossValidationResult,

    pub performance_metrics: PerformanceMetrics,

    pub metadata: AnalysisMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSummary {
    pub total_findings: usize,

    pub by_severity: SeverityBreakdown,

    pub by_scanner_type: ScannerTypeBreakdown,

    pub correlation_summary: String,

    pub critical_findings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityBreakdown {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub informational: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerTypeBreakdown {
    pub deterministic: usize,
    pub llm_based: usize,
    pub correlated: usize,
    pub cross_validated: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationStatistics {
    pub total_correlations: usize,

    pub correlation_rate: f64,

    pub cross_validated_count: usize,

    pub cross_validation_rate: f64,

    pub strategy_breakdown: HashMap<String, usize>,

    pub average_correlation_score: f64,

    pub confidence_boost_stats: ConfidenceBoostStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceBoostStats {
    pub boosted_count: usize,

    pub average_boost: f64,

    pub max_boost: f64,

    pub by_original_confidence: HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossValidationResult {
    pub confirmed_findings: Vec<CrossValidatedFinding>,

    pub confidence_boost: f64,

    pub correlation_scores: HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossValidatedFinding {
    pub deterministic_finding: Finding,

    pub llm_finding: Finding,

    pub correlation_score: f64,

    pub correlation_strategy: String,

    pub confidence_change: ConfidenceChange,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceChange {
    pub original: Confidence,
    pub boosted: Confidence,
    pub increase_percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub total_duration: Duration,

    pub deterministic_duration: Duration,

    pub llm_duration: Duration,

    pub correlation_duration: Duration,

    pub scanners_executed: usize,

    pub scanner_timings: HashMap<String, Duration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisMetadata {
    pub timestamp: DateTime<Utc>,

    pub engine_version: String,

    pub scanner_versions: HashMap<String, String>,

    pub source_info: SourceInfo,

    pub config_summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceInfo {
    pub source_type: String,

    pub file_path: Option<String>,

    pub contract_count: usize,

    pub lines_of_code: Option<usize>,
}

impl AnalysisResponse {
    pub fn new() -> Self {
        Self {
            summary: AnalysisSummary::default(),
            deterministic_findings: Vec::new(),
            llm_findings: Vec::new(),
            correlation_result: CorrelationResult::default(),
            correlation_statistics: CorrelationStatistics::default(),
            cross_validation: CrossValidationResult::default(),
            performance_metrics: PerformanceMetrics::default(),
            metadata: AnalysisMetadata::default(),
        }
    }

    pub fn all_findings(&self) -> Vec<&Finding> {
        self.deterministic_findings
            .iter()
            .chain(self.llm_findings.iter())
            .collect()
    }

    pub fn high_severity_findings(&self) -> Vec<&Finding> {
        self.all_findings()
            .into_iter()
            .filter(|f| matches!(f.severity, Severity::High | Severity::Critical))
            .collect()
    }

    pub fn cross_validated_findings(&self) -> &[CrossValidatedFinding] {
        &self.cross_validation.confirmed_findings
    }

    pub fn correlation_groups(&self) -> &[CorrelationGroup] {
        &self.correlation_result.correlation_groups
    }
}

impl Default for AnalysisSummary {
    fn default() -> Self {
        Self {
            total_findings: 0,
            by_severity: SeverityBreakdown::default(),
            by_scanner_type: ScannerTypeBreakdown::default(),
            correlation_summary: String::new(),
            critical_findings: Vec::new(),
        }
    }
}

impl Default for SeverityBreakdown {
    fn default() -> Self {
        Self {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            informational: 0,
        }
    }
}

impl Default for ScannerTypeBreakdown {
    fn default() -> Self {
        Self {
            deterministic: 0,
            llm_based: 0,
            correlated: 0,
            cross_validated: 0,
        }
    }
}

impl Default for CorrelationStatistics {
    fn default() -> Self {
        Self {
            total_correlations: 0,
            correlation_rate: 0.0,
            cross_validated_count: 0,
            cross_validation_rate: 0.0,
            strategy_breakdown: HashMap::new(),
            average_correlation_score: 0.0,
            confidence_boost_stats: ConfidenceBoostStats::default(),
        }
    }
}

impl Default for ConfidenceBoostStats {
    fn default() -> Self {
        Self {
            boosted_count: 0,
            average_boost: 0.0,
            max_boost: 0.0,
            by_original_confidence: HashMap::new(),
        }
    }
}

impl Default for CrossValidationResult {
    fn default() -> Self {
        Self {
            confirmed_findings: Vec::new(),
            confidence_boost: 0.0,
            correlation_scores: HashMap::new(),
        }
    }
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            total_duration: Duration::from_secs(0),
            deterministic_duration: Duration::from_secs(0),
            llm_duration: Duration::from_secs(0),
            correlation_duration: Duration::from_secs(0),
            scanners_executed: 0,
            scanner_timings: HashMap::new(),
        }
    }
}

impl Default for AnalysisMetadata {
    fn default() -> Self {
        Self {
            timestamp: Utc::now(),
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            scanner_versions: HashMap::new(),
            source_info: SourceInfo::default(),
            config_summary: String::new(),
        }
    }
}

impl Default for SourceInfo {
    fn default() -> Self {
        Self {
            source_type: "unknown".to_string(),
            file_path: None,
            contract_count: 0,
            lines_of_code: None,
        }
    }
}