//! Core abstractions and infrastructure for the scanner framework
//!
//! Fundamental building blocks enabling Tameshi's flexible, multi-modal vulnerability
//! detection. The Scanner trait defines the interface all detectors implement, while
//! the correlation engine cross-validates findings between different analyzers to boost
//! confidence. Provenance tracking maintains audit trails from detection through
//! remediation, and the context layer lets scanners work with multiple program
//! representations simultaneously so IR-based and source-level analysis can complement
//! each other.

pub mod composition;
pub mod context;
pub mod correlation;
pub mod correlation_api;
pub mod fingerprint;
pub mod interfaces;
pub mod provenance;
pub mod result;
pub mod scanner;
pub mod severity;
pub mod severity_calculator;

pub mod analysis_engine;
pub mod analysis_request;
pub mod analysis_response;
pub mod report_generator;

pub use composition::{CompositeScanner, FilteredScanner, ParallelScanner, SequentialScanner};
pub use context::{AnalysisContext, ContractInfo, ScannerConfig};
pub use correlation::{CorrelationEngine, CorrelationGroup, CorrelationResult};
pub use correlation_api::{
    correlate_findings, correlate_findings_with_config, generate_correlation_report,
    get_cross_validated_findings, merge_correlated_findings, CorrelationConfig,
    CorrelationStrategy,
};
pub use fingerprint::{DeduplicationStats, FindingFingerprint};
pub use interfaces::InheritanceProvider;
pub use provenance::{Evidence, EvidenceType, FindingProvenance, ProvenanceSource};
pub use result::{Finding, IRPosition, Location};
pub use scanner::Scanner;
pub use severity::{Confidence, Severity};
pub use severity_calculator::SeverityCalculator;

pub use analysis_engine::AnalysisEngine;
pub use analysis_request::{
    AnalysisConfig, AnalysisRequest, AnalysisSource, LLMConfig, OutputFormat, ScannerSelection,
    Verbosity,
};
pub use analysis_response::{
    AnalysisResponse, AnalysisSummary, CorrelationStatistics, CrossValidatedFinding,
    CrossValidationResult, PerformanceMetrics, SourceInfo,
};
pub use report_generator::ReportGenerator;
