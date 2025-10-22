//! Public API for finding correlation
//!
//! This module provides high-level functions for correlating findings
//! from different scanners, enabling cross-validation between deterministic
//! and LLM-based approaches.

use anyhow::Result;
use crate::core::{
    result::Finding,
    correlation::{CorrelationEngine, CorrelationResult},
};

pub fn correlate_findings(findings: Vec<Finding>) -> Result<CorrelationResult> {
    let engine = CorrelationEngine::new()
        .with_threshold(0.5); // 50% similarity threshold for better correlation

    Ok(engine.correlate(findings))
}

pub fn correlate_findings_with_config(
    findings: Vec<Finding>,
    config: CorrelationConfig,
) -> Result<CorrelationResult> {
    let engine = CorrelationEngine::new()
        .with_threshold(config.threshold);


    Ok(engine.correlate(findings))
}

#[derive(Debug, Clone)]
pub struct CorrelationConfig {
    pub threshold: f64,

    pub boost_confidence: bool,

    pub strategies: Vec<CorrelationStrategy>,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            threshold: 0.7,
            boost_confidence: true,
            strategies: vec![
                CorrelationStrategy::Location,
                CorrelationStrategy::Pattern,
                CorrelationStrategy::Semantic,
            ],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorrelationStrategy {
    Location,

    Pattern,

    Semantic,
}

pub fn get_cross_validated_findings(findings: Vec<Finding>) -> Result<Vec<Finding>> {
    let result = correlate_findings(findings)?;

    let mut validated_findings = Vec::new();

    for group in result.cross_validated_groups() {
        if let Some(best_finding) = group
            .findings
            .values()
            .max_by(|a, b| a.confidence_score.partial_cmp(&b.confidence_score).unwrap())
        {
            validated_findings.push(best_finding.clone());
        }
    }

    Ok(validated_findings)
}

pub fn generate_correlation_report(findings: Vec<Finding>) -> Result<String> {
    let result = correlate_findings(findings)?;
    Ok(result.generate_report())
}

pub fn merge_correlated_findings(findings: Vec<Finding>) -> Result<Vec<Finding>> {
    let result = correlate_findings(findings)?;
    let mut merged = Vec::new();

    for group in &result.correlation_groups {
        if group.findings.len() > 1 {
            let mut best_finding = group
                .findings
                .values()
                .max_by(|a, b| a.confidence_score.partial_cmp(&b.confidence_score).unwrap())
                .unwrap()
                .clone();

            for finding in group.findings.values() {
                if let Some(ref mut best_prov) = best_finding.provenance {
                    if let Some(ref other_prov) = finding.provenance {
                        for evidence in &other_prov.evidence {
                            if !best_prov.evidence.iter().any(|e| e.content == evidence.content) {
                                best_prov.evidence.push(evidence.clone());
                            }
                        }

                        best_prov.related_findings.push(
                            crate::core::provenance::RelatedFinding {
                                finding_id: other_prov.finding_id.clone(),
                                relationship: crate::core::provenance::FindingRelationship::SameVulnerability,
                                correlation_strength: group.average_correlation(),
                                shared_evidence: Vec::new(),
                            }
                        );
                    }
                }

                for loc in &finding.locations {
                    if !best_finding.locations.contains(loc) {
                        best_finding.locations.push(loc.clone());
                    }
                }

                if let Some(ref mut best_meta) = best_finding.metadata {
                    if let Some(ref other_meta) = finding.metadata {
                        for func in &other_meta.affected_functions {
                            if !best_meta.affected_functions.contains(func) {
                                best_meta.affected_functions.push(func.clone());
                            }
                        }
                        for var in &other_meta.affected_variables {
                            if !best_meta.affected_variables.contains(var) {
                                best_meta.affected_variables.push(var.clone());
                            }
                        }
                    }
                }
            }

            best_finding.confidence = crate::core::Confidence::High;
            best_finding.confidence_score =
                (best_finding.confidence_score + 0.2 * group.average_correlation()).min(1.0);

            if group.is_cross_validated() {
                best_finding.title = format!("[Cross-Validated] {}", best_finding.title);
            }

            merged.push(best_finding);
        } else {
            if let Some(finding) = group.findings.values().next() {
                merged.push(finding.clone());
            }
        }
    }

    Ok(merged)
}