//! Finding correlation and cross-validation engine
//!
//! This module provides mechanisms to correlate findings from different scanners,
//! enabling cross-validation between deterministic and LLM-based approaches.

use crate::core::{
    result::Finding,
    Confidence,
};
use std::collections::{HashMap, HashSet};

pub struct CorrelationEngine {
    strategies: Vec<Box<dyn CorrelationStrategy>>,

    threshold: f64,

    confidence_boosting: bool,
}

impl CorrelationEngine {
    pub fn new() -> Self {
        Self {
            strategies: vec![
                Box::new(LocationBasedStrategy::new()),
                Box::new(PatternBasedStrategy::new()),
                Box::new(SemanticStrategy::new()),
            ],
            threshold: 0.5,  // Lowered threshold for better matching
            confidence_boosting: true,
        }
    }

    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.threshold = threshold.clamp(0.0, 1.0);
        self
    }

    pub fn add_strategy(mut self, strategy: Box<dyn CorrelationStrategy>) -> Self {
        self.strategies.push(strategy);
        self
    }

    pub fn correlate(&self, findings: Vec<Finding>) -> CorrelationResult {
        let mut groups = CorrelationGroups::new();
        let mut enhanced_findings = Vec::new();

        for (i, finding) in findings.iter().enumerate() {
            let mut max_correlation = 0.0;
            let mut best_group: Option<usize> = None;

            let mut best_strategy = None;
            for (group_id, group) in groups.groups.iter().enumerate() {
                let (correlation, strategy) = self.calculate_correlation(finding, group);
                if correlation > max_correlation && correlation >= self.threshold {
                    max_correlation = correlation;
                    best_group = Some(group_id);
                    best_strategy = strategy;
                }
            }

            if let Some(group_id) = best_group {
                groups.add_to_group(group_id, i, finding.clone(), max_correlation, best_strategy);
            } else {
                groups.create_group(i, finding.clone());
            }
        }

        for group in &groups.groups {
            let enhanced = self.enhance_group(group);
            enhanced_findings.extend(enhanced);
        }

        let statistics = self.calculate_statistics(&groups);

        CorrelationResult {
            enhanced_findings,
            correlation_groups: groups.groups,
            statistics,
        }
    }

    fn calculate_correlation(&self, finding: &Finding, group: &CorrelationGroup) -> (f64, Option<String>) {
        let mut best_score = 0.0;
        let mut best_strategy = None;

        for strategy in &self.strategies {
            let group_findings: Vec<Finding> = group.findings.values().cloned().collect();
            if let Some(score) = strategy.calculate_correlation(finding, &group_findings) {
                if score > best_score {
                    best_score = score;
                    best_strategy = Some(strategy.name().to_string());
                }
            }
        }

        (best_score, best_strategy)
    }

    fn enhance_group(&self, group: &CorrelationGroup) -> Vec<Finding> {
        let mut enhanced = Vec::new();

        for (_, finding) in &group.findings {
            let mut enhanced_finding = finding.clone();

            if self.confidence_boosting && group.findings.len() > 1 {
                enhanced_finding = self.boost_confidence(enhanced_finding, group);
            }

            if enhanced_finding.metadata.is_none() {
                enhanced_finding.metadata = Some(Default::default());
            }

            enhanced.push(enhanced_finding);
        }

        enhanced
    }

    fn boost_confidence(&self, mut finding: Finding, group: &CorrelationGroup) -> Finding {
        let correlation_factor = group.average_correlation();
        let group_size_factor = (group.findings.len() as f64).ln() / 10.0; // Logarithmic scaling

        let boost = (correlation_factor * group_size_factor).min(0.3); // Cap at 30% boost

        finding.confidence = match finding.confidence {
            Confidence::Low if boost > 0.2 => Confidence::Medium,
            Confidence::Medium if boost > 0.2 => Confidence::High,
            _ => finding.confidence,
        };

        finding.confidence_score = (finding.confidence_score + boost).min(1.0);

        finding
    }

    fn calculate_statistics(&self, groups: &CorrelationGroups) -> CorrelationStatistics {
        let total_findings = groups.groups.iter().map(|g| g.findings.len()).sum();
        let correlated_findings = groups
            .groups
            .iter()
            .filter(|g| g.findings.len() > 1)
            .map(|g| g.findings.len())
            .sum();

        CorrelationStatistics {
            total_findings,
            correlated_findings,
            correlation_groups: groups.groups.len(),
            average_group_size: if groups.groups.is_empty() {
                0.0
            } else {
                total_findings as f64 / groups.groups.len() as f64
            },
            deterministic_llm_correlations: self.count_cross_scanner_correlations(groups),
        }
    }

    fn count_cross_scanner_correlations(&self, groups: &CorrelationGroups) -> usize {
        let mut count = 0;

        for group in &groups.groups {
            let has_deterministic = group
                .findings
                .values()
                .any(|f| !f.scanner_id.contains("llm"));
            let has_llm = group
                .findings
                .values()
                .any(|f| f.scanner_id.contains("llm"));

            if has_deterministic && has_llm {
                count += 1;
            }
        }

        count
    }
}

pub trait CorrelationStrategy: Send + Sync {
    fn calculate_correlation(&self, finding: &Finding, group: &[Finding]) -> Option<f64>;

    fn name(&self) -> &str;
}

pub struct LocationBasedStrategy {
    max_line_distance: usize,
}

impl LocationBasedStrategy {
    pub fn new() -> Self {
        Self {
            max_line_distance: 10,
        }
    }
}

impl CorrelationStrategy for LocationBasedStrategy {
    fn calculate_correlation(&self, finding: &Finding, group: &[Finding]) -> Option<f64> {
        if finding.locations.is_empty() || group.is_empty() {
            return None;
        }

        let mut max_score = 0.0;

        for other in group {
            if other.locations.is_empty() {
                continue;
            }

            for loc1 in &finding.locations {
                for loc2 in &other.locations {
                    if loc1.file != loc2.file {
                        continue;
                    }

                    let line_distance = (loc1.line as i32 - loc2.line as i32).abs() as usize;

                    if line_distance == 0 {
                        max_score = f64::max(max_score, 1.0);
                    } else if line_distance <= self.max_line_distance {
                        let score = 1.0 - (line_distance as f64 / self.max_line_distance as f64);
                        max_score = f64::max(max_score, score);
                    }
                }
            }
        }

        if max_score > 0.0 {
            Some(max_score)
        } else {
            None
        }
    }

    fn name(&self) -> &str {
        "LocationBased"
    }
}

pub struct PatternBasedStrategy {
    patterns: HashMap<String, Vec<String>>,
}

impl PatternBasedStrategy {
    pub fn new() -> Self {
        let mut patterns = HashMap::new();

        patterns.insert(
            "reentrancy".to_string(),
            vec![
                "reentrancy".to_string(),
                "reentrant".to_string(),
                "recursive_call".to_string(),
                "external_call_before_state".to_string(),
            ],
        );

        patterns.insert(
            "access_control".to_string(),
            vec![
                "access".to_string(),
                "unauthorized".to_string(),
                "permission".to_string(),
                "owner".to_string(),
            ],
        );

        Self { patterns }
    }
}

impl CorrelationStrategy for PatternBasedStrategy {
    fn calculate_correlation(&self, finding: &Finding, group: &[Finding]) -> Option<f64> {
        let finding_patterns = self.extract_patterns(&finding.finding_type);

        for other in group {
            let other_patterns = self.extract_patterns(&other.finding_type);

            let overlap: HashSet<_> = finding_patterns
                .intersection(&other_patterns)
                .collect();

            if !overlap.is_empty() {
                let score = overlap.len() as f64
                    / finding_patterns.union(&other_patterns).count() as f64;
                return Some(score);
            }
        }

        None
    }

    fn name(&self) -> &str {
        "PatternBased"
    }
}

impl PatternBasedStrategy {
    fn extract_patterns(&self, finding_type: &str) -> HashSet<String> {
        let mut result = HashSet::new();
        let lower = finding_type.to_lowercase();

        for (pattern_key, pattern_values) in &self.patterns {
            if lower.contains(pattern_key) {
                result.extend(pattern_values.clone());
            }
        }

        for pattern_values in self.patterns.values() {
            for pattern in pattern_values {
                if lower.contains(pattern) {
                    result.insert(pattern.clone());
                    for (key, values) in &self.patterns {
                        if values.contains(pattern) {
                            result.insert(key.clone());
                            result.extend(values.clone());
                        }
                    }
                }
            }
        }

        result.insert(lower);

        result
    }
}

pub struct SemanticStrategy {
    min_overlap_ratio: f64,
}

impl SemanticStrategy {
    pub fn new() -> Self {
        Self {
            min_overlap_ratio: 0.3,
        }
    }

    fn tokenize(&self, text: &str) -> HashSet<String> {
        text.to_lowercase()
            .split_whitespace()
            .filter(|w| w.len() > 3) // Skip short words
            .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()).to_string())
            .collect()
    }
}

impl CorrelationStrategy for SemanticStrategy {
    fn calculate_correlation(&self, finding: &Finding, group: &[Finding]) -> Option<f64> {
        let finding_text = format!("{} {} {}",
            finding.title,
            finding.description,
            finding.finding_type
        );
        let finding_tokens = self.tokenize(&finding_text);

        if finding_tokens.is_empty() {
            return None;
        }

        let mut max_score = 0.0;

        for other in group {
            let other_text = format!("{} {} {}",
                other.title,
                other.description,
                other.finding_type
            );
            let other_tokens = self.tokenize(&other_text);

            if other_tokens.is_empty() {
                continue;
            }

            let intersection = finding_tokens
                .intersection(&other_tokens)
                .count() as f64;
            let union = finding_tokens.union(&other_tokens).count() as f64;

            if union > 0.0 {
                let jaccard = intersection / union;

                if jaccard >= self.min_overlap_ratio * 0.7 {
                    max_score = f64::max(max_score, jaccard);
                }
            }
        }

        if max_score > 0.0 {
            Some(max_score)
        } else {
            None
        }
    }

    fn name(&self) -> &str {
        "Semantic"
    }
}

#[derive(Debug)]
struct CorrelationGroups {
    groups: Vec<CorrelationGroup>,
}

impl CorrelationGroups {
    fn new() -> Self {
        Self { groups: Vec::new() }
    }

    fn create_group(&mut self, index: usize, finding: Finding) {
        self.groups.push(CorrelationGroup {
            findings: vec![(index, finding)].into_iter().collect(),
            correlation_scores: HashMap::new(),
            correlation_strategy: None,
        });
    }

    fn add_to_group(&mut self, group_id: usize, index: usize, finding: Finding, score: f64, strategy: Option<String>) {
        if let Some(group) = self.groups.get_mut(group_id) {
            group.findings.insert(index, finding);
            group.correlation_scores.insert(index, score);
            if group.correlation_strategy.is_none() && strategy.is_some() {
                group.correlation_strategy = strategy;
            }
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CorrelationGroup {
    pub findings: HashMap<usize, Finding>,

    pub correlation_scores: HashMap<usize, f64>,

    pub correlation_strategy: Option<String>,
}

impl CorrelationGroup {
    pub fn average_correlation(&self) -> f64 {
        if self.correlation_scores.is_empty() {
            return 0.0;
        }

        self.correlation_scores.values().sum::<f64>() / self.correlation_scores.len() as f64
    }

    pub fn is_cross_validated(&self) -> bool {
        let scanner_types: HashSet<_> = self
            .findings
            .values()
            .map(|f| {
                if f.scanner_id.contains("llm") {
                    "llm"
                } else {
                    "deterministic"
                }
            })
            .collect();

        scanner_types.len() > 1
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CorrelationResult {
    pub enhanced_findings: Vec<Finding>,

    pub correlation_groups: Vec<CorrelationGroup>,

    pub statistics: CorrelationStatistics,
}

impl Default for CorrelationResult {
    fn default() -> Self {
        Self {
            enhanced_findings: Vec::new(),
            correlation_groups: Vec::new(),
            statistics: CorrelationStatistics::default(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CorrelationStatistics {
    pub total_findings: usize,

    pub correlated_findings: usize,

    pub correlation_groups: usize,

    pub average_group_size: f64,

    pub deterministic_llm_correlations: usize,
}

impl Default for CorrelationStatistics {
    fn default() -> Self {
        Self {
            total_findings: 0,
            correlated_findings: 0,
            correlation_groups: 0,
            average_group_size: 0.0,
            deterministic_llm_correlations: 0,
        }
    }
}

impl CorrelationResult {
    pub fn high_confidence_findings(&self) -> Vec<&Finding> {
        self.enhanced_findings
            .iter()
            .filter(|f| f.confidence == Confidence::High)
            .collect()
    }

    pub fn cross_validated_groups(&self) -> Vec<&CorrelationGroup> {
        self.correlation_groups
            .iter()
            .filter(|g| g.is_cross_validated())
            .collect()
    }

    pub fn generate_report(&self) -> String {
        let mut report = String::new();

        report.push_str("# Correlation Analysis Report\n\n");

        report.push_str(&format!("## Summary\n\n"));
        report.push_str(&format!(
            "- Total findings: {}\n",
            self.statistics.total_findings
        ));
        report.push_str(&format!(
            "- Correlated findings: {} ({:.1}%)\n",
            self.statistics.correlated_findings,
            (self.statistics.correlated_findings as f64 / self.statistics.total_findings as f64)
                * 100.0
        ));
        report.push_str(&format!(
            "- Correlation groups: {}\n",
            self.statistics.correlation_groups
        ));
        report.push_str(&format!(
            "- Average group size: {:.1}\n",
            self.statistics.average_group_size
        ));
        report.push_str(&format!(
            "- Cross-validated groups: {}\n\n",
            self.statistics.deterministic_llm_correlations
        ));

        report.push_str("## Correlation Table\n\n");

        for group in &self.correlation_groups {
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

                    report.push_str("### Correlated Finding\n\n");

                    report.push_str("| Attribute | Deterministic Scanner | LLM Scanner |\n");
                    report.push_str("|-----------|----------------------|-------------|\n");
                    report.push_str(&format!("| **Scanner** | {} | {} |\n", det.scanner_id, llm.scanner_id));
                    report.push_str(&format!("| **Severity** | {} | {} |\n", det.severity, llm.severity));
                    report.push_str(&format!("| **Title** | {} | {} |\n", det.title, llm.title));
                    report.push_str(&format!("| **Confidence** | {} ({:.0}%) | {} ({:.0}%) |\n",
                        det.confidence, det.confidence_score * 100.0,
                        llm.confidence, llm.confidence_score * 100.0
                    ));
                    report.push_str("\n");

                    report.push_str("#### Deterministic Scanner Description:\n");
                    report.push_str("```\n");
                    report.push_str(&det.description);
                    report.push_str("\n```\n\n");

                    report.push_str("#### LLM Scanner Description:\n");
                    report.push_str("```\n");
                    report.push_str(&llm.description);
                    report.push_str("\n```\n\n");

                    report.push_str(&format!("**Overall Confidence:** {:.0}%  \n", avg_confidence * 100.0));
                    report.push_str(&format!("**Correlation Score:** {:.2}  \n", group.average_correlation()));
                    report.push_str(&format!("**Correlation Strategy:** {}  \n\n", strategy));
                    report.push_str("---\n\n");
                }
            }
        }

        report.push_str("\n## Cross-Validated Findings Details\n\n");

        for group in self.cross_validated_groups() {
            report.push_str(&format!(
                "### Group (Correlation: {:.2}, Strategy: {})\n\n",
                group.average_correlation(),
                group.correlation_strategy.as_deref().unwrap_or("Unknown")
            ));

            for finding in group.findings.values() {
                report.push_str(&format!(
                    "- **{}** ({}): {} - Confidence: {}\n",
                    finding.scanner_id, finding.severity, finding.title, finding.confidence
                ));
            }
            report.push_str("\n");
        }

        report
    }
}