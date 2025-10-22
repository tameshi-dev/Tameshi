use crate::core::{AnalysisContext, Scanner, ScannerConfig, Finding, FindingFingerprint, DeduplicationStats};
use crate::representations::RepresentationBundle;
use anyhow::Result;
use rayon::prelude::*;
use std::sync::Arc;
use std::collections::HashMap;

pub struct ScanningEngine {
    scanners: Vec<Arc<dyn Scanner>>,
    config: ScannerConfig,
}

impl ScanningEngine {
    pub fn new(config: ScannerConfig) -> Self {
        Self {
            scanners: Vec::new(),
            config,
        }
    }

    pub fn add_scanner<S: Scanner + 'static>(mut self, scanner: S) -> Self {
        self.scanners.push(Arc::new(scanner));
        self
    }

    pub fn with_scanners(mut self, scanners: Vec<Arc<dyn Scanner>>) -> Self {
        self.scanners.extend(scanners);
        self
    }

    pub fn run(&self, representations: RepresentationBundle) -> Result<ScanReport> {
        let context = AnalysisContext::with_config(representations, self.config.clone());

        let mut findings = if self.config.parallel_execution {
            self.scanners
                .par_iter()
                .filter_map(|scanner| match scanner.scan(&context) {
                    Ok(findings) => Some(findings),
                    Err(e) => {
                        eprintln!("Scanner {} failed: {}", scanner.id(), e);
                        None
                    }
                })
                .flatten()
                .collect()
        } else {
            let mut all_findings = Vec::new();
            for scanner in &self.scanners {
                match scanner.scan(&context) {
                    Ok(findings) => all_findings.extend(findings),
                    Err(e) => eprintln!("Scanner {} failed: {}", scanner.id(), e),
                }
            }
            all_findings
        };

        let dedup_stats = if self.config.deduplication_enabled {
            let (deduped, stats) = self.deduplicate_findings(findings);
            findings = deduped;
            Some(stats)
        } else {
            None
        };

        Ok(ScanReport::new(findings).with_deduplication_stats(dedup_stats))
    }

    pub fn run_scanners(
        &self,
        scanner_ids: &[&str],
        representations: RepresentationBundle,
    ) -> Result<ScanReport> {
        let context = AnalysisContext::with_config(representations, self.config.clone());

        let selected_scanners: Vec<_> = self
            .scanners
            .iter()
            .filter(|s| scanner_ids.contains(&s.id()))
            .collect();

        let findings = selected_scanners
            .par_iter()
            .filter_map(|scanner| match scanner.scan(&context) {
                Ok(findings) => Some(findings),
                Err(e) => {
                    eprintln!("Scanner {} failed: {}", scanner.id(), e);
                    None
                }
            })
            .flatten()
            .collect();

        Ok(ScanReport::new(findings))
    }

    pub fn list_scanners(&self) -> Vec<ScannerInfo> {
        self.scanners
            .iter()
            .map(|s| ScannerInfo {
                id: s.id().to_string(),
                name: s.name().to_string(),
                description: s.description().to_string(),
                severity: s.severity(),
                confidence: s.confidence(),
            })
            .collect()
    }

    fn deduplicate_findings(&self, findings: Vec<Finding>) -> (Vec<Finding>, DeduplicationStats) {
        let original_count = findings.len();

        if findings.is_empty() {
            return (findings, DeduplicationStats {
                original_count: 0,
                deduped_count: 0,
                removed_count: 0,
            });
        }

        let base_path = std::env::current_dir()
            .ok()
            .and_then(|p| p.to_str().map(|s| s.to_string()))
            .unwrap_or_default();

        type GroupKey = (String, String, usize);
        let mut coarse_groups: HashMap<GroupKey, Vec<Finding>> = HashMap::new();

        for finding in findings {
            let fp = FindingFingerprint::from_finding(&finding, &base_path);
            let key = fp.grouping_key();
            coarse_groups.entry(key).or_insert_with(Vec::new).push(finding);
        }

        let mut deduped = Vec::new();
        let line_window = self.config.deduplication_line_window;

        for (_key, group) in coarse_groups {
            if group.is_empty() {
                continue;
            }

            if group.len() == 1 {
                deduped.extend(group);
                continue;
            }

            let mut remaining: Vec<Finding> = group;
            let mut group_deduped: Vec<Finding> = Vec::new();

            while let Some(candidate) = remaining.pop() {
                let candidate_fp = FindingFingerprint::from_finding(&candidate, &base_path);

                let mut merged = false;
                for existing in &mut group_deduped {
                    let existing_fp = FindingFingerprint::from_finding(existing, &base_path);

                    if candidate_fp.can_deduplicate(&existing_fp, line_window) {
                        if candidate.confidence_score > existing.confidence_score {
                            *existing = candidate.clone();
                        }
                        merged = true;
                        break;
                    }
                }

                if !merged {
                    group_deduped.push(candidate);
                }
            }

            deduped.extend(group_deduped);
        }

        let deduped_count = deduped.len();
        let removed_count = original_count - deduped_count;

        let stats = DeduplicationStats {
            original_count,
            deduped_count,
            removed_count,
        };

        (deduped, stats)
    }
}

#[derive(Debug, Clone)]
pub struct ScannerInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: crate::core::Severity,
    pub confidence: crate::core::Confidence,
}

#[derive(Debug)]
pub struct ScanReport {
    findings: Vec<Finding>,
    deduplication_stats: Option<DeduplicationStats>,
}

impl ScanReport {
    pub fn new(mut findings: Vec<Finding>) -> Self {
        findings.sort_by_key(|f| std::cmp::Reverse(f.priority_score()));
        Self {
            findings,
            deduplication_stats: None,
        }
    }

    pub fn with_deduplication_stats(mut self, stats: Option<DeduplicationStats>) -> Self {
        self.deduplication_stats = stats;
        self
    }

    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    pub fn deduplication_stats(&self) -> Option<&DeduplicationStats> {
        self.deduplication_stats.as_ref()
    }

    pub fn with_deduplication(mut self, config: &ScannerConfig) -> Self {
        if !config.deduplication_enabled {
            return self;
        }

        let original_count = self.findings.len();

        if self.findings.is_empty() {
            return self;
        }

        let base_path = std::env::current_dir()
            .ok()
            .and_then(|p| p.to_str().map(|s| s.to_string()))
            .unwrap_or_default();

        type GroupKey = (String, String, usize);
        let mut coarse_groups: HashMap<GroupKey, Vec<Finding>> = HashMap::new();

        for finding in self.findings {
            let fp = FindingFingerprint::from_finding(&finding, &base_path);
            let key = fp.grouping_key();
            coarse_groups.entry(key).or_insert_with(Vec::new).push(finding);
        }

        let mut deduped = Vec::new();
        let line_window = config.deduplication_line_window;

        for (_key, group) in coarse_groups {
            if group.is_empty() {
                continue;
            }

            if group.len() == 1 {
                deduped.extend(group);
                continue;
            }

            let mut remaining: Vec<Finding> = group;
            let mut group_deduped: Vec<Finding> = Vec::new();

            while let Some(candidate) = remaining.pop() {
                let candidate_fp = FindingFingerprint::from_finding(&candidate, &base_path);

                let mut merged = false;
                for existing in &mut group_deduped {
                    let existing_fp = FindingFingerprint::from_finding(existing, &base_path);

                    if candidate_fp.can_deduplicate(&existing_fp, line_window) {
                        if candidate.confidence_score > existing.confidence_score {
                            *existing = candidate.clone();
                        }
                        merged = true;
                        break;
                    }
                }

                if !merged {
                    group_deduped.push(candidate);
                }
            }

            deduped.extend(group_deduped);
        }

        let deduped_count = deduped.len();
        let removed_count = original_count - deduped_count;

        deduped.sort_by_key(|f| std::cmp::Reverse(f.priority_score()));

        self.findings = deduped;
        self.deduplication_stats = Some(DeduplicationStats {
            original_count,
            deduped_count,
            removed_count,
        });

        self
    }

    pub fn count_by_severity(&self) -> SeverityCount {
        let mut count = SeverityCount::default();
        for finding in &self.findings {
            match finding.severity {
                crate::core::Severity::Critical => count.critical += 1,
                crate::core::Severity::High => count.high += 1,
                crate::core::Severity::Medium => count.medium += 1,
                crate::core::Severity::Low => count.low += 1,
                crate::core::Severity::Informational => count.informational += 1,
            }
        }
        count
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(&self.findings)?)
    }

    pub fn to_markdown(&self) -> String {
        let mut md = String::from("# Scan Report\n\n");

        let count = self.count_by_severity();
        md.push_str(&format!("## Summary\n\n"));
        md.push_str(&format!("- Critical: {}\n", count.critical));
        md.push_str(&format!("- High: {}\n", count.high));
        md.push_str(&format!("- Medium: {}\n", count.medium));
        md.push_str(&format!("- Low: {}\n", count.low));
        md.push_str(&format!("- Informational: {}\n\n", count.informational));

        if let Some(stats) = &self.deduplication_stats {
            md.push_str(&format!("## Deduplication\n\n"));
            md.push_str(&format!("- Original findings: {}\n", stats.original_count));
            md.push_str(&format!("- After deduplication: {}\n", stats.deduped_count));
            md.push_str(&format!("- Removed duplicates: {}\n", stats.removed_count));
            md.push_str(&format!("- Reduction: {:.1}%\n\n", stats.reduction_percentage()));
        }

        if !self.findings.is_empty() {
            md.push_str("## Findings\n\n");

            for finding in &self.findings {
                md.push_str(&format!(
                    "### {} {}: {}\n\n",
                    finding.severity.emoji(),
                    finding.severity,
                    finding.title
                ));
                md.push_str(&format!("**Scanner:** {}\n", finding.scanner_id));
                md.push_str(&format!("**Confidence:** {}\n\n", finding.confidence));
                md.push_str(&format!("{}\n\n", finding.description));

                if !finding.locations.is_empty() {
                    md.push_str("**Locations:**\n");
                    for loc in &finding.locations {
                        md.push_str(&format!("- {}:{}:{}\n", loc.file, loc.line, loc.column));
                        if let Some(ref snippet) = loc.snippet {
                            md.push_str(&format!("  ```\n  {}\n  ```\n", snippet));
                        }
                    }
                    md.push_str("\n");
                }
            }
        }

        md
    }
}

#[derive(Debug, Default)]
pub struct SeverityCount {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub informational: usize,
}
