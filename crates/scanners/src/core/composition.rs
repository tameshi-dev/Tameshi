use crate::core::{AnalysisContext, Confidence, Finding, Scanner, Severity};
use crate::representations::RepresentationSet;
use anyhow::Result;
use std::sync::Arc;

pub struct CompositeScanner {
    id: String,
    name: String,
    description: String,
    scanners: Vec<Arc<dyn Scanner>>,
}

impl CompositeScanner {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: String::from("Composite scanner"),
            scanners: Vec::new(),
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn add_scanner<S: Scanner + 'static>(mut self, scanner: S) -> Self {
        self.scanners.push(Arc::new(scanner));
        self
    }

    pub fn add_arc_scanner(mut self, scanner: Arc<dyn Scanner>) -> Self {
        self.scanners.push(scanner);
        self
    }
}

impl Scanner for CompositeScanner {
    fn id(&self) -> &'static str {
        Box::leak(self.id.clone().into_boxed_str())
    }

    fn name(&self) -> &'static str {
        Box::leak(self.name.clone().into_boxed_str())
    }

    fn description(&self) -> &'static str {
        Box::leak(self.description.clone().into_boxed_str())
    }

    fn severity(&self) -> Severity {
        self.scanners
            .iter()
            .map(|s| s.severity())
            .max()
            .unwrap_or(Severity::Low)
    }

    fn confidence(&self) -> Confidence {
        self.scanners
            .iter()
            .map(|s| s.confidence())
            .min()
            .unwrap_or(Confidence::Low)
    }

    fn scan(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        let mut all_findings = Vec::new();

        for scanner in &self.scanners {
            match scanner.scan(context) {
                Ok(findings) => all_findings.extend(findings),
                Err(e) => eprintln!("Scanner {} failed in composite: {}", scanner.id(), e),
            }
        }

        Ok(all_findings)
    }

    fn required_representations(&self) -> RepresentationSet {
        let combined = RepresentationSet::new();
        for scanner in &self.scanners {
            let _ = scanner.required_representations();
        }
        combined
    }
}

// Reduce type complexity for sequential stages
type StageFn = Box<dyn Fn(&[Finding]) -> bool + Send + Sync>;
type Stage = (Arc<dyn Scanner>, StageFn);

pub struct SequentialScanner {
    id: String,
    name: String,
    stages: Vec<Stage>,
}

impl SequentialScanner {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            stages: Vec::new(),
        }
    }

    pub fn add_stage<S, F>(mut self, scanner: S, continue_if: F) -> Self
    where
        S: Scanner + 'static,
        F: Fn(&[Finding]) -> bool + Send + Sync + 'static,
    {
        self.stages.push((Arc::new(scanner), Box::new(continue_if)));
        self
    }
}

impl Scanner for SequentialScanner {
    fn id(&self) -> &'static str {
        Box::leak(self.id.clone().into_boxed_str())
    }

    fn name(&self) -> &'static str {
        Box::leak(self.name.clone().into_boxed_str())
    }

    fn severity(&self) -> Severity {
        self.stages
            .first()
            .map(|(s, _)| s.severity())
            .unwrap_or(Severity::Low)
    }

    fn confidence(&self) -> Confidence {
        self.stages
            .first()
            .map(|(s, _)| s.confidence())
            .unwrap_or(Confidence::Low)
    }

    fn scan(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        let mut all_findings = Vec::new();

        for (scanner, continue_condition) in &self.stages {
            let findings = scanner.scan(context)?;

            let should_continue = continue_condition(&findings);
            all_findings.extend(findings);

            if !should_continue {
                break;
            }
        }

        Ok(all_findings)
    }
}

pub struct FilteredScanner<S: Scanner> {
    inner: S,
    filter: Box<dyn Fn(&Finding) -> bool + Send + Sync>,
}

impl<S: Scanner> FilteredScanner<S> {
    pub fn new(scanner: S, filter: impl Fn(&Finding) -> bool + Send + Sync + 'static) -> Self {
        Self {
            inner: scanner,
            filter: Box::new(filter),
        }
    }
}

impl<S: Scanner> Scanner for FilteredScanner<S> {
    fn id(&self) -> &'static str {
        self.inner.id()
    }

    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn severity(&self) -> Severity {
        self.inner.severity()
    }

    fn confidence(&self) -> Confidence {
        self.inner.confidence()
    }

    fn scan(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        let findings = self.inner.scan(context)?;
        Ok(findings.into_iter().filter(|f| (self.filter)(f)).collect())
    }

    fn required_representations(&self) -> RepresentationSet {
        self.inner.required_representations()
    }
}

pub struct ParallelScanner {
    scanners: Vec<Arc<dyn Scanner>>,
}

impl Default for ParallelScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl ParallelScanner {
    pub fn new() -> Self {
        Self {
            scanners: Vec::new(),
        }
    }

    pub fn with_scanner<S: Scanner + 'static>(mut self, scanner: S) -> Self {
        self.scanners.push(Arc::new(scanner));
        self
    }
}

impl Scanner for ParallelScanner {
    fn id(&self) -> &'static str {
        "parallel-composite"
    }

    fn name(&self) -> &'static str {
        "Parallel Composite Scanner"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn scan(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        use rayon::prelude::*;

        let findings: Vec<_> = self
            .scanners
            .par_iter()
            .filter_map(|scanner| scanner.scan(context).ok())
            .flatten()
            .collect();

        Ok(findings)
    }
}
