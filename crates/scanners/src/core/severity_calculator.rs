use crate::core::result::SeverityContext;
use crate::core::{Finding, Severity};
use std::collections::HashMap;

pub struct SeverityCalculator {
    rules: Vec<Box<dyn SeverityRule>>,
}

impl SeverityCalculator {
    pub fn new() -> Self {
        Self {
            rules: Self::default_rules(),
        }
    }

    pub fn add_rule(mut self, rule: Box<dyn SeverityRule>) -> Self {
        self.rules.push(rule);
        self
    }

    pub fn calculate(&self, finding: &Finding) -> Severity {
        let mut severity = finding.base_severity;
        let mut context = SeverityContext {
            escalation_factors: Vec::new(),
            mitigation_factors: Vec::new(),
            holds_value: false,
            is_public: false,
            custom_factors: HashMap::new(),
        };

        for rule in &self.rules {
            if let Some(adjustment) = rule.evaluate(finding, &context) {
                severity = adjustment.apply_to(severity);
                match adjustment {
                    SeverityAdjustment::Escalate(reason) => {
                        context.escalation_factors.push(reason);
                    }
                    SeverityAdjustment::Mitigate(reason) => {
                        context.mitigation_factors.push(reason);
                    }
                    _ => {}
                }
            }
        }

        severity
    }

    fn default_rules() -> Vec<Box<dyn SeverityRule>> {
        vec![
            Box::new(ValueHoldingRule),
            Box::new(PublicAccessRule),
            Box::new(ReentrancyWithValueRule),
            Box::new(UnusedCodeRule),
        ]
    }
}

pub trait SeverityRule: Send + Sync {
    fn evaluate(&self, finding: &Finding, context: &SeverityContext) -> Option<SeverityAdjustment>;
}

pub enum SeverityAdjustment {
    Escalate(String), // Increase severity with reason
    Mitigate(String), // Decrease severity with reason
    SetTo(Severity),  // Set to specific severity
}

impl SeverityAdjustment {
    fn apply_to(&self, current: Severity) -> Severity {
        match self {
            Self::Escalate(_) => current.escalate(),
            Self::Mitigate(_) => current.mitigate(),
            Self::SetTo(severity) => *severity,
        }
    }
}

impl Severity {
    pub fn escalate(&self) -> Self {
        match self {
            Self::Informational => Self::Low,
            Self::Low => Self::Medium,
            Self::Medium => Self::High,
            Self::High => Self::Critical,
            Self::Critical => Self::Critical,
        }
    }

    pub fn mitigate(&self) -> Self {
        match self {
            Self::Critical => Self::High,
            Self::High => Self::Medium,
            Self::Medium => Self::Low,
            Self::Low => Self::Informational,
            Self::Informational => Self::Informational,
        }
    }
}

struct ValueHoldingRule;
impl SeverityRule for ValueHoldingRule {
    fn evaluate(
        &self,
        finding: &Finding,
        _context: &SeverityContext,
    ) -> Option<SeverityAdjustment> {
        if let Some(ref meta) = finding.metadata {
            if meta
                .affected_contracts
                .iter()
                .any(|c| c.contains("Token") || c.contains("Vault"))
            {
                return Some(SeverityAdjustment::Escalate(
                    "Contract holds value".to_string(),
                ));
            }
        }
        None
    }
}

struct PublicAccessRule;
impl SeverityRule for PublicAccessRule {
    fn evaluate(
        &self,
        finding: &Finding,
        _context: &SeverityContext,
    ) -> Option<SeverityAdjustment> {
        if let Some(ref meta) = finding.metadata {
            if meta
                .affected_functions
                .iter()
                .any(|f| !f.contains("internal") && !f.contains("private"))
            {
                return Some(SeverityAdjustment::Escalate(
                    "Publicly accessible function".to_string(),
                ));
            }
        }
        None
    }
}

struct ReentrancyWithValueRule;
impl SeverityRule for ReentrancyWithValueRule {
    fn evaluate(
        &self,
        finding: &Finding,
        _context: &SeverityContext,
    ) -> Option<SeverityAdjustment> {
        if finding.scanner_id == "reentrancy-simple"
            && (finding.description.contains("withdraw")
                || finding.description.contains("transfer"))
        {
            return Some(SeverityAdjustment::SetTo(Severity::Critical));
        }
        None
    }
}

struct UnusedCodeRule;
impl SeverityRule for UnusedCodeRule {
    fn evaluate(
        &self,
        finding: &Finding,
        _context: &SeverityContext,
    ) -> Option<SeverityAdjustment> {
        if finding.description.contains("never used") || finding.description.contains("unused") {
            return Some(SeverityAdjustment::Mitigate(
                "Code is not actively used".to_string(),
            ));
        }
        None
    }
}

impl Default for SeverityCalculator {
    fn default() -> Self {
        Self::new()
    }
}
