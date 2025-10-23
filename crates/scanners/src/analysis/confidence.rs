//! Confidence Scoring System
//!
//! Calculates confidence scores (0.0-1.0) for findings based on:
//! - Pattern strength
//! - Safe pattern presence
//! - Code context
//! - Heuristics

use super::{SafePattern, SafePatternAnalysis};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfidenceFactor {
    ClearPattern,
    MultipleEvidence,
    NoSafePatterns,
    CriticalOperation,
    KnownSignature,
    ObviousCase,

    SafePatternPresent,
    AmbiguousPattern,
    SelfOperation,
    ConstructorContext,
    TestCode,
}

#[derive(Debug, Clone)]
pub struct ConfidenceScore {
    pub score: f32,
    pub positive_factors: Vec<ConfidenceFactor>,
    pub negative_factors: Vec<ConfidenceFactor>,
    pub explanation: String,
}

impl ConfidenceScore {
    pub fn high(explanation: String) -> Self {
        Self {
            score: 0.9,
            positive_factors: vec![ConfidenceFactor::ClearPattern],
            negative_factors: Vec::new(),
            explanation,
        }
    }

    pub fn medium(explanation: String) -> Self {
        Self {
            score: 0.6,
            positive_factors: vec![ConfidenceFactor::ObviousCase],
            negative_factors: Vec::new(),
            explanation,
        }
    }

    pub fn low(explanation: String) -> Self {
        Self {
            score: 0.3,
            positive_factors: Vec::new(),
            negative_factors: vec![ConfidenceFactor::AmbiguousPattern],
            explanation,
        }
    }
}

pub struct ConfidenceScorer {
    base_confidence: HashMap<String, f32>,
}

impl ConfidenceScorer {
    pub fn new() -> Self {
        let mut base_confidence = HashMap::new();

        base_confidence.insert("reentrancy-ir".to_string(), 0.7);
        base_confidence.insert("cross-function-reentrancy".to_string(), 0.6);
        base_confidence.insert("missing-access-control".to_string(), 0.7);
        base_confidence.insert("weak-access-control-tx-origin".to_string(), 0.9);
        base_confidence.insert("unchecked-return-ir".to_string(), 0.8);

        Self { base_confidence }
    }

    pub fn score_reentrancy(
        &self,
        has_multiple_evidence: bool,
        safe_analysis: &SafePatternAnalysis,
        is_critical_operation: bool,
        function_name: &str,
    ) -> ConfidenceScore {
        let mut score = *self.base_confidence.get("reentrancy-ir").unwrap_or(&0.7);
        let mut positive_factors = Vec::new();
        let mut negative_factors = Vec::new();

        if has_multiple_evidence {
            score += 0.1;
            positive_factors.push(ConfidenceFactor::MultipleEvidence);
        }

        if is_critical_operation {
            score += 0.1;
            positive_factors.push(ConfidenceFactor::CriticalOperation);
        }

        if safe_analysis.has_reentrancy_protection() {
            score -= 0.4;
            negative_factors.push(ConfidenceFactor::SafePatternPresent);

            if safe_analysis.has_pattern(SafePattern::ReentrancyGuard) {
                score = score.min(0.2);
            }
        }

        if self.is_test_function(function_name) {
            score -= 0.3;
            negative_factors.push(ConfidenceFactor::TestCode);
        }

        score = score.clamp(0.0, 1.0);

        let explanation =
            self.explain_reentrancy_score(score, &positive_factors, &negative_factors);

        ConfidenceScore {
            score,
            positive_factors,
            negative_factors,
            explanation,
        }
    }

    pub fn score_access_control(
        &self,
        has_multiple_state_mods: bool,
        safe_analysis: &SafePatternAnalysis,
        is_public: bool,
        is_critical_function: bool,
        function_name: &str,
    ) -> ConfidenceScore {
        let mut score = *self
            .base_confidence
            .get("missing-access-control")
            .unwrap_or(&0.7);
        let mut positive_factors = Vec::new();
        let mut negative_factors = Vec::new();

        if is_public && has_multiple_state_mods {
            score += 0.1;
            positive_factors.push(ConfidenceFactor::ClearPattern);
        }

        if is_critical_function {
            score += 0.2;
            positive_factors.push(ConfidenceFactor::CriticalOperation);
        }

        if safe_analysis.has_access_control() {
            score -= 0.5;
            negative_factors.push(ConfidenceFactor::SafePatternPresent);
        }

        if self.is_self_operation(function_name) {
            score -= 0.4;
            negative_factors.push(ConfidenceFactor::SelfOperation);
        }

        if self.is_constructor_like(function_name) {
            score -= 0.3;
            negative_factors.push(ConfidenceFactor::ConstructorContext);
        }

        if self.is_test_function(function_name) {
            score -= 0.3;
            negative_factors.push(ConfidenceFactor::TestCode);
        }

        score = score.clamp(0.0, 1.0);

        let explanation =
            self.explain_access_control_score(score, &positive_factors, &negative_factors);

        ConfidenceScore {
            score,
            positive_factors,
            negative_factors,
            explanation,
        }
    }

    pub fn score_unchecked_return(
        &self,
        is_critical_call: bool,
        safe_analysis: &SafePatternAnalysis,
        has_error_handling: bool,
        function_name: &str,
    ) -> ConfidenceScore {
        let mut score = *self
            .base_confidence
            .get("unchecked-return-ir")
            .unwrap_or(&0.8);
        let mut positive_factors = Vec::new();
        let mut negative_factors = Vec::new();

        if is_critical_call {
            score += 0.1;
            positive_factors.push(ConfidenceFactor::CriticalOperation);
        }

        if safe_analysis.has_pattern(SafePattern::SafeERC20) {
            score -= 0.5;
            negative_factors.push(ConfidenceFactor::SafePatternPresent);
        }

        if has_error_handling {
            score -= 0.3;
            negative_factors.push(ConfidenceFactor::SafePatternPresent);
        }

        if self.is_test_function(function_name) {
            score -= 0.2;
            negative_factors.push(ConfidenceFactor::TestCode);
        }

        score = score.clamp(0.0, 1.0);

        let explanation =
            self.explain_unchecked_return_score(score, &positive_factors, &negative_factors);

        ConfidenceScore {
            score,
            positive_factors,
            negative_factors,
            explanation,
        }
    }

    fn is_test_function(&self, name: &str) -> bool {
        let lower = name.to_lowercase();
        lower.starts_with("test") || lower.contains("_test_") || lower.contains("example")
    }

    fn is_constructor_like(&self, name: &str) -> bool {
        let lower = name.to_lowercase();
        lower.contains("constructor") || lower.contains("initialize") || lower == "init"
    }

    fn is_self_operation(&self, name: &str) -> bool {
        let lower = name.to_lowercase();
        lower.contains("withdraw")
            || lower.contains("deposit")
            || lower.contains("claim")
            || lower.contains("stake")
            || lower.contains("unstake")
    }

    fn explain_reentrancy_score(
        &self,
        score: f32,
        positive: &[ConfidenceFactor],
        negative: &[ConfidenceFactor],
    ) -> String {
        let mut parts = vec![format!("Confidence: {:.1}%", score * 100.0)];

        if !positive.is_empty() {
            let factors: Vec<_> = positive.iter().map(|f| format!("{:?}", f)).collect();
            parts.push(format!("Increased by: {}", factors.join(", ")));
        }

        if !negative.is_empty() {
            let factors: Vec<_> = negative.iter().map(|f| format!("{:?}", f)).collect();
            parts.push(format!("Decreased by: {}", factors.join(", ")));
        }

        parts.join(". ")
    }

    fn explain_access_control_score(
        &self,
        score: f32,
        positive: &[ConfidenceFactor],
        negative: &[ConfidenceFactor],
    ) -> String {
        let mut parts = vec![format!("Confidence: {:.1}%", score * 100.0)];

        if !positive.is_empty() {
            parts.push("Strong indicators of missing access control".to_string());
        }

        if !negative.is_empty() {
            parts.push("Mitigating factors present".to_string());
        }

        parts.join(". ")
    }

    fn explain_unchecked_return_score(
        &self,
        score: f32,
        positive: &[ConfidenceFactor],
        negative: &[ConfidenceFactor],
    ) -> String {
        let mut parts = vec![format!("Confidence: {:.1}%", score * 100.0)];

        if negative.contains(&ConfidenceFactor::SafePatternPresent) {
            parts.push("Safe library usage detected".to_string());
        }

        parts.join(". ")
    }
}

impl Default for ConfidenceScorer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_confidence_scorer() {
        let scorer = ConfidenceScorer::new();

        let safe_analysis = SafePatternAnalysis {
            patterns: HashSet::new(),
            safety_confidence: 0.0,
            evidence: HashMap::new(),
        };

        let score = scorer.score_reentrancy(true, &safe_analysis, false, "vulnerable");
        assert!(score.score > 0.5);
        assert!(score.score <= 1.0);
    }

    #[test]
    fn test_safe_pattern_reduces_confidence() {
        let scorer = ConfidenceScorer::new();

        let mut patterns = HashSet::new();
        patterns.insert(SafePattern::ReentrancyGuard);

        let safe_analysis = SafePatternAnalysis {
            patterns,
            safety_confidence: 0.9,
            evidence: HashMap::new(),
        };

        let score = scorer.score_reentrancy(true, &safe_analysis, false, "protected");
        assert!(score.score < 0.5); // Should be low due to ReentrancyGuard
    }
}
