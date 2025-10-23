//! Finding Fingerprint for Deduplication
//!
//! Implements canonical fingerprinting to eliminate duplicate findings from multiple scanners.
//! Uses conservative line-window matching to avoid collapsing distinct vulnerabilities.

use crate::core::Finding;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingFingerprint {
    category: String,
    rel_file: String,
    function_signature: String,
    line_bucket: usize,
    exact_line: usize,
}

impl std::hash::Hash for FindingFingerprint {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.category.hash(state);
        self.rel_file.hash(state);
        self.function_signature.hash(state);
        self.line_bucket.hash(state);
        self.exact_line.hash(state);
    }
}

impl FindingFingerprint {
    pub fn from_finding(finding: &Finding, base_path: &str) -> Self {
        let category = Self::extract_category(&finding.scanner_id);

        let rel_file = finding
            .locations
            .first()
            .map(|loc| {
                let mut file_path = loc
                    .file
                    .strip_prefix(base_path)
                    .unwrap_or(&loc.file)
                    .to_string();

                file_path = file_path.trim_start_matches('/').to_string();
                file_path = file_path
                    .strip_prefix("contracts/")
                    .unwrap_or(&file_path)
                    .to_string();

                file_path
            })
            .unwrap_or_default();

        let function_signature = finding
            .metadata
            .as_ref()
            .and_then(|m| m.affected_functions.first())
            .cloned()
            .unwrap_or_else(|| Self::extract_function_name(&finding.title, &finding.description));

        let line = finding.locations.first().map(|loc| loc.line).unwrap_or(0);
        let line_bucket = line / 5;

        Self {
            category,
            rel_file,
            function_signature,
            line_bucket,
            exact_line: line,
        }
    }

    fn extract_category(scanner_id: &str) -> String {
        if scanner_id.contains("reentrancy") {
            return "reentrancy".to_string();
        }
        if scanner_id.contains("access") {
            return "access-control".to_string();
        }
        if scanner_id.contains("unchecked") {
            return "unchecked".to_string();
        }
        if scanner_id.contains("dangerous") || scanner_id.contains("delegatecall") {
            return "dangerous".to_string();
        }
        if scanner_id.contains("dos") {
            return "dos".to_string();
        }
        if scanner_id.contains("overflow") || scanner_id.contains("underflow") {
            return "overflow".to_string();
        }
        if scanner_id.contains("time") || scanner_id.contains("timestamp") {
            return "time".to_string();
        }

        scanner_id
            .split('-')
            .next()
            .unwrap_or(scanner_id)
            .to_string()
    }

    fn extract_function_name(title: &str, description: &str) -> String {
        if let Some(start) = title.find(" in '") {
            if let Some(end) = title[start + 5..].find('\'') {
                return title[start + 5..start + 5 + end].to_string();
            }
        }

        if let Some(start) = description.find("function '") {
            if let Some(end) = description[start + 10..].find('\'') {
                return description[start + 10..start + 10 + end].to_string();
            }
        }

        String::new()
    }

    fn hash_message(message: &str) -> u64 {
        let normalized = message
            .to_lowercase()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>();

        let mut hasher = DefaultHasher::new();
        normalized.hash(&mut hasher);
        hasher.finish()
    }

    pub fn can_deduplicate(&self, other: &Self, line_window: usize) -> bool {
        if self.category != other.category {
            return false;
        }

        let line_diff = self.exact_line.abs_diff(other.exact_line);

        if line_diff <= 1 {
            return true;
        }

        if !self.function_signature.is_empty()
            && !other.function_signature.is_empty()
            && self.function_signature == other.function_signature
            && line_diff <= 20
        {
            return true;
        }

        let bucket_diff = self.line_bucket.abs_diff(other.line_bucket);

        bucket_diff <= (line_window / 5).max(1)
    }

    pub fn category(&self) -> &str {
        &self.category
    }

    pub fn function_signature(&self) -> &str {
        &self.function_signature
    }

    pub fn line_bucket(&self) -> usize {
        self.line_bucket
    }

    pub fn exact_line(&self) -> usize {
        self.exact_line
    }

    pub fn grouping_key(&self) -> (String, String, usize) {
        (
            self.category.clone(),
            self.rel_file.clone(),
            self.line_bucket,
        )
    }
}

#[derive(Debug, Default)]
pub struct DeduplicationStats {
    pub original_count: usize,
    pub deduped_count: usize,
    pub removed_count: usize,
}

impl DeduplicationStats {
    pub fn reduction_percentage(&self) -> f64 {
        if self.original_count == 0 {
            0.0
        } else {
            (self.removed_count as f64 / self.original_count as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::result::Location;
    use crate::core::{Confidence, Severity};

    #[test]
    fn test_fingerprint_creation() {
        let finding = Finding::new(
            "reentrancy-ir".to_string(),
            Severity::High,
            Confidence::High,
            "Reentrancy in 'withdraw'".to_string(),
            "Test description".to_string(),
        )
        .with_contract("TestContract")
        .with_function("withdraw")
        .with_location(Location {
            file: "/path/to/test.sol".to_string(),
            line: 42,
            column: 10,
            end_line: Some(45),
            end_column: Some(20),
            snippet: None,
            ir_position: None,
        });

        let fp = FindingFingerprint::from_finding(&finding, "/path/to");

        assert_eq!(fp.category(), "reentrancy");
        assert_eq!(fp.line_bucket(), 42 / 5); // Line 42 -> bucket 8
        assert!(fp.function_signature().contains("withdraw"));
    }

    #[test]
    fn test_can_deduplicate_same_category_function_nearby_lines() {
        let finding1 = Finding::new(
            "reentrancy-ir".to_string(),
            Severity::High,
            Confidence::High,
            "Reentrancy in 'withdraw'".to_string(),
            "Test 1".to_string(),
        )
        .with_contract("Test")
        .with_function("withdraw")
        .with_location(Location {
            file: "test.sol".to_string(),
            line: 42,
            column: 0,
            end_line: None,
            end_column: None,
            snippet: None,
            ir_position: None,
        });

        let finding2 = Finding::new(
            "reentrancy-source".to_string(),
            Severity::High,
            Confidence::High,
            "Reentrancy in 'withdraw'".to_string(),
            "Test 2".to_string(),
        )
        .with_contract("Test")
        .with_function("withdraw")
        .with_location(Location {
            file: "test.sol".to_string(),
            line: 44, // Within ±3 lines
            column: 0,
            end_line: None,
            end_column: None,
            snippet: None,
            ir_position: None,
        });

        let fp1 = FindingFingerprint::from_finding(&finding1, "");
        let fp2 = FindingFingerprint::from_finding(&finding2, "");

        assert!(fp1.can_deduplicate(&fp2, 3));
    }

    #[test]
    fn test_cannot_deduplicate_different_categories() {
        let finding1 = Finding::new(
            "reentrancy-ir".to_string(),
            Severity::High,
            Confidence::High,
            "Test".to_string(),
            "Test".to_string(),
        )
        .with_location(Location {
            file: "test.sol".to_string(),
            line: 42,
            column: 0,
            end_line: None,
            end_column: None,
            snippet: None,
            ir_position: None,
        });

        let finding2 = Finding::new(
            "access-control".to_string(),
            Severity::High,
            Confidence::High,
            "Test".to_string(),
            "Test".to_string(),
        )
        .with_location(Location {
            file: "test.sol".to_string(),
            line: 42,
            column: 0,
            end_line: None,
            end_column: None,
            snippet: None,
            ir_position: None,
        });

        let fp1 = FindingFingerprint::from_finding(&finding1, "");
        let fp2 = FindingFingerprint::from_finding(&finding2, "");

        assert!(!fp1.can_deduplicate(&fp2, 3));
    }

    #[test]
    fn test_cannot_deduplicate_far_apart_lines() {
        let finding1 = Finding::new(
            "reentrancy-ir".to_string(),
            Severity::High,
            Confidence::High,
            "Reentrancy in 'withdraw'".to_string(),
            "Test".to_string(),
        )
        .with_contract("Test")
        .with_location(Location {
            file: "test.sol".to_string(),
            line: 10,
            column: 0,
            end_line: None,
            end_column: None,
            snippet: None,
            ir_position: None,
        });

        let finding2 = Finding::new(
            "reentrancy-source".to_string(),
            Severity::High,
            Confidence::High,
            "Reentrancy in 'withdraw'".to_string(),
            "Test".to_string(),
        )
        .with_contract("Test")
        .with_location(Location {
            file: "test.sol".to_string(),
            line: 50, // Far apart
            column: 0,
            end_line: None,
            end_column: None,
            snippet: None,
            ir_position: None,
        });

        let fp1 = FindingFingerprint::from_finding(&finding1, "");
        let fp2 = FindingFingerprint::from_finding(&finding2, "");

        assert!(!fp1.can_deduplicate(&fp2, 3));
    }
}
