//! Secure Pattern Recognition
//!
//! Recognizes industry-standard secure patterns (e.g., OpenZeppelin) to reduce false positives.

use crate::core::Finding;
use std::collections::HashSet;

pub struct SecurePatternRecognizer {
    secure_modifiers: HashSet<String>,
    secure_libraries: HashSet<String>,
}

impl Default for SecurePatternRecognizer {
    fn default() -> Self {
        let mut secure_modifiers = HashSet::new();
        secure_modifiers.insert("nonReentrant".to_string());
        secure_modifiers.insert("onlyOwner".to_string());
        secure_modifiers.insert("whenNotPaused".to_string());
        secure_modifiers.insert("whenPaused".to_string());
        secure_modifiers.insert("onlyRole".to_string());

        let mut secure_libraries = HashSet::new();
        secure_libraries.insert("safeTransfer".to_string());
        secure_libraries.insert("safeTransferFrom".to_string());
        secure_libraries.insert("safeApprove".to_string());
        secure_libraries.insert("safeIncreaseAllowance".to_string());
        secure_libraries.insert("safeDecreaseAllowance".to_string());
        secure_libraries.insert("sendValue".to_string());
        secure_libraries.insert("functionCall".to_string());
        secure_libraries.insert("functionCallWithValue".to_string());

        Self {
            secure_modifiers,
            secure_libraries,
        }
    }
}

impl SecurePatternRecognizer {
    pub fn is_likely_false_positive(&self, finding: &Finding, source_code: Option<&str>) -> bool {
        let source = match source_code {
            Some(s) => s,
            None => return false,
        };

        match finding.scanner_id.as_str() {
            id if id.contains("reentrancy") => {
                self.check_reentrancy_protection(finding, source)
            },
            id if id.contains("unchecked") && id.contains("return") => {
                self.check_safe_erc20_usage(finding, source)
            },
            id if id.contains("access") => {
                self.check_access_control(finding, source)
            },
            _ => false,
        }
    }

    fn check_reentrancy_protection(&self, finding: &Finding, source: &str) -> bool {
        let function_name = finding.metadata.as_ref()
            .and_then(|m| m.affected_functions.first())
            .map(|s| s.as_str())
            .unwrap_or("");

        if function_name.is_empty() {
            return false;
        }

        if let Some(func_start) = source.find(&format!("function {}", function_name)) {
            let window_end = (func_start + 500).min(source.len());
            let function_window = &source[func_start..window_end];

            if function_window.contains("nonReentrant") {
                return true;
            }

            if self.has_checks_effects_interactions(function_window) {
                return true;
            }
        }

        false
    }

    fn has_checks_effects_interactions(&self, function_text: &str) -> bool {

        let call_patterns = ["call{", ".call(", ".transfer(", ".send("];
        let first_call_pos = call_patterns.iter()
            .filter_map(|pattern| function_text.find(pattern))
            .min();

        if let Some(call_pos) = first_call_pos {
            let before_call = &function_text[..call_pos];

            for line in before_call.lines() {
                let trimmed = line.trim();

                if trimmed.starts_with("uint ") ||
                   trimmed.starts_with("address ") ||
                   trimmed.starts_with("bool ") ||
                   trimmed.starts_with("bytes") ||
                   trimmed.starts_with("string ") ||
                   trimmed.starts_with("int ") ||
                   trimmed.starts_with("mapping") ||
                   trimmed.starts_with("//") ||
                   trimmed.is_empty() {
                    continue;
                }

                if trimmed.contains('=') &&
                   !trimmed.contains("==") &&
                   !trimmed.contains("!=") &&
                   !trimmed.contains("=>") {

                    let parts: Vec<&str> = trimmed.split('=').collect();
                    if !parts.is_empty() {
                        let left = parts[0].trim();

                        if (left.contains('[') && left.contains(']')) ||  // mapping/array
                           (left.contains('.') && !left.starts_with("msg.") &&
                            !left.starts_with("tx.") && !left.starts_with("block.")) || // member
                           (!left.contains(' ') && !left.contains('(')) {  // direct state var
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    fn check_safe_erc20_usage(&self, finding: &Finding, source: &str) -> bool {
        let line = finding.locations.first()
            .map(|loc| loc.line)
            .unwrap_or(0);

        if line == 0 {
            return false;
        }

        let lines: Vec<&str> = source.lines().collect();
        if line > lines.len() {
            return false;
        }

        let line_content = lines[line - 1];

        for safe_func in &self.secure_libraries {
            if line_content.contains(safe_func) {
                return true;
            }
        }

        if line_content.contains(".transfer(") && !line_content.contains(".send(")
            && (line_content.contains("payable") || line_content.contains("{value:")) {
            return true; // Native ETH transfer - safe
        }

        false
    }

    fn check_access_control(&self, finding: &Finding, source: &str) -> bool {
        let function_name = finding.metadata.as_ref()
            .and_then(|m| m.affected_functions.first())
            .map(|s| s.as_str())
            .unwrap_or("");

        if function_name.is_empty() {
            return false;
        }

        if let Some(func_start) = source.find(&format!("function {}", function_name)) {
            let window_end = (func_start + 200).min(source.len());
            let function_window = &source[func_start..window_end];

            if let Some(brace_pos) = function_window.find('{') {
                let signature = &function_window[..brace_pos];

                for modifier in &self.secure_modifiers {
                    if signature.contains(modifier) {
                        return true;
                    }
                }

                if signature.contains("require") && signature.contains("msg.sender") {
                    return true;
                }
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{Severity, Confidence};
    use crate::core::result::Location;

    #[test]
    fn test_recognizes_nonreentrant_modifier() {
        let recognizer = SecurePatternRecognizer::default();

        let finding = Finding::new(
            "reentrancy-ir".to_string(),
            Severity::High,
            Confidence::High,
            "Reentrancy in 'withdraw'".to_string(),
            "Test".to_string(),
        )
        .with_function("withdraw");

        let source = r#"
            function withdraw() external nonReentrant {
                balances[msg.sender] -= amount;
                msg.sender.call{value: amount}("");
            }
        "#;

        assert!(recognizer.is_likely_false_positive(&finding, Some(source)));
    }

    #[test]
    fn test_recognizes_safe_erc20() {
        let recognizer = SecurePatternRecognizer::default();

        let finding = Finding::new(
            "unchecked-return".to_string(),
            Severity::High,
            Confidence::High,
            "Unchecked return".to_string(),
            "Test".to_string(),
        )
        .with_location(Location {
            file: "test.sol".to_string(),
            line: 2,
            column: 0,
            end_line: None,
            end_column: None,
            snippet: None,
            ir_position: None,
        });

        let source = r#"
token.safeTransfer(recipient, amount);
        "#;

        assert!(recognizer.is_likely_false_positive(&finding, Some(source)));
    }

    #[test]
    fn test_recognizes_only_owner_modifier() {
        let recognizer = SecurePatternRecognizer::default();

        let finding = Finding::new(
            "missing-access-control".to_string(),
            Severity::High,
            Confidence::High,
            "Missing access control".to_string(),
            "Test".to_string(),
        )
        .with_function("setOwner");

        let source = r#"
            function setOwner(address newOwner) external onlyOwner {
                owner = newOwner;
            }
        "#;

        assert!(recognizer.is_likely_false_positive(&finding, Some(source)));
    }

    #[test]
    fn test_does_not_flag_vulnerable_code() {
        let recognizer = SecurePatternRecognizer::default();

        let finding = Finding::new(
            "reentrancy-ir".to_string(),
            Severity::High,
            Confidence::High,
            "Reentrancy in 'vulnerableWithdraw'".to_string(),
            "Test".to_string(),
        )
        .with_function("vulnerableWithdraw");

        let source = r#"
            function vulnerableWithdraw() external {
                msg.sender.call{value: balances[msg.sender]}("");
                balances[msg.sender] = 0;  // State change AFTER call!
            }
        "#;

        assert!(!recognizer.is_likely_false_positive(&finding, Some(source)));
    }
}
