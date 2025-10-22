//! Source-Level Access Control Modifier Detector
//!
//! This scanner analyzes Solidity source code using tree-sitter queries to detect
//! access control modifiers that are lost or invisible in IR transformation.
//! It helps reduce false positives by identifying functions that DO have proper
//! access control via modifiers.

use crate::core::{Confidence, Finding, Severity, Scanner, AnalysisContext};
use crate::representations::source::SourceRepresentation;
use anyhow::Result;
use std::collections::HashMap;

pub struct SourceAccessControlScanner;

impl SourceAccessControlScanner {
    pub fn new() -> Self {
        Self
    }

    fn analyze_ast(&self, source_repr: &SourceRepresentation) -> Result<HashMap<String, Vec<String>>> {
        let mut function_modifiers: HashMap<String, Vec<String>> = HashMap::new();

        #[cfg(test)]
        {
            eprintln!("Modifiers found in contract:");
            for (mod_name, mod_info) in &source_repr.modifiers {
                eprintln!("  {} -> is_access_control: {}", mod_name, mod_info.is_access_control);
            }
        }

        for (func_name, func_info) in &source_repr.functions {
            #[cfg(test)]
            eprintln!("Function {}: modifiers = {:?}", func_name, func_info.modifiers);

            let access_control_modifiers: Vec<String> = func_info.modifiers.iter()
                .filter(|modifier_name| {
                    let is_ac = source_repr.modifiers.get(modifier_name.as_str())
                        .map(|m| m.is_access_control)
                        .unwrap_or(false);

                    #[cfg(test)]
                    eprintln!("  Checking modifier '{}': is_access_control = {}", modifier_name, is_ac);

                    is_ac
                })
                .cloned()
                .collect();

            if !access_control_modifiers.is_empty() {
                function_modifiers.insert(func_name.clone(), access_control_modifiers);
            }
        }

        Ok(function_modifiers)
    }
}

impl Default for SourceAccessControlScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner for SourceAccessControlScanner {
    fn id(&self) -> &'static str {
        "source-access-control-modifiers"
    }

    fn name(&self) -> &'static str {
        "Source-Level Access Control Modifier Detector"
    }

    fn description(&self) -> &'static str {
        "Detects access control modifiers in Solidity source using tree-sitter queries (to reduce false positives)"
    }

    fn severity(&self) -> Severity {
        Severity::Low  // This scanner is for reducing false positives, not finding new issues
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn scan(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        Ok(Vec::new())
    }

    fn required_representations(&self) -> crate::representations::RepresentationSet {
        crate::representations::RepresentationSet::new()
    }
}

pub fn get_functions_with_modifiers(source: &str, contract_name: &str) -> HashMap<String, Vec<String>> {
    let source_repr = match SourceRepresentation::from_source(source, "unknown.sol", contract_name) {
        Ok(repr) => repr,
        Err(_) => return HashMap::new(),
    };

    let scanner = SourceAccessControlScanner::new();
    scanner.analyze_ast(&source_repr).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modifier_detection() {
        let source = r#"
        contract Test {
            modifier onlyOwner() {
                require(msg.sender == owner);
                _;
            }

            function setOwner(address newOwner) external onlyOwner {
                owner = newOwner;
            }

            function unsafeSetOwner(address newOwner) external {
                owner = newOwner;
            }
        }
        "#;

        let result = get_functions_with_modifiers(source, "Test");

        eprintln!("Functions found: {:?}", result.keys().collect::<Vec<_>>());
        for (func, mods) in &result {
            eprintln!("  {} -> {:?}", func, mods);
        }

        assert!(result.contains_key("setOwner"));
        assert!(result["setOwner"].contains(&"onlyOwner".to_string()));

        assert!(!result.contains_key("unsafeSetOwner"));
    }

    #[test]
    fn test_multiple_modifiers() {
        let source = r#"
        contract Test {
            modifier onlyAdmin() { _; }
            modifier whenNotPaused() { _; }

            function criticalOp() external onlyAdmin whenNotPaused {
            }
        }
        "#;

        let result = get_functions_with_modifiers(source, "Test");

        assert!(result.contains_key("criticalOp"));
        assert_eq!(result["criticalOp"].len(), 1);
        assert!(result["criticalOp"].contains(&"onlyAdmin".to_string()));
    }

    #[test]
    fn test_no_access_control_modifiers() {
        let source = r#"
        contract Test {
            modifier validAddress(address addr) {
                require(addr != address(0));
                _;
            }

            function setAddress(address addr) external validAddress(addr) {
            }
        }
        "#;

        let result = get_functions_with_modifiers(source, "Test");

        assert!(!result.contains_key("setAddress"));
    }
}
