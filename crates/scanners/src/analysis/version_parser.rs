//! Solidity Version Parser
//!
//! Extracts and parses Solidity version from pragma statements to enable
//! version-aware vulnerability detection.

use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolidityVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl SolidityVersion {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }

    pub fn is_at_least(&self, major: u32, minor: u32, patch: u32) -> bool {
        match self.major.cmp(&major) {
            Ordering::Greater => true,
            Ordering::Less => false,
            Ordering::Equal => match self.minor.cmp(&minor) {
                Ordering::Greater => true,
                Ordering::Less => false,
                Ordering::Equal => self.patch >= patch,
            },
        }
    }

    pub fn has_builtin_overflow_protection(&self) -> bool {
        self.is_at_least(0, 8, 0)
    }
}

impl PartialOrd for SolidityVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SolidityVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.major.cmp(&other.major) {
            Ordering::Equal => match self.minor.cmp(&other.minor) {
                Ordering::Equal => self.patch.cmp(&other.patch),
                other => other,
            },
            other => other,
        }
    }
}

pub fn parse_solidity_version(source: &str) -> Option<SolidityVersion> {
    let pragma_start = source.find("pragma solidity")?;
    let pragma_section = &source[pragma_start..];

    let pragma_end = pragma_section.find(';')?;
    let pragma = &pragma_section[..pragma_end];

    let version_str = pragma.trim_start_matches("pragma solidity").trim();

    parse_version_constraint(version_str)
}

fn parse_version_constraint(constraint: &str) -> Option<SolidityVersion> {
    let cleaned = constraint
        .trim()
        .trim_start_matches('^')
        .trim_start_matches('~')
        .trim_start_matches(">=")
        .trim_start_matches("<=")
        .trim_start_matches('>')
        .trim_start_matches('<')
        .trim();

    let version_part = cleaned.split_whitespace().next()?;

    let parts: Vec<&str> = version_part.split('.').collect();

    if parts.is_empty() {
        return None;
    }

    let major = parts.get(0)?.parse::<u32>().ok()?;
    let minor = parts.get(1).and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    let patch = parts.get(2).and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);

    Some(SolidityVersion::new(major, minor, patch))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_exact_version() {
        let source = "pragma solidity 0.8.19;";
        let version = parse_solidity_version(source).unwrap();
        assert_eq!(version, SolidityVersion::new(0, 8, 19));
    }

    #[test]
    fn test_parse_caret_version() {
        let source = "pragma solidity ^0.8.0;";
        let version = parse_solidity_version(source).unwrap();
        assert_eq!(version, SolidityVersion::new(0, 8, 0));
    }

    #[test]
    fn test_parse_range_version() {
        let source = "pragma solidity >=0.7.0 <0.9.0;";
        let version = parse_solidity_version(source).unwrap();
        assert_eq!(version, SolidityVersion::new(0, 7, 0));
    }

    #[test]
    fn test_parse_tilde_version() {
        let source = "pragma solidity ~0.8.0;";
        let version = parse_solidity_version(source).unwrap();
        assert_eq!(version, SolidityVersion::new(0, 8, 0));
    }

    #[test]
    fn test_is_at_least() {
        let v = SolidityVersion::new(0, 8, 19);
        assert!(v.is_at_least(0, 8, 0));
        assert!(v.is_at_least(0, 8, 19));
        assert!(v.is_at_least(0, 7, 0));
        assert!(!v.is_at_least(0, 9, 0));
        assert!(!v.is_at_least(1, 0, 0));
    }

    #[test]
    fn test_has_builtin_overflow_protection() {
        assert!(SolidityVersion::new(0, 8, 0).has_builtin_overflow_protection());
        assert!(SolidityVersion::new(0, 8, 19).has_builtin_overflow_protection());
        assert!(SolidityVersion::new(1, 0, 0).has_builtin_overflow_protection());
        assert!(!SolidityVersion::new(0, 7, 6).has_builtin_overflow_protection());
        assert!(!SolidityVersion::new(0, 6, 12).has_builtin_overflow_protection());
    }

    #[test]
    fn test_version_ordering() {
        let v1 = SolidityVersion::new(0, 7, 0);
        let v2 = SolidityVersion::new(0, 8, 0);
        let v3 = SolidityVersion::new(0, 8, 19);

        assert!(v2 > v1);
        assert!(v3 > v2);
        assert!(v1 < v2);
        assert!(v2 < v3);
    }

    #[test]
    fn test_real_world_pragma() {
        let source = r#"
            pragma solidity ^0.8.0;

            contract Token {
            }
        "#;

        let version = parse_solidity_version(source).unwrap();
        assert_eq!(version, SolidityVersion::new(0, 8, 0));
        assert!(version.has_builtin_overflow_protection());
    }

    #[test]
    fn test_old_version() {
        let source = "pragma solidity ^0.6.12;";
        let version = parse_solidity_version(source).unwrap();
        assert_eq!(version, SolidityVersion::new(0, 6, 12));
        assert!(!version.has_builtin_overflow_protection());
    }
}
