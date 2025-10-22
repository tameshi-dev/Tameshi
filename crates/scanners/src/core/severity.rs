use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical => write!(f, "Critical"),
            Self::High => write!(f, "High"),
            Self::Medium => write!(f, "Medium"),
            Self::Low => write!(f, "Low"),
            Self::Informational => write!(f, "Informational"),
        }
    }
}

impl Severity {
    pub fn color(&self) -> &'static str {
        match self {
            Self::Critical => "red",
            Self::High => "bright red",
            Self::Medium => "yellow",
            Self::Low => "bright yellow",
            Self::Informational => "blue",
        }
    }

    pub fn emoji(&self) -> &'static str {
        match self {
            Self::Critical => "🔴",
            Self::High => "🟠",
            Self::Medium => "🟡",
            Self::Low => "🟢",
            Self::Informational => "🔵",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::High => write!(f, "High"),
            Self::Medium => write!(f, "Medium"),
            Self::Low => write!(f, "Low"),
        }
    }
}

impl Confidence {
    pub fn percentage(&self) -> u8 {
        match self {
            Self::High => 90,
            Self::Medium => 60,
            Self::Low => 30,
        }
    }

    pub fn to_score(&self) -> f64 {
        self.percentage() as f64 / 100.0
    }
}
