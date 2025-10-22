use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMConfig {
    pub provider: ProviderConfig,

    pub enabled_scanners: Vec<String>,

    pub global: GlobalSettings,

    #[serde(default)]
    pub custom_scanners: Vec<CustomScannerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ProviderConfig {
    #[serde(rename = "openai")]
    OpenAI {
        model: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        api_key: Option<String>, // If not provided, use OPENAI_API_KEY env var
        #[serde(skip_serializing_if = "Option::is_none")]
        base_url: Option<String>, // For custom endpoints
    },
    #[serde(rename = "anthropic")]
    Anthropic {
        model: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        api_key: Option<String>,
    },
    #[serde(rename = "local")]
    Local { endpoint: String, model: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalSettings {
    #[serde(default = "default_temperature")]
    pub default_temperature: f32,

    #[serde(default = "default_max_tokens")]
    pub default_max_tokens: u32,

    #[serde(default = "default_confidence_threshold")]
    pub default_confidence_threshold: f32,

    #[serde(default = "default_include_low_severity")]
    pub include_low_severity: bool,

    #[serde(default = "default_retry_attempts")]
    pub retry_attempts: u32,

    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,

    #[serde(default = "default_concurrent_requests")]
    pub concurrent_requests: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomScannerConfig {
    pub name: String,
    pub template: String,
    pub description: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence_threshold: Option<f32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_low_severity: Option<bool>,

    #[serde(default)]
    pub focus_areas: Vec<String>,
}

fn default_temperature() -> f32 {
    0.2
}
fn default_max_tokens() -> u32 {
    4000
}
fn default_confidence_threshold() -> f32 {
    0.5
}
fn default_include_low_severity() -> bool {
    false
}
fn default_retry_attempts() -> u32 {
    3
}
fn default_timeout_seconds() -> u64 {
    60
}
fn default_concurrent_requests() -> usize {
    4
}

impl Default for GlobalSettings {
    fn default() -> Self {
        Self {
            default_temperature: default_temperature(),
            default_max_tokens: default_max_tokens(),
            default_confidence_threshold: default_confidence_threshold(),
            include_low_severity: default_include_low_severity(),
            retry_attempts: default_retry_attempts(),
            timeout_seconds: default_timeout_seconds(),
            concurrent_requests: default_concurrent_requests(),
        }
    }
}

impl Default for LLMConfig {
    fn default() -> Self {
        Self {
            provider: ProviderConfig::OpenAI {
                model: "gpt-4o".to_string(),
                api_key: None,
                base_url: None,
            },
            enabled_scanners: vec![
                "general".to_string(),
                "reentrancy".to_string(),
                "access_control".to_string(),
            ],
            global: GlobalSettings::default(),
            custom_scanners: Vec::new(),
        }
    }
}

impl LLMConfig {
    pub fn from_yaml_file(path: impl AsRef<Path>) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    pub fn from_json_file(path: impl AsRef<Path>) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = serde_json::from_str(&content)?;
        Ok(config)
    }

    pub fn from_env() -> Result<Self> {
        let mut config = Self::default();

        if let Ok(model) = std::env::var("LLM_MODEL") {
            if let ProviderConfig::OpenAI {
                model: ref mut m, ..
            } = config.provider
            {
                *m = model;
            }
        }

        if let Ok(temp) = std::env::var("LLM_TEMPERATURE") {
            if let Ok(t) = temp.parse::<f32>() {
                config.global.default_temperature = t;
            }
        }

        if let Ok(threshold) = std::env::var("LLM_CONFIDENCE_THRESHOLD") {
            if let Ok(t) = threshold.parse::<f32>() {
                config.global.default_confidence_threshold = t;
            }
        }

        if let Ok(scanners) = std::env::var("LLM_ENABLED_SCANNERS") {
            config.enabled_scanners = scanners.split(',').map(|s| s.trim().to_string()).collect();
        }

        Ok(config)
    }

    pub fn save_yaml(&self, path: impl AsRef<Path>) -> Result<()> {
        let content = serde_yaml::to_string(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    pub fn save_json(&self, path: impl AsRef<Path>) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

pub const EXAMPLE_CONFIG: &str = r#"
# LLM Scanner Configuration

provider:
  type: openai
  model: gpt-4o
  # api_key: sk-...  # Optional, defaults to OPENAI_API_KEY env var

enabled_scanners:
  - general
  - reentrancy
  - access_control
  - overflow
  - logic_error

global:
  default_temperature: 0.2
  default_max_tokens: 4000
  default_confidence_threshold: 0.5
  include_low_severity: false
  retry_attempts: 3
  timeout_seconds: 60
  concurrent_requests: 4

custom_scanners:
  - name: defi_specific
    template: general_vulnerability
    description: "DeFi-specific vulnerability scanner"
    temperature: 0.25
    max_tokens: 5000
    confidence_threshold: 0.6
    focus_areas:
      - "Flash loan attacks"
      - "Price manipulation"
      - "MEV vulnerabilities"
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = LLMConfig::default();
        assert!(matches!(config.provider, ProviderConfig::OpenAI { .. }));
        assert_eq!(config.global.default_temperature, 0.2);
    }

    #[test]
    fn test_config_serialization() {
        let config = LLMConfig::default();
        let yaml = serde_yaml::to_string(&config).unwrap();
        let parsed: LLMConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(config.enabled_scanners, parsed.enabled_scanners);
    }
}
