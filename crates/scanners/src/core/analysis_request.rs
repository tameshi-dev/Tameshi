use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisRequest {
    pub source: AnalysisSource,

    pub config: AnalysisConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnalysisSource {
    File(PathBuf),

    Memory(String),

    Directory(PathBuf),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    pub scanners: ScannerSelection,

    pub llm_config: Option<LLMConfig>,

    pub correlation_config: CorrelationConfig,

    pub output: OutputConfig,

    pub performance: PerformanceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerSelection {
    pub enable_deterministic: bool,

    pub enable_llm: bool,

    pub include: Vec<String>,

    pub exclude: Vec<String>,

    pub vulnerability_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMConfig {
    pub model: String,

    pub temperature: f32,

    pub max_tokens: u32,

    pub timeout_seconds: u64,

    pub debug_prompts: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationConfig {
    pub enabled: bool,

    pub threshold: f64,

    pub strategies: Vec<String>,

    pub enable_cross_validation: bool,

    pub confidence_boost: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    pub format: OutputFormat,

    pub include_snippets: bool,

    pub include_data_flow: bool,

    pub include_remediation: bool,

    pub verbosity: Verbosity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OutputFormat {
    Markdown,

    Json,

    Sarif,

    Lsp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verbosity {
    Quiet,
    Normal,
    Verbose,
    Debug,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub parallel_scanners: bool,

    pub max_parallel: usize,

    pub scanner_timeout: u64,

    pub enable_caching: bool,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            scanners: ScannerSelection::default(),
            llm_config: Some(LLMConfig::default()),
            correlation_config: CorrelationConfig::default(),
            output: OutputConfig::default(),
            performance: PerformanceConfig::default(),
        }
    }
}

impl Default for ScannerSelection {
    fn default() -> Self {
        Self {
            enable_deterministic: true,
            enable_llm: true,
            include: Vec::new(),
            exclude: Vec::new(),
            vulnerability_types: Vec::new(),
        }
    }
}

impl Default for LLMConfig {
    fn default() -> Self {
        Self {
            model: "o1-mini".to_string(),
            temperature: 0.1,
            max_tokens: 4000,
            timeout_seconds: 60,
            debug_prompts: false,
        }
    }
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: 0.5,
            strategies: vec![
                "LocationBased".to_string(),
                "PatternBased".to_string(),
                "Enhanced".to_string(),
            ],
            enable_cross_validation: true,
            confidence_boost: 0.2,
        }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: OutputFormat::Markdown,
            include_snippets: true,
            include_data_flow: false,
            include_remediation: true,
            verbosity: Verbosity::Normal,
        }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            parallel_scanners: true,
            max_parallel: 8,
            scanner_timeout: 300,
            enable_caching: false,
        }
    }
}

impl AnalysisRequest {
    pub fn from_file(path: PathBuf) -> Self {
        Self {
            source: AnalysisSource::File(path),
            config: AnalysisConfig::default(),
        }
    }

    pub fn from_source(source: String) -> Self {
        Self {
            source: AnalysisSource::Memory(source),
            config: AnalysisConfig::default(),
        }
    }

    pub fn with_config(mut self, config: AnalysisConfig) -> Self {
        self.config = config;
        self
    }

    pub fn deterministic_only(mut self) -> Self {
        self.config.scanners.enable_llm = false;
        self
    }

    pub fn llm_only(mut self) -> Self {
        self.config.scanners.enable_deterministic = false;
        self
    }

    pub fn with_llm_model(mut self, model: String) -> Self {
        if let Some(ref mut llm_config) = self.config.llm_config {
            llm_config.model = model;
        }
        self
    }

    pub fn without_correlation(mut self) -> Self {
        self.config.correlation_config.enabled = false;
        self
    }

    pub fn with_format(mut self, format: OutputFormat) -> Self {
        self.config.output.format = format;
        self
    }
}

impl AnalysisSource {
    pub fn load(&self) -> anyhow::Result<String> {
        match self {
            AnalysisSource::File(path) => std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("Failed to read file {}: {}", path.display(), e)),
            AnalysisSource::Memory(source) => Ok(source.clone()),
            AnalysisSource::Directory(_) => {
                Err(anyhow::anyhow!("Directory analysis not yet implemented"))
            }
        }
    }
}
