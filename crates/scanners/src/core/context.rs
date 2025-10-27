use crate::representations::{Representation, RepresentationBundle};
use anyhow::Result;
use lru::LruCache;
use parking_lot::RwLock;
use std::any::Any;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;

#[derive(Debug, Clone, Default)]
pub struct ContractInfo {
    pub name: String,
    pub source_path: Option<String>,
    pub source_code: Option<String>,
    pub compiler_version: Option<String>,
    pub optimization_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub parallel_execution: bool,
    pub cache_enabled: bool,
    pub max_cache_size: usize,
    pub timeout_ms: Option<u64>,
    pub deduplication_enabled: bool,
    pub deduplication_line_window: usize,
    pub min_confidence: Option<f64>,
    pub category_thresholds: HashMap<String, f64>,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        let mut category_thresholds = HashMap::new();

        category_thresholds.insert("reentrancy".to_string(), 0.60);
        category_thresholds.insert("access".to_string(), 0.55);
        category_thresholds.insert("unchecked".to_string(), 0.60);
        category_thresholds.insert("dos".to_string(), 0.60);
        category_thresholds.insert("dangerous".to_string(), 0.65);

        Self {
            parallel_execution: true,
            cache_enabled: true,
            max_cache_size: 1000,
            timeout_ms: Some(60_000), // 1 minute default
            deduplication_enabled: true,
            deduplication_line_window: 3,
            min_confidence: None, // Show all by default
            category_thresholds,
        }
    }
}

impl ScannerConfig {
    pub fn meets_threshold(&self, scanner_id: &str, confidence: f64) -> bool {
        if let Some(min_conf) = self.min_confidence {
            if confidence < min_conf {
                return false;
            }
        }

        let category = Self::extract_category(scanner_id);
        if let Some(&threshold) = self.category_thresholds.get(&category) {
            confidence >= threshold
        } else {
            true // No threshold defined, allow
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
}

pub struct AnalysisCache {
    entries: LruCache<String, Arc<dyn Any + Send + Sync>>,
}

impl AnalysisCache {
    pub fn new(max_size: usize) -> Self {
        let capacity = NonZeroUsize::new(max_size.max(1)).unwrap();
        Self {
            entries: LruCache::new(capacity),
        }
    }

    pub fn get_or_compute<T, F>(&mut self, key: &str, compute: F) -> Result<Arc<T>>
    where
        T: Send + Sync + 'static,
        F: FnOnce() -> Result<T>,
    {
        if let Some(entry) = self.entries.get(key) {
            if let Some(value) = entry.downcast_ref::<Arc<T>>() {
                return Ok(value.clone());
            }
        }

        let value = Arc::new(compute()?);
        self.entries
            .put(key.to_string(), value.clone() as Arc<dyn Any + Send + Sync>);

        Ok(value)
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn stats(&self) -> CacheStats {
        CacheStats {
            size: self.entries.len(),
            capacity: self.entries.cap().get(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub size: usize,
    pub capacity: usize,
}

pub struct AnalysisContext {
    representations: RepresentationBundle,
    cache: Arc<RwLock<AnalysisCache>>,
    contract_info: ContractInfo,
    config: ScannerConfig,
    metadata: HashMap<String, Arc<dyn Any + Send + Sync>>,
}

impl AnalysisContext {
    pub fn new(representations: RepresentationBundle) -> Self {
        Self {
            representations,
            cache: Arc::new(RwLock::new(AnalysisCache::new(1000))),
            contract_info: ContractInfo::default(),
            config: ScannerConfig::default(),
            metadata: HashMap::new(),
        }
    }

    pub fn with_config(representations: RepresentationBundle, config: ScannerConfig) -> Self {
        let cache_size = config.max_cache_size;
        Self {
            representations,
            cache: Arc::new(RwLock::new(AnalysisCache::new(cache_size))),
            contract_info: ContractInfo::default(),
            config,
            metadata: HashMap::new(),
        }
    }

    pub fn new_with_source(
        representations: RepresentationBundle,
        contract_info: ContractInfo,
        config: ScannerConfig,
        source_code: &str,
    ) -> Self {
        let cache_size = config.max_cache_size;
        let mut contract_info = contract_info;
        contract_info.source_code = Some(source_code.to_string());

        Self {
            representations,
            cache: Arc::new(RwLock::new(AnalysisCache::new(cache_size))),
            contract_info,
            config,
            metadata: HashMap::new(),
        }
    }

    pub fn get_representation<T: Representation + 'static>(&self) -> Result<&T> {
        self.representations.get::<T>()
    }

    pub fn has_representation<T: Representation + 'static>(&self) -> bool {
        self.representations.has::<T>()
    }

    pub fn get_or_compute<T, F>(&self, key: &str, compute: F) -> Result<Arc<T>>
    where
        T: Send + Sync + 'static,
        F: FnOnce() -> Result<T>,
    {
        if self.config.cache_enabled {
            self.cache.write().get_or_compute(key, compute)
        } else {
            Ok(Arc::new(compute()?))
        }
    }

    pub fn set_contract_info(&mut self, info: ContractInfo) {
        self.contract_info = info;
    }

    pub fn contract_info(&self) -> &ContractInfo {
        &self.contract_info
    }

    pub fn config(&self) -> &ScannerConfig {
        &self.config
    }

    pub fn set_metadata<T: Send + Sync + 'static>(&mut self, key: String, value: T) {
        self.metadata.insert(key, Arc::new(value));
    }

    pub fn get_metadata<T: 'static>(&self, key: &str) -> Option<&T> {
        self.metadata.get(key).and_then(|v| v.downcast_ref::<T>())
    }

    pub fn source_code(&self) -> Option<&str> {
        self.contract_info.source_code.as_deref()
    }

    pub fn contract_name(&self) -> Option<&str> {
        if self.contract_info.name.is_empty() {
            None
        } else {
            Some(&self.contract_info.name)
        }
    }
}