use crate::core::Scanner;
use std::collections::HashMap;
use std::sync::Arc;

pub struct ScannerRegistry {
    scanners: HashMap<String, Arc<dyn Scanner>>,
}

impl ScannerRegistry {
    pub fn new() -> Self {
        Self {
            scanners: HashMap::new(),
        }
    }

    pub fn register<S: Scanner + 'static>(&mut self, scanner: S) {
        let id = scanner.id().to_string();
        self.scanners.insert(id, Arc::new(scanner));
    }

    pub fn register_llm_scanner(&mut self, scanner: Arc<dyn Scanner>) {
        let id = scanner.id().to_string();
        self.scanners.insert(id, scanner);
    }

    pub fn get(&self, id: &str) -> Option<Arc<dyn Scanner>> {
        self.scanners.get(id).cloned()
    }

    pub fn all(&self) -> Vec<Arc<dyn Scanner>> {
        self.scanners.values().cloned().collect()
    }

    pub fn by_severity(&self, severity: crate::core::Severity) -> Vec<Arc<dyn Scanner>> {
        self.scanners
            .values()
            .filter(|s| s.severity() == severity)
            .cloned()
            .collect()
    }

    pub fn enabled(&self) -> Vec<Arc<dyn Scanner>> {
        self.scanners
            .values()
            .filter(|s| s.enabled_by_default())
            .cloned()
            .collect()
    }

    pub fn list_ids(&self) -> Vec<String> {
        self.scanners.keys().cloned().collect()
    }
}

impl Default for ScannerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ScannerRegistryBuilder {
    registry: ScannerRegistry,
}

impl ScannerRegistryBuilder {
    pub fn new() -> Self {
        Self {
            registry: ScannerRegistry::new(),
        }
    }

    pub fn with_scanner<S: Scanner + 'static>(mut self, scanner: S) -> Self {
        self.registry.register(scanner);
        self
    }

    pub fn with_defaults(mut self) -> Self {
        let defaults = ScannerRegistry::default();
        for (id, scanner) in defaults.scanners {
            self.registry.scanners.insert(id, scanner);
        }
        self
    }

    pub fn build(self) -> ScannerRegistry {
        self.registry
    }
}

impl Default for ScannerRegistryBuilder {
    fn default() -> Self {
        Self::new()
    }
}
